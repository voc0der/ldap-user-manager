<?php
declare(strict_types=1);

set_include_path(".:" . __DIR__ . "/../includes/");
require_once "web_functions.inc.php";
require_once "ldap_functions.inc.php";
require_once "module_functions.inc.php";
require_once "apprise_helpers.inc.php";

@session_start();
set_page_access('admin');

// ====== TUNABLES =============================================================
// We consider a subject "NOT orphan" only if it matches an LDAP UID (case-insensitive).
// Emails are intentionally ignored here to avoid hiding real orphans.
$MATCH_BY_UID_ONLY = true;

// CSRF token (harmless if authelia.php ignores it; future-proof)
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$CSRF = $_SESSION['csrf'];

// Resolve Authelia paths (like authelia.php)
$AUTHELIA_DIR = getenv('AUTHELIA_DIR')
  ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
$STATUS = $AUTHELIA_DIR . '/status.json';
$API    = $THIS_MODULE_PATH . '/authelia.php';

// Helpers
function h(?string $s): string {
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ----------------------------------------------------------------------------
// Load snapshot
$status = ['generated_ts'=>0,'totp'=>[],'webauthn'=>[]];
$STATUS_EXISTS = is_file($STATUS);
$STATUS_BYTES  = $STATUS_EXISTS ? (int)@filesize($STATUS) : 0;

if ($STATUS_EXISTS) {
  $raw = @file_get_contents($STATUS);
  if ($raw !== false) {
    $j = json_decode($raw, true);
    if (is_array($j)) $status = $j;
  }
}
$gen  = (int)($status['generated_ts'] ?? 0);
$totp = is_array($status['totp'] ?? null) ? $status['totp'] : [];
$web  = is_array($status['webauthn'] ?? null) ? $status['webauthn'] : [];

// LDAP valid sets
$ldap   = open_ldap_connection();
$people = ldap_get_user_list($ldap);

$uidsLC = []; // lower(uid) => canonical uid
foreach ($people as $uid => $attribs) {
  $uidsLC[strtolower($uid)] = $uid;
}

// Build orphan lists
$orphTOTP = [];      // [subject]
$orphWeb  = [];      // [subject => count]
$subjects = [];      // unique set of orphan subjects

$resolveNotOrphan = function(string $subject) use ($uidsLC, $MATCH_BY_UID_ONLY): bool {
  $sl = strtolower(trim($subject));
  if ($MATCH_BY_UID_ONLY) {
    return isset($uidsLC[$sl]); // UID match only
  }
  // (kept for future extension if you ever want to toggle email logic again)
  return isset($uidsLC[$sl]);
};

foreach ($totp as $subj => $present) {
  if (!$present) continue;
  if (!$resolveNotOrphan((string)$subj)) {
    $orphTOTP[] = (string)$subj;
    $subjects[(string)$subj] = true;
  }
}
foreach ($web as $subj => $count) {
  // accept any "has devices" truthiness: int>0, or array with count key
  $has = is_array($count) ? (int)($count['count'] ?? 1) > 0 : ((int)$count > 0);
  if (!$has) continue;
  if (!$resolveNotOrphan((string)$subj)) {
    $orphWeb[(string)$subj] = is_array($count) ? (int)($count['count'] ?? 1) : (int)$count;
    if ($orphWeb[(string)$subj] <= 0) $orphWeb[(string)$subj] = 1; // at least one
    $subjects[(string)$subj] = true;
  }
}

$totalSubjects = count($subjects);

// ----------------------------------------------------------------------------
// Render
render_header("$ORGANISATION_NAME account manager");
render_submenu();
?>
<style>
/* ---- higher-contrast dark UI, Bootstrap 3 friendly ---- */
.wrap-narrow { max-width: 1100px; margin: 18px auto 32px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.10); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading {
  background:linear-gradient(180deg, rgba(255,255,255,.08), rgba(255,255,255,.02));
  color:#e4f3ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase;
  padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.12);
}
.panel-modern .panel-title { margin:0; font-size:16px; letter-spacing:.3px; }
.panel-modern .panel-body { padding:16px 16px 18px; }
.help-min { color:#9bb1c7; font-size:12px; margin-top:6px; }
.badge-soft { background:#0e1a28; color:#e4f3ff; border:1px solid rgba(255,255,255,.18); border-radius:999px; padding:2px 8px; font-weight:700; }
.table-modern > thead > tr > th { border-color:rgba(255,255,255,.14); color:#c7dbef; font-weight:700; }
.table-modern > tbody > tr > td { border-color:rgba(255,255,255,.10); color:#e9f3ff; vertical-align:middle; }
.table-modern > tbody > tr:hover { background:#101722; }
.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.18); color:#d9ecff; }
.btn-soft:hover { background:#17202b; }
.kv { color:#c7dbef; font-size:13px; margin-top:8px; }
.kv code { background:#0c1422; color:#e9f3ff; padding:2px 6px; border-radius:6px; border:1px solid rgba(255,255,255,.12); }

/* snapshot banner for status.json visibility */
.snap-hint { margin:10px 0 0; font-size:12px; color:#9bb1c7; }
.snap-hint .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.18); background:#0e1a28; color:#e4f3ff; }
</style>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <div class="pull-left">
        <h3 class="panel-title">
          MFA Orphans
          <span class="badge-soft" title="Unique subjects"><?php echo (int)$totalSubjects; ?> subjects</span>
          <span class="badge-soft" title="TOTP entries"><?php echo count($orphTOTP); ?> TOTP</span>
          <span class="badge-soft" title="WebAuthn entries"><?php echo count($orphWeb); ?> WebAuthn</span>
        </h3>
        <div class="kv">
          Snapshot: <code><?php echo $gen ? h(date('Y-m-d H:i:s T',$gen)) : 'unknown'; ?></code>
          <div class="snap-hint">
            status.json: <span class="pill"><?php echo $STATUS_EXISTS ? 'present' : 'missing'; ?></span>
            <?php if ($STATUS_EXISTS): ?> • size: <span class="pill"><?php echo (int)$STATUS_BYTES; ?> bytes</span><?php endif; ?>
          </div>
        </div>
      </div>
      <div class="pull-right">
        <?php if ($totalSubjects > 0): ?>
          <button id="bulk_delete_all" class="btn btn-danger btn-pill">Delete ALL orphans</button>
        <?php endif; ?>
      </div>
    </div>

    <div class="panel-body">
      <?php if (!$STATUS_EXISTS): ?>
        <div class="alert alert-warning" role="alert" style="margin:0 0 10px;">
          Couldn’t find <code><?php echo h($STATUS); ?></code>. The worker generates this file.
        </div>
      <?php endif; ?>

      <?php if ($totalSubjects === 0): ?>
        <div class="alert alert-success" role="alert" style="margin:0;">
          No MFA orphans detected. 🎉
        </div>
      <?php else: ?>

      <?php if (!empty($orphTOTP)): ?>
      <h4 style="margin-top:0;">TOTP (orphaned)</h4>
      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <thead><tr><th style="width:40px"><input type="checkbox" id="chk_all_totp"></th><th>Authelia subject</th><th style="width:180px">Action</th></tr></thead>
          <tbody>
          <?php foreach ($orphTOTP as $subj): ?>
            <tr data-kind="totp" data-user="<?php echo h($subj); ?>">
              <td><input type="checkbox" class="chk_one"></td>
              <td><code><?php echo h($subj); ?></code></td>
              <td>
                <form method="post" action="<?php echo h($API); ?>" class="inline frm-one">
                  <input type="hidden" name="op" value="totp.delete">
                  <input type="hidden" name="user" value="<?php echo h($subj); ?>">
                  <input type="hidden" name="csrf" value="<?php echo h($CSRF); ?>">
                  <button type="submit" class="btn btn-xs btn-danger btn-pill">Delete TOTP</button>
                </form>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <?php if (!empty($orphWeb)): ?>
      <h4>WebAuthn (orphaned)</h4>
      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <thead><tr><th style="width:40px"><input type="checkbox" id="chk_all_web"></th><th>Authelia subject</th><th>Device count</th><th style="width:220px">Action</th></tr></thead>
          <tbody>
          <?php foreach ($orphWeb as $subj => $cnt): ?>
            <tr data-kind="web" data-user="<?php echo h($subj); ?>">
              <td><input type="checkbox" class="chk_one"></td>
              <td><code><?php echo h($subj); ?></code></td>
              <td><?php echo (int)$cnt; ?></td>
              <td>
                <form method="post" action="<?php echo h($API); ?>" class="inline frm-one">
                  <input type="hidden" name="op" value="webauthn.delete">
                  <input type="hidden" name="user" value="<?php echo h($subj); ?>">
                  <input type="hidden" name="scope" value="all">
                  <input type="hidden" name="csrf" value="<?php echo h($CSRF); ?>">
                  <button type="submit" class="btn btn-xs btn-danger btn-pill">Delete WebAuthn (all)</button>
                </form>
                <button type="button" class="btn btn-xs btn-soft btn-pill btn-delete-both" data-user="<?php echo h($subj); ?>">Delete BOTH</button>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <div>
        <button id="bulk_delete_selected" class="btn btn-danger btn-pill">Delete selected</button>
        <span id="bulk_status" class="help-min" style="margin-left:10px;"></span>
      </div>

      <?php endif; ?>
    </div>
  </div>
</div>

<script>
// basic jQuery is already present in LUM
(function($){
  function postOne(payload) {
    return $.ajax({
      url: <?php echo json_encode($API); ?>,
      type: 'POST',
      data: payload,
      dataType: 'json'
    });
  }

  // master checkboxes
  $('#chk_all_totp').on('change', function(){
    $('tr[data-kind="totp"] .chk_one').prop('checked', this.checked);
  });
  $('#chk_all_web').on('change', function(){
    $('tr[data-kind="web"] .chk_one').prop('checked', this.checked);
  });

  // delete BOTH (TOTP + WebAuthn) for a row
  $('.btn-delete-both').on('click', function(){
    var user = $(this).data('user');
    var $status = $('#bulk_status');
    $status.text('Queuing deletes for ' + user + '…');

    // Queue TOTP then WebAuthn
    postOne({op:'totp.delete', user:user, csrf:<?php echo json_encode($CSRF); ?>})
      .always(function(){
        return postOne({op:'webauthn.delete', user:user, scope:'all', csrf:<?php echo json_encode($CSRF); ?>});
      })
      .done(function(){ $status.text('Queued BOTH for ' + user); })
      .fail(function(xhr){ $status.text('Failed queue for ' + user + ': ' + (xhr.responseText || xhr.status)); });
  });

  // bulk delete selected
  $('#bulk_delete_selected').on('click', function(){
    var picked = $('tr[data-kind]').has('input.chk_one:checked');
    var list = [];
    picked.each(function(){
      var $tr = $(this);
      var user = $tr.data('user');
      var kind = $tr.data('kind'); // 'totp' or 'web'
      if (kind === 'totp') list.push({op:'totp.delete', user:user});
      if (kind === 'web')  list.push({op:'webauthn.delete', user:user, scope:'all'});
    });
    if (!list.length) return;

    var $status = $('#bulk_status');
    $status.text('Queuing ' + list.length + ' action(s)…');

    (async function run(){
      var ok=0, fail=0;
      for (const p of list) {
        try { await postOne(Object.assign({csrf: <?php echo json_encode($CSRF); ?>}, p)); ok++; }
        catch(e){ fail++; }
      }
      $status.text('Queued: ' + ok + ', failed: ' + fail);
    })();
  });

  // bulk delete ALL
  $('#bulk_delete_all').on('click', function(){
    $('tr[data-kind] .chk_one').prop('checked', true);
    $('#bulk_delete_selected').click();
  });

})(jQuery);
</script>

<?php
ldap_close($ldap);
render_footer();
