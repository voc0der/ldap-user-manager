<?php
declare(strict_types=1);

set_include_path(".:" . __DIR__ . "/../includes/");
require_once "web_functions.inc.php";
require_once "ldap_functions.inc.php";
require_once "module_functions.inc.php";
require_once "apprise_helpers.inc.php";

@session_start();
set_page_access('admin');

// CSRF token (harmless if authelia.php ignores it; future-proof)
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$CSRF = $_SESSION['csrf'];

// Resolve Authelia paths (like authelia.php)
$AUTHELIA_DIR = getenv('AUTHELIA_DIR')
  ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
$STATUS = $AUTHELIA_DIR . '/status.json';
$API    = $THIS_MODULE_PATH . '/authelia.php';

// Options
$PLUS_ALIAS_NORMALIZATION = true;

// Helpers
function h(?string $s): string {
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function strip_plus_tag(string $email): string {
  if (strpos($email, '+') === false) return $email;
  return preg_replace('/^([^+@]+)\+[^@]+(@.+)$/', '$1$2', $email) ?: $email;
}

// Load snapshot
$status = ['generated_ts'=>0,'totp'=>[],'webauthn'=>[]];
if (is_file($STATUS)) {
  $raw = @file_get_contents($STATUS);
  if ($raw !== false) {
    $j = json_decode($raw, true);
    if (is_array($j)) $status = $j;
  }
}
$gen = (int)($status['generated_ts'] ?? 0);
$totp = is_array($status['totp'] ?? null) ? $status['totp'] : [];
$web  = is_array($status['webauthn'] ?? null) ? $status['webauthn'] : [];

// LDAP valid sets
$ldap = open_ldap_connection();
$people = ldap_get_user_list($ldap);
$uidsLC = []; $emailsLC = [];
foreach ($people as $uid => $attribs) {
  $uidsLC[strtolower($uid)] = $uid;
  $mail = '';
  if (isset($attribs['mail'])) $mail = is_array($attribs['mail']) ? ($attribs['mail'][0] ?? '') : $attribs['mail'];
  if ($mail) $emailsLC[strtolower($mail)] = $uid;
}

// Build orphan lists
$orphTOTP = [];      // [subject]
$orphWeb  = [];      // [subject => count]
$subjects = [];      // unique set of orphan subjects

$resolveNotOrphan = function(string $subject) use ($uidsLC, $emailsLC, $PLUS_ALIAS_NORMALIZATION): bool {
  $sl = strtolower(trim($subject));
  if (isset($uidsLC[$sl])) return true;
  if (strpos($sl, '@') !== false) {
    $key = $PLUS_ALIAS_NORMALIZATION ? strtolower(strip_plus_tag($subject)) : $sl;
    if (isset($emailsLC[$sl]) || isset($emailsLC[$key])) return true;
  }
  return false;
};

foreach ($totp as $subj => $present) {
  if (!$present) continue;
  if (!$resolveNotOrphan((string)$subj)) {
    $orphTOTP[] = (string)$subj;
    $subjects[(string)$subj] = true;
  }
}
foreach ($web as $subj => $count) {
  if ((int)$count <= 0) continue;
  if (!$resolveNotOrphan((string)$subj)) {
    $orphWeb[(string)$subj] = (int)$count;
    $subjects[(string)$subj] = true;
  }
}

$totalSubjects = count($subjects);

// Render
render_header("$ORGANISATION_NAME account manager");
render_submenu();
?>
<style>
.wrap-narrow { max-width: 1100px; margin: 18px auto 32px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.08); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading { background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02)); color:#cfe9ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase; padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08); }
.panel-modern .panel-title { margin:0; font-size:16px; letter-spacing:.3px; }
.panel-modern .panel-body { padding:16px 16px 18px; }
.help-min { color:#8aa0b2; font-size:12px; margin-top:6px; }
.badge-soft { background:#15202b; color:#9ad1ff; border:1px solid rgba(255,255,255,.12); border-radius:999px; padding:2px 8px; font-weight:600; }
.table-modern > thead > tr > th { border-color:rgba(255,255,255,.08); color:#a9c4da; font-weight:600; }
.table-modern > tbody > tr > td { border-color:rgba(255,255,255,.06); color:#cfe9ff; vertical-align:middle; }
.table-modern > tbody > tr:hover { background:#0f151c; }
.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.12); color:#cfe9ff; }
.btn-soft:hover { background:#17202b; }
.kv { color:#9fb6c9; font-size:12px; margin-top:8px; }
.kv code { color:#cfe9ff; }
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
        </div>
      </div>
      <div class="pull-right">
        <?php if ($totalSubjects > 0): ?>
          <button id="bulk_delete_all" class="btn btn-danger btn-pill">Delete ALL orphans</button>
        <?php endif; ?>
      </div>
    </div>

    <div class="panel-body">
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
    var rows = $('#orphans tbody tr').length ? $('#orphans tbody tr') : $('tr[data-kind]');
    var picked = rows.has('input.chk_one:checked');
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
      <?php
      // tiny admin-facing Apprise (bulk queued)
      $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
      $admin = $GLOBALS['USER_ID'] ?? ($_SESSION['user_id'] ?? 'unknown');
      $appriseBody = '🧹 `' . h($host) . '` **MFA Orphans bulk queued** by <code>' . h($admin) . '</code>';
      ?>
      // fire-and-forget via img beacon to avoid CORS; backend uses curl anyway
      (new Image()).src = 'data:image/gif;base64,R0lGODlhAQABAAAAACw=';
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
