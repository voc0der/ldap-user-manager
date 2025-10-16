<?php
declare(strict_types=1);

/**
 * MFA Orphans (TOTP + WebAuthn) — no full-page refresh
 * - Reads status.json
 * - Compares subjects to LDAP UIDs (case-insensitive)
 * - Queues deletes via authelia_api.php (AJAX)
 * - Polls status.json every 3s after actions until changes are visible
 */

set_include_path(".:" . __DIR__ . "/../includes/");
require_once "web_functions.inc.php";
require_once "ldap_functions.inc.php";
require_once "module_functions.inc.php";
require_once "apprise_helpers.inc.php";

@session_start();
set_page_access('admin');

// ====== OPTIONS ==============================================================
$MATCH_BY_UID_ONLY = true; // consider orphan if subject does not match an LDAP uid

// CSRF token (harmless if API ignores; future-proof)
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
$CSRF = $_SESSION['csrf'];

// Resolve Authelia paths
$AUTHELIA_DIR = getenv('AUTHELIA_DIR')
  ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
$STATUS = $AUTHELIA_DIR . '/status.json';

// Correct API endpoint
$API    = $THIS_MODULE_PATH . '/authelia_api.php';

function h(?string $s): string {
  return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function human_time_diff($now, $ts) {
  $diff = abs($now - $ts);
  $units = [31536000=>'year',2592000=>'month',604800=>'week',86400=>'day',3600=>'hour',60=>'minute',1=>'second'];
  foreach ($units as $secs=>$name) {
    if ($diff >= $secs) { $v = (int)floor($diff/$secs); return $v.' '.$name.($v>1?'s':''); }
  }
  return '0 seconds';
}

// ----------------------------------------------------------------------------
// Load snapshot on first render
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

// LDAP valid UIDs
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
  $has = is_array($count) ? (int)($count['count'] ?? 1) > 0 : ((int)$count > 0);
  if (!$has) continue;
  if (!$resolveNotOrphan((string)$subj)) {
    $orphWeb[(string)$subj] = is_array($count) ? (int)($count['count'] ?? 1) : (int)$count;
    if ($orphWeb[(string)$subj] <= 0) $orphWeb[(string)$subj] = 1;
    $subjects[(string)$subj] = true;
  }
}
$totalSubjects = count($subjects);

// Sets for rendering “Delete BOTH” only when truly in both lists
$hasTotp = [];
foreach ($orphTOTP as $s) $hasTotp[$s] = true;
$hasWeb  = [];
foreach ($orphWeb as $s => $_) $hasWeb[$s] = true;

// ----------------------------------------------------------------------------
// Render
render_header("$ORGANISATION_NAME account manager");
render_submenu();
?>
<style>
/* ---- dark UI, Bootstrap 3 friendly ---- */
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
.snap-hint { margin:10px 0 0; font-size:12px; color:#9bb1c7; }
.snap-hint .pill { display:inline-block; padding:2px 8px; border-radius:999px; border:1px solid rgba(255,255,255,.18); background:#0e1a28; color:#e4f3ff; }
.inline { display:inline-block; margin:0; }
.hidden { display:none !important; }
</style>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <div class="pull-left">
        <h3 class="panel-title">
          MFA Orphans
          <span class="badge-soft" id="count_subjects" title="Unique subjects"><?php echo (int)$totalSubjects; ?> subjects</span>
          <span class="badge-soft" id="count_totp" title="TOTP entries"><?php echo count($orphTOTP); ?> TOTP</span>
          <span class="badge-soft" id="count_web"  title="WebAuthn entries"><?php echo count($orphWeb); ?> WebAuthn</span>
        </h3>
        <div class="kv">
          Snapshot:
          <code id="snap_ts" title="UTC: <?php echo $gen ? h(gmdate('Y-m-d H:i:s \U\T\C', $gen)) : 'unknown'; ?>">
            <?php
              if ($gen) {
                $dt = new DateTime("@$gen");
                $dt->setTimezone(new DateTimeZone(date_default_timezone_get()));
                echo h($dt->format('Y-m-d H:i:s T'));
              } else {
                echo 'unknown';
              }
            ?>
          </code>
          <?php if ($gen): ?>
          <span class="help-min" id="snap_age">(≈ <?php echo h(human_time_diff(time(), $gen)); ?> ago)</span>
          <?php else: ?>
          <span class="help-min" id="snap_age"></span>
          <?php endif; ?>
          <div class="snap-hint">
            status.json: <span class="pill" id="snap_present"><?php echo $STATUS_EXISTS ? 'present' : 'missing'; ?></span>
            <?php if ($STATUS_EXISTS): ?> • size: <span class="pill" id="snap_size"><?php echo (int)$STATUS_BYTES; ?> bytes</span><?php else: ?>
              • size: <span class="pill" id="snap_size">0 bytes</span>
            <?php endif; ?>
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

      <div id="zero_state" class="<?php echo $totalSubjects === 0 ? '' : 'hidden'; ?>">
        <div class="alert alert-success" role="alert" style="margin:0;">
          No MFA orphans detected. 🎉
        </div>
      </div>

      <div id="tables_wrap" class="<?php echo $totalSubjects === 0 ? 'hidden' : ''; ?>">

      <?php if (!empty($orphTOTP)): ?>
      <h4 style="margin-top:0;">TOTP (orphaned)</h4>
      <div class="table-responsive">
        <table class="table table-striped table-modern" id="table_totp">
          <thead><tr><th style="width:40px"><input type="checkbox" id="chk_all_totp"></th><th>Authelia subject</th><th style="width:320px">Action</th></tr></thead>
          <tbody>
          <?php foreach ($orphTOTP as $subj): ?>
            <tr data-kind="totp" data-user="<?php echo h($subj); ?>">
              <td><input type="checkbox" class="chk_one"></td>
              <td class="col-user"><code><?php echo h($subj); ?></code></td>
              <td class="col-actions">
                <button type="button" class="btn btn-xs btn-danger btn-pill btn-del-totp" data-user="<?php echo h($subj); ?>">Delete TOTP</button>
                <?php if (isset($hasWeb[$subj])): ?>
                  <button type="button" class="btn btn-xs btn-soft btn-pill btn-delete-both" data-user="<?php echo h($subj); ?>">Delete TOTP + WebAuthn</button>
                <?php endif; ?>
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
        <table class="table table-striped table-modern" id="table_web">
          <thead><tr><th style="width:40px"><input type="checkbox" id="chk_all_web"></th><th>Authelia subject</th><th>Device count</th><th style="width:360px">Action</th></tr></thead>
          <tbody>
          <?php foreach ($orphWeb as $subj => $cnt): ?>
            <tr data-kind="web" data-user="<?php echo h($subj); ?>">
              <td><input type="checkbox" class="chk_one"></td>
              <td class="col-user"><code><?php echo h($subj); ?></code></td>
              <td class="col-count"><?php echo (int)$cnt; ?></td>
              <td class="col-actions">
                <button type="button" class="btn btn-xs btn-danger btn-pill btn-del-web" data-user="<?php echo h($subj); ?>">Delete WebAuthn (all)</button>
                <?php if (isset($hasTotp[$subj])): ?>
                  <button type="button" class="btn btn-xs btn-soft btn-pill btn-delete-both" data-user="<?php echo h($subj); ?>">Delete TOTP + WebAuthn</button>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>

      <div id="bulk_controls" class="<?php echo $totalSubjects > 0 ? '' : 'hidden'; ?>">
        <button id="bulk_delete_selected" class="btn btn-danger btn-pill">Delete selected</button>
        <span id="bulk_status" class="help-min" style="margin-left:10px;"></span>
      </div>

      </div><!-- /tables_wrap -->
    </div>
  </div>
</div>

<script>
(function($){
  var API  = <?php echo json_encode($API); ?>;
  var CSRF = <?php echo json_encode($CSRF); ?>;

  // Keep a local copy of the last-seen generated_ts so we can update snapshot header
  var lastGenTs = <?php echo (int)$gen; ?>;

  function setStatus(msg){ $('#bulk_status').text(msg); }

  function updateHeaderCounts(){
    // recompute from DOM
    var totpCount = $('tr[data-kind="totp"]').length;
    var webCount  = $('tr[data-kind="web"]').length;

    // unique subjects across both tables
    var seen = {};
    $('tr[data-kind]').each(function(){ seen[$(this).data('user')] = true; });
    var subjCount = Object.keys(seen).length;

    $('#count_totp').text(totpCount + ' TOTP');
    $('#count_web').text(webCount + ' WebAuthn');
    $('#count_subjects').text(subjCount + ' subjects');

    // hide/show zero state and controls
    if (totpCount + webCount === 0){
      $('#tables_wrap').addClass('hidden');
      $('#bulk_controls').addClass('hidden');
      $('#zero_state').removeClass('hidden');
    } else {
      $('#zero_state').addClass('hidden');
      $('#tables_wrap').removeClass('hidden');
      $('#bulk_controls').removeClass('hidden');
    }
  }

  function updateBothButtons(){
    // Only show "Delete TOTP + WebAuthn" when the subject exists in both tables currently
    $('tr[data-kind]').each(function(){
      var $tr  = $(this);
      var subj = $tr.data('user');
      var inTotp = $('tr[data-kind="totp"][data-user="'+subj+'"]').length > 0;
      var inWeb  = $('tr[data-kind="web"][data-user="'+subj+'"]').length > 0;
      var $bothBtn = $tr.find('.btn-delete-both');
      if (inTotp && inWeb){
        if (!$bothBtn.length){
          // add the button after the first action button
          var btn = $('<button type="button" class="btn btn-xs btn-soft btn-pill btn-delete-both" data-user="'+$('<div>').text(subj).html()+'">Delete TOTP + WebAuthn</button>');
          $tr.find('.col-actions').append(' ').append(btn);
        }
      } else {
        $bothBtn.remove();
      }
    });
  }

  function formatLocal(ts){
    var d = new Date(ts*1000);
    var pad = n => (n<10?'0':'')+n;
    var z  = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())+' '+z;
  }
  function humanAge(ts){
    var diff = Math.abs(Math.floor(Date.now()/1000) - ts);
    var units = [[31536000,'year'],[2592000,'month'],[604800,'week'],[86400,'day'],[3600,'hour'],[60,'minute'],[1,'second']];
    for (var i=0;i<units.length;i++){
      var s = units[i][0], n = units[i][1];
      if (diff>=s){ var v = Math.floor(diff/s); return v+' '+n+(v>1?'s':''); }
    }
    return '0 seconds';
  }

  // ---- status fetcher ----
  function fetchStatus(){
    return $.ajax({
      url: API + '?action=status&t=' + Date.now(),
      type: 'GET',
      dataType: 'json'
    });
  }

  // Apply a newly fetched snapshot to DOM for a set of "targets"
  // wantMap: { user: { totp:false? (meaning we want totp absent), web:0? (want web count == 0) } }
  function applySnapshot(snapshot, wantMap){
    if (!snapshot || typeof snapshot !== 'object') return {done:false};

    var totp = snapshot.totp || {};
    var web  = snapshot.webauthn || {};
    var changedSomething = false;
    var satisfiedAll = true;

    // Update header snapshot info if generated_ts changed
    if (snapshot.generated_ts && snapshot.generated_ts !== lastGenTs){
      lastGenTs = snapshot.generated_ts;
      $('#snap_ts').text(formatLocal(lastGenTs)).attr('title', 'UTC: ' + new Date(lastGenTs*1000).toUTCString());
      $('#snap_age').text('(≈ ' + humanAge(lastGenTs) + ' ago)');
      // We also update size/present opportunistically (we don’t know size here)
      $('#snap_present').text('present');
    }

    // For each target, check if desired state now visible
    Object.keys(wantMap).forEach(function(user){
      var want = wantMap[user] || {};
      // current presence:
      var curTotp = !!totp[user];
      var curWeb  = 0;
      if (web.hasOwnProperty(user)) {
        curWeb = (typeof web[user] === 'number') ? web[user] : (web[user] && typeof web[user].count === 'number' ? web[user].count : 0);
      }

      // Evaluate fulfillment
      var totpFulfilled = (want.hasOwnProperty('totp') ? (want.totp === false && curTotp === false) : true);
      var webFulfilled  = (want.hasOwnProperty('web')  ? (want.web  === 0     && curWeb  === 0)    : true);

      if (!totpFulfilled || !webFulfilled) satisfiedAll = false;

      // If fulfilled, mutate DOM for that section
      if (totpFulfilled){
        var $rowT = $('tr[data-kind="totp"][data-user="'+user+'"]');
        if ($rowT.length){
          $rowT.remove();
          changedSomething = true;
        }
      }
      if (webFulfilled){
        var $rowW = $('tr[data-kind="web"][data-user="'+user+'"]');
        if ($rowW.length){
          $rowW.remove();
          changedSomething = true;
        }
      }
    });

    if (changedSomething){
      updateHeaderCounts();
      updateBothButtons();
      // Also uncheck “select all” if lists changed
      $('#chk_all_totp, #chk_all_web').prop('checked', false);
    }

    return {done: satisfiedAll};
  }

  // Poller that keeps asking until wantMap is satisfied or timeout reached
  function pollUntilReflected(wantMap, maxTries){
    var tries = 0, max = maxTries || 60; // ~3 minutes @ 3s
    setStatus('Waiting for status.json update…');

    function tick(){
      tries++;
      fetchStatus()
        .done(function(snap){
          var res = applySnapshot(snap, wantMap);
          if (res.done){
            setStatus('Update reflected in status.json.');
            return; // stop (don’t schedule another tick)
          }
          if (tries < max){
            setTimeout(tick, 3000);
          } else {
            setStatus('Gave up waiting for status.json (will catch up later).');
          }
        })
        .fail(function(){
          if (tries < max){
            setTimeout(tick, 3000);
          } else {
            setStatus('Failed to read status.json repeatedly.');
          }
        });
    }
    setTimeout(tick, 3000);
  }

  function queueTotp(user){
    return $.ajax({ url: API, type: 'POST', dataType:'json', data: {op:'totp.delete', user:user, csrf:CSRF} });
  }
  function queueWeb(user){
    return $.ajax({ url: API, type: 'POST', dataType:'json', data: {op:'webauthn.delete', user:user, scope:'all', csrf:CSRF} });
  }

  // Single-row: Delete TOTP
  $(document).on('click', '.btn-del-totp', function(){
    var user = $(this).data('user');
    var $btn = $(this);
    $btn.prop('disabled', true).text('Queuing…');
    setStatus('Queuing TOTP delete for ' + user + '…');
    queueTotp(user)
      .done(function(res){
        setStatus('Queued TOTP for ' + user + (res && res.action_id ? ' ('+res.action_id+')' : ''));
        var want = {}; want[user] = {totp:false}; // we want totp to be absent
        pollUntilReflected(want, 80);
      })
      .fail(function(xhr){
        setStatus('Failed TOTP for ' + user + ': ' + (xhr.responseText || xhr.status));
        $btn.prop('disabled', false).text('Delete TOTP');
      });
  });

  // Single-row: Delete WebAuthn (all)
  $(document).on('click', '.btn-del-web', function(){
    var user = $(this).data('user');
    var $btn = $(this);
    $btn.prop('disabled', true).text('Queuing…');
    setStatus('Queuing WebAuthn delete for ' + user + '…');
    queueWeb(user)
      .done(function(res){
        setStatus('Queued WebAuthn for ' + user + (res && res.action_id ? ' ('+res.action_id+')' : ''));
        var want = {}; want[user] = {web:0}; // we want web count to be 0
        pollUntilReflected(want, 80);
      })
      .fail(function(xhr){
        setStatus('Failed WebAuthn for ' + user + ': ' + (xhr.responseText || xhr.status));
        $btn.prop('disabled', false).text('Delete WebAuthn (all)');
      });
  });

  // Single-row: Delete BOTH (TOTP then WebAuthn)
  $(document).on('click', '.btn-delete-both', function(){
    var user = $(this).data('user');
    var $btn = $(this);
    $btn.prop('disabled', true).text('Queuing…');
    setStatus('Queuing BOTH for ' + user + '…');

    // Queue both (sequential is fine)
    queueTotp(user)
      .always(function(){ return queueWeb(user); })
      .done(function(res){
        setStatus('Queued BOTH for ' + user + (res && res.action_id ? ' ('+res.action_id+')' : ''));
        var want = {}; want[user] = {totp:false, web:0};
        pollUntilReflected(want, 100);
      })
      .fail(function(xhr){
        setStatus('Failed BOTH for ' + user + ': ' + (xhr.responseText || xhr.status));
        $btn.prop('disabled', false).text('Delete TOTP + WebAuthn');
      });
  });

  // master checkboxes
  $('#chk_all_totp').on('change', function(){
    $('tr[data-kind="totp"] .chk_one').prop('checked', this.checked);
  });
  $('#chk_all_web').on('change', function(){
    $('tr[data-kind="web"] .chk_one').prop('checked', this.checked);
  });

  // bulk delete selected (AJAX + poll until reflected)
  $('#bulk_delete_selected').on('click', function(){
    var picked = $('tr[data-kind]').has('input.chk_one:checked');
    if (!picked.length) { setStatus('Nothing selected.'); return; }

    // Build want map and queue list
    var want = {}; // user => desired states
    var ops = [];  // promises
    picked.each(function(){
      var $tr = $(this);
      var user = $tr.data('user');
      var kind = $tr.data('kind');
      if (!want[user]) want[user] = {};
      if (kind === 'totp'){ want[user].totp = false; ops.push(queueTotp(user)); }
      if (kind === 'web') { want[user].web  = 0;     ops.push(queueWeb(user));  }
    });

    setStatus('Queuing ' + ops.length + ' action(s)…');

    // Run queues (not necessarily sequential)
    var done = 0, fail = 0;
    Promise.all(ops.map(p => p.then(()=>{done++}).catch(()=>{fail++}))).then(function(){
      setStatus('Queued: ' + done + ', failed: ' + fail + '. Waiting for status.json…');
      pollUntilReflected(want, 120);
    });
  });

  // bulk delete ALL
  $('#bulk_delete_all').on('click', function(){
    // Check all, then use bulk selected
    $('tr[data-kind] .chk_one').prop('checked', true);
    $('#bulk_delete_selected').click();
  });

})(jQuery);
</script>

<?php
ldap_close($ldap);
render_footer();
