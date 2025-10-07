<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';

// Require authenticated session (proxy headers provided by Authelia)
set_page_access('auth');
@session_start();

// Trusted proxy headers (must be set by your reverse proxy)
function h(string $k): ?string {
  $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k));
  return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null;
}

$uid         = h('Remote-User')   ?: ($_SESSION['uid']   ?? null);
$email       = h('Remote-Email')  ?: ($_SESSION['email'] ?? null);
$groups_raw  = h('Remote-Groups') ?: '';
$groups_list = array_filter(array_map('trim', preg_split('/[;,\s]+/', (string)$groups_raw)));
$has_mtls    = in_array('mtls', $groups_list, true);

if (!$uid || !$has_mtls) {
  render_header("mTLS Certificate");
  echo '<div class="container" style="max-width:860px;margin-top:20px"><div class="alert alert-danger">Access denied: you must be a member of the <code>mtls</code> group.</div></div>';
  render_footer();
  exit;
}

// CSRF token for API posts
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

render_header("mTLS Certificate");
?>
<div class="container" style="max-width:860px;margin-top:20px">
  <h2 class="page-header">mTLS Certificate</h2>
  <p class="text-muted">A one-time code will be sent to your account email. After verification, you’ll have 5 minutes to fetch your certificate (single-use link). Identity and group membership are enforced by the proxy headers.</p>

  <div class="panel panel-default">
    <div class="panel-heading">Identity</div>
    <div class="panel-body">
      <p><strong>User:</strong> <code><?=htmlentities($uid)?></code><br/>
         <strong>Email:</strong> <code><?=htmlentities($email ?? '(unknown)')?></code><br/>
         <strong>Groups:</strong> <code><?=htmlentities(implode(', ', $groups_list))?></code></p>
    </div>
  </div>

  <div class="panel panel-default">
    <div class="panel-heading">1. Send verification code</div>
    <div class="panel-body">
      <button id="btn-send" class="btn btn-primary">Send code</button>
      <span id="send-status" class="text-info" style="margin-left:10px"></span>
    </div>
  </div>

  <div class="panel panel-default">
    <div class="panel-heading">2. Verify code</div>
    <div class="panel-body">
      <form id="verify-form" class="form-inline" onsubmit="return false">
        <div class="form-group">
          <label for="code">Code:</label>
          <input type="text" id="code" class="form-control" maxlength="8" pattern="\d{4,8}" placeholder="6-digit code" required>
        </div>
        <button id="btn-verify" class="btn btn-success" style="margin-left:10px">Verify</button>
        <span id="verify-status" class="text-info" style="margin-left:10px"></span>
      </form>
    </div>
  </div>

  <div class="panel panel-default">
    <div class="panel-heading">3. Download</div>
    <div class="panel-body">
      <div id="dl-area" class="text-muted">No token yet.</div>
      <div id="expiry-hint" class="help-block" style="margin-top:10px;"></div>
    </div>
  </div>
</div>

<script>
(function(){
  const csrf = <?= json_encode($_SESSION['csrf']) ?>;
  function q(sel){ return document.querySelector(sel); }
  function msg(el, text, kind){ el.textContent = text; el.className = kind ? ('text-' + kind) : ''; }

  q('#btn-send').addEventListener('click', async () => {
    const s = q('#send-status'); msg(s, 'Sending...', 'info');
    try {
      const r = await fetch('mtls_api.php?action=send_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));
      msg(s, 'Code sent. Check your email.', 'success');
    } catch(e) {
      msg(s, e.message, 'danger');
    }
  });

  q('#btn-verify').addEventListener('click', async () => {
    const s = q('#verify-status'); msg(s, 'Verifying...', 'info');
    const v = q('#code').value.trim();
    try {
      const r = await fetch('mtls_api.php?action=verify_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf, code: v})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));

      // Download link
      const area = q('#dl-area');
      area.innerHTML = '';
      const a = document.createElement('a');
      a.href = 'mtls_download.php?token=' + encodeURIComponent(j.token);
      a.textContent = 'Download certificate (valid 5 minutes, single-use)';
      a.className = 'btn btn-warning';
      area.appendChild(a);

      // Expiry hint
      const hint = q('#expiry-hint');
      if (typeof j.expires_days === 'number') {
        const d = j.expires_days;
        if (d < 0) {
          hint.textContent = 'Certificate appears expired.';
          hint.className = 'text-danger';
        } else {
          hint.textContent = 'Your current certificate expires in about ' + d + ' day' + (d===1?'':'s') + '.';
          hint.className = 'text-muted';
        }
      } else {
        hint.textContent = 'Expiry could not be determined.';
        hint.className = 'text-warning';
      }

      msg(s, 'Verified. Token issued.', 'success');
    } catch(e) {
      msg(s, e.message, 'danger');
    }
  });
})();
</script>
<?php
render_footer();
