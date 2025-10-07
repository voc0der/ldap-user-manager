<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
include_once 'module_functions.inc.php';

// Page requires authenticated session; Authelia should front this path.
set_page_access('auth'); // enforces $VALIDATED and session

@session_start();

// --- Security: trust only proxy headers (ensure your reverse proxy strips inbound X-*) ---
function header_val(string $k): ?string {
  $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k));
  return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null;
}

$uid   = header_val('Remote-User') ?: ($_SESSION['uid'] ?? null);
$email = header_val('Remote-Email') ?: ($_SESSION['email'] ?? null);
$groups_raw = header_val('Remote-Groups') ?: '';

// Optionally re-resolve via LDAP (safer). If available, prefer LDAP canonical values.
try {
  // Robust exact group check
$groups = array_filter(array_map('trim', preg_split('/[;,\s]+/', (string)$groups_raw)));
$has_mtls = in_array('mtls', $groups, true);

if (!$uid || !$has_mtls) {
  render_header("mTLS Certificate", false);
  echo '<div class="container"><div class="alert alert-danger" role="alert">Access denied: you must be a member of the <code>mtls</code> group.</div></div>';
  render_footer();
  exit;
}

// CSRF token
if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));

render_header("mTLS Certificate", false);
?>
<div class="container" style="max-width:860px;margin-top:20px">
  <h2>mTLS Certificate</h2>
  <p class="text-muted">Step-up verification required. A one-time code will be sent to your account email. After verification, you’ll have 5 minutes to fetch your certificate (single-use download token).</p>

  <div class="panel panel-default">
    <div class="panel-heading">1. Send verification code</div>
    <div class="panel-body">
      <p><strong>User:</strong> <code><?=htmlentities($uid)?></code><br/>
         <strong>Email:</strong> <code><?=htmlentities($email ?? '(unknown)')?></code></p>
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
    <div class="panel-heading">3. Download (activated after verification)</div>
    <div class="panel-body">
      <div id="dl-area" class="text-muted">No token yet.</div>
    </div>
  </div>
</div>

<script>
(function(){
  const csrf = <?= json_encode($_SESSION['csrf']) ?>;
  function q(sel){ return document.querySelector(sel); }
  function msg(el, text, cls){ el.textContent = text; if(cls) {el.className='text-' + cls;} }
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
    const v = q('#code').value.trim();
    const s = q('#verify-status'); msg(s, 'Verifying...', 'info');
    try {
      const r = await fetch('mtls_api.php?action=verify_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf, code: v})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));
      // Show download link (single-use token)
      const area = q('#dl-area');
      area.innerHTML = '';
      const a = document.createElement('a');
      a.href = 'mtls_download.php?token=' + encodeURIComponent(j.token);
      a.textContent = 'Download certificate (valid 5 minutes, single-use)';
      a.className = 'btn btn-warning';
      area.appendChild(a);
      msg(s, 'Verified. Token issued.', 'success');
    } catch(e) {
      msg(s, e.message, 'danger');
    }
  });
})();
</script>
<?php
render_footer();
