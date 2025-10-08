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
  <div class="panel panel-default">
    <div class="panel-heading text-center">Identity</div>
    <div class="panel-body">
      <p><strong>User:</strong> <code><?=htmlentities($uid)?></code><br/>
         <strong>Email:</strong> <code><?=htmlentities($email ?? '(unknown)')?></code><br/>
         <strong>Groups:</strong> <code><?=htmlentities(implode(', ', $groups_list))?></code></p>
    </div>
  </div>

  <div class="panel panel-default">
    <div class="panel-heading text-center">1. Send verification code</div>
    <div class="panel-body">
      <button id="btn-send" class="btn btn-primary">Send code</button>
      <span id="send-status" class="text-info" style="margin-left:10px"></span>
    </div>
  </div>

  <div class="panel panel-default">
    <div class="panel-heading text-center">2. Verify code</div>
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
    <div class="panel-heading text-center">3. Download</div>
    <div class="panel-body">
      <div id="dl-area" class="text-muted">No token yet.</div>
      <div id="expiry-hint" class="help-block" style="margin-top:10px;"></div>
    </div>
  </div>
</div>

<script>
(function(){
  const csrf = <?= json_encode($_SESSION['csrf']) ?>;

  // UX constants
  const STAGE_GRACE_MS = 1200;   // briefly gate the download link to avoid early 404s
  const POLL_MAX = 8;            // how many times to poll token_info
  const POLL_DELAY_MS = 1000;    // delay between polls

  function q(sel){ return document.querySelector(sel); }
  function msg(el, text, kind){ el.textContent = text; el.className = kind ? ('text-' + kind) : ''; }

  function setDisabledLink(a, disabled) {
    if (!a) return;
    if (disabled) {
      a.classList.add('disabled');
      a.setAttribute('aria-disabled','true');
      a.style.pointerEvents = 'none';
    } else {
      a.classList.remove('disabled');
      a.removeAttribute('aria-disabled');
      a.style.pointerEvents = '';
    }
  }

  async function pollTokenInfo(token){
    const hint = q('#expiry-hint');
    for (let i=0; i<POLL_MAX; i++){
      try {
        const r = await fetch('mtls_api.php?action=token_info', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({csrf, token})
        });
        const j = await r.json();
        if (r.ok && j.ok) {
          if (typeof j.expires_days === 'number') {
            const d = j.expires_days;
            if (d < 0) {
              hint.textContent = 'Certificate appears expired.';
              hint.className = 'text-danger';
            } else {
              hint.textContent = 'Your current certificate expires in about ' + d + ' day' + (d===1?'':'s') + '.';
              hint.className = 'text-muted';
            }
            return;
          }
        }
      } catch(e) {
        // ignore and keep polling
      }
      await new Promise(res => setTimeout(res, POLL_DELAY_MS));
    }
    hint.textContent = 'Expiry could not be determined.';
    hint.className = 'text-warning';
  }

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

      // Download link (initially disabled for a brief grace window)
      const area = q('#dl-area');
      area.innerHTML = '';
      const a = document.createElement('a');
      a.href = 'mtls_download.php?token=' + encodeURIComponent(j.token);
      a.textContent = 'Download certificate (valid 5 minutes, single-use)';
      a.className = 'btn btn-warning';
      setDisabledLink(a, true);
      area.appendChild(a);

      // Enable after short grace period to let the host stager place the file
      setTimeout(() => setDisabledLink(a, false), STAGE_GRACE_MS);

      // Poll for expiry (filled by host stager), update hint when available
      const hint = q('#expiry-hint');
      hint.textContent = 'Preparing certificate...';
      hint.className = 'text-info';
      pollTokenInfo(j.token);

      msg(s, 'Verified. Token issued.', 'success');
    } catch(e) {
      msg(s, e.message, 'danger');
    }
  });
})();
</script>
<?php
render_footer();
