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

// Gate by group (no identity leak)
if (!$uid || !$has_mtls) {
  render_header("mTLS Certificate");
  echo '<div class="container" style="max-width:860px;margin-top:20px"><div class="alert alert-danger">Access denied: this page is only available to members of the <code>mtls</code> group.</div></div>';
  render_footer();
  exit;
}

// CSRF token for API posts
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}

render_header("mTLS Certificate");
?>
<style>
/* Minimal wizard styling (Bootstrap 3 friendly) */
.mtls-card {background:#0b0b0b; border:1px solid rgba(255,255,255,.08); border-radius:10px; padding:18px 16px;}
.mtls-steps {display:flex; list-style:none; padding:0; margin:0 0 14px 0; gap:10px; align-items:center;}
.mtls-steps li {display:flex; align-items:center; font-size:12px; letter-spacing:.3px; text-transform:uppercase; color:#9aa3ad;}
.mtls-steps .dot {width:22px; height:22px; border-radius:50%; display:inline-flex; align-items:center; justify-content:center; margin-right:8px; border:1px solid #3a3f44;}
.mtls-steps li.active .dot {border-color:#7fd1ff;}
.mtls-steps li.active {color:#cfe9ff;}
.mtls-steps li.done .dot {background:#22c55e; border-color:#22c55e; color:#08130a;}
.mtls-steps .sep {flex:1; height:1px; background:linear-gradient(90deg, rgba(255,255,255,.08), rgba(255,255,255,.02)); margin:0 6px;}
.mtls-body {border-top:1px solid rgba(255,255,255,.08); padding-top:14px;}
.mtls-row + .mtls-row {border-top:1px dashed rgba(255,255,255,.08); margin-top:12px; padding-top:12px;}
.mtls-row h5 {margin:0 0 8px 0; font-size:13px; letter-spacing:.3px; color:#cfe9ff; text-transform:uppercase;}
.help-min {color:#8aa0b2; font-size:12px;}
.btn-inline-gap {margin-left:8px}
a.btn.disabled, .btn[aria-disabled="true"] {opacity:.55;}
#dl-area a.btn {white-space:normal}
/* Keep code + Verify + status on one line (even on mobile) */
#verify-form { display:flex !important; align-items:center; gap:8px; flex-wrap:nowrap; }
#verify-form #code { width: clamp(108px, 38vw, 170px); min-width: 0; flex: 0 0 auto; }
#btn-verify { white-space: nowrap; flex: 0 0 auto; }
#verify-status { flex: 1 1 auto; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
#verify-form .form-control { width: auto; }
#send-status, #verify-status, #expiry-hint, #p12-pass-row {min-height:20px}
.copy-btn { margin-left:8px; }
code.k { padding:2px 6px; background:#111; border:1px solid rgba(255,255,255,.08); border-radius:6px; }
</style>

<div class="container" style="max-width:720px; margin-top:20px">
  <div class="mtls-card">
    <ol class="mtls-steps" aria-label="Steps">
      <li class="active" data-step="1"><span class="dot">1</span>Send code</li>
      <span class="sep" aria-hidden="true"></span>
      <li data-step="2"><span class="dot">2</span>Verify</li>
      <span class="sep" aria-hidden="true"></span>
      <li data-step="3"><span class="dot">3</span>Download</li>
    </ol>

    <div class="mtls-body">

      <div class="mtls-row" id="step-1">
        <h5>Send verification code</h5>
        <p class="help-min">We’ll email a one-time code to confirm it’s you. This keeps the certificate link private.</p>
        <button id="btn-send" class="btn btn-primary">Send code</button>
        <button id="btn-resend" class="btn btn-default btn-inline-gap" style="display:none">Resend</button>
        <span id="send-status" class="text-info btn-inline-gap" aria-live="polite"></span>
      </div>

      <div class="mtls-row" id="step-2" aria-disabled="true">
        <h5>Enter code</h5>
        <form id="verify-form" class="form-inline" onsubmit="return false">
          <label for="code" class="sr-only">Verification code</label>
          <input type="text" id="code" class="form-control" maxlength="8" pattern="\d{4,8}" placeholder="6-digit code" disabled required>
          <button id="btn-verify" class="btn btn-success btn-inline-gap" disabled>Verify</button>
          <span id="verify-status" class="text-info btn-inline-gap" aria-live="polite"></span>
        </form>
      </div>

      <div class="mtls-row" id="step-3" aria-disabled="true">
        <h5>Download</h5>
        <div id="dl-area" class="text-muted">Waiting for verification…</div>
        <div id="expiry-hint" class="help-block help-min" style="margin-top:8px;"></div>
        <div id="p12-pass-row" class="help-block help-min" style="margin-top:6px;"></div>
      </div>

    </div>
  </div>

  <div class="help-min" style="margin-top:10px;">
    <strong>User:</strong> <code><?=htmlentities($uid)?></code>
    <?php if ($email): ?> · <strong>Email:</strong> <code><?=htmlentities($email)?></code><?php endif; ?>
  </div>
</div>

<script>
(function(){
  const csrf = <?= json_encode($_SESSION['csrf']) ?>;

  // UX constants
  const STAGE_GRACE_MS = 1200;   // briefly gate the download link to avoid early 404s
  const POLL_MAX = 10;           // how many times to poll token_info
  const POLL_DELAY_MS = 1000;    // delay between polls

  function q(sel){ return document.querySelector(sel); }
  function msg(el, text, kind){ el.textContent = text; el.className = kind ? ('text-' + kind) : ''; }
  function enable(el, on){ if(!el) return; el.disabled = !on; if (on) el.removeAttribute('disabled'); else el.setAttribute('disabled',''); }
  function setAriaDisabled(block, on){ if(!block) return; block.setAttribute('aria-disabled', on ? 'true' : 'false'); }
  function markStep(n, state){
    Array.prototype.forEach.call(document.querySelectorAll('.mtls-steps li[data-step]'), li => {
      li.classList.remove('active','done');
      const step = li.getAttribute('data-step');
      if (step == n && state === 'active') li.classList.add('active');
      if (step < n) li.classList.add('done');
      if (state === 'done' && step == n) li.classList.add('done');
    });
  }
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
  function copyToClipboard(text){
    try {
      navigator.clipboard.writeText(text);
    } catch(e) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch(_) {}
      document.body.removeChild(ta);
    }
  }

  async function pollTokenInfo(token){
    const hint = q('#expiry-hint');
    const passRow = q('#p12-pass-row');
    for (let i=0; i<POLL_MAX; i++){
      try {
        const r = await fetch('mtls_api.php?action=token_info', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({csrf, token})
        });
        const j = await r.json();
        if (r.ok && j.ok) {
          // expiry
          if (typeof j.expires_days === 'number') {
            const d = j.expires_days;
            if (d < 0) {
              hint.textContent = 'Certificate appears expired.';
              hint.className = 'text-danger help-min';
            } else {
              hint.textContent = 'Your current certificate expires in about ' + d + ' day' + (d===1?'':'s') + '.';
              hint.className = 'text-muted help-min';
            }
          } else {
            hint.textContent = 'Checking certificate status…';
            hint.className = 'text-info help-min';
          }
          // password
          if (typeof j.p12_password === 'string' && j.p12_password.length > 0) {
            passRow.innerHTML = '';
            const label = document.createElement('span');
            label.textContent = 'PKCS#12 password: ';
            const code = document.createElement('code');
            code.className = 'k';
            code.textContent = j.p12_password;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-xs btn-default copy-btn';
            btn.textContent = 'Copy';
            btn.addEventListener('click', () => copyToClipboard(j.p12_password));
            passRow.appendChild(label);
            passRow.appendChild(code);
            passRow.appendChild(btn);
            return; // we got the password, stop polling
          }
        } else {
          // break on 4xx except 403/404 might still race
          if (r.status >= 400 && r.status < 500) break;
        }
      } catch(e) { /* keep polling */ }
      await new Promise(res => setTimeout(res, POLL_DELAY_MS));
    }
    // final fallback
    if (!q('#p12-pass-row').textContent.trim()) {
      passRow.textContent = 'PKCS#12 password not available.';
      passRow.className = 'text-warning help-min';
    }
    if (!q('#expiry-hint').textContent.trim()) {
      hint.textContent = 'Expiry could not be determined.';
      hint.className = 'text-warning help-min';
    }
  }

  // Initial state: only step 1 enabled
  markStep(1, 'active');
  setAriaDisabled(q('#step-2'), true);
  setAriaDisabled(q('#step-3'), true);

  // SEND
  const btnSend   = q('#btn-send');
  const btnResend = q('#btn-resend');
  btnSend.addEventListener('click', sendCode);
  btnResend.addEventListener('click', sendCode);

  async function sendCode() {
    const s = q('#send-status'); msg(s, 'Sending…', 'info');
    enable(btnSend, false); enable(btnResend, false);
    try {
      const r = await fetch('mtls_api.php?action=send_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));
      msg(s, 'Code sent. Check your email.', 'success');

      // Unlock step 2
      markStep(2, 'active');
      setAriaDisabled(q('#step-2'), false);
      enable(q('#code'), true);
      enable(q('#btn-verify'), true);
      // Show resend after first attempt
      btnResend.style.display = '';
    } catch(e) {
      msg(s, e.message, 'danger');
      enable(btnSend, true); enable(btnResend, true);
    }
  }

  // VERIFY
  const input = q('#code');
  input.addEventListener('input', () => {
    const v = input.value.trim();
    enable(q('#btn-verify'), /^\d{4,8}$/.test(v));
  });

  q('#btn-verify').addEventListener('click', async () => {
    const s = q('#verify-status'); msg(s, 'Verifying…', 'info');
    enable(q('#btn-verify'), false);
    try {
      const v = input.value.trim();
      const r = await fetch('mtls_api.php?action=verify_code', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({csrf, code: v})
      });
      const j = await r.json();
      if(!r.ok || !j.ok) throw new Error(j.error || ('HTTP ' + r.status));

      // Build download button (disabled briefly while the stager prepares file)
      const area = q('#dl-area');
      area.innerHTML = '';
      const a = document.createElement('a');
      a.href = 'mtls_download.php?token=' + encodeURIComponent(j.token);
      a.textContent = 'Download certificate (single-use, valid 5 min)';
      a.className = 'btn btn-warning';
      setDisabledLink(a, true);
      area.appendChild(a);

      // Unlock step 3
      markStep(3, 'active');
      setAriaDisabled(q('#step-3'), false);

      // Grace period then enable link
      setTimeout(() => setDisabledLink(a, false), STAGE_GRACE_MS);

      // Poll for expiry + P12 password (host stager injects into token JSON)
      const hint = q('#expiry-hint');
      hint.textContent = 'Preparing certificate…';
      hint.className = 'text-info help-min';
      q('#p12-pass-row').textContent = 'Waiting for password…';
      q('#p12-pass-row').className = 'text-info help-min';
      pollTokenInfo(j.token);

      msg(s, 'Verified. Token issued.', 'success');
    } catch(e) {
      msg(s, e.message, 'danger');
      enable(q('#btn-verify'), true);
    }
  });
})();
</script>
<?php
render_footer();
