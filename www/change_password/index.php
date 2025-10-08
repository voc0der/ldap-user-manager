<?php
// change_password/index.php (modernized)

set_include_path(".:" . __DIR__ . "/../includes/");
include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";

set_page_access("user");

// ---- Policy (adjust as you like) ----
const DEFAULT_MIN_LEN = 12;
const ADMIN_MIN_LEN   = 15;
const NO_MFA_MIN_LEN  = 15;
const MAX_LEN         = 256;

// Multibyte length helper (count Unicode code points)
function pw_len(string $s): int {
    if (function_exists('mb_strlen')) return mb_strlen($s, 'UTF-8');
    return strlen($s);
}

@session_start();
global $IS_ADMIN, $USER_ID;
$is_admin = isset($IS_ADMIN) ? (bool)$IS_ADMIN : (!empty($_SESSION['is_admin']));
$has_mfa  = true;
if (function_exists('user_has_mfa')) {
    try { $has_mfa = (bool)user_has_mfa($USER_ID); } catch (Throwable $e) { $has_mfa = true; }
}

$min_len = DEFAULT_MIN_LEN;
if ($is_admin)  $min_len = max($min_len, ADMIN_MIN_LEN);
if (!$has_mfa)  $min_len = max($min_len, NO_MFA_MIN_LEN);

// ---- POST handling ----
if (isset($_POST['change_password'])) {
    $password = $_POST['password']        ?? '';
    $confirm  = $_POST['password_match']  ?? '';

    if ($password === '') { $empty_pw = 1; }
    if ($confirm  === '') { $empty_confirm = 1; }
    if ($password !== '' && $confirm !== '' && $password !== $confirm) { $mismatched = 1; }

    if ($password !== '') {
        $len = pw_len($password);
        if ($len < $min_len) { $too_short = 1; }
        if ($len > MAX_LEN)  { $too_long  = 1; }
    }

    if (!isset($empty_pw, $empty_confirm, $mismatched, $too_short, $too_long)) {
        $ldap_connection = open_ldap_connection();
        ldap_change_password($ldap_connection, $USER_ID, $password) or die("change_ldap_password() failed.");

        render_header("$ORGANISATION_NAME account manager - password changed"); ?>
        <style>
          .panel-modern{background:#0b0f13;border:1px solid rgba(255,255,255,.08);border-radius:12px}
          .panel-modern .panel-heading{background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02));color:#cfe9ff;letter-spacing:.4px;text-transform:uppercase;border-bottom:1px solid rgba(255,255,255,.08)}
        </style>
        <div class="container" style="max-width:720px;margin:24px auto">
          <div class="panel panel-modern">
            <div class="panel-heading text-center">Success</div>
            <div class="panel-body">
              <p>Your password has been updated.</p>
            </div>
          </div>
        </div>
        <?php render_footer(); exit;
    }
}

// ---- Render form ----
render_header("Change your $ORGANISATION_NAME password");

// collect alert messages for inline display
$alerts = [];
if (isset($empty_pw))     $alerts[] = "Please enter a password.";
if (isset($empty_confirm))$alerts[] = "Please confirm your password.";
if (isset($mismatched))   $alerts[] = "The passwords didn't match.";
if (isset($too_short))    $alerts[] = "Password is too short. Minimum length is " . (int)$min_len . " characters.";
if (isset($too_long))     $alerts[] = "Password is too long. Maximum length is " . (int)MAX_LEN . " characters.";
?>
<style>
/* ---------- modern chrome (Bootstrap 3 friendly) ---------- */
.wrap-narrow { max-width: 720px; margin: 22px auto 40px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.08); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading {
  background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
  color:#cfe9ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase;
  padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08);
}
.panel-modern .panel-body { padding:16px 16px 18px; }
.help-min { color:#8aa0b2; font-size:12px; }
.policy-box { background:rgba(255,255,255,.02); border:1px dashed rgba(255,255,255,.08); border-radius:10px; padding:10px 12px; margin:0 0 12px; }
.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.12); color:#cfe9ff; }
.btn-soft:hover { background:#17202b; }
.progress-modern { height:18px; background:#0e151d; border:1px solid rgba(255,255,255,.08); border-radius:10px; }
.progress-modern .progress-bar { line-height:16px; font-size:12px; }
.inline-controls { display:flex; align-items:center; justify-content:space-between; gap:10px; }
.toggle-line { margin-top:6px; display:flex; align-items:center; gap:8px; }
.alert-modern { background:#251a08; border:1px solid #77521b; color:#ffd9a3; border-radius:10px; padding:8px 12px; margin:0 0 10px; }
</style>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading text-center">Change your password</div>
    <div class="panel-body">

      <?php if (!empty($alerts)): ?>
        <?php foreach ($alerts as $msg): ?>
          <div class="alert-modern" role="alert"><?php echo htmlspecialchars($msg); ?></div>
        <?php endforeach; ?>
      <?php endif; ?>

      <div class="policy-box help-min">
        <strong>Policy.</strong>
        Minimum <strong><?php echo (int)$min_len; ?></strong> characters<?php
          if ($is_admin || !$has_mfa) {
            echo " (admins &amp; no-MFA accounts: <strong>" . (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) . "+</strong>)";
          }
        ?>; maximum <strong><?php echo (int)MAX_LEN; ?></strong>. No composition rules—any characters allowed (spaces & full Unicode). Paste from your password manager is encouraged.
      </div>

      <form class="form-horizontal" action="" method="post" autocomplete="off" novalidate>
        <input type="hidden" id="change_password" name="change_password" value="1">

        <div class="form-group" id="password_div">
          <label for="password" class="col-sm-4 control-label">Password</label>
          <div class="col-sm-8">
            <div class="inline-controls">
              <input
                type="password"
                class="form-control"
                id="password"
                name="password"
                autocomplete="new-password"
                maxlength="<?php echo (int)MAX_LEN; ?>"
                oninput="updateMeter(); checkPasswordsMatch(); gateSubmit();"
              >
            </div>
            <div class="toggle-line">
              <label class="help-min" style="margin:0"><input type="checkbox" onclick="togglePw()"> Show password</label>
              <span id="caps-hint" class="help-min" aria-live="polite"></span>
            </div>
            <div class="help-min text-left" id="pw_help" style="margin-top:6px;"></div>
          </div>
        </div>

        <div class="form-group" id="confirm_div">
          <label for="confirm" class="col-sm-4 control-label">Confirm</label>
          <div class="col-sm-8">
            <input
              type="password"
              class="form-control"
              id="confirm"
              name="password_match"
              autocomplete="new-password"
              maxlength="<?php echo (int)MAX_LEN; ?>"
              oninput="checkPasswordsMatch(); gateSubmit();"
            >
          </div>
        </div>

        <div class="form-group">
          <div class="col-sm-12">
            <div class="progress progress-modern">
              <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
                <span id="LengthLabel">0 / <?php echo (int)$min_len; ?></span>
              </div>
            </div>
          </div>
        </div>

        <div class="form-group text-center">
          <button id="submit-btn" type="submit" class="btn btn-primary btn-pill" disabled>Change password</button>
          <span class="help-min" style="margin-left:8px;">Button enables when requirements are met.</span>
        </div>
      </form>

    </div>
  </div>
</div>

<script type="text/javascript">
// Count Unicode code points
function codePointLen(str){ return Array.from(str).length; }
function clamp(v,min,max){ return Math.max(min, Math.min(max,v)); }

function updateMeter(){
  var minLen = <?php echo (int)$min_len; ?>;
  var maxLen = <?php echo (int)MAX_LEN; ?>;
  var pw = document.getElementById('password').value || "";
  var len = codePointLen(pw);

  var pct   = clamp(Math.round((len / minLen) * 100), 0, 100);
  var bar   = document.getElementById('LengthProgress');
  var label = document.getElementById('LengthLabel');
  var help  = document.getElementById('pw_help');

  bar.style.width = pct + "%";
  label.textContent = len + " / " + minLen;

  bar.className = "progress-bar";
  if (pct >= 100) bar.className += " progress-bar-success";
  else if (pct >= 50) bar.className += " progress-bar-info";

  if (len === 0)        help.textContent = "Tip: a long passphrase is easiest to remember and strongest under this policy.";
  else if (len < minLen)help.textContent = "Keep going—minimum " + minLen + " characters.";
  else if (len > maxLen)help.textContent = "Too long—maximum " + maxLen + " characters.";
  else                  help.textContent = "Looks good. No special character requirements.";
}

function checkPasswordsMatch(){
  var pw = document.getElementById('password').value;
  var cf = document.getElementById('confirm').value;
  var pwDiv = document.getElementById('password_div');
  var cfDiv = document.getElementById('confirm_div');

  if (cf.length === 0){ pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error"); return; }
  if (pw !== cf){ pwDiv.classList.add("has-error"); cfDiv.classList.add("has-error"); }
  else { pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error"); }
}

function togglePw(){
  var f = document.getElementById('password');
  f.type = (f.type === 'password') ? 'text' : 'password';
}

// Enable submit when both: min length & match & <= MAX
function gateSubmit(){
  var btn = document.getElementById('submit-btn');
  var pw = document.getElementById('password').value || "";
  var cf = document.getElementById('confirm').value || "";
  var minLen = <?php echo (int)$min_len; ?>;
  var maxLen = <?php echo (int)MAX_LEN; ?>;
  var ok = (codePointLen(pw) >= minLen) && (codePointLen(pw) <= maxLen) && (pw === cf) && pw.length > 0;
  btn.disabled = !ok;
}

// Simple CapsLock hint
(function capsLockHint(){
  var hint = document.getElementById('caps-hint');
  function onKey(e){
    try{
      var caps = e.getModifierState && e.getModifierState('CapsLock');
      hint.textContent = caps ? "Caps Lock is ON" : "";
    }catch(_){}
  }
  document.getElementById('password').addEventListener('keydown', onKey);
  document.getElementById('password').addEventListener('keyup', onKey);
})();

document.addEventListener('DOMContentLoaded', function(){
  updateMeter(); gateSubmit();
});
</script>

<?php render_footer(); ?>
