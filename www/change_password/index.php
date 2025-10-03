<?php
// change_password/index.php

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
    if (function_exists('mb_strlen')) {
        return mb_strlen($s, 'UTF-8');
    }
    // Fallback: byte length (good enough if mbstring is missing)
    return strlen($s);
}

// Decide effective min length for this user
@session_start();
global $IS_ADMIN, $USER_ID;

$is_admin = isset($IS_ADMIN) ? (bool)$IS_ADMIN : (!empty($_SESSION['is_admin']));
$has_mfa  = true;
if (function_exists('user_has_mfa')) {
    try { $has_mfa = (bool)user_has_mfa($USER_ID); } catch (Throwable $e) { $has_mfa = true; }
} else {
    // If you store MFA state in session, uncomment this:
    // $has_mfa = isset($_SESSION['mfa_enabled']) ? (bool)$_SESSION['mfa_enabled'] : true;
}

$min_len = DEFAULT_MIN_LEN;
if ($is_admin)  $min_len = max($min_len, ADMIN_MIN_LEN);
if (!$has_mfa)  $min_len = max($min_len, NO_MFA_MIN_LEN);

// ---- POST handling ----
if (isset($_POST['change_password'])) {
    $password = $_POST['password']        ?? '';
    $confirm  = $_POST['password_match']  ?? '';

    // Basic checks
    if ($password === '') { $empty_pw = 1; }
    if ($confirm  === '') { $empty_confirm = 1; }
    if ($password !== '' && $confirm !== '' && $password !== $confirm) { $mismatched = 1; }

    // Length checks (Unicode-aware)
    if ($password !== '') {
        $len = pw_len($password);
        if ($len < $min_len) { $too_short = 1; }
        if ($len > MAX_LEN)  { $too_long  = 1; }
    }

    // Accept if all checks pass
    if (!isset($empty_pw, $empty_confirm, $mismatched, $too_short, $too_long)) {
        $ldap_connection = open_ldap_connection();
        ldap_change_password($ldap_connection, $USER_ID, $password) or die("change_ldap_password() failed.");

        render_header("$ORGANISATION_NAME account manager - password changed");
        ?>
        <div class="container">
          <div class="col-sm-6 col-sm-offset-3">
            <div class="panel panel-success">
              <div class="panel-heading">Success</div>
              <div class="panel-body">
                Your password has been updated.
              </div>
            </div>
          </div>
        </div>
        <?php
        render_footer();
        exit(0);
    }
}

// ---- Render form ----
render_header("Change your $ORGANISATION_NAME password");

// Alerts
if (isset($empty_pw)) { ?>
<div class="alert alert-warning"><p class="text-center">Please enter a password.</p></div>
<?php }
if (isset($empty_confirm)) { ?>
<div class="alert alert-warning"><p class="text-center">Please confirm your password.</p></div>
<?php }
if (isset($mismatched)) { ?>
<div class="alert alert-warning"><p class="text-center">The passwords didn't match.</p></div>
<?php }
if (isset($too_short)) { ?>
<div class="alert alert-warning">
  <p class="text-center">Password is too short. Minimum length is <?php echo (int)$min_len; ?> characters.</p>
</div>
<?php }
if (isset($too_long)) { ?>
<div class="alert alert-warning">
  <p class="text-center">Password is too long. Maximum length is <?php echo (int)MAX_LEN; ?> characters.</p>
</div>
<?php } ?>

<!-- No zxcvbn scripts; purely informational UI below -->
<div class="container">
  <div class="col-sm-6 col-sm-offset-3">

    <div class="panel panel-default">
      <div class="panel-heading text-center">Change your password</div>

      <ul class="list-group">
        <li class="list-group-item">
          <strong>Policy:</strong> minimum <strong><?php echo (int)$min_len; ?></strong> characters<?php
            if ($is_admin || !$has_mfa) {
                echo " (admins &amp; accounts without MFA: <strong>" . (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) . "+</strong>)";
            }
          ?>; maximum <strong><?php echo (int)MAX_LEN; ?></strong>.
        </li>
        <li class="list-group-item">No composition rules. Use any characters, including spaces and full Unicode.</li>
        <li class="list-group-item">Pasting from a password manager is allowed and recommended.</li>
      </ul>

      <div class="panel-body text-center">
        <form class="form-horizontal" action="" method="post" autocomplete="off" novalidate>
          <input type="hidden" id="change_password" name="change_password" value="1">

          <div class="form-group" id="password_div">
            <label for="password" class="col-sm-4 control-label">Password</label>
            <div class="col-sm-6">
              <input
                type="password"
                class="form-control"
                id="password"
                name="password"
                autocomplete="new-password"
                maxlength="<?php echo (int)MAX_LEN; ?>"
                oninput="updateMeter(); checkPasswordsMatch();"
              >
              <div class="checkbox text-left" style="margin-top:6px;">
                <label><input type="checkbox" onclick="togglePw()"> Show password</label>
              </div>
              <div class="help-block text-left" id="pw_help" style="margin-top:6px;"></div>
            </div>
          </div>

          <div class="form-group" id="confirm_div">
            <label for="confirm" class="col-sm-4 control-label">Confirm</label>
            <div class="col-sm-6">
              <input
                type="password"
                class="form-control"
                id="confirm"
                name="password_match"
                autocomplete="new-password"
                maxlength="<?php echo (int)MAX_LEN; ?>"
                oninput="checkPasswordsMatch();"
              >
            </div>
          </div>

          <div class="form-group">
            <button type="submit" class="btn btn-default">Change password</button>
          </div>
        </form>

        <!-- Simple length-only meter -->
        <div class="progress" style="height: 18px;">
          <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
            <span id="LengthLabel">0 / <?php echo (int)$min_len; ?></span>
          </div>
        </div>

      </div>
    </div>

  </div>
</div>

<script type="text/javascript">
// Count Unicode code points correctly
function codePointLen(str) {
  // Array.from splits by code point
  return Array.from(str).length;
}

function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

function updateMeter() {
  var minLen  = <?php echo (int)$min_len; ?>;
  var maxLen  = <?php echo (int)MAX_LEN; ?>;
  var pw      = document.getElementById('password').value || "";
  var len     = codePointLen(pw);

  var pct     = clamp(Math.round((len / minLen) * 100), 0, 100);
  var bar     = document.getElementById('LengthProgress');
  var label   = document.getElementById('LengthLabel');
  var help    = document.getElementById('pw_help');

  bar.style.width = pct + "%";
  label.textContent = len + " / " + minLen;

  // Color hint: <50% default, >=50% add 'progress-bar-info', >=100% 'progress-bar-success'
  bar.className = "progress-bar";
  if (pct >= 100) {
    bar.className += " progress-bar-success";
  } else if (pct >= 50) {
    bar.className += " progress-bar-info";
  }

  // Informational help text
  if (len === 0) {
    help.textContent = "Tip: a long passphrase is easiest to remember and strongest under this policy.";
  } else if (len < minLen) {
    help.textContent = "Keep going—minimum " + minLen + " characters.";
  } else if (len > maxLen) {
    help.textContent = "Too long—maximum " + maxLen + " characters.";
  } else {
    help.textContent = "Looks good. No special character requirements.";
  }
}

function checkPasswordsMatch() {
  var pw = document.getElementById('password').value;
  var cf = document.getElementById('confirm').value;
  var pwDiv = document.getElementById('password_div');
  var cfDiv = document.getElementById('confirm_div');

  if (cf.length === 0) {
    pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error");
    return;
  }
  if (pw !== cf) {
    pwDiv.classList.add("has-error"); cfDiv.classList.add("has-error");
  } else {
    pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error");
  }
}

function togglePw() {
  var field = document.getElementById('password');
  field.type = (field.type === 'password') ? 'text' : 'password';
}

// Initialize once DOM is ready (jQuery not required for this part)
document.addEventListener('DOMContentLoaded', updateMeter);
</script>

<?php render_footer(); ?>
