<?php
// www/account_manager/new_user.php  (modernized styling + hard validation + Apprise on create)

set_include_path(".:" . __DIR__ . "/../includes/");

include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";
include_once "module_functions.inc.php";
include_once "apprise_helpers.inc.php"; // for mtls_apprise_notify + helpers

// ---- Password Policy (adjust as needed) ----
const DEFAULT_MIN_LEN = 12;
const ADMIN_MIN_LEN   = 15;   // for admin/privileged roles
const NO_MFA_MIN_LEN  = 15;   // for accounts without MFA
const MAX_LEN         = 256;  // allow long passphrases

// make sure mail sending flag is defined to avoid notices
if (!isset($EMAIL_SENDING_ENABLED)) {
  // infer from SMTP config if present
  $EMAIL_SENDING_ENABLED = !empty($SMTP['host'] ?? '');
}

// Unicode-aware length
function pw_len(string $s): int {
  if (function_exists('mb_strlen')) return mb_strlen($s, 'UTF-8');
  return strlen($s);
}

// Safely predeclare common attribute arrays to avoid undefined-index notices
$uid = $cn = $givenname = $sn = $mail = [];

// -------- Attribute map wiring --------
$attribute_map = $LDAP['default_attribute_map'];
if (isset($LDAP['account_additional_attributes'])) {
  $attribute_map = ldap_complete_attribute_array($attribute_map, $LDAP['account_additional_attributes']);
}
if (!array_key_exists($LDAP['account_attribute'], $attribute_map)) {
  $attribute_map = array_merge($attribute_map, array($LDAP['account_attribute'] => array("label" => "Account UID")));
}

if (isset($_POST['setup_admin_account'])) {
  $admin_setup = TRUE;
  validate_setup_cookie();
  set_page_access("setup");
  $completed_action = "{$SERVER_PATH}log_in";
  $page_title = "New administrator account";
  render_header("$ORGANISATION_NAME account manager - setup administrator account", FALSE);
} else {
  set_page_access("admin");
  $completed_action = "{$THIS_MODULE_PATH}/";
  $page_title = "New account";
  $admin_setup = FALSE;
  render_header("$ORGANISATION_NAME account manager");
  render_submenu();
}

$invalid_email = FALSE;
$invalid_cn = FALSE;
$invalid_givenname = FALSE;
$invalid_sn = FALSE;
$invalid_account_identifier = FALSE;
$mismatched_passwords = FALSE;
$too_short = FALSE;
$too_long = FALSE;

$disabled_email_tickbox = TRUE;
$account_attribute = $LDAP['account_attribute'];

$new_account_r = array();

// -------- Build attribute values from POST/FILE/defaults (robust) --------
foreach ($attribute_map as $attribute => $attr_r) {

  // Files
  if (!empty($_FILES[$attribute]['size'])) {
    $this_attribute = array();
    $this_attribute['count'] = 1;
    $this_attribute[0] = @file_get_contents($_FILES[$attribute]['tmp_name']) ?: '';
    $$attribute = $this_attribute;
    $new_account_r[$attribute] = $this_attribute;
    unset($new_account_r[$attribute]['count']);
  }

  // POST (strings or arrays)
  if (isset($_POST[$attribute])) {
    $this_attribute = array();

    if (is_array($_POST[$attribute]) && count($_POST[$attribute]) > 0) {
      foreach($_POST[$attribute] as $key => $value) {
        $value = (string)$value;
        if ($value !== "") { $this_attribute[$key] = filter_var($value, FILTER_SANITIZE_FULL_SPECIAL_CHARS); }
      }
      if (count($this_attribute) > 0) {
        $this_attribute['count'] = count($this_attribute);
        $$attribute = $this_attribute;
      }
    } else {
      $val = (string)$_POST[$attribute];
      if ($val !== "") {
        $this_attribute['count'] = 1;
        $this_attribute[0] = filter_var($val, FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $$attribute = $this_attribute;
      }
    }
  }

  // Defaults
  if (!isset($$attribute) && isset($attr_r['default'])) {
    $$attribute['count'] = 1;
    $$attribute[0] = $attr_r['default'];
  }

  if (isset($$attribute)) {
    $new_account_r[$attribute] = $$attribute;
    unset($new_account_r[$attribute]['count']);
  }
}

// -------- Pre-fill from account_request (optional; safe) --------
if (isset($_GET['account_request'])) {
  $givenname0 = isset($_GET['first_name']) ? (string)$_GET['first_name'] : '';
  $sn0        = isset($_GET['last_name'])  ? (string)$_GET['last_name']  : '';
  $mail0      = isset($_GET['email'])      ? (string)$_GET['email']      : '';

  if ($givenname0 !== '') {
    $givenname = ['count'=>1, 0 => filter_var($givenname0, FILTER_SANITIZE_FULL_SPECIAL_CHARS)];
    $new_account_r['givenname'] = $givenname;
    unset($new_account_r['givenname']['count']);
  }
  if ($sn0 !== '') {
    $sn = ['count'=>1, 0 => filter_var($sn0, FILTER_SANITIZE_FULL_SPECIAL_CHARS)];
    $new_account_r['sn'] = $sn;
    unset($new_account_r['sn']['count']);
  }

  if ($mail0 !== '') {
    $mail = ['count'=>1, 0 => filter_var($mail0, FILTER_SANITIZE_EMAIL)];
    $disabled_email_tickbox = FALSE;
  } else {
    // synthesize from UID if available
    $uid0 = $uid[0] ?? '';
    if ($uid0 !== '' && isset($EMAIL_DOMAIN)) {
      $mail = ['count'=>1, 0 => ($uid0 . '@' . $EMAIL_DOMAIN)];
      $disabled_email_tickbox = FALSE;
    }
  }
  if (!empty($mail)) {
    $new_account_r['mail'] = $mail;
    unset($new_account_r['mail']['count']);
  }
}

// -------- Generate missing uid/cn on request or form post --------
if (isset($_GET['account_request']) || isset($_POST['create_account'])) {
  $given0 = $givenname[0] ?? '';
  $sn0    = $sn[0] ?? '';
  if (!isset($uid[0]) || $uid[0] === '') {
    $uid0 = generate_username($given0, $sn0);
    $uid  = ['count'=>1, 0 => $uid0];
    $new_account_r['uid'] = $uid;
    unset($new_account_r['uid']['count']);
  }
  if (!isset($cn[0]) || $cn[0] === '') {
    if (!empty($ENFORCE_SAFE_SYSTEM_NAMES)) {
      $cn0 = $given0 . $sn0;
    } else {
      $cn0 = trim($given0 . ' ' . $sn0);
    }
    $cn = ['count'=>1, 0 => $cn0];
    $new_account_r['cn'] = $cn;
    unset($new_account_r['cn']['count']);
  }
}

// -------- Process create --------
if (isset($_POST['create_account'])) {
  $password = (string)($_POST['password'] ?? '');
  if ($password !== '') { $new_account_r['password'][0] = $password; }

  // Safe getters
  $account_identifier = (string)($new_account_r[$account_attribute][0] ?? ($uid[0] ?? ''));
  $this_cn        = (string)($cn[0]        ?? '');
  $this_mail      = (string)($mail[0]      ?? '');
  $this_givenname = (string)($givenname[0] ?? '');
  $this_sn        = (string)($sn[0]        ?? '');
  $this_password  = $password;

  // ---- Server-side hard validation (requireds)
  if ($this_cn === "") { $invalid_cn = TRUE; }
  if ($account_identifier === "") { $invalid_account_identifier = TRUE; }
  if ($this_givenname === "") { $invalid_givenname = TRUE; }
  if ($this_sn === "") { $invalid_sn = TRUE; }
  if ($this_mail !== "" && !is_valid_email($this_mail)) { $invalid_email = TRUE; }
  if ($password !== ($_POST['password_match'] ?? '')) { $mismatched_passwords = TRUE; }
  if (!empty($ENFORCE_SAFE_SYSTEM_NAMES) && !preg_match("/$USERNAME_REGEX/", $account_identifier)) { $invalid_account_identifier = TRUE; }

  // ---- Length-only password policy (new accounts)
  $min_len = ($admin_setup ? max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) : NO_MFA_MIN_LEN);
  $len = pw_len($password);
  if ($len < $min_len) { $too_short = TRUE; }
  if ($len > MAX_LEN)  { $too_long  = TRUE; }

  // ---- Decide whether to send email
  $send_user_email = false;
  if (isset($_POST['send_email']) && $EMAIL_SENDING_ENABLED == TRUE && $this_mail !== '' && is_valid_email($this_mail)) {
    $send_user_email = true;
  }

  $has_errors =
        $mismatched_passwords
     || $too_short
     || $too_long
     || $invalid_account_identifier
     || $invalid_cn
     || $invalid_email
     || $invalid_givenname
     || $invalid_sn
     || $this_password === '';

  if (!$has_errors) {
    $ldap_connection = open_ldap_connection();
    $new_account = ldap_new_account($ldap_connection, $new_account_r);

    if ($new_account) {
      $creation_message = "The account was created.";

      // Send email to user (optional)
      if ($send_user_email) {
        include_once "mail_functions.inc.php";
        $mail_body    = parse_mail_text($new_account_mail_body, $password, $account_identifier, $this_givenname, $this_sn);
        $mail_subject = parse_mail_text($new_account_mail_subject, $password, $account_identifier, $this_givenname, $this_sn);

        $sent_email = send_email($this_mail, "$this_givenname $this_sn", $mail_subject, $mail_body);
        $creation_message = "The account was created";
        if ($sent_email) {
          $creation_message .= " and an email sent to $this_mail.";
        } else {
          $creation_message .= " but unfortunately the email wasn't sent.<br>More information will be available in the logs.";
        }
      }

      // Admin-setup: add to admins group and clean temporary entries
      if ($admin_setup === TRUE) {
        $member_add = ldap_add_member_to_group($ldap_connection, $LDAP['admins_group'], $account_identifier);
        if (!$member_add) { ?>
          <div class="alert alert-warning">
            <p class="text-center"><?php print $creation_message; ?> Unfortunately adding it to the admin group failed.</p>
          </div>
        <?php
        }
        // Tidy up empty uniquemember entries left over from the setup wizard
        $USER_ID="tmp_admin";
        ldap_delete_member_from_group($ldap_connection, $LDAP['admins_group'], "");
        if (isset($DEFAULT_USER_GROUP)) { ldap_delete_member_from_group($ldap_connection, $DEFAULT_USER_GROUP, ""); }
      }

      // ---- Apprise: User Created (after any group adjustments)
      $admin_uid   = $GLOBALS['USER_ID'] ?? ($_SESSION['user_id'] ?? 'unknown');
      $post_groups = ldap_user_group_membership($ldap_connection, $account_identifier);
      // helper might not exist in older include—fallback gracefully
      if (!function_exists('apprise_notify_user_created')) {
        // local inline variant using the same style
        if (function_exists('mtls_apprise_notify')) {
          $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
          $ip   = function_exists('apprise_client_ip') ? apprise_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
          $grp  = trim(implode(', ', $post_groups));
          $grp  = $grp === '' ? 'none' : $grp;
          $body = '🔐 `' . htmlspecialchars($host, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '` **User Created**:<br />'
                . 'User: <code>' . htmlspecialchars($account_identifier, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
                . 'Email: <code>' . htmlspecialchars(($this_mail ?: 'none'), ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
                . 'By: <code>'   . htmlspecialchars($admin_uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
                . 'IP: <code>'   . htmlspecialchars($ip, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
                . 'Groups: <code>' . htmlspecialchars($grp, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code>';
          mtls_apprise_notify($body);
        }
      } else {
        // use helper if you've added it to apprise_helpers.inc.php
        apprise_notify_user_created($account_identifier, $admin_uid, $this_mail, $post_groups);
      }
      // -------------------------------------------------------

      ?>
      <div class="alert alert-success">
        <p class="text-center"><?php print $creation_message; ?></p>
      </div>
      <form action='<?php print $completed_action; ?>'>
        <p align="center"><input type='submit' class="btn btn-success" value='Finished'></p>
      </form>
      <?php
      render_footer();
      exit(0);
    } else { ?>
      <div class="alert alert-warning">
        <p class="text-center">Failed to create the account:</p>
        <pre>
<?php
          print ldap_error($ldap_connection) . "\n";
          ldap_get_option($ldap_connection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $detailed_err);
          print $detailed_err;
?>
        </pre>
      </div>
<?php
      render_footer();
      exit(0);
    }
  }
}

// ---------- Enable "Email these credentials" if a valid recipient email is present ----------
if ($EMAIL_SENDING_ENABLED == TRUE && $admin_setup != TRUE) {
  // Try to discover the current email value
  $recipient_email = '';

  // Prefer what you've already collected in $new_account_r
  if (isset($new_account_r['mail'][0]) && is_string($new_account_r['mail'][0])) {
    $recipient_email = trim($new_account_r['mail'][0]);
  } elseif (isset($mail[0]) && is_string($mail[0])) {
    $recipient_email = trim($mail[0]);
  }

  // Optional: synthesize from UID + EMAIL_DOMAIN if we have both and no email yet
  if ($recipient_email === '' && isset($EMAIL_DOMAIN) && !empty($uid[0] ?? '')) {
    $recipient_email = $uid[0] . '@' . $EMAIL_DOMAIN;
    // reflect it back into the structures so the form shows it
    $mail[0] = $recipient_email;
    $new_account_r['mail'] = ['0' => $recipient_email];
  }

  // Finally decide if checkbox should be enabled
  $disabled_email_tickbox = !($recipient_email !== '' && is_valid_email($recipient_email));
}


// -------- Render errors (if any) --------
$errors = "";
if ($invalid_cn)                 { $errors .= "<li>The Common Name is required</li>\n"; }
if ($invalid_givenname)          { $errors .= "<li>First Name is required</li>\n"; }
if ($invalid_sn)                 { $errors .= "<li>Last Name is required</li>\n"; }
if ($invalid_account_identifier) { $errors .= "<li>The account identifier (" . $attribute_map[$account_attribute]['label'] . ") is invalid.</li>\n"; }
if ($invalid_email)              { $errors .= "<li>The email address is invalid</li>\n"; }
if ($mismatched_passwords)       { $errors .= "<li>The passwords are mismatched</li>\n"; }
if ($too_short)                  { $errors .= "<li>Password is too short (minimum " . (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) . " characters for new accounts)</li>\n"; }
if ($too_long)                   { $errors .= "<li>Password is too long (maximum " . (int)MAX_LEN . " characters)</li>\n"; }

if ($errors !== "") { ?>
  <div class="alert alert-warning">
    <p class="text-align: center">
      There were issues creating the account:
      <ul><?php print $errors; ?></ul>
    </p>
  </div>
<?php
}

render_js_username_check();
render_js_username_generator('givenname','sn','uid','uid_div');
render_js_cn_generator('givenname','sn','cn','cn_div');
render_js_email_generator('uid','mail');
render_js_homedir_generator('uid','homedirectory');

$tabindex = 1;
?>

<!-- keep your generator scripts -->
<script type="text/javascript" src="<?php print $SERVER_PATH; ?>js/generate_passphrase.js"></script>
<script type="text/javascript" src="<?php print $SERVER_PATH; ?>js/wordlist.js"></script>

<script type="text/javascript">
function codePointLen(str){return Array.from(str||"").length;}
function clamp(v,min,max){return Math.max(min,Math.min(max,v));}

function updateMeter(minLen){
  var pw   = document.getElementById('password').value || "";
  var len  = codePointLen(pw);
  var pct  = clamp(Math.round((len / minLen) * 100), 0, 100);

  var bar   = document.getElementById('LengthProgress');
  var label = document.getElementById('LengthLabel');

  bar.style.width = pct + "%";
  bar.className = "progress-bar";
  if (pct >= 100) bar.className += " progress-bar-success";
  else if (pct >= 50) bar.className += " progress-bar-info";

  label.textContent = len + " / " + minLen;
}

function check_passwords_match(){
  var pw = document.getElementById('password').value;
  var cf = document.getElementById('confirm').value;
  var pwDiv = document.getElementById('password_div');
  var cfDiv = document.getElementById('confirm_div');
  if (cf.length === 0){ pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error"); return; }
  if (pw !== cf){ pwDiv.classList.add("has-error"); cfDiv.classList.add("has-error"); }
  else { pwDiv.classList.remove("has-error"); cfDiv.classList.remove("has-error"); }
}

function random_password(){
  generatePassword(4,'-','password','confirm');
  updateMeter(<?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?>);
}

document.addEventListener('DOMContentLoaded', function(){
  updateMeter(<?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?>);
});
</script>

<script type="text/javascript">
// enable/disable "Email these credentials" based on visible email input
document.addEventListener('DOMContentLoaded', function () {
  var emailInput = document.getElementById('mail');
  var sendBox    = document.getElementById('send_email_checkbox');
  if (!emailInput || !sendBox) return;

  function looksLikeEmail(v){
    v = (v || '').trim();
    return v.length > 3 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
  }
  function refreshCheckbox() {
    sendBox.disabled = !looksLikeEmail(emailInput.value);
  }
  emailInput.addEventListener('input', refreshCheckbox);
  refreshCheckbox();
});
</script>

<style>
/* ---------- modern chrome (Bootstrap 3 friendly) ---------- */
.wrap-narrow { max-width: 980px; margin: 22px auto 40px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.08); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading {
  background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
  color:#cfe9ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase;
  padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08);
}
.panel-modern .panel-body { padding:16px 16px 18px; }
.help-min { color:#8aa0b2; font-size:12px; }
.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.12); color:#cfe9ff; }
.btn-soft:hover { background:#17202b; }
.progress-modern { height:18px; background:#0e151d; border:1px solid rgba(255,255,255,.08); border-radius:10px; }
.progress-modern .progress-bar { line-height:16px; font-size:12px; }
</style>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading text-center"><?php print $page_title; ?></div>
    <div class="panel-body">

      <form class="form-horizontal" action="" enctype="multipart/form-data" method="post">
        <?php if ($admin_setup == TRUE) { ?><input type="hidden" name="setup_admin_account" value="true"><?php } ?>
        <input type="hidden" name="create_account">

        <?php
          $tabindex = 1;
          foreach ($attribute_map as $attribute => $attr_r) {
            $label = $attr_r['label'];
            $onkeyup = isset($attr_r['onkeyup']) ? $attr_r['onkeyup'] : "";
            if ($attribute == $LDAP['account_attribute']) { $label = "<strong>$label</strong><sup>&ast;</sup>"; }
            if (!empty($attr_r['required'])) { $label = "<strong>$label</strong><sup>&ast;</sup>"; }
            $these_values = isset($$attribute) ? $$attribute : array();
            $inputtype = isset($attr_r['inputtype']) ? $attr_r['inputtype'] : "";
            render_attribute_fields($attribute,$label,$these_values,"",$onkeyup,$inputtype,$tabindex);
            $tabindex++;
          }
        ?>

        <div class="form-group" id="password_div">
          <label for="password" class="col-sm-3 control-label">Password</label>
          <div class="col-sm-6">
            <input tabindex="<?php print $tabindex+1; ?>" type="password" class="form-control" id="password" name="password"
                   maxlength="<?php echo (int)MAX_LEN; ?>"
                   oninput="updateMeter(<?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?>); check_passwords_match();">
            <div class="help-min text-left" style="margin-top:6px;">
              Policy: minimum <strong><?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?></strong> characters for new accounts; maximum <strong><?php echo (int)MAX_LEN; ?></strong>. No composition rules.
            </div>
          </div>
          <div class="col-sm-3">
            <input tabindex="<?php print $tabindex+2; ?>" type="button" class="btn btn-soft btn-pill btn-sm" id="password_generator" onclick="random_password();" value="Generate password">
          </div>
        </div>

        <div class="form-group" id="confirm_div">
          <label for="confirm" class="col-sm-3 control-label">Confirm</label>
          <div class="col-sm-6">
            <input tabindex="<?php print $tabindex+3; ?>" type="password" class="form-control" id="confirm" name="password_match"
                   maxlength="<?php echo (int)MAX_LEN; ?>"
                   oninput="check_passwords_match();">
          </div>
        </div>

<?php if ($EMAIL_SENDING_ENABLED == TRUE && $admin_setup != TRUE) { ?>
        <div class="form-group" id="send_email_div">
          <label for="send_email" class="col-sm-3 control-label"> </label>
          <div class="col-sm-6">
            <label class="help-min" style="margin:0">
              <input tabindex="<?php print $tabindex+4; ?>" type="checkbox" class="form-check-input" id="send_email_checkbox" name="send_email" <?php if ($disabled_email_tickbox == TRUE) { print "disabled"; } ?>>
              Email these credentials to the user?
            </label>
          </div>
        </div>
<?php } ?>

        <div class="form-group text-center">
          <button tabindex="<?php print $tabindex+5; ?>" type="submit" class="btn btn-primary btn-pill">Create account</button>
        </div>
      </form>

      <!-- Length-only progress bar -->
      <div class="progress progress-modern">
        <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
          <span id="LengthLabel">0</span>
        </div>
      </div>

      <div class="help-min text-center" style="margin-top:6px;">
        <sup>&ast;</sup>The account identifier
      </div>
    </div>
  </div>
</div>

<?php render_footer(); ?>
