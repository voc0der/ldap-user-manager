<?php
// www/account_manager/new_user.php

set_include_path(".:" . __DIR__ . "/../includes/");

include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";
include_once "module_functions.inc.php";

// ---- Password Policy (adjust as needed) ----
const DEFAULT_MIN_LEN = 12;
const ADMIN_MIN_LEN   = 15;   // for admin/privileged roles
const NO_MFA_MIN_LEN  = 15;   // for accounts without MFA
const MAX_LEN         = 256;  // allow long passphrases

// Unicode-aware length
function pw_len(string $s): int {
  if (function_exists('mb_strlen')) return mb_strlen($s, 'UTF-8');
  return strlen($s);
}

$attribute_map = $LDAP['default_attribute_map'];
if (isset($LDAP['account_additional_attributes'])) {
  $attribute_map = ldap_complete_attribute_array($attribute_map, $LDAP['account_additional_attributes']);
}
if (!array_key_exists($LDAP['account_attribute'], $attribute_map)) {
  $attribute_r = array_merge($attribute_map, array($LDAP['account_attribute'] => array("label" => "Account UID")));
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

// Build attribute values from POST/FILE/defaults
foreach ($attribute_map as $attribute => $attr_r) {

  if (isset($_FILES[$attribute]['size']) && $_FILES[$attribute]['size'] > 0) {
    $this_attribute = array();
    $this_attribute['count'] = 1;
    $this_attribute[0] = file_get_contents($_FILES[$attribute]['tmp_name']);
    $$attribute = $this_attribute;
    $new_account_r[$attribute] = $this_attribute;
    unset($new_account_r[$attribute]['count']);
  }

  if (isset($_POST[$attribute])) {
    $this_attribute = array();

    if (is_array($_POST[$attribute]) && count($_POST[$attribute]) > 0) {
      foreach($_POST[$attribute] as $key => $value) {
        if ($value !== "") { $this_attribute[$key] = filter_var($value, FILTER_SANITIZE_FULL_SPECIAL_CHARS); }
      }
      if (count($this_attribute) > 0) {
        $this_attribute['count'] = count($this_attribute);
        $$attribute = $this_attribute;
      }
    } elseif ($_POST[$attribute] !== "") {
      $this_attribute['count'] = 1;
      $this_attribute[0] = filter_var($_POST[$attribute], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
      $$attribute = $this_attribute;
    }
  }

  if (!isset($$attribute) && isset($attr_r['default'])) {
    $$attribute['count'] = 1;
    $$attribute[0] = $attr_r['default'];
  }

  if (isset($$attribute)) {
    $new_account_r[$attribute] = $$attribute;
    unset($new_account_r[$attribute]['count']);
  }
}

// Pre-fill from account_request (optional)
if (isset($_GET['account_request'])) {
  $givenname[0] = filter_var($_GET['first_name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
  $new_account_r['givenname'] = $givenname[0];

  $sn[0] = filter_var($_GET['last_name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
  $new_account_r['sn'] = $sn[0];

  $mail[0] = filter_var($_GET['email'], FILTER_SANITIZE_EMAIL);
  if ($mail[0] == "") {
    if (isset($EMAIL_DOMAIN)) {
      $mail[0] = $uid . "@" . $EMAIL_DOMAIN;
      $disabled_email_tickbox = FALSE;
    }
  } else {
    $disabled_email_tickbox = FALSE;
  }
  $new_account_r['mail'] = $mail;
  unset($new_account_r['mail']['count']);
}

// Generate missing uid/cn on request or form post
if (isset($_GET['account_request']) || isset($_POST['create_account'])) {
  if (!isset($uid[0])) {
    $uid[0] = generate_username($givenname[0], $sn[0]);
    $new_account_r['uid'] = $uid;
    unset($new_account_r['uid']['count']);
  }
  if (!isset($cn[0])) {
    if ($ENFORCE_SAFE_SYSTEM_NAMES == TRUE) {
      $cn[0] = $givenname[0] . $sn[0];
    } else {
      $cn[0] = $givenname[0] . " " . $sn[0];
    }
    $new_account_r['cn'] = $cn;
    unset($new_account_r['cn']['count']);
  }
}

if (isset($_POST['create_account'])) {
  $password = $_POST['password'] ?? '';
  $new_account_r['password'][0] = $password;

  $account_identifier = $new_account_r[$account_attribute][0] ?? '';
  $this_cn        = $cn[0]          ?? '';
  $this_mail      = $mail[0]        ?? '';
  $this_givenname = $givenname[0]   ?? '';
  $this_sn        = $sn[0]          ?? '';
  $this_password  = $password;

  // Basic required fields
  if ($this_cn === "") { $invalid_cn = TRUE; }
  if (($account_identifier === "") && !$invalid_cn) { $invalid_account_identifier = TRUE; }
  if ($this_givenname === "") { $invalid_givenname = TRUE; }
  if ($this_sn === "") { $invalid_sn = TRUE; }
  if (isset($this_mail) && !is_valid_email($this_mail)) { $invalid_email = TRUE; }
  if ($password !== ($_POST['password_match'] ?? '')) { $mismatched_passwords = TRUE; }
  if ($ENFORCE_SAFE_SYSTEM_NAMES == TRUE && !preg_match("/$USERNAME_REGEX/", $account_identifier)) { $invalid_account_identifier = TRUE; }

  // ---- Length-only password policy
  // New users typically don't have MFA yet => require NO_MFA_MIN_LEN.
  $min_len = ($admin_setup ? max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) : NO_MFA_MIN_LEN);
  $len = pw_len($password);
  if ($len < $min_len) { $too_short = TRUE; }
  if ($len > MAX_LEN)  { $too_long  = TRUE; }

  // Send email?
  if (isset($_POST['send_email']) && isset($mail) && $EMAIL_SENDING_ENABLED == TRUE) {
    $send_user_email = TRUE;
  }

  if (    !$mismatched_passwords
      &&  !$too_short
      &&  !$too_long
      &&  !$invalid_account_identifier
      &&  !$invalid_cn
      &&  !$invalid_email
      &&  !$invalid_givenname
      &&  !$invalid_sn
      &&   isset($this_password)
     ) {

    $ldap_connection = open_ldap_connection();
    $new_account = ldap_new_account($ldap_connection, $new_account_r);

    if ($new_account) {
      $creation_message = "The account was created.";

      if (isset($send_user_email) && $send_user_email === TRUE) {
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

// Show any errors
$errors = "";
if ($invalid_cn)                { $errors .= "<li>The Common Name is required</li>\n"; }
if ($invalid_givenname)         { $errors .= "<li>First Name is required</li>\n"; }
if ($invalid_sn)                { $errors .= "<li>Last Name is required</li>\n"; }
if ($invalid_account_identifier){ $errors .= "<li>The account identifier (" . $attribute_map[$account_attribute]['label'] . ") is invalid.</li>\n"; }
if ($invalid_email)             { $errors .= "<li>The email address is invalid</li>\n"; }
if ($mismatched_passwords)      { $errors .= "<li>The passwords are mismatched</li>\n"; }
if ($too_short)                 { $errors .= "<li>Password is too short (minimum " . max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN) . " characters for new accounts)</li>\n"; }
if ($too_long)                  { $errors .= "<li>Password is too long (maximum " . (int)MAX_LEN . " characters)</li>\n"; }

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

<div class="container">
  <div class="col-sm-8 col-md-offset-2">

    <div class="panel panel-default">
      <div class="panel-heading text-center"><?php print $page_title; ?></div>
      <div class="panel-body text-center">

        <form class="form-horizontal" action="" enctype="multipart/form-data" method="post">
          <?php if ($admin_setup == TRUE) { ?><input type="hidden" name="setup_admin_account" value="true"><?php } ?>
          <input type="hidden" name="create_account">

          <?php
            foreach ($attribute_map as $attribute => $attr_r) {
              $label = $attr_r['label'];
              $onkeyup = isset($attr_r['onkeyup']) ? $attr_r['onkeyup'] : "";
              if ($attribute == $LDAP['account_attribute']) { $label = "<strong>$label</strong><sup>&ast;</sup>"; }
              if (isset($attr_r['required']) && $attr_r['required'] == TRUE) { $label = "<strong>$label</strong><sup>&ast;</sup>"; }
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
              <div class="help-block text-left" style="margin-top:6px;">
                Policy: minimum <strong><?php echo (int)max(ADMIN_MIN_LEN, NO_MFA_MIN_LEN); ?></strong> characters for new accounts; maximum <strong><?php echo (int)MAX_LEN; ?></strong>. No composition rules.
              </div>
            </div>
            <div class="col-sm-1">
              <input tabindex="<?php print $tabindex+2; ?>" type="button" class="btn btn-sm" id="password_generator" onclick="random_password();" value="Generate password">
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
              <input tabindex="<?php print $tabindex+4; ?>" type="checkbox" class="form-check-input" id="send_email_checkbox" name="send_email" <?php if ($disabled_email_tickbox == TRUE) { print "disabled"; } ?>>  Email these credentials to the user?
            </div>
          </div>
<?php } ?>

          <div class="form-group">
            <button tabindex="<?php print $tabindex+5; ?>" type="submit" class="btn btn-warning">Create account</button>
          </div>
        </form>

        <!-- Length-only progress bar -->
        <div class="progress" style="height: 18px;">
          <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
            <span id="LengthLabel">0</span>
          </div>
        </div>

        <div><sup>&ast;</sup>The account identifier</div>
      </div>
    </div>

  </div>
</div>

<?php render_footer(); ?>
