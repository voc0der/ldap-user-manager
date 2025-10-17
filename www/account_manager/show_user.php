<?php
// www/account_manager/show_user.php  (modernized styling + Authelia MFA inline resets, avatar endpoint)

declare(strict_types=1);

set_include_path(".:" . __DIR__ . "/../includes/");

include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";
include_once "module_functions.inc.php";
set_page_access("admin"); // keep gating for both HTML and avatar endpoint

// ---- Early avatar endpoint (same file) ---------------------------------------
if (isset($_GET['avatar'])) {
  // Minimal helpers (avoid any prior output!)
  header('X-Content-Type-Options: nosniff');

  // Resolve account_identifier from GET (required)
  $account_identifier = $_GET['account_identifier'] ?? '';
  if ($account_identifier === '') { http_response_code(400); exit; }

  // Open LDAP and fetch photo attributes
  $ldap_connection = open_ldap_connection();
  $uidAttr = $LDAP['account_attribute'];
  $filter  = "({$uidAttr}=" . ldap_escape($account_identifier, "", LDAP_ESCAPE_FILTER) . ")";
  $attrs   = ['jpegPhoto','thumbnailPhoto','photo'];
  $sr      = @ldap_search($ldap_connection, $LDAP['user_dn'], $filter, $attrs);

  if (!$sr) { http_response_code(500); exit; }
  $e = @ldap_get_entries($ldap_connection, $sr);
  if (!is_array($e) || ($e['count'] ?? 0) < 1) { http_response_code(404); exit; }

  $entry = $e[0];
  // LDAP array keys are lower-cased by PHP
  $photo = $entry['jpegphoto'][0] ?? ($entry['thumbnailphoto'][0] ?? ($entry['photo'][0] ?? null));
  if (!$photo) { http_response_code(404); exit; }

  // Detect MIME (fallback to image/jpeg)
  $mime = 'image/jpeg';
  if (function_exists('finfo_open')) {
    $fi = finfo_open(FILEINFO_MIME_TYPE);
    if ($fi) {
      $det = @finfo_buffer($fi, $photo);
      finfo_close($fi);
      if (is_string($det) && strpos($det, 'image/') === 0) $mime = $det;
    }
  }

  $etag = '"' . sha1($photo) . '"';
  header('Cache-Control: private, max-age=300');
  header('ETag: ' . $etag);
  if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && trim($_SERVER['HTTP_IF_NONE_MATCH']) === $etag) {
    http_response_code(304); exit;
  }

  header('Content-Type: ' . $mime);
  header('Content-Length: ' . strlen($photo));
  echo $photo;
  exit;
}

// ---- Password Policy (global) ----
const DEFAULT_MIN_LEN = 12;
const MAX_LEN         = 256;

function pw_len(string $s): int {
  if (function_exists('mb_strlen')) return mb_strlen($s, 'UTF-8');
  return strlen($s);
}

render_header("$ORGANISATION_NAME account manager");
render_submenu();

$invalid_username = FALSE;
$mismatched_passwords = FALSE;
$too_short = FALSE;
$too_long = FALSE;

$to_update = array();
$can_send_email = ($SMTP['host'] != "");

// allow typing email to toggle send checkbox
$LDAP['default_attribute_map']["mail"] = array("label" => "Email", "onkeyup" => "check_if_we_should_enable_sending_email();");

$attribute_map = $LDAP['default_attribute_map'];
if (isset($LDAP['account_additional_attributes'])) {
  $attribute_map = ldap_complete_attribute_array($attribute_map,$LDAP['account_additional_attributes']);
}
if (!array_key_exists($LDAP['account_attribute'], $attribute_map)) {
  $attribute_r = array_merge($attribute_map, array($LDAP['account_attribute'] => array("label" => "Account UID")));
}

$SELF = htmlentities($_SERVER['PHP_SELF']);

if (!isset($_POST['account_identifier']) && !isset($_GET['account_identifier'])) { ?>
  <div class="alert alert-danger">
    <p class="text-center">The account identifier is missing.</p>
  </div>
<?php
  render_footer();
  exit(0);
} else {
  $account_identifier = (isset($_POST['account_identifier']) ? $_POST['account_identifier'] : $_GET['account_identifier']);
  $account_identifier = urldecode($account_identifier);
}

$ldap_connection = open_ldap_connection();
$ldap_search_query = "({$LDAP['account_attribute']}=" . ldap_escape($account_identifier, "", LDAP_ESCAPE_FILTER) . ")";
$ldap_search = ldap_search($ldap_connection, $LDAP['user_dn'], $ldap_search_query);

if ($ldap_search) {
  $user = ldap_get_entries($ldap_connection, $ldap_search);

  if ($user["count"] > 0) {
    // Load current attributes or defaults
    foreach ($attribute_map as $attribute => $attr_r) {
      if (isset($user[0][$attribute]) && $user[0][$attribute]['count'] > 0) {
        $$attribute = $user[0][$attribute];
      } else {
        $$attribute = array();
      }

      if (isset($_FILES[$attribute]['size']) && $_FILES[$attribute]['size'] > 0) {
        $this_attribute = array();
        $this_attribute['count'] = 1;
        $this_attribute[0] = file_get_contents($_FILES[$attribute]['tmp_name']);
        $$attribute = $this_attribute;
        $to_update[$attribute] = $this_attribute;
        unset($to_update[$attribute]['count']);
      }

      if (isset($_POST['update_account']) && isset($_POST[$attribute])) {
        $this_attribute = array();
        if (is_array($_POST[$attribute])) {
          foreach($_POST[$attribute] as $key => $value) {
            if ($value !== "") { $this_attribute[$key] = filter_var($value, FILTER_SANITIZE_FULL_SPECIAL_CHARS); }
          }
          $this_attribute['count'] = count($this_attribute);
        } elseif ($_POST[$attribute] !== "") {
          $this_attribute['count'] = 1;
          $this_attribute[0] = filter_var($_POST[$attribute], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }

        if ($this_attribute != $$attribute) {
          $$attribute = $this_attribute;
          $to_update[$attribute] = $this_attribute;
          unset($to_update[$attribute]['count']);
        }
      }

      if (!isset($$attribute) && isset($attr_r['default'])) {
        $$attribute['count'] = 1;
        $$attribute[0] = $attr_r['default'];
      }
    }

    $dn = $user[0]['dn'];
  } else { ?>
    <div class="alert alert-danger">
      <p class="text-center">This account doesn't exist.</p>
    </div>
<?php
    render_footer();
    exit(0);
  }

  // ---- Determine policy for this target account (global min only) ----
  $target_groups = ldap_user_group_membership($ldap_connection, $account_identifier);
  $min_len = DEFAULT_MIN_LEN;

  // ---- Updates ----
  if (isset($_POST['update_account'])) {

    // Ensure uid & cn if missing
    if (!isset($uid[0])) {
      $uid[0] = generate_username($givenname[0], $sn[0]);
      $to_update['uid'] = $uid;
      unset($to_update['uid']['count']);
    }
    if (!isset($cn[0])) {
      if ($ENFORCE_SAFE_SYSTEM_NAMES == TRUE) { $cn[0] = $givenname[0] . $sn[0]; }
      else { $cn[0] = $givenname[0] . " " . $sn[0]; }
      $to_update['cn'] = $cn;
      unset($to_update['cn']['count']);
    }

    // Password change (optional)
    if (isset($_POST['password']) && $_POST['password'] !== "") {
      $password = $_POST['password'];

      if ($password !== ($_POST['password_match'] ?? '')) { $mismatched_passwords = TRUE; }
      if ($ENFORCE_SAFE_SYSTEM_NAMES == TRUE && !preg_match("/$USERNAME_REGEX/", $account_identifier)) { $invalid_username = TRUE; }

      $len = pw_len($password);
      if ($len < $min_len) { $too_short = TRUE; }
      if ($len > MAX_LEN)  { $too_long  = TRUE; }

      if (!$mismatched_passwords && !$invalid_username && !$too_short && !$too_long) {
        $to_update['userpassword'][0] = ldap_hashed_password($password);
      }
    }

    // If account identifier changed, rename DN
    if (array_key_exists($LDAP['account_attribute'], $to_update)) {
      $account_attribute_name = $LDAP['account_attribute'];
      $new_account_identifier = $to_update[$account_attribute_name][0];
      $new_rdn = "{$account_attribute_name}={$new_account_identifier}";
      $renamed_entry = ldap_rename($ldap_connection, $dn, $new_rdn, $LDAP['user_dn'], true);
      if ($renamed_entry) {
        $dn = "{$new_rdn},{$LDAP['user_dn']}";
        $account_identifier = $new_account_identifier;
      } else {
        ldap_get_option($ldap_connection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $detailed_err);
        error_log("$log_prefix Failed to rename the DN for {$account_identifier}: " . ldap_error($ldap_connection) . " -- " . $detailed_err, 0);
      }
    }

    // Ensure objectclasses match policy
    $existing_objectclasses = $user[0]['objectclass'];
    unset($existing_objectclasses['count']);
    if ($existing_objectclasses != $LDAP['account_objectclasses']) { $to_update['objectclass'] = $LDAP['account_objectclasses']; }

    $updated_account = @ldap_mod_replace($ldap_connection, $dn, $to_update);
    if (!$updated_account) {
      ldap_get_option($ldap_connection, LDAP_OPT_DIAGNOSTIC_MESSAGE, $detailed_err);
      error_log("$log_prefix Failed to modify account details for {$account_identifier}: " . ldap_error($ldap_connection) . " -- " . $detailed_err, 0);
    }

    // Optional email send when password changed
    $sent_email_message = "";
    if ($updated_account && isset($mail) && $can_send_email == TRUE && isset($_POST['send_email']) && isset($password) && $password !== "") {
      include_once "mail_functions.inc.php";
      $mail_body    = parse_mail_text($new_account_mail_body, $password, $account_identifier, $givenname[0], $sn[0]);
      $mail_subject = parse_mail_text($new_account_mail_subject, $password, $account_identifier, $givenname[0], $sn[0]);

      $sent_email = send_email($mail[0], "{$givenname[0]} {$sn[0]}", $mail_subject, $mail_body);
      if ($sent_email) {
        $sent_email_message .= "  An email sent to {$mail[0]}.";
      } else {
        $sent_email_message .= "  Unfortunately the email wasn't sent; check the logs for more information.";
      }
    }

    if ($updated_account) {
      render_alert_banner("The account has been updated.$sent_email_message");
    } else {
      render_alert_banner("There was a problem updating the account.  Check the logs for more information.", "danger", 15000);
    }
  }

  // ---- Authelia MFA status (read-only) ----
  $AUTHELIA_DIR    = getenv('AUTHELIA_DIR') ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
  $AUTHELIA_STATUS = $AUTHELIA_DIR . '/status.json';

  $authelia_status = [];
  if (is_file($AUTHELIA_STATUS)) {
    $raw = @file_get_contents($AUTHELIA_STATUS);
    if ($raw !== false) $authelia_status = json_decode($raw, true) ?: [];
  }
  $totp_present   = !empty(($authelia_status['totp'] ?? [])[$account_identifier]);
  $webauthn_count = (int)(($authelia_status['webauthn'] ?? [])[$account_identifier] ?? 0);
  $status_ts      = isset($authelia_status['generated_ts']) ? (int)$authelia_status['generated_ts'] : 0;

  // ---- Block MFA actions if target is in the "admin" group ----
  $ADMIN_GROUP_NAME = getenv('ADMIN_GROUP_NAME') ?: 'admin';
  $MFA_BLOCKED_FOR_USER = false;
  foreach ($target_groups as $g) {
    if (strcasecmp($g, $ADMIN_GROUP_NAME) === 0) { $MFA_BLOCKED_FOR_USER = true; break; }
  }

  // Errors (after update attempt)
  if ($too_short) { ?>
    <div class="alert alert-warning"><p class="text-center">Password is too short. Minimum length is <?php echo (int)$min_len; ?> characters.</p></div>
  <?php }
  if ($too_long) { ?>
    <div class="alert alert-warning"><p class="text-center">Password is too long. Maximum length is <?php echo (int)MAX_LEN; ?> characters.</p></div>
  <?php }
  if ($mismatched_passwords) { ?>
    <div class="alert alert-warning"><p class="text-center">The passwords didn't match.</p></div>
  <?php }

  // ---- Group lists ----
  $all_groups = ldap_get_group_list($ldap_connection);
  $currently_member_of = $target_groups;
  $not_member_of = array_diff($all_groups, $currently_member_of);

  if (isset($_POST["update_member_of"])) {
    $updated_group_membership = array();
    foreach ($_POST as $index => $group) {
      if (is_numeric($index)) array_push($updated_group_membership, $group);
    }
    if ($USER_ID == $account_identifier && !array_search($USER_ID, $updated_group_membership)){
      array_push($updated_group_membership, $LDAP["admins_group"]);
    }
    $groups_to_add = array_diff($updated_group_membership, $currently_member_of);
    $groups_to_del = array_diff($currently_member_of, $updated_group_membership);
    foreach ($groups_to_del as $this_group) { ldap_delete_member_from_group($ldap_connection,$this_group,$account_identifier); }
    foreach ($groups_to_add as $this_group) { ldap_add_member_to_group($ldap_connection,$this_group,$account_identifier); }
    $not_member_of = array_diff($all_groups, $updated_group_membership);
    $member_of = $updated_group_membership;
    render_alert_banner("The group membership has been updated.");
  } else {
    $member_of = $currently_member_of;
  }

} // end if ($ldap_search)
?>
<script type="text/javascript" src="<?php print $SERVER_PATH; ?>js/generate_passphrase.js"></script>
<script type="text/javascript" src="<?php print $SERVER_PATH; ?>js/wordlist.js"></script>
<script type="text/javascript">
function codePointLen(str){return Array.from(str||"").length;}
function clamp(v,min,max){return Math.max(min,Math.min(max,v));}

var MIN_LEN = <?php echo (int)$min_len; ?>;
var MAX_LEN = <?php echo (int)MAX_LEN; ?>;

function updateMeter(){
  var pw   = document.getElementById('password').value || "";
  var len  = codePointLen(pw);
  var pct  = clamp(Math.round((len / MIN_LEN) * 100), 0, 100);

  var bar   = document.getElementById('LengthProgress');
  var label = document.getElementById('LengthLabel');

  bar.style.width = pct + "%";
  bar.className = "progress-bar";
  if (pct >= 100) bar.className += " progress-bar-success";
  else if (pct >= 50) bar.className += " progress-bar-info";

  label.textContent = len + " / " + MIN_LEN;
}

function random_password(){
  generatePassword(4,'-','password','confirm');
  updateMeter();
  check_if_we_should_enable_sending_email();
}

function back_to_hidden(passwordField,confirmField){
  return; // no-op, kept for compatibility
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

function check_if_we_should_enable_sending_email(){
  var check_regex = <?php print $JS_EMAIL_REGEX; ?>;
  <?php if ($can_send_email == TRUE) { ?>
  var ok = check_regex.test(document.getElementById("mail").value) && (document.getElementById("password").value.length > 0);
  document.getElementById("send_email_checkbox").disabled = !ok;
  <?php } ?>
  if (check_regex.test(document.getElementById('mail').value)) {
    document.getElementById("mail_div").classList.remove("has-error");
  } else {
    document.getElementById("mail_div").classList.add("has-error");
  }
}

document.addEventListener('DOMContentLoaded', updateMeter);
</script>

<?php render_dynamic_field_js(); ?>

<style type='text/css'>
/* ---------- modern chrome ---------- */
.wrap-narrow { max-width: 1100px; margin: 18px auto 32px; }
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
.btn-ghost { background:transparent; border:1px solid rgba(255,255,255,.14); color:#b9d7f3; }
.btn-ghost:hover { background:rgba(255,255,255,.06); }
.btn-xxs { padding:3px 8px; font-size:11px; line-height:1.2; border-radius:10px; vertical-align:middle; margin-left:8px; }
.label { vertical-align:middle; }
.progress-modern { height:18px; background:#0e151d; border:1px solid rgba(255,255,255,.08); border-radius:10px; }
.progress-modern .progress-bar { line-height:16px; font-size:12px; }
.dual-list .well { background:#0e151d; border:1px solid rgba(255,255,255,.08); border-radius:10px; }
.dual-list .list-group-item { background:transparent; border-color:rgba(255,255,255,.08); color:#cfe9ff; }
.dual-list .list-group-item.active { background:#1a2b3a; border-color:#294155; }
.list-arrows button { margin-bottom: 12px; }
.panel-title h3 { margin:0; font-size:18px; letter-spacing:.2px; }
.invisible { visibility:hidden; } .visible { visibility:visible; }
.right_button { width: 200px; float: right; }
.avatar {
  width:40px;height:40px;border-radius:50%;object-fit:cover;margin-right:10px;vertical-align:middle;border:1px solid rgba(255,255,255,.18);
}
</style>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <div class="pull-left">
        <img class="avatar" alt="Avatar"
             src="<?php echo $SELF; ?>?avatar=1&account_identifier=<?php echo urlencode($account_identifier); ?>&t=<?php echo (int)$status_ts; ?>"
             onerror="this.style.display='none'">
        <span class="panel-title"><h3 style="display:inline-block;vertical-align:middle;margin:0;"><?php print $account_identifier; ?></h3></span>
      </div>
      <div class="pull-right">
        <button class="btn btn-warning btn-pill" onclick="show_delete_user_button();" <?php if ($account_identifier == $USER_ID) { print "disabled"; }?>>Delete account</button>
        <form action="<?php print "{$THIS_MODULE_PATH}"; ?>/index.php" method="post" style="display:inline;">
          <input type="hidden" name="delete_user" value="<?php print urlencode($account_identifier); ?>">
          <button class="btn btn-danger btn-pill invisible" id="delete_user">Confirm deletion</button>
        </form>
      </div>
    </div>

    <ul class="list-group">
      <li class="list-group-item" style="background:transparent;border-color:rgba(255,255,255,.08);color:#9fb6c9;"><?php print $dn; ?></li>
    </ul>

    <div class="panel-body">
      <form class="form-horizontal" action="" enctype="multipart/form-data" method="post">
        <input type="hidden" name="update_account">
        <input type="hidden" name="account_identifier" value="<?php print $account_identifier; ?>">

        <?php
          // Render attributes; avoid inline data: previews for photo attrs
          $photo_attrs = ['jpegPhoto','jpegphoto','thumbnailPhoto','thumbnailphoto','photo'];
          foreach ($attribute_map as $attribute => $attr_r) {
            $label    = $attr_r['label'];
            $onkeyup  = isset($attr_r['onkeyup']) ? $attr_r['onkeyup'] : "";
            $inputtype= isset($attr_r['inputtype']) ? $attr_r['inputtype'] : "";
            if ($attribute == $LDAP['account_attribute']) { $label = "<strong>$label</strong><sup>&ast;</sup>"; }
            $these_values = isset($$attribute) ? $$attribute : array();

            if (in_array($attribute, $photo_attrs, true)) {
              // Custom rendering: preview via self endpoint + plain file input (no data: URIs)
              ?>
              <div class="form-group">
                <label class="col-sm-3 control-label"><?php echo $label; ?></label>
                <div class="col-sm-6">
                  <img class="avatar" alt="Avatar preview"
                       src="<?php echo $SELF; ?>?avatar=1&account_identifier=<?php echo urlencode($account_identifier); ?>&t=<?php echo (int)$status_ts; ?>"
                       onerror="this.style.display='none'">
                  <input type="file" class="form-control" name="<?php echo htmlspecialchars($attribute); ?>" accept="image/*">
                  <div class="help-min">Upload a new image to replace the existing photo. Leave blank to keep the current one.</div>
                </div>
              </div>
              <?php
            } else {
              render_attribute_fields($attribute,$label,$these_values,$dn,$onkeyup,$inputtype);
            }
          }
        ?>

        <div class="form-group" id="password_div">
          <label for="password" class="col-sm-3 control-label">Password</label>
          <div class="col-sm-6">
            <input type="password" class="form-control" id="password" name="password"
                   maxlength="<?php echo (int)MAX_LEN; ?>"
                   oninput="back_to_hidden('password','confirm'); check_if_we_should_enable_sending_email(); updateMeter();">
            <div class="help-min text-left" style="margin-top:6px;">
              Policy: minimum <strong><?php echo (int)$min_len; ?></strong> characters; maximum <strong><?php echo (int)MAX_LEN; ?></strong>. No composition rules.
            </div>
          </div>
          <div class="col-sm-3">
            <input type="button" class="btn btn-soft btn-pill btn-sm right_button" id="password_generator" onclick="random_password();" value="Generate password">
          </div>
        </div>

        <div class="form-group" id="confirm_div">
          <label for="confirm" class="col-sm-3 control-label">Confirm</label>
          <div class="col-sm-6">
            <input type="password" class="form-control" id="confirm" name="password_match"
                   maxlength="<?php echo (int)MAX_LEN; ?>"
                   oninput="check_passwords_match();">
          </div>
        </div>

<?php if ($can_send_email == TRUE) { ?>
        <div class="form-group" id="send_email_div">
          <label for="send_email" class="col-sm-3 control-label"> </label>
          <div class="col-sm-6">
            <label class="help-min" style="margin:0">
              <input type="checkbox" class="form-check-input" id="send_email_checkbox" name="send_email" disabled>
              Email the updated credentials to the user?
            </label>
          </div>
        </div>
<?php } ?>

        <div class="form-group">
          <p class='text-center'>
            <button type="submit" class="btn btn-primary btn-pill">Update account details</button>
          </p>
        </div>
      </form>

      <!-- Length-only progress bar -->
      <div class="progress progress-modern">
        <div id="LengthProgress" class="progress-bar" role="progressbar" style="width:0%;">
          <span id="LengthLabel">0</span>
        </div>
      </div>

      <div class="help-min text-center" style="margin-top:6px;">
        <sup>&ast;</sup>The account identifier. Changing this will change the full <strong>DN</strong>.
      </div>
    </div>
  </div>
</div>

<!-- ===== Authelia MFA Panel (inline reset buttons) ===== -->
<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <h3 class="panel-title pull-left" style="padding-top:7.5px;">Authelia MFA</h3>
      <div class="pull-right">
        <button class="btn btn-soft btn-pill btn-sm" id="mfa-refresh"
                onclick="refreshMfa()"
                title="Re-read status.json (stager refreshes automatically after ops)">Refresh</button>
      </div>
    </div>
    <div class="panel-body">
      <?php if ($MFA_BLOCKED_FOR_USER) { ?>
        <div class="alert alert-warning" style="margin-bottom:14px;">
          MFA actions are disabled for accounts in the “<?php echo htmlspecialchars($ADMIN_GROUP_NAME); ?>” group.
        </div>
      <?php } ?>
      <div class="row" style="margin-bottom:8px;">
        <div class="col-sm-3"><strong>TOTP</strong></div>
        <div class="col-sm-6">
          <span id="totp-badge" class="label <?php echo $totp_present ? 'label-success' : 'label-default'; ?>">
            <?php echo $totp_present ? 'Yes' : 'No'; ?>
          </span>
          <?php if ($totp_present && !$MFA_BLOCKED_FOR_USER) { ?>
            <button id="btn-reset-totp" class="btn btn-ghost btn-xxs"
                    onclick="resetTotp('<?php echo htmlspecialchars($account_identifier, ENT_QUOTES); ?>')"
                    title="Delete TOTP secret for this user">
              Reset
            </button>
          <?php } ?>
        </div>
        <div class="col-sm-3 text-right help-min">
          <span id="mfa-age"><?php
            echo $status_ts ? ('Updated ' . date('Y-m-d H:i:s', $status_ts)) : 'No status yet';
          ?></span>
        </div>
      </div>

      <div class="row" style="margin-top:6px;">
        <div class="col-sm-3"><strong>WebAuthn</strong></div>
        <div class="col-sm-6">
          <span id="webauthn-badge" class="label <?php echo ($webauthn_count>0) ? 'label-info' : 'label-default'; ?>">
            <?php echo (int)$webauthn_count; ?> device<?php echo ($webauthn_count==1)?'':'s'; ?>
          </span>
          <?php if ($webauthn_count > 0 && !$MFA_BLOCKED_FOR_USER) { ?>
            <button id="btn-reset-wa" class="btn btn-ghost btn-xxs"
                    onclick="resetWebAuthnAll('<?php echo htmlspecialchars($account_identifier, ENT_QUOTES); ?>')"
                    title="Delete all WebAuthn devices for this user">
              Reset
            </button>
          <?php } ?>
        </div>
      </div>

      <div id="mfa-toast" class="help-min" style="margin-top:10px; display:none;"></div>
    </div>
  </div>
</div>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <h3 class="panel-title pull-left" style="padding-top:7.5px;">Group membership</h3>
    </div>
    <div class="panel-body">

      <div class="row">
        <div class="dual-list list-left col-md-5">
          <strong>Member of</strong>
          <div class="well">
            <div class="row">
              <div class="col-md-10">
                <div class="input-group">
                  <span class="input-group-addon glyphicon glyphicon-search"></span>
                  <input type="text" name="SearchDualList" class="form-control" placeholder="search" />
                </div>
              </div>
              <div class="col-md-2">
                <div class="btn-group">
                  <a class="btn btn-soft btn-pill selector" title="select all"><i class="glyphicon glyphicon-unchecked"></i></a>
                </div>
              </div>
            </div>
            <ul class="list-group" id="member_of_list">
              <?php
              foreach ($member_of as $group) {
                if ($group == $LDAP["admins_group"] && $USER_ID == $account_identifier) {
                  print "<div class='list-group-item' style='opacity: 0.5; pointer-events:none;'>{$group}</div>\n";
                } else {
                  print "<li class='list-group-item'>$group</li>\n";
                }
              }
              ?>
            </ul>
          </div>
        </div>

        <div class="list-arrows col-md-1 text-center">
          <button class="btn btn-soft btn-sm btn-pill move-left"><span class="glyphicon glyphicon-chevron-left"></span></button>
          <button class="btn btn-soft btn-sm btn-pill move-right"><span class="glyphicon glyphicon-chevron-right"></span></button>
          <form id="update_with_groups" action="<?php print $CURRENT_PAGE ?>" method="post">
            <input type="hidden" name="update_member_of">
            <input type="hidden" name="account_identifier" value="<?php print $account_identifier; ?>">
          </form>
          <button id="submit_members" class="btn btn-primary btn-pill" disabled type="submit" onclick="update_form_with_groups()">Save</button>
        </div>

        <div class="dual-list list-right col-md-5">
          <strong>Available groups</strong>
          <div class="well">
            <div class="row">
              <div class="col-md-2">
                <div class="btn-group">
                  <a class="btn btn-soft btn-pill selector" title="select all"><i class="glyphicon glyphicon-unchecked"></i></a>
                </div>
              </div>
              <div class="col-md-10">
                <div class="input-group">
                  <input type="text" name="SearchDualList" class="form-control" placeholder="search" />
                  <span class="input-group-addon glyphicon glyphicon-search"></span>
                </div>
              </div>
            </div>
            <ul class="list-group">
              <?php foreach ($not_member_of as $group) { print "<li class='list-group-item'>$group</li>\n"; } ?>
            </ul>
          </div>
        </div>
      </div><!-- /row -->

    </div><!-- /panel-body -->
  </div><!-- /panel -->
</div>

<script type="text/javascript">
function show_delete_user_button(){
  var group_del_submit = document.getElementById('delete_user');
  group_del_submit.classList.replace('invisible','visible');
}
function update_form_with_groups(){
  var group_form = document.getElementById('update_with_groups');
  var group_list_ul = document.getElementById('member_of_list');
  var group_list = group_list_ul.getElementsByTagName("li");
  for (var i = 0; i < group_list.length; ++i) {
    var hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = i;
    hidden.value = group_list[i]['textContent'];
    group_form.appendChild(hidden);
  }
  group_form.submit();
}
(function () {
  $('body').on('click', '.list-group .list-group-item', function () {
      $(this).toggleClass('active');
  });
  $('.list-arrows button').click(function () {
      var $button = $(this), actives = '';
      if ($button.hasClass('move-left')) {
          actives = $('.list-right ul li.active');
          actives.clone().appendTo('.list-left ul');
          $('.list-left ul li.active').removeClass('active');
          actives.remove();
      } else if ($button.hasClass('move-right')) {
          actives = $('.list-left ul li.active');
          actives.clone().appendTo('.list-right ul');
          $('.list-right ul li.active').removeClass('active');
          actives.remove();
      }
      $("#submit_members").prop("disabled", false);
  });
  $('.dual-list .selector').click(function () {
      var $checkBox = $(this);
      if (!$checkBox.hasClass('selected')) {
          $checkBox.addClass('selected').closest('.well').find('ul li:not(.active)').addClass('active');
          $checkBox.children('i').removeClass('glyphicon-unchecked').addClass('glyphicon-check');
      } else {
          $checkBox.removeClass('selected').closest('.well').find('ul li.active').removeClass('active');
          $checkBox.children('i').removeClass('glyphicon-check').addClass('glyphicon-unchecked');
      }
  });
  $('[name="SearchDualList"]').keyup(function (e) {
      var code = e.keyCode || e.which;
      if (code == '9') return;
      if (code == '27') $(this).val(null);
      var $rows = $(this).closest('.dual-list').find('.list-group li');
      var val = $.trim($(this).val()).replace(/ +/g, ' ').toLowerCase();
      $rows.show().filter(function () {
          var text = $(this).text().replace(/\s+/g, ' ').toLowerCase();
          return !~text.indexOf(val);
      }).hide();
  });
})();
</script>

<!-- ===== Authelia integration JS ===== -->
<script type="text/javascript">
var MFA_BLOCKED = <?php echo $MFA_BLOCKED_FOR_USER ? 'true' : 'false'; ?>;
var TARGET_UID  = <?php echo json_encode($account_identifier); ?>;

function showToast(msg, isErr){
  var t = document.getElementById('mfa-toast');
  if (!t) return;
  t.style.display = 'block';
  t.style.color = isErr ? '#ffb3b3' : '#9fd1a5';
  t.textContent = msg;
  setTimeout(function(){ t.style.display='none'; }, 7000);
}

async function refreshMfa(){
  try{
    const res = await fetch('authelia_api.php?action=status&t=' + Date.now(), { credentials:'include' });
    if(!res.ok){ showToast('Failed to refresh status ('+res.status+')', true); return; }
    const j = await res.json();
    const uid = TARGET_UID;
    const totp = !!(j.totp && j.totp[uid]);
    const webn = (j.webauthn && j.webauthn[uid])|0;

    var tb = document.getElementById('totp-badge');
    if (tb){ tb.textContent = totp ? 'Yes' : 'No';
             tb.className   = 'label ' + (totp ? 'label-success' : 'label-default'); }

    var wb = document.getElementById('webauthn-badge');
    if (wb){ wb.textContent = webn + ' device' + (webn===1?'':'s');
             wb.className   = 'label ' + (webn>0 ? 'label-info' : 'label-default'); }

    // Toggle inline buttons depending on state + block
    var btnT = document.getElementById('btn-reset-totp');
    if (btnT){
      if (!totp || MFA_BLOCKED) btnT.remove();
    }

    var btnW = document.getElementById('btn-reset-wa');
    if (btnW){
      if (webn<=0 || MFA_BLOCKED) btnW.remove();
    }

    var age = document.getElementById('mfa-age');
    if (age && j.generated_ts) {
      var d = new Date(j.generated_ts * 1000);
      var pad = n => (n<10?'0':'')+n;
      age.textContent = 'Updated ' + d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) +
                        ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }
  }catch(e){
    showToast('Refresh failed: ' + e, true);
  }
}

async function resetTotp(user){
  if (MFA_BLOCKED) { showToast('MFA actions are disabled for this account.', true); return; }
  const btn = document.getElementById('btn-reset-totp');
  if (btn){ btn.disabled = true; btn.textContent = 'Resetting…'; }

  try{
    const body = new URLSearchParams({ op:'totp.delete', user:user });
    const res  = await fetch('authelia_api.php', {
      method:'POST',
      headers:{ 'Content-Type':'application/x-www-form-urlencoded' },
      credentials:'include',
      body
    });
    const j = await res.json();
    if (!j.ok){ showToast('Queue failed: ' + (j.error || 'unknown'), true);
                if(btn){btn.disabled=false;btn.textContent='Reset';}
                return; }

    const id = j.action_id;
    let tries = 0;

    const poll = async () => {
      tries++;
      const r = await fetch('authelia_api.php?action=result&id=' + encodeURIComponent(id) + '&t=' + Date.now(),
                            { credentials:'include' });
      if (r.status === 404) {
        if (tries < 40) { setTimeout(poll, 750); }
        else { showToast('Timed out waiting for result', true);
               if(btn){btn.disabled=false;btn.textContent='Reset';} }
        return;
      }
      const jr = await r.json();
      if (!jr.ok) {
        showToast(jr.details || 'Delete failed', true);
        if(btn){btn.disabled=false;btn.textContent='Reset';}
        return;
      }
      showToast(jr.details || 'TOTP deleted');
      var tb = document.getElementById('totp-badge');
      if (tb){ tb.textContent = 'No'; tb.className = 'label label-default'; }
      if (btn) btn.remove();
      setTimeout(refreshMfa, 600);
    };
    poll();
  }catch(e){
    showToast('Error: ' + e, true);
    if(btn){btn.disabled=false;btn.textContent='Reset';}
  }
}

async function resetWebAuthnAll(user){
  if (MFA_BLOCKED) { showToast('MFA actions are disabled for this account.', true); return; }
  const btn = document.getElementById('btn-reset-wa');
  if (btn){ btn.disabled = true; btn.textContent = 'Resetting…'; }

  try{
    const body = new URLSearchParams({ op:'webauthn.delete', user:user, scope:'all' });
    const res  = await fetch('authelia_api.php', {
      method:'POST',
      headers:{ 'Content-Type':'application/x-www-form-urlencoded' },
      credentials:'include',
      body
    });
    const j = await res.json();
    if (!j.ok){ showToast('Queue failed: ' + (j.error || 'unknown'), true);
                if(btn){btn.disabled=false;btn.textContent='Reset';}
                return; }

    const id = j.action_id;
    let tries = 0;

    const poll = async () => {
      tries++;
      const r = await fetch('authelia_api.php?action=result&id=' + encodeURIComponent(id) + '&t=' + Date.now(),
                            { credentials:'include' });
      if (r.status === 404) {
        if (tries < 40) { setTimeout(poll, 750); }
        else { showToast('Timed out waiting for result', true);
               if(btn){btn.disabled=false;btn.textContent='Reset';} }
        return;
      }
      const jr = await r.json();
      if (!jr.ok) {
        showToast(jr.details || 'Delete failed', true);
        if(btn){btn.disabled=false;btn.textContent='Reset';}
        return;
      }
      showToast(jr.details || 'WebAuthn devices deleted');
      var wb = document.getElementById('webauthn-badge');
      if (wb){ wb.textContent = '0 devices'; wb.className = 'label label-default'; }
      if (btn) btn.remove();
      setTimeout(refreshMfa, 600);
    };
    poll();
  }catch(e){
    showToast('Error: ' + e, true);
    if(btn){btn.disabled=false;btn.textContent='Reset';}
  }
}
</script>

<?php render_footer(); ?>
