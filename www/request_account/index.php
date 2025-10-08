<?php
set_include_path(".:" . __DIR__ . "/../includes/");
session_start();

include_once "web_functions.inc.php";

render_header("$ORGANISATION_NAME - request an account");

if ($ACCOUNT_REQUESTS_ENABLED == FALSE) { ?>
  <div class='alert alert-warning'><p class='text-center'>Account requesting is disabled.</p></div>
<?php render_footer(); exit; }

if($_POST) {

  $error_messages = array();

  if(! isset($_POST['validate']) or strcasecmp($_POST['validate'], $_SESSION['proof_of_humanity']) != 0) {
    array_push($error_messages, "The validation text didn't match the image.");
  }

  if (! isset($_POST['firstname']) or $_POST['firstname'] == "") {
    array_push($error_messages, "You didn't enter your first name.");
  } else {
    $firstname = filter_var($_POST['firstname'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
  }

  if (! isset($_POST['lastname']) or $_POST['lastname'] == "") {
    array_push($error_messages, "You didn't enter your last name.");
  } else {
    $lastname = filter_var($_POST['lastname'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
  }

  if (isset($_POST['email']) and $_POST['email'] != "") {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
  }

  if (isset($_POST['notes']) and $_POST['notes'] != "") {
    $notes = filter_var($_POST['notes'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
  }

  if (count($error_messages) > 0) { ?>
    <div class="alert alert-danger" role="alert">
      The request couldn't be sent because:
      <ul style="margin-top:.5em">
        <?php foreach($error_messages as $message) { echo "<li>".htmlentities($message)."</li>"; } ?>
      </ul>
    </div>
  <?php
  } else {
    $mail_subject = "$firstname $lastname has requested an account for $ORGANISATION_NAME.";

    $link_url="{$SITE_PROTOCOL}{$SERVER_HOSTNAME}{$SERVER_PATH}account_manager/new_user.php?account_request&first_name=$firstname&last_name=$lastname&email=$email";

    if (!isset($email)) { $email = "n/a"; }
    if (!isset($notes)) { $notes = "n/a"; }

    $mail_body = <<<EoT
A request for an $ORGANISATION_NAME account has been sent:
<p>
First name: <b>$firstname</b><br>
Last name: <b>$lastname</b><br>
Email: <b>$email</b><br>
Notes: <pre>$notes</pre><br>
<p>
<a href="$link_url">Create this account.</a>
EoT;

    include_once "mail_functions.inc.php";
    $sent_email = send_email($ACCOUNT_REQUESTS_EMAIL,"$ORGANISATION_NAME account requests",$mail_subject,$mail_body);
    ?>
    <style>
      .panel-modern{background:#0b0f13;border:1px solid rgba(255,255,255,.08);border-radius:12px}
      .panel-modern .panel-heading{background:linear-gradient(180deg,rgba(255,255,255,.06),rgba(255,255,255,.02));color:#cfe9ff;letter-spacing:.4px;text-transform:uppercase;border-bottom:1px solid rgba(255,255,255,.08)}
    </style>
    <div class="container" style="max-width:720px;margin:24px auto">
      <div class="panel panel-modern">
        <div class="panel-heading text-center"><?php echo $sent_email ? "Thank you" : "Error"; ?></div>
        <div class="panel-body">
          <?php if ($sent_email): ?>
            The request was sent and the administrator will process it as soon as possible.
          <?php else: ?>
            Unfortunately the account request wasn't sent because of a technical issue.
          <?php endif; ?>
        </div>
      </div>
    </div>
    <?php
    render_footer(); exit;
  }
}
?>
<style>
/* ---------- modern chrome (Bootstrap 3 friendly) ---------- */
.wrap-narrow { max-width: 860px; margin: 22px auto 40px; }
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
.header-note { color:#9fb6c9; }
.form-wide .control-label { padding-top:8px; }
</style>

<div class="container wrap-narrow">

  <div class="panel panel-modern" style="margin-bottom:16px;">
    <div class="panel-body">
      Use this form to request an account at <strong><?php echo htmlentities($ORGANISATION_NAME); ?></strong>.
      If approved, an administrator will contact you with credentials.
    </div>
  </div>

  <div class="panel panel-modern">
    <div class="panel-heading text-center">Request an account for <?php print $ORGANISATION_NAME; ?></div>
    <div class="panel-body">

      <div class="policy-box help-min">
        Required: first and last name + validation text. Email/notes are optional but helpful.
      </div>

      <form class="form-horizontal form-wide" action="" method="post" autocomplete="off" novalidate>

        <div class="form-group">
          <label for="firstname" class="col-sm-3 control-label">First name</label>
          <div class="col-sm-7">
            <input type="text" class="form-control" id="firstname" name="firstname" placeholder="Required"
                   <?php if (isset($firstname)) { echo "value='".htmlentities($firstname, ENT_QUOTES)."'"; } ?>>
          </div>
        </div>

        <div class="form-group">
          <label for="lastname" class="col-sm-3 control-label">Last name</label>
          <div class="col-sm-7">
            <input type="text" class="form-control" id="lastname" name="lastname" placeholder="Required"
                   <?php if (isset($lastname)) { echo "value='".htmlentities($lastname, ENT_QUOTES)."'"; } ?>>
          </div>
        </div>

        <div class="form-group">
          <label for="email" class="col-sm-3 control-label">Email</label>
          <div class="col-sm-7">
            <input type="text" class="form-control" id="email" name="email"
                   <?php if (isset($email)) { echo "value='".htmlentities($email, ENT_QUOTES)."'"; } ?>>
            <div class="help-min">Optional (for follow-up).</div>
          </div>
        </div>

        <div class="form-group">
          <label for="notes" class="col-sm-3 control-label">Notes</label>
          <div class="col-sm-7">
            <textarea class="form-control" id="notes" name="notes" rows="3"
                      placeholder="Anything the admin should know (system access, group, etc.)"><?php
                      if (isset($notes)) { echo htmlentities($notes); } ?></textarea>
          </div>
        </div>

        <div class="form-group">
          <label for="validate" class="col-sm-3 control-label">Validation</label>
          <div class="col-sm-7">
            <div class="help-min" style="margin-bottom:6px;">Enter the characters from the image.</div>
            <div class="clearfix" style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <img src="human.php" class="human-check" alt="Non-human detection" style="border:1px solid rgba(255,255,255,.12); border-radius:8px;">
              <button type="button" class="btn btn-soft btn-pill btn-sm"
                      onclick="document.querySelector('.human-check').src = 'human.php?' + Date.now()">
                <span class="glyphicon glyphicon-refresh"></span> Refresh
              </button>
            </div>
            <input type="text" class="form-control" id="validate" name="validate"
                   placeholder="Enter the characters from the image" style="margin-top:8px;">
          </div>
        </div>

        <div class="form-group text-center">
          <button id="send-btn" type="submit" class="btn btn-primary btn-pill" disabled>Send request</button>
          <span class="help-min" style="margin-left:8px;">Button enables when required fields are filled.</span>
        </div>

      </form>
    </div>
  </div>
</div>

<script>
// enable submit only when firstname, lastname, and validation have values
function gate(){
  var ok = !!document.getElementById('firstname').value.trim()
        && !!document.getElementById('lastname').value.trim()
        && !!document.getElementById('validate').value.trim();
  document.getElementById('send-btn').disabled = !ok;
}
['firstname','lastname','validate'].forEach(id=>{
  var el = document.getElementById(id);
  el && el.addEventListener('input', gate);
});
document.addEventListener('DOMContentLoaded', gate);
</script>

<?php render_footer(); ?>
