<?php
// www/account_manager/index.php  (modernized styling with TOTAL in header)

set_include_path( ".:" . __DIR__ . "/../includes/");

include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";
include_once "module_functions.inc.php";
set_page_access("admin");

render_header("$ORGANISATION_NAME account manager");
render_submenu();

$ldap_connection = open_ldap_connection();

if (isset($_POST['delete_user'])) {
  $this_user = htmlspecialchars(urldecode($_POST['delete_user']), ENT_QUOTES, 'UTF-8');
  $del_user = ldap_delete_account($ldap_connection,$this_user);
  if ($del_user) {
    render_alert_banner("User <strong>$this_user</strong> was deleted.");
  } else {
    render_alert_banner("User <strong>$this_user</strong> wasn't deleted.  See the logs for more information.","danger",15000);
  }
}

$people = ldap_get_user_list($ldap_connection);
$totalUsers = count($people);
?>

<style>
/* ---- modern chrome (Bootstrap 3 compatible) ---- */
.wrap-narrow { max-width: 1100px; margin: 18px auto 32px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.08); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading {
  background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
  color:#cfe9ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase;
  padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08);
}
.panel-modern .panel-title { margin:0; font-size:16px; letter-spacing:.3px; }
.panel-modern .panel-body { padding:16px 16px 18px; }
.header-total { margin-left:14px; color:#a9c4da; letter-spacing:.6px; font-weight:600; }
.help-min { color:#8aa0b2; font-size:12px; margin-top:6px; }
.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.12); color:#cfe9ff; }
.btn-soft:hover { background:#17202b; }
.table-modern > thead > tr > th { border-color:rgba(255,255,255,.08); color:#a9c4da; font-weight:600; }
.table-modern > tbody > tr > td { border-color:rgba(255,255,255,.06); color:#cfe9ff; }
.table-modern > tbody > tr:hover { background:#0f151c; }
.table-modern a { color:#8ec7ff; }
.input-group-addon.glyphicon { background:#0e151d; border-color:rgba(255,255,255,.12); color:#9fb6c9; }
</style>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <div class="pull-left">
        <h3 class="panel-title">
          Users
          <span class="header-total">TOTAL: <?php echo number_format($totalUsers); ?></span>
        </h3>
      </div>
      <div class="pull-right">
        <form action="<?php print $THIS_MODULE_PATH; ?>/new_user.php" method="post" style="display:inline;">
          <button id="add_group" class="btn btn-primary btn-pill" type="submit">New user</button>
        </form>
      </div>
    </div>

    <div class="panel-body">
      <div class="row" style="margin-bottom:12px;">
        <div class="col-sm-6">
          <div class="input-group">
            <span class="input-group-addon glyphicon glyphicon-search"></span>
            <input class="form-control" id="search_input" type="text" placeholder="Search users, names, email, groups…">
          </div>
          <div class="help-min">Type to filter the table below.</div>
        </div>
      </div>

      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <thead>
            <tr>
              <th>Account name</th>
              <th>First name</th>
              <th>Last name</th>
              <th>Email</th>
              <th>Member of</th>
            </tr>
          </thead>
          <tbody id="userlist">
<?php
foreach ($people as $account_identifier => $attribs){
  $group_membership = ldap_user_group_membership($ldap_connection,$account_identifier);
  $this_mail = isset($people[$account_identifier]['mail']) ? $people[$account_identifier]['mail'] : "";
  print "  <tr>\n";
  print "    <td><a href='{$THIS_MODULE_PATH}/show_user.php?account_identifier=" . urlencode($account_identifier) . "'>$account_identifier</a></td>\n";
  print "    <td>" . $people[$account_identifier]['givenname'] . "</td>\n";
  print "    <td>" . $people[$account_identifier]['sn'] . "</td>\n";
  print "    <td>$this_mail</td>\n";
  print "    <td>" . implode(", ", $group_membership) . "</td>\n";
  print "  </tr>\n";
}
?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
// simple client-side filter (keeps your original IDs)
$(function(){
  var $input = $("#search_input");
  var $rows  = $("#userlist tr");
  $input.on("keyup input", function(){
    var v = $(this).val().toLowerCase();
    $rows.each(function(){
      var show = $(this).text().toLowerCase().indexOf(v) > -1;
      $(this).toggle(show);
    });
  });
});
</script>

<?php
ldap_close($ldap_connection);
render_footer();
?>
