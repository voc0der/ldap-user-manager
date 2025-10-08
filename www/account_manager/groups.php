<?php
// www/account_manager/groups.php  (modernized styling only)

set_include_path( ".:" . __DIR__ . "/../includes/");

include_once "web_functions.inc.php";
include_once "ldap_functions.inc.php";
include_once "module_functions.inc.php";
set_page_access("admin");

render_header("$ORGANISATION_NAME account manager");
render_submenu();

$ldap_connection = open_ldap_connection();

if (isset($_POST['delete_group'])) {
  $this_group = $_POST['delete_group'];
  $this_group = urldecode($this_group);

  $del_group = ldap_delete_group($ldap_connection,$this_group);

  if ($del_group) {
    render_alert_banner("Group <strong>$this_group</strong> was deleted.");
  } else {
    render_alert_banner("Group <strong>$this_group</strong> wasn't deleted.  See the logs for more information.","danger",15000);
  }
}

$groups = ldap_get_group_list($ldap_connection);
ldap_close($ldap_connection);

render_js_username_check();
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

.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.12); color:#cfe9ff; }
.btn-soft:hover { background:#17202b; }

.input-group-addon.glyphicon { background:#0e151d; border-color:rgba(255,255,255,.12); color:#9fb6c9; }
.help-min { color:#8aa0b2; font-size:12px; margin-top:6px; }

.table-modern > thead > tr > th { border-color:rgba(255,255,255,.08); color:#a9c4da; font-weight:600; }
.table-modern > tbody > tr > td { border-color:rgba(255,255,255,.06); color:#cfe9ff; }
.table-modern > tbody > tr:hover { background:#0f151c; }
.table-modern a { color:#8ec7ff; }

.invisible { visibility:hidden; }
.visible { visibility:visible; }
</style>

<script type="text/javascript">
function show_new_group_form(){
  var group_form   = document.getElementById('group_name');
  var group_submit = document.getElementById('add_group');
  group_form.classList.replace('invisible','visible');
  group_submit.classList.replace('invisible','visible');
}
</script>

<div class="container wrap-narrow">
  <div class="panel panel-modern">
    <div class="panel-heading clearfix">
      <div class="pull-left">
        <h3 class="panel-title">Groups</h3>
      </div>
      <div class="pull-right">
        <form action="<?php print "{$THIS_MODULE_PATH}"; ?>/show_group.php" method="post" class="form-inline" style="display:inline;">
          <input type="hidden" name="new_group">
          <button type="button" class="btn btn-soft btn-pill">
            <?php print count($groups);?> group<?php if (count($groups) != 1) { print "s"; } ?>
          </button>
          &nbsp;
          <button id="show_new_group" class="btn btn-primary btn-pill" type="button" onclick="show_new_group_form();">New group</button>
          &nbsp;
          <input type="text" class="form-control invisible" name="group_name" id="group_name"
                 placeholder="Group name"
                 onkeyup="check_entity_name_validity(document.getElementById('group_name').value,'new_group_div');">
          <button id="add_group" class="btn btn-success btn-pill btn-sm invisible" type="submit">Add</button>
        </form>
      </div>
    </div>

    <div class="panel-body">
      <div class="row" style="margin-bottom:12px;">
        <div class="col-sm-6">
          <div class="input-group">
            <span class="input-group-addon glyphicon glyphicon-search"></span>
            <input class="form-control" id="search_input" type="text" placeholder="Search groups…">
          </div>
          <div class="help-min">Type to filter the list below.</div>
        </div>
      </div>

      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <thead>
            <tr>
              <th>Group name</th>
            </tr>
          </thead>
          <tbody id="grouplist">
<?php foreach ($groups as $group){
  print "  <tr>\n    <td><a href='{$THIS_MODULE_PATH}/show_group.php?group_name=" . urlencode($group) . "'>$group</a></td>\n  </tr>\n";
} ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
// Keep your original filter behavior (same IDs)
$(function(){
  var $input = $("#search_input");
  var $rows  = $("#grouplist tr");
  $input.on("keyup input", function(){
    var v = $(this).val().toLowerCase();
    $rows.each(function(){
      var show = $(this).text().toLowerCase().indexOf(v) > -1;
      $(this).toggle(show);
    });
  });
});
</script>

<?php render_footer(); ?>
