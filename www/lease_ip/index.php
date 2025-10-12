<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/web_functions.inc.php';
set_page_access('auth');

@session_start();
global $IS_ADMIN, $USER_ID;
$isAdmin = !empty($IS_ADMIN);
$username = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

function canon_ip(?string $ip): ?string {
    if (!$ip) return null;
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) return null;
    $bin = @inet_pton($ip);
    return $bin === false ? null : inet_ntop($bin);
}
function get_client_ip(): ?string {
    $c = [];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) $c[] = trim($p);
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) $c[] = trim($_SERVER['HTTP_X_REAL_IP']);
    if (!empty($_SERVER['REMOTE_ADDR']))   $c[] = trim($_SERVER['REMOTE_ADDR']);
    foreach ($c as $v) if ($v = canon_ip($v)) return $v;
    return null;
}
$clientIp = get_client_ip();

render_header('Lease IP');
?>
<style>
/* ---------- modern chrome (Bootstrap 3 friendly) ---------- */
.lease-wrap { max-width: 980px; margin: 18px auto 40px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.08); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading {
  background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
  color:#cfe9ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase;
  padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08);
}
.panel-modern .panel-body { padding:14px; }

.table-modern { margin:0; }
.table-modern>thead>tr>th,
.table-modern>tbody>tr>td,
.table-modern tfoot td { border-color: rgba(255,255,255,.08); }

.table-modern>thead>tr>th {
  color:#9fb6c9; font-size:12px; text-transform:uppercase; letter-spacing:.35px; border-bottom-width:1px;
}

/* Zebra striping to match Users/Groups pages */
.table-modern.table-striped>tbody>tr:nth-of-type(odd)  { background: rgba(255,255,255,.03); }
.table-modern.table-striped>tbody>tr:nth-of-type(even) { background: rgba(255,255,255,.015); }

/* Hover */
.table-modern>tbody>tr:hover td { background: rgba(255,255,255,.06); }

/* Stronger stripes on small screens so it doesn’t look flat */
@media (max-width: 768px) {
  .panel-modern .panel-body { padding:12px; }
  .table-modern.table-striped>tbody>tr:nth-of-type(odd)  { background: rgba(255,255,255,.06); }
  .table-modern.table-striped>tbody>tr:nth-of-type(even) { background: rgba(255,255,255,.03); }
  .table-modern>tbody>tr:hover td { background: rgba(255,255,255,.09); }
  .table-modern>tbody>tr>td, .table-modern>thead>tr>th { padding:10px 8px; }
}

.badge-chip { display:inline-block; padding:2px 8px; border-radius:10px; font-family:monospace; font-size:.95em;
  background:#1a2b3a; color:#a9e1ff; border:1px solid rgba(127,209,255,.35); }
.smallprint, .help-note { color:#8aa0b2; font-size:12px; }
.btn-pill { border-radius:999px; }
.btn-soft { background:#121820; border:1px solid rgba(255,255,255,.12); color:#cfe9ff; }
.btn-soft:hover { background:#17202b; }
.btn-primary.btn-pill { background:#2a8bdc; border-color:#2a8bdc; }
.btn-danger.btn-pill { background:#cf4444; border-color:#cf4444; }
.btn-muted { background:transparent; border:1px solid rgba(255,255,255,.12); color:#9fb6c9; }

.header-inline { display:flex; align-items:center; gap:12px; }
.header-inline .grow { flex:1; }
.header-title { font-size:13px; letter-spacing:.35px; }
.header-count { color:#9fb6c9; font-weight:600; margin-left:8px; letter-spacing:.6px; }

tfoot td { background:rgba(255,255,255,.02); }
.input-slim { max-width: 22rem; }
.control-line { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
td.text-right .btn { margin-left:6px; }
.code-mono { font-family:monospace; }
</style>

<div class="container lease-wrap">

  <!-- USER CARD -->
  <div class="panel panel-modern">
    <div class="panel-heading text-center header-title">LEASE IP</div>
    <div class="panel-body">
      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <tbody>
          <tr>
            <td>Signed in as</td>
            <td><span class="badge-chip"><?php echo htmlspecialchars($username); ?></span></td>
          </tr>
          <tr>
            <td>Detected client IP</td>
            <td>
              <span class="badge-chip" id="detected-ip"><?php echo htmlspecialchars($clientIp ?? 'unknown'); ?></span>
            </td>
          </tr>
          <tr>
            <td>Actions</td>
            <td class="control-line">
              <button id="btn-add" class="btn btn-primary btn-pill">Add my IP</button>
              <button id="btn-del" class="btn btn-soft btn-pill">Remove my IP</button>
            </td>
          </tr>
          <tr>
            <td>Status</td>
            <td><span id="user-status" class="smallprint"></span></td>
          </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- MY LEASES (visible to everyone; filtered by server for non-admins) -->
  <div class="panel panel-modern" style="margin-top:22px;">
    <div class="panel-heading">
      <div class="header-inline">
        <div class="grow">
          <span class="header-title">MY LEASES</span>
          <span class="header-count">COUNT: <span id="my-count">–</span></span>
        </div>
        <button id="my-refresh" class="btn btn-muted btn-pill">Refresh</button>
      </div>
    </div>
    <div class="panel-body">
      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <thead>
          <tr>
            <th>User</th>
            <th>Source</th>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Expiry</th>
            <th class="text-right">Actions</th>
          </tr>
          </thead>
          <tbody id="my-tbody"></tbody>
          <tfoot>
          <tr>
            <td colspan="6">
              <span id="my-status" class="smallprint"></span>
            </td>
          </tr>
          </tfoot>
        </table>
      </div>
    </div>
  </div>

  <?php if ($isAdmin): ?>
  <!-- ADMIN CARD -->
  <div class="panel panel-modern" style="margin-top:22px;">
    <div class="panel-heading">
      <div class="header-inline">
        <div class="grow">
          <span class="header-title">ACTIVE LEASES</span>
          <span class="header-count">TOTAL: <span id="count">–</span></span>
        </div>
        <button id="btn-refresh" class="btn btn-muted btn-pill">Refresh list</button>
      </div>
    </div>
    <div class="panel-body">
      <div class="table-responsive">
        <table class="table table-striped table-modern">
          <thead>
          <tr>
            <th>User</th>
            <th>Source</th>
            <th>Timestamp</th>
            <th>IP</th>
            <th>Expiry</th>
            <th class="text-right">Actions</th>
          </tr>
          </thead>
          <tbody id="tbody"></tbody>
          <tfoot>
          <tr>
            <td colspan="6">
              <div class="control-line">
                <label class="smallprint">Add IP (admin):</label>
                <input id="manual-ip" type="text" class="form-control input-slim"
                       placeholder="e.g. 203.0.113.7 or 2001:db8::1">
                <label class="smallprint" style="margin:0 6px 0 2px;">
                  <input id="manual-static" type="checkbox"> Static
                </label>
                <button id="btn-add-manual" class="btn btn-soft btn-pill">Add IP</button>
                <span class="help-note">Static entries are skipped by prune.</span>
              </div>
            </td>
          </tr>
          <tr>
            <td colspan="6">
              <div class="control-line">
                <button id="btn-clear" class="btn btn-soft btn-pill">Clear all</button>
                <label class="smallprint">Prune (hours):</label>
                <input id="prune-hours" type="number" min="1" value="96" class="form-control" style="width:6.5em;">
                <button id="btn-prune" class="btn btn-soft btn-pill">Run prune</button>
                <span id="admin-status" class="smallprint"></span>
              </div>
            </td>
          </tr>
          </tfoot>
        </table>
      </div>
    </div>
  </div>
  <?php endif; ?>

</div>

<script>
  window.LEASE_IP = {
    clientIp: <?php echo json_encode($clientIp); ?>,
    isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>,
    userId: <?php echo json_encode($username); ?>
  };
</script>
<script src="lease_ui.js"></script>

<?php render_footer(); ?>
