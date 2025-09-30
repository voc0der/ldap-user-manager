<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/web_functions.inc.php';
set_page_access('auth');

@session_start();
global $IS_ADMIN;
$isAdmin = !empty($IS_ADMIN);

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

<div class="container">

  <!-- User section -->
  <table class="table table-striped">
    <thead>
      <tr><th colspan="2">Lease IP (Internal)</th></tr>
    </thead>
    <tbody>
      <tr>
        <td>Detected client IP</td>
        <td><code id="detected-ip"><?php echo htmlspecialchars($clientIp ?? 'unknown'); ?></code></td>
      </tr>
      <tr>
        <td>Actions</td>
        <td>
          <button id="btn-add" class="btn btn-default">Add my IP</button>
          <button id="btn-del" class="btn btn-default">Remove my IP</button>
        </td>
      </tr>
      <tr>
        <td>Status</td>
        <td><span id="user-status" class="smallprint"></span></td>
      </tr>
    </tbody>
  </table>

  <?php if ($isAdmin): ?>
  <!-- Admin section -->
  <table class="table table-striped">
    <thead>
      <tr>
        <th colspan="4">
          Active Leases
          <span class="smallprint"> &nbsp; Total: <span id="count">–</span></span>
          &nbsp; <button id="btn-refresh" class="btn btn-default">Refresh list</button>
        </th>
      </tr>
      <tr>
        <th>Label</th>
        <th>Timestamp</th>
        <th>IP</th>
        <th class="text-right">Actions</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
    <tfoot>
      <tr>
        <td colspan="4">
          <!-- Manual add (admin) -->
          <label style="margin-right:.5rem;">Add IP (admin):</label>
          <input id="manual-ip" type="text" placeholder="e.g. 203.0.113.7 or 2001:db8::1" style="max-width: 20rem;">
          &nbsp; <label style="margin:0 .5rem 0 .75rem;"><input id="manual-static" type="checkbox"> Static</label>
          <button id="btn-add-manual" class="btn btn-default">Add IP</button>
          <span class="smallprint" style="margin-left:.5rem;">Static entries are skipped by prune.</span>
        </td>
      </tr>
      <tr>
        <td colspan="4">
          <button id="btn-clear" class="btn btn-default">Clear all</button>
          &nbsp;
          <label>Prune (hours):
            <input id="prune-hours" type="number" min="1" value="24" style="width:6em;">
          </label>
          <button id="btn-prune" class="btn btn-default">Run prune</button>
          <span id="admin-status" class="smallprint" style="margin-left:.5rem;"></span>
        </td>
      </tr>
    </tfoot>
  </table>
  <?php endif; ?>

</div>

<script>
  window.LEASE_IP = {
    clientIp: <?php echo json_encode($clientIp); ?>,
    isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>
  };
</script>
<script src="lease_ui.js"></script>

<?php render_footer(); ?>
