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

<div class="box">
  <h2>Lease IP</h2>
  <p>Detected client IP: <code id="detected-ip"><?php echo htmlspecialchars($clientIp ?? 'unknown'); ?></code></p>
  <p>
    <button id="btn-add" class="button">Add my IP</button>
    <button id="btn-del" class="button">Remove my IP</button>
  </p>
  <div id="user-status" class="smallprint"></div>
</div>

<?php if ($isAdmin): ?>
<div class="box">
  <h3>Active Leases</h3>
  <p>
    <button id="btn-refresh" class="button">Refresh list</button>
    <span class="smallprint">Total: <span id="count">–</span></span>
  </p>

  <div class="tablecontainer">
    <table class="results">
      <thead>
        <tr><th>Label</th><th>Timestamp</th><th>IP</th><th style="text-align:right;">Actions</th></tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <p>
    <button id="btn-clear" class="button danger">Clear all</button>
    <label> Prune (hours):
      <input id="prune-hours" type="number" min="1" value="24" style="width:6em;">
    </label>
    <button id="btn-prune" class="button">Run prune</button>
  </p>
  <div id="admin-status" class="smallprint"></div>
</div>
<?php endif; ?>

<script>
  window.LEASE_IP = {
    clientIp: <?php echo json_encode($clientIp); ?>,
    isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>
  };
</script>
<script src="lease_ui.js"></script>

<?php render_footer(); ?>
