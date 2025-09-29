<?php
declare(strict_types=1);

// Use the same wrapper/helpers as other modules
require_once __DIR__ . '/../includes/web_functions.inc.php';

// Require a signed-in user (matches `'lease_ip' => 'auth'` in modules.inc.php)
set_page_access('auth');

// Optional: figure out admin the same way other pages do
@session_start();
global $IS_ADMIN, $USER_ID;
$isAdmin = isset($IS_ADMIN) ? (bool)$IS_ADMIN : (!empty($_SESSION['is_admin']));

// Helper to detect client IP for the “My IP” buttons (same logic as api.php)
function canon_ip(?string $ip): ?string {
    if (!$ip) return null;
    $ip = trim($ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) return null;
    $bin = @inet_pton($ip);
    if ($bin === false) return null;
    return inet_ntop($bin);
}
function get_client_ip(): ?string {
    $candidates = [];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) { $candidates[] = trim($p); }
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) $candidates[] = trim($_SERVER['HTTP_X_REAL_IP']);
    if (!empty($_SERVER['REMOTE_ADDR']))   $candidates[] = trim($_SERVER['REMOTE_ADDR']);
    foreach ($candidates as $c) { if ($c = canon_ip($c)) return $c; }
    return null;
}
$clientIp = get_client_ip();

// Render standard header/nav (title will show in the chrome)
render_header('Lease IP');
?>

<div class="content">

  <div class="box">
    <h2>Lease IP</h2>
    <p><span class="muted">Detected client IP:</span>
       <code id="detected-ip"><?php echo htmlspecialchars($clientIp ?? 'unknown'); ?></code>
    </p>
    <p>
      <button id="btn-add" class="btn">Add my IP</button>
      <button id="btn-del" class="btn">Remove my IP</button>
    </p>
    <div id="user-status" class="muted"></div>
  </div>

  <?php if ($isAdmin): ?>
  <div class="box">
    <h3>Active Leases (Admin)</h3>
    <p>
      <button id="btn-refresh" class="btn">Refresh list</button>
      <span class="muted">Total: <span id="count">–</span></span>
    </p>
    <div class="table-responsive">
      <table class="table">
        <thead>
          <tr><th>Label</th><th>Timestamp</th><th>IP</th><th style="text-align:right;">Actions</th></tr>
        </thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div style="margin-top:.5rem;">
      <button id="btn-clear" class="btn btn-danger">Clear all</button>
      <span class="muted"> | </span>
      <label>Prune (hours):
        <input id="prune-hours" type="number" min="1" value="24" style="width:90px;">
      </label>
      <button id="btn-prune" class="btn">Run prune</button>
    </div>
    <div id="admin-status" class="muted" style="margin-top:.5rem;"></div>
  </div>
  <?php endif; ?>

</div>

<script>
  // Pass state to the JS (no absolute paths needed)
  window.LEASE_IP = {
    clientIp: <?php echo json_encode($clientIp); ?>,
    isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>
  };
</script>
<script src="lease_ui.js"></script>

<?php render_footer(); ?>
