<?php
declare(strict_types=1);
// Lease IP tab for ldap-user-manager
@session_start();

// Config: path to SWAG endpoint (override with LEASE_API_BASE)
$apiBase = getenv('LEASE_API_BASE') ?: '/endpoints/ip_lease.php';
// Backward-compat fallback if you still use lease_poc.php
if (!$apiBase && file_exists('/endpoints/lease_poc.php')) { $apiBase = '/endpoints/lease_poc.php'; }

// Detect admin (best-effort; adjust if your fork uses a different session key)
$isAdmin = false;
if (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true) {
    $isAdmin = true;
} elseif ((getenv('LEASE_UI_ASSUME_ADMIN') ?: '') === '1') {
    $isAdmin = true;
}

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
    foreach ($candidates as $c) {
        $canon = canon_ip($c);
        if ($canon) return $canon;
    }
    return null;
}
$clientIp = get_client_ip();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lease IP</title>
  <style>
    :root { --pad: 12px; --gap: 10px; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, sans-serif; margin: 0; padding: var(--pad); }
    h1 { font-size: 1.4rem; margin: 0 0 var(--pad) 0; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: var(--pad); margin-bottom: var(--pad); }
    .row { display: flex; gap: var(--gap); align-items: center; flex-wrap: wrap; }
    button { padding: 8px 12px; border-radius: 8px; border: 1px solid #ccc; cursor: pointer; }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .muted { color: #666; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #eee; text-align: left; padding: 8px; }
    th { font-weight: 600; }
    .right { text-align: right; }
    .danger { color: #a00; }
    .pill { background: #f4f4f4; border-radius: 999px; padding: 2px 8px; display: inline-block; }
  </style>
</head>
<body>
  <h1>Lease IP</h1>

  <div class="card">
    <div class="row">
      <div>
        <div class="muted">Detected client IP</div>
        <div class="mono pill" id="detected-ip"><?php echo htmlspecialchars($clientIp ?? 'unknown'); ?></div>
      </div>
      <div class="row">
        <button id="btn-add">Add my IP</button>
        <button id="btn-del">Remove my IP</button>
      </div>
      <div class="muted">Calls: <span class="mono" id="api-base"><?php echo htmlspecialchars($apiBase); ?></span></div>
    </div>
    <div id="user-status" class="muted" style="margin-top: 8px;"></div>
  </div>

  <?php if ($isAdmin): ?>
  <div class="card">
    <h2 style="margin-top:0;">Admin</h2>
    <div class="row" style="margin-bottom:8px;">
      <button id="btn-refresh">Refresh list</button>
      <span class="muted">Total: <span id="count">–</span></span>
    </div>
    <div style="overflow:auto;">
      <table>
        <thead><tr><th>Label</th><th>Timestamp</th><th>IP</th><th class="right">Actions</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div class="row" style="margin-top:8px;">
      <button id="btn-clear" class="danger">Clear all</button>
      <span class="muted">|</span>
      <label>Prune (hours): <input id="prune-hours" type="number" min="1" value="24" style="width:80px; padding:6px; border-radius:8px; border:1px solid #ccc;"></label>
      <button id="btn-prune">Run prune</button>
    </div>
    <div id="admin-status" class="muted" style="margin-top:8px;"></div>
  </div>
  <?php else: ?>
  <div class="card">
    <div class="muted">Admin features hidden.</div>
  </div>
  <?php endif; ?>

  <script>
    window.LEASE_IP = {{
      apiBase: <?php echo json_encode($apiBase); ?>,
      clientIp: <?php echo json_encode($clientIp); ?>,
      isAdmin: <?php echo $isAdmin ? 'true' : 'false'; ?>
    }};
  </script>
  <script src="./lease_ui.js"></script>
</body>
</html>
