<?php
declare(strict_types=1);
@session_start();
set_include_path(__DIR__ . "/../includes/");
include_once "web_functions.inc.php";

header('Content-Type: application/json');

// Ensure logged-in to use
set_page_access("user");

// Determine admin (reuse LUM's $IS_ADMIN if available)
global $IS_ADMIN, $USER_ID;
$isAdmin = isset($IS_ADMIN) ? (bool)$IS_ADMIN : (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true);
$userId  = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

// ---- Config / URL normalization ----
$rawBase = getenv('LEASE_API_BASE') ?: '/endpoints/ip_lease.php';   // can be full URL or path
$explicitOrigin = getenv('LEASE_API_ORIGIN') ?: '';                 // optional, e.g. https://your-fqdn

function normalize_api_base(string $base, string $explicitOrigin): string {
    if (preg_match('#^https?://#i', $base)) {
        return rtrim($base, "&?");
    }
    if ($explicitOrigin !== '') {
        $origin = rtrim($explicitOrigin, '/');
    } else {
        $scheme =
            $_SERVER['HTTP_X_FORWARDED_PROTO']
            ?? $_SERVER['REQUEST_SCHEME']
            ?? ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
        $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
        $origin = $scheme . '://' . $host;
    }
    return $origin . (str_starts_with($base, '/') ? $base : '/' . $base);
}
$apiBase = normalize_api_base($rawBase, $explicitOrigin);

// ---- Helpers ----
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

// ---- Matrix/Apprise notify helper ----
function apprise_notify(string $title, string $htmlBody): void {
    // Build notify URL: APPRISE_URL wins; else https://notify.$EMAIL_DOMAIN/notify/apprise
    $domain = getenv('EMAIL_DOMAIN') ?: getenv('DOMAIN_NAME') ?: ($_SERVER['SERVER_NAME'] ?? 'localhost');
    $url = getenv('APPRISE_URL') ?: ('https://notify.' . $domain . '/notify/apprise');
    $tag = getenv('APPRISE_TAG') ?: 'matrix_group_system_alerts';

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => [
            'body' => "🔐 `{$title}`<br />{$htmlBody}",
            'tag'  => $tag,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT => 3,
        CURLOPT_USERAGENT => 'LUM-Lease-UI/1.0',
    ]);
    @curl_exec($ch); // fire-and-forget
    curl_close($ch);
}

// ---- Inputs ----
$action = $_GET['action'] ?? $_POST['action'] ?? null;
$ip     = $_GET['ip'] ?? $_POST['ip'] ?? null;
$hours  = $_GET['hours'] ?? $_POST['hours'] ?? null;

if (!$action) {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>'Missing action']);
    exit;
}

// ---- Permissions ----
// Non-admin can only add/delete their own IP; cannot clear/prune
if (!$isAdmin) {
    if (in_array($action, ['clear','prune'], true)) {
        http_response_code(403);
        echo json_encode(['ok'=>false, 'error'=>'Admin required']);
        exit;
    }
    if (in_array($action, ['add','delete'], true)) {
        if (!$clientIp) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Cannot detect client IP']); exit; }
        $ip = $clientIp; // ignore supplied IP for non-admin
    }
} else {
    if (in_array($action, ['add','delete'], true) && !$ip) { $ip = $clientIp; }
}

// ---- Build upstream query ----
$query = [];
if ($action === 'list')            { $query['list']  = '1'; }
elseif ($action === 'clear')       { $query['clear'] = '1'; }
elseif ($action === 'prune') {
    $n = is_numeric($hours) ? (int)$hours : 0;
    if ($n <= 0) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid hours']); exit; }
    $query['prune'] = (string)$n;
}
elseif ($action === 'add') {
    $ip_c = canon_ip($ip);
    if (!$ip_c) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid IP for add']); exit; }
    $query['add'] = $ip_c;
}
elseif ($action === 'delete') {
    $ip_c = canon_ip($ip);
    if (!$ip_c) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid IP for delete']); exit; }
    $query['delete'] = $ip_c;
}
else {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>'Unknown action']);
    exit;
}

$qs  = http_build_query($query);
$url = $apiBase . (str_contains($apiBase, '?') ? '&' : '?') . $qs;

// ---- Upstream call ----
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_TIMEOUT => 8,
    CURLOPT_USERAGENT => 'LUM-Lease-UI/1.0',
    CURLOPT_HTTPHEADER => [
        'Accept: application/json',
        'X-IP-Lease-Label: LUM ' . $userId,   // label for your SWAG script
    ],
    // If your internal TLS is self-signed, either trust the CA in the image or (last resort) disable verification:
    // CURLOPT_SSL_VERIFYPEER => false,
    // CURLOPT_SSL_VERIFYHOST => 0,
]);
$resp = curl_exec($ch);
$err  = curl_error($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($resp === false) {
    http_response_code(502);
    echo json_encode(['ok'=>false, 'error'=>'Upstream call failed: '.$err]);
    exit;
}

$data = json_decode($resp, true);
if ($data === null) {
    echo json_encode(['ok'=>false, 'error'=>'Invalid JSON from lease endpoint', 'status'=>$code, 'body'=>$resp]);
    exit;
}

// ---- Send Matrix notifications for successful mutations ----
if ($code >= 200 && $code < 300 && is_array($data) && ($data['ok'] ?? null) !== false) {
    $who  = htmlspecialchars((string)$userId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $ipH  = htmlspecialchars((string)($data['ip'] ?? $ip ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $host = htmlspecialchars((string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $ts   = date('Y-m-d H:i:s T');

    switch ($action) {
        case 'add':
            if (($data['result'] ?? '') === 'added') {
                apprise_notify('Lease IP Added', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
            }
            break;
        case 'delete':
            if (($data['result'] ?? '') === 'deleted') {
                apprise_notify('Lease IP Removed', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
            }
            break;
        case 'clear':
            apprise_notify('Lease List Cleared', "by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
            break;
        case 'prune':
            $hrs = (int)($hours ?? 0);
            apprise_notify('Lease List Pruned', "older than <code>{$hrs}h</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
            break;
        // list: no notify
    }
}

http_response_code(($code >= 200 && $code < 300) ? 200 : $code);
header('Cache-Control: no-store');
echo json_encode($data);
