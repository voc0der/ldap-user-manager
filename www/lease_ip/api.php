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
    if (preg_match('#^https?://#i', $base)) return rtrim($base, "&?");
    $origin = $explicitOrigin !== '' ? rtrim($explicitOrigin, '/')
             : (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? $_SERVER['REQUEST_SCHEME'] ?? ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http')) . '://' .
                ($_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost')));
    return $origin . (str_starts_with($base, '/') ? $base : '/' . $base);
}
$apiBase = normalize_api_base($rawBase, $explicitOrigin);

// ---- Helpers ----
function canon_ip(?string $ip): ?string {
    if (!$ip) return null;
    $ip = trim($ip);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) return null;
    $bin = @inet_pton($ip);
    return $bin === false ? null : inet_ntop($bin);
}
function get_client_ip(): ?string {
    $c = [];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) $c[] = trim($p);
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) $c[] = trim($_SERVER['HTTP_X_REAL_IP']);
    if (!empty($_SERVER['REMOTE_ADDR']))    $c[] = trim($_SERVER['REMOTE_ADDR']);
    foreach ($c as $v) { $canon = canon_ip($v); if ($canon) return $canon; }
    return null;
}
$clientIp = get_client_ip();

// ---- Matrix/Apprise notify helper ----
function apprise_notify(string $title, string $htmlBody): void {
    $domain = getenv('EMAIL_DOMAIN') ?: getenv('DOMAIN_NAME') ?: ($_SERVER['SERVER_NAME'] ?? 'localhost');
    $url = getenv('APPRISE_URL') ?: ('https://notify.' . $domain . '/notify/apprise');
    $tag = getenv('APPRISE_TAG') ?: 'matrix_group_system_alerts';

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => [
            'body' => "🔐 <b>{$title}</b><br />{$htmlBody}",
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

// ---- Single-parameter input enforcement ----
$allowed = ['list','clear','add','delete','prune'];
$getKeys = array_keys($_GET ?? []);
if (count($getKeys) !== 1) {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>'Exactly one GET parameter required', 'received'=>$getKeys]);
    exit;
}
$key = $getKeys[0];
$val = (string)($_GET[$key] ?? '');

if (!in_array($key, $allowed, true)) {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>'Unknown operation', 'allowed'=>$allowed, 'received'=>$key]);
    exit;
}

// Optional static toggle header from browser -> forwarded to SWAG
$lumStaticHdr = strtolower(trim($_SERVER['HTTP_X_LUM_STATIC'] ?? '')); // '1'|'0'|''

// ---- Permissions & effective IP/hours ----
$effectiveIp = null;
$hours = null;

switch ($key) {
    case 'list':
        // allowed for all
        break;

    case 'clear':
        if (!$isAdmin) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Admin required']); exit; }
        break;

    case 'prune':
        if (!$isAdmin) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Admin required']); exit; }
        $hours = is_numeric($val) ? (int)$val : 0;
        if ($hours <= 0) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid hours']); exit; }
        break;

    case 'add':
    case 'delete':
        if ($isAdmin) {
            $effectiveIp = canon_ip($val) ?: $clientIp;
            if (!$effectiveIp) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid IP']); exit; }
        } else {
            if (!$clientIp) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Cannot detect client IP']); exit; }
            $effectiveIp = $clientIp; // ignore supplied IP for non-admin
        }
        break;
}

// ---- Build upstream URL with exactly one parameter ----
$one = [];
if     ($key === 'list')   $one = ['list' => '1'];
elseif ($key === 'clear')  $one = ['clear' => '1'];
elseif ($key === 'prune')  $one = ['prune' => (string)$hours];
elseif ($key === 'add')    $one = ['add' => $effectiveIp];
elseif ($key === 'delete') $one = ['delete' => $effectiveIp];

$qs  = http_build_query($one, '', '&', PHP_QUERY_RFC3986);
$url = $apiBase . (str_contains($apiBase, '?') ? '&' : '?') . $qs;

// ---- Upstream call ----
$headers = [
    'Accept: application/json',
    'X-IP-Lease-Label: LUM ' . $userId,
];
// forward static intent ONLY on add (still one GET var)
if ($key === 'add' && $lumStaticHdr !== '') {
    $headers[] = 'X-IP-Lease-Static: ' . (($lumStaticHdr === '1' || $lumStaticHdr === 'yes' || $lumStaticHdr === 'true') ? 'yes' : 'no');
}

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_CONNECTTIMEOUT => 3,
    CURLOPT_TIMEOUT => 8,
    CURLOPT_USERAGENT => 'LUM-Lease-UI/1.0',
    CURLOPT_HTTPHEADER => $headers,
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

// ---- Matrix notifications on success ----
if ($code >= 200 && $code < 300 && is_array($data) && ($data['ok'] ?? null) !== false) {
    $who  = htmlspecialchars((string)$userId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $ipH  = htmlspecialchars((string)($data['ip'] ?? $effectiveIp ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $host = htmlspecialchars((string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $ts   = date('Y-m-d H:i:s T');

    switch ($key) {
        case 'add':
            if (($data['result'] ?? '') === 'added') {
                if ($lumStaticHdr === '1' || $lumStaticHdr === 'yes' || $lumStaticHdr === 'true') {
                    apprise_notify('Lease IP Added (Static)', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
                } elseif ($lumStaticHdr === '0' || $lumStaticHdr === 'no' || $lumStaticHdr === 'false') {
                    apprise_notify('Lease IP Added / Unmarked Static', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
                } else {
                    apprise_notify('Lease IP Added', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
                }
            } else {
                // If endpoint updates existing block on add, honor static header for notice
                if ($lumStaticHdr === '1' || $lumStaticHdr === 'yes' || $lumStaticHdr === 'true') {
                    apprise_notify('Lease IP Marked Static', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
                } elseif ($lumStaticHdr === '0' || $lumStaticHdr === 'no' || $lumStaticHdr === 'false') {
                    apprise_notify('Lease IP Unmarked Static', "<code>{$ipH}</code> by <code>{$who}</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
                }
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
            apprise_notify('Lease List Pruned', "by <code>{$who}</code> older than <code>{$hours}h</code><br />on <code>{$host}</code> @ <code>{$ts}</code>");
            break;
    }
}

http_response_code(($code >= 200 && $code < 300) ? 200 : $code);
header('Cache-Control: no-store');
echo json_encode($data);
