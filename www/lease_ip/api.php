<?php
declare(strict_types=1);
@session_start();
set_include_path(__DIR__ . "/../includes/");
include_once "web_functions.inc.php";
include_once "jf_map.inc.php";

header('Content-Type: application/json');
header('Cache-Control: no-store');

// Ensure logged-in to use
set_page_access("user");

// Determine admin / user
global $IS_ADMIN, $USER_ID;
$isAdmin = isset($IS_ADMIN) ? (bool)$IS_ADMIN : (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true);
$userId  = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

// Optional ?user= override (beats session/vhost) — typically for admin tools
$userOverride = trim((string)($_GET['user'] ?? ''));
if ($userOverride !== '') {
    $userId = $userOverride;
}

// ---- Config / URL normalization ----
$rawBase = getenv('LEASE_API_BASE') ?: '/endpoints/ip_lease.php';   // can be full URL or path
$explicitOrigin = getenv('LEASE_API_ORIGIN') ?: '';                 // optional, e.g. https://your-fqdn

function normalize_api_base(string $base, string $explicitOrigin): string {
    if (preg_match('#^https?://#i', $base)) return rtrim($base, "&?");
    $scheme = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? ($_SERVER['REQUEST_SCHEME'] ?? ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http'));
    $host   = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
    $origin = $explicitOrigin !== '' ? rtrim($explicitOrigin, '/') : ($scheme . '://' . $host);
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
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) $c[] = trim($p = $_SERVER['HTTP_X_REAL_IP']);
    if (!empty($_SERVER['REMOTE_ADDR']))    $c[] = trim($_SERVER['REMOTE_ADDR']);
    foreach ($c as $v) { $canon = canon_ip($v); if ($canon) return $canon; }
    return null;
}
$clientIp = get_client_ip();

// tiny fetcher for list->entries; returns normalized entries with 'user' key set
function fetch_entries(string $apiBase, array $headers): array {
    $url = $apiBase . (str_contains($apiBase, '?') ? '&' : '?') . http_build_query(['list'=>'1'], '', '&', PHP_QUERY_RFC3986);
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

    if ($resp === false || $code < 200 || $code >= 300) {
        return [];
    }
    $data = json_decode($resp, true);
    if (!is_array($data)) return [];

    $data = jf_map_rewrite_response($data);
    $entries = $data['entries'] ?? [];

    // Normalize: ensure 'user' exists; keep original 'label' for back-compat
    $out = [];
    foreach ((array)$entries as $e) {
        $user = $e['user'] ?? ($e['label'] ?? ($e['host'] ?? 'unknown'));
        $e['user'] = (string)$user;
        $out[] = $e;
    }
    return $out;
}

// ---- Operation selection ----
$allowed = ['list','clear','add','delete','prune'];
$getKeys = array_keys($_GET ?? []);
$opKeys  = array_values(array_diff($getKeys, ['user']));  // allow ?user=
if (count($opKeys) !== 1) {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>'Exactly one GET parameter required', 'received'=>$opKeys]);
    exit;
}
$key = $opKeys[0];
$val = (string)($_GET[$key] ?? '');
if (!in_array($key, $allowed, true)) {
    http_response_code(400);
    echo json_encode(['ok'=>false, 'error'=>'Unknown operation', 'allowed'=>$allowed, 'received'=>$key]);
    exit;
}

// Optional static toggle header from browser -> forwarded to SWAG
$lumStaticHdr = strtolower(trim($_SERVER['HTTP_X_LUM_STATIC'] ?? '')); // '1'|'0'|''

// Common headers to upstream
$headers = [
    'Accept: application/json',
    'X-IP-Lease-Label: ' . $userId,   // upstream still expects "Label" header; UI shows it as "User"
    'X-IP-Lease-Source: LUM',
];

// ---- Permissions & effective IP/hours ----
$effectiveIp = null;
$hours = null;

if ($key === 'list') {
    // handled later (we’ll fetch, normalize, and filter server-side)
} elseif ($key === 'clear' || $key === 'prune') {
    if (!$isAdmin) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Admin required']); exit; }
    if ($key === 'prune') {
        $hours = is_numeric($val) ? (int)$val : 0;
        if ($hours <= 0) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid hours']); exit; }
    }
} elseif ($key === 'add' || $key === 'delete') {
    if ($isAdmin) {
        $effectiveIp = canon_ip($val) ?: $clientIp;
        if (!$effectiveIp) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid IP']); exit; }
    } else {
        // Non-admin:
        $wantIp = canon_ip($val);

        // If toggling static (X-LUM-Static present) OR deleting an arbitrary IP,
        // require that the target IP belongs to this user.
        $isStaticToggle = ($key === 'add' && $lumStaticHdr !== '');
        $isArbDelete    = ($key === 'delete' && $wantIp !== null);

        if ($isStaticToggle || $isArbDelete) {
            if (!$wantIp) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Invalid IP']); exit; }
            $entries = fetch_entries($apiBase, $headers);
            $owned = false;
            foreach ($entries as $e) {
                if (($e['ip'] ?? '') === $wantIp && ($e['user'] ?? '') === $userId) {
                    $owned = true; break;
                }
            }
            if (!$owned) { http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Not permitted for this IP']); exit; }
            $effectiveIp = $wantIp;
        } else {
            // Plain add (no static header) or delete without IP => operate on detected client IP
            if (!$clientIp) { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Cannot detect client IP']); exit; }
            $effectiveIp = $clientIp;
        }
    }
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

// ---- Upstream call (except special handling for list) ----
if ($key !== 'list') {
    $fwdHeaders = $headers;
    // forward static intent ONLY on add (still one GET var)
    if ($key === 'add' && $lumStaticHdr !== '') {
        $fwdHeaders[] = 'X-IP-Lease-Static: ' . (($lumStaticHdr === '1' || $lumStaticHdr === 'yes' || $lumStaticHdr === 'true') ? 'yes' : 'no');
    }

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_USERAGENT => 'LUM-Lease-UI/1.0',
        CURLOPT_HTTPHEADER => $fwdHeaders,
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

    $data = jf_map_rewrite_response($data);
    http_response_code(($code >= 200 && $code < 300) ? 200 : $code);
    echo json_encode($data);
    exit;
}

// ---- LIST handling: normalize + filter + ETag --------------------------------
$entries = fetch_entries($apiBase, $headers);

// For non-admins: only show entries where user === current user
if (!$isAdmin) {
    $entries = array_values(array_filter($entries, function($e) use ($userId) {
        $u = $e['user'] ?? ($e['label'] ?? ($e['host'] ?? ''));
        return ($u === $userId);
    }));
}

// Compute weak ETag based on entries content
$etag = 'W/"' . substr(sha1(json_encode($entries)), 0, 20) . '"';
$ifNone = $_SERVER['HTTP_IF_NONE_MATCH'] ?? '';
if ($ifNone !== '' && trim($ifNone) === $etag) {
    header('ETag: ' . $etag);
    http_response_code(304);
    exit;
}

header('ETag: ' . $etag);
echo json_encode(['ok'=>true, 'entries'=>$entries]);
