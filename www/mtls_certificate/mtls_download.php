<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
@session_start();

// Helper for headers
function h(string $k): ?string { $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k)); return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null; }
function hard_fail(int $code, string $msg){ http_response_code($code); header('Content-Type: text/plain'); echo $msg; exit; }

$uid   = h('Remote-User') ?: ($_SESSION['uid'] ?? null);
$groups = preg_split('/[;,\s]+/', (string)(h('Remote-Groups')??''));
if (!$uid || !in_array('mtls', array_map('trim',$groups), true)) hard_fail(403, 'Forbidden');

$token = isset($_GET['token']) ? (string)$_GET['token'] : '';
if (!preg_match('/^[a-f0-9]{48}$/', $token)) hard_fail(400, 'Bad token');

$DATA = dirname(__DIR__) . '/../data/mtls';
$TOKENS = $DATA . '/tokens';
$LOGS = $DATA . '/logs';
$APPRISE_URL = getenv('APPRISE_URL');

$tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
if (!file_exists($tfile)) hard_fail(400, 'Invalid or used token');

$rec = json_decode((string)file_get_contents($tfile), true) ?: null;
if (!$rec) hard_fail(400, 'Token parse error');
if ($rec['exp'] < time()) { @unlink($tfile); hard_fail(400, 'Token expired'); }
if (!hash_equals($rec['session'] ?? '', session_id())) hard_fail(400, 'Session mismatch');
if (!empty($rec['used'])) hard_fail(400, 'Already used');

// Resolve the per-user cert path server-side only
// You can customize this mapping. Example assumes a base path with uid-based directory.
$CERT_BASE = getenv('MTLS_CERT_BASE') ?: '/mnt/mtls-certs'; // INTERNAL mount, not web-exposed
$cert_dir = $CERT_BASE . '/' . preg_replace('/[^a-zA-Z0-9_.-]/', '_', $uid);
$artifact = $cert_dir . '/client.p12'; // customize file name as needed

if (!is_file($artifact)) {
  hard_fail(404, 'Certificate not found for user');
}

// Mark token as used (atomic-ish)
$rec['used'] = true;
file_put_contents($tfile, json_encode($rec), LOCK_EX);
@rename($tfile, $tfile . '.used');

// Set headers and delegate to Nginx via X-Accel-Redirect (requires Nginx mapping)
$opaque = '/_protected_mtls/' . rawurlencode($uid) . '/client.p12'; // internal alias mapped to MTLS_CERT_BASE/<uid>/client.p12
header('Content-Type: application/octet-stream');
header('X-Accel-Redirect: ' . $opaque);
header('Content-Disposition: attachment; filename="mtls-' . basename($artifact) . '"');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Log/notify
$evt = ['evt'=>'download','uid'=>$uid,'ip'=>($_SERVER['REMOTE_ADDR']??''),'ua'=>($_SERVER['HTTP_USER_AGENT']??''),'t'=>time(),'artifact'=>$artifact];
file_put_contents($LOGS . '/events.log', json_encode($evt) . "\n", FILE_APPEND);

// Apprise via curl (fire-and-forget)
if (!empty($APPRISE_URL)) {
  $msg = "mTLS certificate downloaded by {$uid}";
  $cmd = 'curl -s -X POST --form-string ' . escapeshellarg('body=' . $msg) . ' ' . escapeshellarg($APPRISE_URL) . ' >/dev/null 2>&1 &';
  @exec($cmd);
}

// End: Nginx will serve the file from internal mapping.
exit;
