<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
@session_start();

/**
 * mtls_download.php
 * - Validates single-use token
 * - Marks it used
 * - Hands file delivery to SWAG via X-Accel-Redirect
 * - Sends a styled Apprise notification with a tag
 *
 * NOTE: This version assumes SWAG serves from a per-token staged path:
 *       /_protected_mtls/<sha256(token)>/client.p12  ->  /mtls_stage/<sha256(token)>/client.p12
 */

// ---------- Helpers ----------
function h(string $k): ?string {
  $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k));
  return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null;
}
function hard_fail(int $code, string $msg){
  http_response_code($code);
  header('Content-Type: text/plain');
  echo $msg;
  exit;
}
function mtls_apprise_notify(string $body, ?string $tag = null): void {
  $url = getenv('APPRISE_URL');
  if (!$url) return;
  $tag = $tag ?: (getenv('APPRISE_TAG') ?: 'matrix_group_system_alerts');
  $cmd = 'curl -s -X POST'
       . ' -F ' . escapeshellarg('body=' . $body)
       . ' -F ' . escapeshellarg('tag=' . $tag)
       . ' '   . escapeshellarg($url)
       . ' >/dev/null 2>&1 &';
  @exec($cmd);
}

// ---------- AuthZ (Authelia) ----------
$uid    = h('Remote-User') ?: ($_SESSION['uid'] ?? null);
$groups = preg_split('/[;,\s]+/', (string)(h('Remote-Groups') ?? ''));
if (!$uid || !in_array('mtls', array_map('trim',$groups), true)) hard_fail(403, 'Forbidden');

// ---------- Input ----------
$token = isset($_GET['token']) ? (string)$_GET['token'] : '';
if (!preg_match('/^[a-f0-9]{48}$/', $token)) hard_fail(400, 'Bad token');

// ---------- Paths ----------
$APP_ROOT = dirname(__DIR__);        // /opt/ldap_user_manager
$DATA     = $APP_ROOT . '/data/mtls';
$TOKENS   = $DATA . '/tokens';
$LOGS     = $DATA . '/logs';

// ---------- Validate token ----------
$tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
if (!file_exists($tfile)) hard_fail(400, 'Invalid or used token');

$rec = json_decode((string)file_get_contents($tfile), true) ?: null;
if (!$rec) hard_fail(400, 'Token parse error');
if (($rec['exp'] ?? 0) < time()) { @unlink($tfile); hard_fail(400, 'Token expired'); }
if (!hash_equals((string)($rec['session'] ?? ''), session_id())) hard_fail(400, 'Session mismatch');
if (!empty($rec['used'])) hard_fail(400, 'Already used');

// ---------- Mark token used (atomic-ish) ----------
$rec['used'] = true;
file_put_contents($tfile, json_encode($rec), LOCK_EX);
@rename($tfile, $tfile . '.used');

// ---------- Hand off to SWAG (per-token staging) ----------
$token_hash = hash('sha256', $token);
$opaque     = '/_protected_mtls/' . $token_hash . '/client.p12';

header('Content-Type: application/octet-stream');
header('X-Accel-Redirect: ' . $opaque);
header('Content-Disposition: attachment; filename="mtls-client.p12"');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// ---------- Log ----------
$evt = [
  'evt'    => 'download',
  'uid'    => $uid,
  'ip'     => ($_SERVER['REMOTE_ADDR'] ?? ''),
  'ua'     => ($_SERVER['HTTP_USER_AGENT'] ?? ''),
  't'      => time(),
  'opaque' => $opaque,
];
@file_put_contents($LOGS . '/events.log', json_encode($evt) . "\n", FILE_APPEND);

// ---------- Apprise (styled + tagged) ----------
$host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
$ip   = $_SERVER['REMOTE_ADDR'] ?? '';
$ua   = $_SERVER['HTTP_USER_AGENT'] ?? '';
$body = '🔐 `' . $host . '` **mTLS Download**:<br />'
      . 'User: <code>' . htmlspecialchars($uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
      . 'IP: <code>'   . htmlspecialchars($ip,  ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
      . 'Token: <code>' . substr($token_hash, 0, 8) . '…</code><br />'
      . 'UA: <code>'   . htmlspecialchars($ua,  ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code>';
mtls_apprise_notify($body);

exit; // SWAG serves the file via X-Accel-Redirect
