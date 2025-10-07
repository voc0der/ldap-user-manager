<?php
declare(strict_types=1);

// Includes
set_include_path(__DIR__ . '/../includes' . PATH_SEPARATOR . get_include_path());
include_once 'web_functions.inc.php';

@session_start();
header('Content-Type: application/json');

// ---------- Helpers ----------
function json_fail(string $msg, int $code=400) {
  http_response_code($code);
  echo json_encode(['ok'=>false,'error'=>$msg]);
  exit;
}
function json_ok(array $o=[]) {
  echo json_encode(['ok'=>true] + $o);
  exit;
}
function h(string $k): ?string {
  $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k));
  return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null;
}
// Simple file-based rate limiter (sliding window)
function rate_key(string $uid, string $kind): string { return hash('sha256', $uid . '|' . $kind); }
function rate_allow(string $dir, string $key, int $limit, int $perSeconds): bool {
  $f = $dir . '/rate_' . $key . '.json';
  $now = time();
  $winStart = $now - $perSeconds;
  $arr = [];
  if (file_exists($f)) { $arr = json_decode((string)file_get_contents($f), true) ?: []; }
  $arr = array_values(array_filter($arr, fn($t) => (int)$t >= $winStart));
  if (count($arr) >= $limit) return false;
  $arr[] = $now;
  file_put_contents($f, json_encode($arr), LOCK_EX);
  return true;
}

// ---------- CSRF ----------
$Body = json_decode(file_get_contents('php://input'), true) ?? [];
if (empty($_SESSION['csrf']) || empty($Body['csrf']) || !hash_equals($_SESSION['csrf'], (string)$Body['csrf'])) {
  json_fail('CSRF check failed', 403);
}

// ---------- Identity (proxy headers only) ----------
$uid    = h('Remote-User')   ?: ($_SESSION['uid'] ?? null);
$email  = h('Remote-Email')  ?: ($_SESSION['email'] ?? null);
$groups = preg_split('/[;,\s]+/', (string)(h('Remote-Groups') ?? ''), -1, PREG_SPLIT_NO_EMPTY);
$groups = array_map('trim', $groups);

if (!$uid) json_fail('Not authenticated', 401);
if (!in_array('mtls', $groups, true)) json_fail('Not in mtls group', 403);

// ---------- Storage paths ----------
$APP_ROOT = dirname(__DIR__, 1);           // /opt/ldap_user_manager
$DATA     = $APP_ROOT . '/data/mtls';
$CODES    = $DATA . '/codes';
$TOKENS   = $DATA . '/tokens';
$LOGS     = $DATA . '/logs';

@mkdir($CODES, 0775, true);
@mkdir($TOKENS, 0775, true);
@mkdir($LOGS, 0775, true);

// ---------- Config ----------
$MAIL_FROM      = getenv('MTLS_MAIL_FROM') ?: 'no-reply@localhost';
$CODE_TTL_SEC   = 300; // 5 minutes
$TOKEN_TTL_SEC  = 300; // 5 minutes
$APPRISE_URL    = getenv('APPRISE_URL'); // optional
$CERT_BASE      = getenv('MTLS_CERT_BASE') ?: '/mnt/mtls-certs';
$P12_PASS       = getenv('MTLS_P12_PASS') ?: '';

// ---------- Actions ----------
$action = $_GET['action'] ?? '';

if ($action === 'send_code') {
  if (!$email) json_fail('No email associated with this account', 400);
  // Rate-limit: 3 sends per hour per user
  if (!rate_allow($LOGS, rate_key($uid, 'send'), 3, 3600)) {
    json_fail('Too many code requests, try later', 429);
  }

  $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
  $hash = password_hash($code, PASSWORD_DEFAULT);

  $rec = [
    'uid'      => $uid,
    'hash'     => $hash,
    'ip'       => ($_SERVER['REMOTE_ADDR'] ?? ''),
    'ua'       => ($_SERVER['HTTP_USER_AGENT'] ?? ''),
    'ts'       => time(),
    'exp'      => time() + $CODE_TTL_SEC,
    'attempts' => 0,
    'session'  => session_id(),
  ];
  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  // Send the email (basic mail(); replace if you have a mailer helper)
  $subj = 'Your one-time code';
  $msg  = "Your verification code is: {$code}\nThis code expires in 5 minutes.\nIf you did not request this, ignore this message.";
  $hdrs = "From: {$MAIL_FROM}\r\nContent-Type: text/plain; charset=UTF-8";
  @mail($email, $subj, $msg, $hdrs);

  // Log
  file_put_contents($LOGS . '/events.log', json_encode(['evt'=>'code_sent','uid'=>$uid,'t'=>time()]) . "\n", FILE_APPEND);
  json_ok();
}

if ($action === 'verify_code') {
  $code = (string)($Body['code'] ?? '');
  if (!preg_match('/^\d{4,8}$/', $code)) json_fail('Invalid code format');

  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  if (!file_exists($fname)) json_fail('No active code', 400);
  $rec = json_decode((string)file_get_contents($fname), true) ?: null;
  if (!$rec) json_fail('Code record parse error', 400);
  if (($rec['exp'] ?? 0) < time()) { @unlink($fname); json_fail('Code expired', 400); }
  if (($rec['attempts'] ?? 0) >= 5) { @unlink($fname); json_fail('Too many attempts', 429); }

  $rec['attempts'] = (int)($rec['attempts'] ?? 0) + 1;
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  if (!password_verify($code, $rec['hash'])) json_fail('Incorrect code', 400);

  // Code is valid → remove challenge and mint a single-use token
  @unlink($fname);

  $token = bin2hex(random_bytes(24));
  $tokRec = [
    'uid'     => $uid,
    'issued'  => time(),
    'exp'     => time() + $TOKEN_TTL_SEC,
    'used'    => false,
    'ip'      => ($_SERVER['REMOTE_ADDR'] ?? ''),
    'session' => session_id(),
  ];
  $tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
  file_put_contents($tfile, json_encode($tokRec), LOCK_EX);

  // Compute expiry days (best effort)
  $expires_days = null;
  $safeUid = preg_replace('/[^a-zA-Z0-9_.-]/', '_', $uid);
  $crt_path = $CERT_BASE . '/' . $safeUid . '/client.crt';
  $p12_path = $CERT_BASE . '/' . $safeUid . '/client.p12';

  if (is_file($crt_path)) {
    $pem = @file_get_contents($crt_path);
    if ($pem !== false) {
      $x = @openssl_x509_parse($pem);
      if ($x && isset($x['validTo_time_t'])) {
        $expires_days = (int) floor(($x['validTo_time_t'] - time()) / 86400);
      }
    }
  } elseif (is_file($p12_path) && $P12_PASS !== '') {
    $p12 = @file_get_contents($p12_path);
    $out = [];
    if ($p12 !== false && @openssl_pkcs12_read($p12, $out, $P12_PASS)) {
      if (!empty($out['cert'])) {
        $x = @openssl_x509_parse($out['cert']);
        if ($x && isset($x['validTo_time_t'])) {
          $expires_days = (int) floor(($x['validTo_time_t'] - time()) / 86400);
        }
      }
    }
  }

  // Optional Apprise: token issued
  if (!empty($APPRISE_URL)) {
    $msg = "mTLS token issued for {$uid}, expires in 5m";
    $cmd = 'curl -s -X POST --form-string ' . escapeshellarg('body=' . $msg) . ' ' . escapeshellarg($APPRISE_URL) . ' >/dev/null 2>&1 &';
    @exec($cmd);
  }

  json_ok(['token'=>$token, 'expires_days'=>$expires_days]);
}

// Unknown action
json_fail('Unknown action', 400);
