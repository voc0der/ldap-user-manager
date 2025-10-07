<?php
declare(strict_types=1);
set_include_path('.:' . __DIR__ . '/../includes/');
include_once 'web_functions.inc.php';
@session_start();
header('Content-Type: application/json');

function json_fail(string $msg, int $code=400){ http_response_code($code); echo json_encode(['ok'=>false,'error'=>$msg]); exit; }
function json_ok(array $o=[]){ echo json_encode(['ok'=>true] + $o); exit; }

// CSRF
$Body = json_decode(file_get_contents('php://input'), true) ?? [];
if (empty($_SESSION['csrf']) || empty($Body['csrf']) || !hash_equals($_SESSION['csrf'], (string)$Body['csrf'])) {
  json_fail('CSRF check failed', 403);
}

// Helper: get trusted headers
function h(string $k): ?string { $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k)); return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null; }
$uid   = h('Remote-User') ?: ($_SESSION['uid'] ?? null);
$email = h('Remote-Email') ?: ($_SESSION['email'] ?? null);
$groups = preg_split('/[;,\s]+/', (string)(h('Remote-Groups')??''));

if (!$uid) json_fail('Not authenticated', 401);
if (!in_array('mtls', array_map('trim',$groups), true)) json_fail('Not in mtls group', 403);

// Storage (no LDAP). Identity is from proxy headers only.
$DATA = dirname(__DIR__) . '/../data/mtls';
$CODES = $DATA . '/codes';
$TOKENS = $DATA . '/tokens';
$LOGS = $DATA . '/logs';

if (!is_dir($CODES)) @mkdir($CODES, 0775, true);
if (!is_dir($TOKENS)) @mkdir($TOKENS, 0775, true);
if (!is_dir($LOGS)) @mkdir($LOGS, 0775, true);

// Config (adjust as needed)
$MAIL_FROM = getenv('MTLS_MAIL_FROM') ?: 'no-reply@localhost';
$CODE_TTL_SEC = 300; // 5 minutes
$TOKEN_TTL_SEC = 300; // 5 minutes
$APPRISE_URL = getenv('APPRISE_URL'); // optional for events

// Optionally re-derive email from LDAP
try {
  $action = $_GET['action'] ?? '';

// Rate limit helpers (simple file-based sliding window)
function rate_key($uid, $kind){ return hash('sha256', $uid . '|' . $kind); }
function rate_allow($dir, $key, $limit, $perSeconds) {
  $f = $dir . '/rate_' . $key . '.json';
  $now = time();
  $win_start = $now - $perSeconds;
  $arr = [];
  if (file_exists($f)) $arr = json_decode((string)file_get_contents($f), true) ?: [];
  $arr = array_values(array_filter($arr, fn($t)=>$t>=$win_start));
  if (count($arr) >= $limit) return false;
  $arr[] = $now;
  file_put_contents($f, json_encode($arr), LOCK_EX);
  return true;
}

if ($action === 'send_code') {
  if (!$email) json_fail('No email on file', 400);
  // Send limit: 3/hour
  if (!rate_allow($LOGS, rate_key($uid,'send'), 3, 3600)) json_fail('Too many code requests, try later', 429);

  $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
  $hash = password_hash($code, PASSWORD_DEFAULT);
  $rec = [
    'uid'=>$uid,
    'hash'=>$hash,
    'ip'=>$_SERVER['REMOTE_ADDR'] ?? '',
    'ua'=>$_SERVER['HTTP_USER_AGENT'] ?? '',
    'ts'=>time(),
    'exp'=>time() + $CODE_TTL_SEC,
    'attempts'=>0,
    'session'=>session_id()
  ];
  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  // Send the email (basic PHP mail; replace with your SMTP integration if needed)
  $subj = 'Your one-time code';
  $msg = "Your verification code is: {$code}\nThis code expires in 5 minutes.\nIf you did not request this, ignore this message.";
  $hdrs = "From: {$MAIL_FROM}\r\nContent-Type: text/plain; charset=UTF-8";
  @mail($email, $subj, $msg, $hdrs);

  // Optional log
  file_put_contents($LOGS . '/events.log', json_encode(['evt'=>'code_sent','uid'=>$uid,'t'=>time()]) . "\n", FILE_APPEND);
  json_ok();
}

if ($action === 'verify_code') {
  $code = (string)($Body['code'] ?? '');
  if (!preg_match('/^\d{4,8}$/', $code)) json_fail('Invalid code format');

  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  if (!file_exists($fname)) json_fail('No active code', 400);
  $rec = json_decode((string)file_get_contents($fname), true) ?: null;
  if (!$rec) json_fail('Code record missing', 400);
  if ($rec['exp'] < time()) { @unlink($fname); json_fail('Code expired', 400); }
  if (($rec['attempts'] ?? 0) >= 5) { @unlink($fname); json_fail('Too many attempts', 429); }

  $rec['attempts'] = ($rec['attempts'] ?? 0) + 1;
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  if (!password_verify($code, $rec['hash'])) json_fail('Incorrect code', 400);

  // Correct => issue single-use download token
  @unlink($fname);
  $token = bin2hex(random_bytes(24));
  $tok = [
    'uid'=>$uid,
    'issued'=>time(),
    'exp'=>time()+$TOKEN_TTL_SEC,
    'used'=>false,
    'ip'=>$_SERVER['REMOTE_ADDR'] ?? '',
    'session'=>session_id(),
    // Derived cert path info stays server-side; download endpoint will resolve.
  ];
  $tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
  file_put_contents($tfile, json_encode($tok), LOCK_EX);

  // Optional apprise notify token issued
  if (!empty($APPRISE_URL)) {
    $msg = "mTLS token issued for {$uid}, expires in 5m";
    @exec('curl -s -X POST --form-string ' . escapeshellarg('body=' . $msg) . ' ' . escapeshellarg($APPRISE_URL) . ' >/dev/null 2>&1 &');
  }

  json_ok(['token'=>$token]);
}

json_fail('Unknown action', 400);
