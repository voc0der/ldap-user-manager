<?php
// Includes
set_include_path(__DIR__ . '/../includes' . PATH_SEPARATOR . get_include_path());
include_once 'web_functions.inc.php';

@session_start();
header('Content-Type: application/json');

// ---------- Helpers ----------
// --- MAILER wired to your env (PHPMailer SMTP) ---
// Uses: SMTP_HOSTNAME, SMTP_HOST_PORT, SMTP_USERNAME, SMTP_PASSWORD_FILE
// Optional: SMTP_PASSWORD, SMTP_ENCRYPTION (tls|ssl|none), SMTP_FROM
function mtls_send_mail($to, $subject, $body, $fallbackFrom) {
  $host = getenv('SMTP_HOSTNAME');            // REQUIRED to use SMTP
  $port = getenv('SMTP_HOST_PORT');          // optional (default 587)
  $user = getenv('SMTP_USERNAME');           // optional
  $pass = null;

  // Prefer secret file for password
  $pwFile = getenv('SMTP_PASSWORD_FILE');
  if ($pwFile && is_readable($pwFile)) {
    $pass = trim((string)@file_get_contents($pwFile));
  }
  // Fallback to env var (if provided)
  if ($pass === null) {
    $pass = getenv('SMTP_PASSWORD') ?: '';
  }

  // If no host, fallback to PHP mail()
  if (!$host) {
    $from = $fallbackFrom ?: ($user ?: 'no-reply@localhost');
    $headers = "From: {$from}\r\nContent-Type: text/plain; charset=UTF-8";
    return @mail($to, $subject, $body, $headers);
  }

  // Resolve defaults
  $port  = (int)($port ?: 587);
  $enc   = strtolower(getenv('SMTP_ENCRYPTION') ?: 'tls'); // tls|ssl|none
  $from  = getenv('SMTP_FROM') ?: ($fallbackFrom ?: ($user ?: 'no-reply@localhost'));

  // Load PHPMailer from your image path
  $base = '/opt/PHPMailer/src';
  if (!file_exists("$base/PHPMailer.php")) {
    error_log('[mtls] PHPMailer not found at /opt/PHPMailer/src; cannot use SMTP, falling back to mail()');
    $headers = "From: {$from}\r\nContent-Type: text/plain; charset=UTF-8";
    return @mail($to, $subject, $body, $headers);
  }

  require_once "$base/PHPMailer.php";
  require_once "$base/SMTP.php";
  require_once "$base/Exception.php";

  $PHPMailer = 'PHPMailer\\PHPMailer\\PHPMailer';

  try {
    $mail = new $PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = $host;
    $mail->Port       = $port;

    // encryption
    if ($enc === 'ssl' || $port === 465)      { $mail->SMTPSecure = 'ssl'; }
    elseif ($enc === 'tls')                   { $mail->SMTPSecure = 'tls'; }
    else                                      { $mail->SMTPSecure = false; }

    // auth if we have creds
    if ($user !== '' || $pass !== '') {
      $mail->SMTPAuth = true;
      $mail->Username = $user ?: '';
      $mail->Password = $pass ?: '';
    } else {
      $mail->SMTPAuth = false;
    }

    $mail->setFrom($from);
    $mail->addAddress($to);
    $mail->Subject = $subject;
    $mail->Body    = $body;
    $mail->AltBody = $body;

    $mail->send();
    return true;
  } catch (\Throwable $e) {
    error_log('[mtls] SMTP send failed: ' . $e->getMessage());
    return false;
  }
}

function json_fail($msg, $code=400) {
  http_response_code($code);
  echo json_encode(array('ok'=>false,'error'=>$msg));
  exit;
}
function json_ok($o=array()) {
  echo json_encode(array('ok'=>true) + $o);
  exit;
}
function h($k) {
  $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k));
  return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null;
}
// Simple file-based rate limiter (sliding window)
function rate_key($uid, $kind) { return hash('sha256', $uid . '|' . $kind); }
function rate_allow($dir, $key, $limit, $perSeconds) {
  $f = $dir . '/rate_' . $key . '.json';
  $now = time();
  $winStart = $now - $perSeconds;
  $arr = array();
  if (file_exists($f)) { $tmp = json_decode((string)file_get_contents($f), true); if (is_array($tmp)) $arr = $tmp; }

  // remove old timestamps
  $arr = array_values(array_filter($arr, function($t) use ($winStart) {
    return (int)$t >= $winStart;
  }));

  if (count($arr) >= $limit) return false;
  $arr[] = $now;
  file_put_contents($f, json_encode($arr), LOCK_EX);
  return true;
}

// ---------- CSRF ----------
$Body = json_decode(file_get_contents('php://input'), true);
if (!is_array($Body)) $Body = array();
if (empty($_SESSION['csrf']) || empty($Body['csrf']) || !hash_equals($_SESSION['csrf'], (string)$Body['csrf'])) {
  json_fail('CSRF check failed', 403);
}

// ---------- Identity (proxy headers only) ----------
$uid    = h('Remote-User');   if (!$uid && isset($_SESSION['uid']))    $uid = $_SESSION['uid'];
$email  = h('Remote-Email');  if (!$email && isset($_SESSION['email'])) $email = $_SESSION['email'];
$groups_raw = (string)(h('Remote-Groups') ? h('Remote-Groups') : '');
$groups = preg_split('/[;,\s]+/', $groups_raw, -1, PREG_SPLIT_NO_EMPTY);
$groups = array_map('trim', is_array($groups)?$groups:array());

if (!$uid) json_fail('Not authenticated', 401);
if (!in_array('mtls', $groups, true)) json_fail('Not in mtls group', 403);

// ---------- Storage paths ----------
$APP_ROOT = dirname(__DIR__, 1);           // e.g. /opt/ldap_user_manager
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
$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action === 'send_code') {
  if (!$email) json_fail('No email associated with this account', 400);
  // Rate-limit: 3 sends per hour per user
  if (!rate_allow($LOGS, rate_key($uid, 'send'), 3, 3600)) {
    json_fail('Too many code requests, try later', 429);
  }

  $code = str_pad((string)mt_rand(0, 999999), 6, '0', STR_PAD_LEFT);
  $hash = password_hash($code, PASSWORD_DEFAULT);

  $rec = array(
    'uid'      => $uid,
    'hash'     => $hash,
    'ip'       => (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''),
    'ua'       => (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
    'ts'       => time(),
    'exp'      => time() + $CODE_TTL_SEC,
    'attempts' => 0,
    'session'  => session_id(),
  );
  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  $subj = 'Your one-time code';
  $msg  = "Your verification code is: {$code}\nThis code expires in 5 minutes.\nIf you did not request this, ignore this message.";

  $sent = mtls_send_mail($email, $subj, $msg, $MAIL_FROM);
  if (!$sent) {
    json_fail('Failed to send verification email', 500);
  }

  file_put_contents($LOGS . '/events.log', json_encode(array('evt'=>'code_sent','uid'=>$uid,'t'=>time())) . "\n", FILE_APPEND);
  json_ok();
}

if ($action === 'verify_code') {
  $code = isset($Body['code']) ? (string)$Body['code'] : '';
  if (!preg_match('/^\d{4,8}$/', $code)) json_fail('Invalid code format');

  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  if (!file_exists($fname)) json_fail('No active code', 400);
  $rec_raw = (string)file_get_contents($fname);
  $rec = json_decode($rec_raw, true);
  if (!is_array($rec)) json_fail('Code record parse error', 400);
  if ((isset($rec['exp']) ? $rec['exp'] : 0) < time()) { @unlink($fname); json_fail('Code expired', 400); }
  if ((isset($rec['attempts']) ? $rec['attempts'] : 0) >= 5) { @unlink($fname); json_fail('Too many attempts', 429); }

  $rec['attempts'] = (int)((isset($rec['attempts']) ? $rec['attempts'] : 0) + 1);
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  if (!password_verify($code, $rec['hash'])) json_fail('Incorrect code', 400);

  // Code is valid → remove challenge and mint a single-use token
  @unlink($fname);

  $token = bin2hex(openssl_random_pseudo_bytes(24));
  $tokRec = array(
    'uid'     => $uid,
    'issued'  => time(),
    'exp'     => time() + $TOKEN_TTL_SEC,
    'used'    => false,
    'ip'      => (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''),
    'session' => session_id(),
  );
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
    $out = array();
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

  json_ok(array('token'=>$token, 'expires_days'=>$expires_days));
}

// Unknown action
json_fail('Unknown action', 400);
