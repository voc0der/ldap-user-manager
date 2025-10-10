<?php
// mtls_api.php
declare(strict_types=1);
set_include_path(__DIR__ . '/../includes' . PATH_SEPARATOR . get_include_path());
include_once 'web_functions.inc.php';

@session_start();
header('Content-Type: application/json');

// ---- Make JSON responses robust (no PHP warnings leaking) ----
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(0);
if (!ob_get_level()) { ob_start(); }

// ---------- Helpers ----------
function json_out(array $o, int $code = 200): void {
  while (ob_get_level()) { @ob_end_clean(); }
  http_response_code($code);
  echo json_encode($o, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
  exit;
}
function json_fail(string $msg, int $code=400): void { json_out(['ok'=>false,'error'=>$msg], $code); }
function json_ok(array $o=[]): void { json_out(['ok'=>true] + $o); }

function h(string $k): ?string {
  $k = 'HTTP_' . strtoupper(str_replace('-', '_', $k));
  return isset($_SERVER[$k]) ? trim((string)$_SERVER[$k]) : null;
}
function safe_uid(string $u): string {
  return preg_replace('/[^a-zA-Z0-9_.-]/', '_', $u);
}

// ---- Apprise notify (multipart -F like your working script) ----
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

// --- MAILER, app display name (kept from your working version) ---
$__MTLS_MAIL_ERR = '';
function mtls_last_mail_error(): string { return $GLOBALS['__MTLS_MAIL_ERR'] ?: 'unknown mail error'; }

function mtls_app_display_name(): string {
  static $name = null;
  if ($name !== null) return $name;
  foreach (['get_site_name','site_name','app_name','appTitle','siteTitle'] as $fn) {
    if (function_exists($fn)) { $n = trim((string)@$fn()); if ($n !== '') return $name = $n; }
  }
  foreach (['APP_NAME','SITE_NAME','WEB_TITLE','LUM_TITLE'] as $g) {
    if (!empty($GLOBALS[$g])) return $name = trim((string)$GLOBALS[$g]);
  }
  foreach (['APP_NAME','SITE_NAME','WEB_TITLE'] as $ek) { $n = getenv($ek); if ($n) return $name = trim($n); }
  $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
  if ($host) { $host = preg_replace('/:\d+$/','',$host); $host = preg_replace('/^www\./i','',$host); return $name = ucfirst(explode('.',$host)[0]); }
  return $name = 'LDAP';
}

function mtls_send_mail($to, $subject, $body, $fallbackFrom) {
  $GLOBALS['__MTLS_MAIL_ERR'] = '';

  $host = getenv('SMTP_HOSTNAME') ?: '';
  $port = (int)(getenv('SMTP_HOST_PORT') ?: 587);
  $user = getenv('SMTP_USERNAME') ?: '';
  $pass = getenv('SMTP_PASSWORD') ?: '';

  $fromAddr = getenv('MTLS_MAIL_FROM')
           ?: getenv('SMTP_FROM')
           ?: getenv('EMAIL_FROM_ADDRESS')
           ?: ($fallbackFrom ?: ($user ?: 'no-reply@localhost'));

  if (preg_match('/^\s*([^<]+?)\s*<\s*([^>]+)\s*>\s*$/', $fromAddr, $m)) $fromAddr = trim($m[2]);

  $baseName = mtls_app_display_name();
  $suffix   = preg_match('/user manager$/i', $baseName) ? '' : ' User Manager';
  $fromName = trim($baseName . $suffix);
  $sender   = getenv('MTLS_MAIL_SENDER') ?: '';

  $enc = 'tls';
  $use_tls = getenv('SMTP_USE_TLS');
  if ($use_tls !== false && $use_tls !== '') $enc = (strtolower(trim($use_tls)) === 'true' || trim($use_tls) === '1') ? 'tls' : 'none';
  else $enc = strtolower(getenv('SMTP_ENCRYPTION') ?: 'tls');
  $autotls = ($enc === 'tls');

  $base = '/opt/PHPMailer/src';
  $havePHPMailer = false;
  if (is_file("$base/PHPMailer.php")) {
    require_once "$base/PHPMailer.php";
    require_once "$base/SMTP.php";
    require_once "$base/Exception.php";
    $havePHPMailer = class_exists('PHPMailer\\PHPMailer\\PHPMailer');
  }
  if (!$host) { $GLOBALS['__MTLS_MAIL_ERR'] = 'SMTP_HOSTNAME not set'; return false; }

  if ($havePHPMailer) {
    $PHPMailer = 'PHPMailer\\PHPMailer\\PHPMailer';
    try {
      $mail = new $PHPMailer(true);
      $mail->isSMTP();
      $mail->Host = $host;
      $mail->Port = $port;
      if ($enc === 'ssl' || $port === 465) { $mail->SMTPSecure='ssl'; $mail->SMTPAutoTLS=false; }
      elseif ($enc === 'tls') { $mail->SMTPSecure='tls'; $mail->SMTPAutoTLS=$autotls; }
      else { $mail->SMTPSecure=false; $mail->SMTPAutoTLS=false; }

      if ($user !== '' || $pass !== '') { $mail->SMTPAuth = true; $mail->Username=$user; $mail->Password=$pass; }
      else $mail->SMTPAuth = false;

      if (strtolower(getenv('SMTP_ALLOW_SELF_SIGNED') ?: 'false') === 'true') {
        $mail->SMTPOptions = ['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false,'allow_self_signed'=>true]];
      }
      $caf = getenv('SMTP_CA_FILE');
      if ($caf && is_readable($caf)) { $mail->SMTPOptions = $mail->SMTPOptions ?: []; $mail->SMTPOptions['ssl']['cafile']=$caf; }

      if (strtolower(getenv('SMTP_DEBUG') ?: 'false') === 'true') { $mail->SMTPDebug=2; $mail->Debugoutput=function($s,$l){ error_log('[mtls] SMTP: '.$s); }; }

      $mail->setFrom($fromAddr, $fromName);
      if ($sender) $mail->Sender = $sender;
      $mail->addAddress($to);
      $mail->Subject = $subject;
      $mail->Body    = $body;
      $mail->AltBody = $body;

      $mail->send();
      return true;
    } catch (\Throwable $e) { $GLOBALS['__MTLS_MAIL_ERR'] = 'PHPMailer: '.$e->getMessage(); return false; }
  }

  $fromHeaderName = function_exists('mb_encode_mimeheader') ? mb_encode_mimeheader($fromName, 'UTF-8') : $fromName;
  $headers = "From: {$fromHeaderName} <{$fromAddr}>\r\nContent-Type: text/plain; charset=UTF-8";
  if ($sender) $headers .= "\r\nReturn-Path: {$sender}";
  $ok = @mail($to, $subject, $body, $headers);
  if (!$ok) $GLOBALS['__MTLS_MAIL_ERR'] = 'mail() failed (no local MTA?)';
  return $ok;
}

// Simple file-based rate limiter (sliding window)
function rate_key($uid, $kind) { return hash('sha256', $uid . '|' . $kind); }
function rate_allow($dir, $key, $limit, $perSeconds) {
  $f = $dir . '/rate_' . $key . '.json';
  $now = time();
  $winStart = $now - $perSeconds;
  $arr = array();
  if (file_exists($f)) { $tmp = json_decode((string)file_get_contents($f), true); if (is_array($tmp)) $arr = $tmp; }
  $arr = array_values(array_filter($arr, function($t) use ($winStart) { return (int)$t >= $winStart; }));
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
$APP_ROOT = dirname(__DIR__);              // /opt/ldap_user_manager
$DATA     = $APP_ROOT . '/data/mtls';
$CODES    = $DATA . '/codes';
$TOKENS   = $DATA . '/tokens';
$LOGS     = $DATA . '/logs';

function ensure_dir(string $d) {
  if (is_dir($d)) return;
  if (!@mkdir($d, 0775, true) && !is_dir($d)) json_fail("Cannot create directory: $d", 500);
}
ensure_dir($CODES);
ensure_dir($TOKENS);
ensure_dir($LOGS);

// ---------- Config ----------
$MAIL_FROM        = getenv('MTLS_MAIL_FROM') ?: (getenv('EMAIL_FROM_ADDRESS') ?: 'no-reply@localhost');
$CODE_TTL_SEC     = 300; // 5 minutes
$TOKEN_TTL_SEC    = 300; // 5 minutes
$APPRISE_URL      = getenv('APPRISE_URL'); // optional

// For token_info: where to read cert + secret password
$CERT_BASE        = getenv('MTLS_CERT_BASE') ?: '/mnt/mtls-certs';
$P12_SECRET_BASE  = getenv('MTLS_P12_SECRET_BASE') ?: '/docker-secrets/certificates';

// ---------- Actions ----------
$action = isset($_GET['action']) ? $_GET['action'] : '';

// send_code
if ($action === 'send_code') {
  if (!$email) json_fail('No email associated with this account', 400);
  if (!rate_allow($LOGS, rate_key($uid, 'send'), 3, 3600)) json_fail('Too many code requests, try later', 429);

  $code = str_pad((string)mt_rand(0, 999999), 6, '0', STR_PAD_LEFT);
  $hash = password_hash($code, PASSWORD_DEFAULT);

  $rec = array(
    'uid'      => $uid,
    'hash'     => $hash,
    'ip'       => ($_SERVER['REMOTE_ADDR'] ?? ''),
    'ua'       => ($_SERVER['HTTP_USER_AGENT'] ?? ''),
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
  if (!$sent) json_fail('Failed to send verification email: ' . mtls_last_mail_error(), 500);

  @file_put_contents($LOGS . '/events.log', json_encode(['evt'=>'code_sent','uid'=>$uid,'t'=>time()]) . "\n", FILE_APPEND);
  json_ok();
}

// verify_code
if ($action === 'verify_code') {
  $code = isset($Body['code']) ? (string)$Body['code'] : '';
  if (!preg_match('/^\d{4,8}$/', $code)) json_fail('Invalid code format');

  $fname = $CODES . '/' . hash('sha256', $uid . '|' . session_id()) . '.json';
  if (!file_exists($fname)) json_fail('No active code', 400);

  $rec = json_decode((string)file_get_contents($fname), true);
  if (!is_array($rec)) json_fail('Code record parse error', 400);
  if (($rec['exp'] ?? 0) < time()) { @unlink($fname); json_fail('Code expired', 400); }
  if ((int)($rec['attempts'] ?? 0) >= 5) { @unlink($fname); json_fail('Too many attempts', 429); }

  $rec['attempts'] = (int)($rec['attempts'] ?? 0) + 1;
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
    'ip'      => ($_SERVER['REMOTE_ADDR'] ?? ''),
    'session' => session_id(),
  );
  $tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
  file_put_contents($tfile, json_encode($tokRec), LOCK_EX);

  // Notify (no secrets)
  $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
  $ip   = $_SERVER['REMOTE_ADDR'] ?? '';
  $body = '🔐 `' . $host . '` **mTLS Token Issued**:<br />'
        . 'User: <code>' . htmlspecialchars($uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'IP: <code>' . htmlspecialchars($ip, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'TTL: 5m';
  mtls_apprise_notify($body);

  // UI will poll token_info for expiry + password
  json_ok(['token'=>$token, 'expires_days'=>null]);
}

// token_info
if ($action === 'token_info') {
  $token = isset($Body['token']) ? (string)$Body['token'] : '';
  if (!preg_match('/^[a-f0-9]{48}$/', $token)) json_fail('Bad token');

  $tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
  $ufile = $tfile . '.used';

  $rec2 = null;
  if (is_file($tfile)) { $rec2 = json_decode((string)file_get_contents($tfile), true); }
  elseif (is_file($ufile)) { $rec2 = json_decode((string)file_get_contents($ufile), true); }
  if (!is_array($rec2)) json_fail('Token not found', 404);
  if (($rec2['session'] ?? '') !== session_id()) json_fail('Session mismatch', 403);

  $uid_safe = safe_uid((string)$rec2['uid']);
  $expires_days = null;
  $p12_pass = null;

  // Try CRT first (either client.crt or cert.crt)
  $dir = rtrim($CERT_BASE, '/') . '/user_' . $uid_safe;
  $crt1 = $dir . '/client.crt';
  $crt2 = $dir . '/cert.crt';
  $pem = null;
  if (is_file($crt1)) $pem = @file_get_contents($crt1);
  elseif (is_file($crt2)) $pem = @file_get_contents($crt2);
  if ($pem !== false && $pem) {
    $x = @openssl_x509_parse($pem);
    if ($x && isset($x['validTo_time_t'])) {
      $expires_days = (int) floor(($x['validTo_time_t'] - time()) / 86400);
    }
  }

  // If no CRT info, try PFX with secret pass
  if ($expires_days === null) {
    $pfx = $dir . '/user_' . $uid_safe . '.pfx';
    $passFile = rtrim($P12_SECRET_BASE,'/') . '/user_' . $uid_safe . '/pkcs12.pass';
    if (is_file($pfx) && is_file($passFile)) {
      $pf = @file_get_contents($passFile);
      if ($pf !== false) {
        $p12_raw = @file_get_contents($pfx);
        $out = [];
        if ($p12_raw !== false && @openssl_pkcs12_read($p12_raw, $out, trim($pf))) {
          if (!empty($out['cert'])) {
            $x = @openssl_x509_parse($out['cert']);
            if ($x && isset($x['validTo_time_t'])) {
              $expires_days = (int) floor(($x['validTo_time_t'] - time()) / 86400);
            }
          }
        }
      }
    }
  }

  // Always try to load pkcs12 password for the UI (user asked to show it)
  $passFile2 = rtrim($P12_SECRET_BASE,'/') . '/user_' . $uid_safe . '/pkcs12.pass';
  if (is_file($passFile2)) {
    $p = @file_get_contents($passFile2);
    if ($p !== false) $p12_pass = rtrim($p, "\r\n");
  }

  json_ok([
    'expires_days' => is_numeric($expires_days) ? (int)$expires_days : null,
    'p12_pass'     => ($p12_pass !== null ? $p12_pass : null),
  ]);
}

// Unknown action
json_fail('Unknown action', 400);
