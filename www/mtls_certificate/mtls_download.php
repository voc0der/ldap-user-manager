<?php
declare(strict_types=1);
set_include_path(__DIR__ . '/../includes' . PATH_SEPARATOR . get_include_path());
include_once 'web_functions.inc.php';

@session_start();
header('Content-Type: application/json');

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Apprise notify (multipart -F like your working script)
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

// Last mail error tracker
$__MTLS_MAIL_ERR = '';
function mtls_last_mail_error(): string {
  return $GLOBALS['__MTLS_MAIL_ERR'] ?: 'unknown mail error';
}

// App/site display name (match rest of app if possible)
function mtls_app_display_name(): string {
  static $name = null;
  if ($name !== null) return $name;

  foreach (['get_site_name','site_name','app_name','appTitle','siteTitle'] as $fn) {
    if (function_exists($fn)) {
      $n = trim((string)@$fn());
      if ($n !== '') return $name = $n;
    }
  }
  foreach (['APP_NAME','SITE_NAME','WEB_TITLE','LUM_TITLE'] as $g) {
    if (!empty($GLOBALS[$g])) return $name = trim((string)$GLOBALS[$g]);
  }
  foreach (['APP_NAME','SITE_NAME','WEB_TITLE'] as $ek) {
    $n = getenv($ek);
    if ($n) return $name = trim($n);
  }
  $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '';
  if ($host) {
    $host = preg_replace('/:\d+$/', '', $host);
    $host = preg_replace('/^www\./i', '', $host);
    $base = ucfirst(explode('.', $host)[0]);
    return $name = $base;
  }
  return $name = 'LDAP';
}

// Mailer (PHPMailer if available), with "<APP> User Manager <addr>" From:
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

  if (preg_match('/^\s*([^<]+?)\s*<\s*([^>]+)\s*>\s*$/', $fromAddr, $m)) {
    $fromAddr = trim($m[2]); // normalize to plain email
  }

  $baseName = mtls_app_display_name();
  $suffix   = preg_match('/user manager$/i', $baseName) ? '' : ' User Manager';
  $fromName = trim($baseName . $suffix);

  $sender = getenv('MTLS_MAIL_SENDER') ?: '';

  $enc = 'tls';
  $use_tls = getenv('SMTP_USE_TLS');
  if ($use_tls !== false && $use_tls !== '') {
    $enc = (strtolower(trim($use_tls)) === 'true' || trim($use_tls) === '1') ? 'tls' : 'none';
  } else {
    $enc = strtolower(getenv('SMTP_ENCRYPTION') ?: 'tls');
  }
  $autotls = ($enc === 'tls');

  if ($host) { @fsockopen($host, $port, $errno, $errstr, 5); }

  $base = '/opt/PHPMailer/src';
  $havePHPMailer = false;
  if (is_file("$base/PHPMailer.php")) {
    require_once "$base/PHPMailer.php";
    require_once "$base/SMTP.php";
    require_once "$base/Exception.php";
    $havePHPMailer = class_exists('PHPMailer\\PHPMailer\\PHPMailer');
  }

  if (!$host) {
    $GLOBALS['__MTLS_MAIL_ERR'] = 'SMTP_HOSTNAME not set';
    return false;
  }

  if ($havePHPMailer) {
    $PHPMailer = 'PHPMailer\\PHPMailer\\PHPMailer';
    try {
      $mail = new $PHPMailer(true);
      $mail->isSMTP();
      $mail->Host = $host;
      $mail->Port = $port;

      if ($enc === 'ssl' || $port === 465) {
        $mail->SMTPSecure  = 'ssl';
        $mail->SMTPAutoTLS = false;
      } elseif ($enc === 'tls') {
        $mail->SMTPSecure  = 'tls';
        $mail->SMTPAutoTLS = $autotls;
      } else {
        $mail->SMTPSecure  = false;
        $mail->SMTPAutoTLS = false;
      }

      if ($user !== '' || $pass !== '') {
        $mail->SMTPAuth = true;
        $mail->Username = $user;
        $mail->Password = $pass;
      } else {
        $mail->SMTPAuth = false;
      }

      if (strtolower(getenv('SMTP_ALLOW_SELF_SIGNED') ?: 'false') === 'true') {
        $mail->SMTPOptions = [
          'ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
          ],
        ];
      }
      $caf = getenv('SMTP_CA_FILE');
      if ($caf && is_readable($caf)) {
        $mail->SMTPOptions = $mail->SMTPOptions ?: [];
        $mail->SMTPOptions['ssl']['cafile'] = $caf;
      }
      if (strtolower(getenv('SMTP_DEBUG') ?: 'false') === 'true') {
        $mail->SMTPDebug = 2;
        $mail->Debugoutput = function($str, $lvl) { error_log('[mtls] SMTP: ' . $str); };
      }

      $mail->setFrom($fromAddr, $fromName);
      if ($sender) $mail->Sender = $sender;

      $mail->addAddress($to);
      $mail->Subject = $subject;
      $mail->Body    = $body;
      $mail->AltBody = $body;

      $mail->send();
      return true;
    } catch (\Throwable $e) {
      $GLOBALS['__MTLS_MAIL_ERR'] = 'PHPMailer: ' . $e->getMessage();
      return false;
    }
  }

  $fromHeaderName = $fromName;
  if (function_exists('mb_encode_mimeheader')) {
    $fromHeaderName = mb_encode_mimeheader($fromHeaderName, 'UTF-8');
  }
  $headers = "From: {$fromHeaderName} <{$fromAddr}>\r\nContent-Type: text/plain; charset=UTF-8";
  if ($sender) $headers .= "\r\nReturn-Path: {$sender}";
  $ok = @mail($to, $subject, $body, $headers);
  if (!$ok) $GLOBALS['__MTLS_MAIL_ERR'] = 'mail() failed (no local MTA?)';
  return $ok;
}

function json_fail($msg, $code=400) {
  http_response_code($code);
  echo json_encode(['ok'=>false,'error'=>$msg]);
  exit;
}
function json_ok($o=[]) {
  echo json_encode(['ok'=>true] + $o);
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
  $arr = [];
  if (file_exists($f)) { $tmp = json_decode((string)file_get_contents($f), true); if (is_array($tmp)) $arr = $tmp; }
  $arr = array_values(array_filter($arr, function($t) use ($winStart) { return (int)$t >= $winStart; }));
  if (count($arr) >= $limit) return false;
  $arr[] = $now;
  file_put_contents($f, json_encode($arr), LOCK_EX);
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// CSRF
// ─────────────────────────────────────────────────────────────────────────────
$Body = json_decode(file_get_contents('php://input'), true);
if (!is_array($Body)) $Body = [];
if (empty($_SESSION['csrf']) || empty($Body['csrf']) || !hash_equals($_SESSION['csrf'], (string)$Body['csrf'])) {
  json_fail('CSRF check failed', 403);
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity (proxy headers only; Authelia)
// ─────────────────────────────────────────────────────────────────────────────
$uid    = h('Remote-User');   if (!$uid && isset($_SESSION['uid']))    $uid = $_SESSION['uid'];
$email  = h('Remote-Email');  if (!$email && isset($_SESSION['email'])) $email = $_SESSION['email'];
$groups_raw = (string)(h('Remote-Groups') ? h('Remote-Groups') : '');
$groups = preg_split('/[;,\s]+/', $groups_raw, -1, PREG_SPLIT_NO_EMPTY);
$groups = array_map('trim', is_array($groups)?$groups:[]);

if (!$uid) json_fail('Not authenticated', 401);
if (!in_array('mtls', $groups, true)) json_fail('Not in mtls group', 403);

// ─────────────────────────────────────────────────────────────────────────────
// Storage paths
// ─────────────────────────────────────────────────────────────────────────────
$APP_ROOT = dirname(__DIR__);              // /opt/ldap_user_manager
$DATA     = $APP_ROOT . '/data/mtls';
$CODES    = $DATA . '/codes';
$TOKENS   = $DATA . '/tokens';
$LOGS     = $DATA . '/logs';

function ensure_dir(string $d) {
  if (is_dir($d)) return;
  if (!@mkdir($d, 0775, true) && !is_dir($d)) {
    json_fail("Cannot create directory: $d", 500);
  }
}
ensure_dir($CODES);
ensure_dir($TOKENS);
ensure_dir($LOGS);

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────
$MAIL_FROM      = getenv('MTLS_MAIL_FROM') ?: (getenv('EMAIL_FROM_ADDRESS') ?: 'no-reply@localhost');
$CODE_TTL_SEC   = 300; // 5 minutes
$TOKEN_TTL_SEC  = 300; // 5 minutes

// Where to read pkcs12 password (bind the host dir here):
//   host: /docker_3000/secrets/certificates/user_<uid>/pkcs12.pass
//   cont: /docker-secrets/certificates/user_<uid>/pkcs12.pass
$PASS_BASE      = getenv('MTLS_P12_PASS_BASE') ?: '/docker-secrets/certificates';

// ─────────────────────────────────────────────────────────────────────────────
// Actions
// ─────────────────────────────────────────────────────────────────────────────
$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action === 'send_code') {
  if (!$email) json_fail('No email associated with this account', 400);
  if (!rate_allow($LOGS, rate_key($uid, 'send'), 3, 3600)) {
    json_fail('Too many code requests, try later', 429);
  }

  $code = str_pad((string)mt_rand(0, 999999), 6, '0', STR_PAD_LEFT);
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

  $subj = 'Your one-time code';
  $msg  = "Your verification code is: {$code}\nThis code expires in 5 minutes.\nIf you did not request this, ignore this message.";
  $sent = mtls_send_mail($email, $subj, $msg, $MAIL_FROM);
  if (!$sent) json_fail('Failed to send verification email: ' . mtls_last_mail_error(), 500);

  file_put_contents($LOGS . '/events.log', json_encode(['evt'=>'code_sent','uid'=>$uid,'t'=>time()]) . "\n", FILE_APPEND);
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
  if (($rec['exp'] ?? 0) < time()) { @unlink($fname); json_fail('Code expired', 400); }
  if (($rec['attempts'] ?? 0) >= 5) { @unlink($fname); json_fail('Too many attempts', 429); }

  $rec['attempts'] = (int)(($rec['attempts'] ?? 0) + 1);
  file_put_contents($fname, json_encode($rec), LOCK_EX);

  if (!password_verify($code, $rec['hash'])) json_fail('Incorrect code', 400);

  // Valid → remove challenge, mint single-use token
  @unlink($fname);

  $token = bin2hex(openssl_random_pseudo_bytes(24));
  $tokRec = [
    'uid'     => $uid,
    'issued'  => time(),
    'exp'     => time() + $TOKEN_TTL_SEC,
    'used'    => false,
    'ip'      => ($_SERVER['REMOTE_ADDR'] ?? ''),
    'session' => session_id(),
    // 'expires_days' may be added later by the host stager (optional)
  ];
  $tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
  file_put_contents($tfile, json_encode($tokRec), LOCK_EX);

  // Styled, tagged Apprise
  $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
  $ip   = $_SERVER['REMOTE_ADDR'] ?? '';
  $body = '🔐 `' . $host . '` **mTLS Token Issued**:<br />'
        . 'User: <code>' . htmlspecialchars($uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'IP: <code>'   . htmlspecialchars($ip,  ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'TTL: 5m';
  mtls_apprise_notify($body);

  json_ok(['token'=>$token, 'expires_days'=>null]);
}

if ($action === 'token_info') {
  $token = isset($Body['token']) ? (string)$Body['token'] : '';
  if (!preg_match('/^[a-f0-9]{48}$/', $token)) json_fail('Bad token');

  $tfile = $TOKENS . '/' . hash('sha256', $token) . '.json';
  $ufile = $tfile . '.used';

  $rec2 = null;
  if (is_file($tfile)) {
    $rec2 = json_decode((string)file_get_contents($tfile), true);
  } elseif (is_file($ufile)) {
    $rec2 = json_decode((string)file_get_contents($ufile), true);
  }
  if (!is_array($rec2)) json_fail('Token not found', 404);
  if (($rec2['session'] ?? '') !== session_id()) json_fail('Session mismatch', 403);

  $uid2 = (string)($rec2['uid'] ?? '');
  $safeUid = preg_replace('/[^a-zA-Z0-9_.-]/', '_', $uid2);

  // Read PKCS#12 pass from mounted secrets dir
  $pass_path = rtrim($PASS_BASE, '/')
             . '/user_' . $safeUid . '/pkcs12.pass';
  $p12_pass = null;
  if (is_file($pass_path) && is_readable($pass_path)) {
    $p12_pass = trim((string)file_get_contents($pass_path));
    // keep it short-ish to avoid dumping huge files by mistake
    if (strlen($p12_pass) > 512) $p12_pass = substr($p12_pass, 0, 512);
  }

  // Prefer any precomputed expiry written by stager; else null
  $days = (isset($rec2['expires_days']) && is_numeric($rec2['expires_days']))
    ? (int)$rec2['expires_days'] : null;

  json_ok(['expires_days' => $days, 'p12_pass' => $p12_pass]);
}

// Unknown action
json_fail('Unknown action', 400);
