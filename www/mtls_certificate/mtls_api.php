<?php
// Includes
set_include_path(__DIR__ . '/../includes' . PATH_SEPARATOR . get_include_path());
include_once 'web_functions.inc.php';

@session_start();
header('Content-Type: application/json');

// ---------- Helpers ----------
// ---- Apprise notify (multipart -F like your working script) ----
function mtls_apprise_notify(string $body, ?string $tag = null): void {
  $url = getenv('APPRISE_URL');
  if (!$url) return;
  $tag = $tag ?: (getenv('APPRISE_TAG') ?: 'matrix_group_system_alerts');

  // Build: curl -s -X POST -F "body=..." -F "tag=..." "$url"  & (fire-and-forget)
  $cmd = 'curl -s -X POST'
       . ' -F ' . escapeshellarg('body=' . $body)
       . ' -F ' . escapeshellarg('tag=' . $tag)
       . ' '   . escapeshellarg($url)
       . ' >/dev/null 2>&1 &';
  @exec($cmd);
}

// track the last mail error so we can bubble it to JSON
$__MTLS_MAIL_ERR = '';
function mtls_last_mail_error(): string {
  return $GLOBALS['__MTLS_MAIL_ERR'] ?: 'unknown mail error';
}

// --- MAILER: display "APPNAME User Manager <addr>" like rest of app ---
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

  // Strip any embedded name—we'll set our own
  if (preg_match('/^\s*([^<]+?)\s*<\s*([^>]+)\s*>\s*$/', $fromAddr, $m)) {
    $fromAddr = trim($m[2]);
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

  // Fallback: mail()
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
$APP_ROOT = dirname(__DIR__);              // -> /opt/ldap_user_manager
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

// ---------- Config ----------
$CODE_TTL_SEC   = 300; // 5 minutes
$TOKEN_TTL_SEC  = 300; // 5 minutes

// ---------- Actions ----------
$action = isset($_GET['action']) ? $_GET['action'] : '';

// --- send_code ---
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

  $sent = mtls_send_mail($email, $subj, $msg, '');
  if (!$sent) {
    json_fail('Failed to send verification email: ' . mtls_last_mail_error(), 500);
  }

  file_put_contents($LOGS . '/events.log', json_encode(array('evt'=>'code_sent','uid'=>$uid,'t'=>time())) . "\n", FILE_APPEND);
  json_ok();
}

// --- verify_code ---
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

  // Styled Apprise: token issued
  $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
  $ip   = $_SERVER['REMOTE_ADDR'] ?? '';
  $body = '🔐 `' . $host . '` **mTLS Token Issued**:<br />'
        . 'User: <code>' . htmlspecialchars($uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'IP: <code>' . htmlspecialchars($ip,  ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'TTL: 5m';
  mtls_apprise_notify($body);

  // expires_days & password will be injected by the host stager; UI should poll token_info
  json_ok(array('token'=>$token, 'expires_days'=>null));
}

// --- token_info (polled by UI; returns expiry + PKCS#12 password if available) ---
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

  $days = (isset($rec2['expires_days']) && is_numeric($rec2['expires_days']))
    ? (int)$rec2['expires_days'] : null;

  $p12_password = null;
  if (!empty($rec2['p12_pass_b64'])) {
    $p = base64_decode((string)$rec2['p12_pass_b64'], true);
    if ($p !== false) $p12_password = trim($p);
  }

  json_ok(['expires_days' => $days, 'p12_password' => $p12_password]);
}

// Unknown action
json_fail('Unknown action', 400);
