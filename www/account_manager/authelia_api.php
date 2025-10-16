<?php
declare(strict_types=1);

set_include_path(".:" . __DIR__ . "/../includes/");
require_once "web_functions.inc.php";
require_once "ldap_functions.inc.php";
@session_start();
set_page_access('admin');

header('Content-Type: application/json');

// ----- Resolve the mounted authelia dir inside LUM -----
$AUTHELIA_DIR = getenv('AUTHELIA_DIR')
  ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));

$Q       = $AUTHELIA_DIR . '/actions/queued';
$R       = $AUTHELIA_DIR . '/actions/results';
$STATUS  = $AUTHELIA_DIR . '/status.json';

function out($arr, int $code = 200) {
  http_response_code($code);
  echo json_encode($arr, JSON_UNESCAPED_SLASHES);
  exit;
}

/* ---------------- Apprise + helpers (do not reinvent apprise) --------------- */

// Fire-and-forget POST like your working script
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

function site_name_guess(): string {
  if (!empty($GLOBALS['ORGANISATION_NAME'])) return (string)$GLOBALS['ORGANISATION_NAME'];
  $env = getenv('SITE_NAME') ?: getenv('APP_NAME') ?: getenv('WEB_TITLE') ?: '';
  if ($env) return $env;
  $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'LDAP');
  return preg_replace('/^www\./i', '', (string)$host);
}
function support_email_guess(): string {
  $env = getenv('SUPPORT_EMAIL') ?: getenv('EMAIL_SUPPORT') ?: '';
  if ($env) return $env;
  $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
  $host = preg_replace('/:\d+$/', '', (string)$host);
  return 'support@' . $host;
}

/* ----------------------------- GET helpers ---------------------------------- */

$action = $_GET['action'] ?? '';

if ($action === 'status') {
  if (!is_file($STATUS)) out(['ok'=>false,'error'=>'status.json missing'], 404);
  $raw = @file_get_contents($STATUS);
  if ($raw === false) out(['ok'=>false,'error'=>'read failed'], 500);
  echo $raw; exit;
}

if ($action === 'result') {
  $id = preg_replace('/[^A-Za-z0-9._:-]/','', $_GET['id'] ?? '');
  if (!$id) out(['ok'=>false,'error'=>'missing id'], 400);
  $p = $R . '/' . $id . '.json';
  if (!is_file($p)) out(['ok'=>false,'error'=>'not ready'], 404);

  $raw = @file_get_contents($p);
  if ($raw === false) out(['ok'=>false,'error'=>'read failed'], 500);

  // Try to decode; if successful and not yet notified, send mail + apprise
  $j = json_decode($raw, true) ?: [];
  $metaPath     = $R . '/' . $id . '.meta.json';
  $notifiedPath = $R . '/' . $id . '.notified';

  // Heuristic success: prefer explicit ok=true, else look for "deleted" in details
  $ok = isset($j['ok']) ? (bool)$j['ok'] : (stripos((string)($j['details'] ?? ''), 'deleted') !== false);

  if ($ok && !is_file($notifiedPath)) {
    // Collect context
    $meta   = is_file($metaPath) ? (json_decode((string)@file_get_contents($metaPath), true) ?: []) : [];
    $op     = (string)($j['op']        ?? ($meta['op']        ?? ''));
    $userId = (string)($j['user']      ?? ($meta['user']      ?? ''));
    $admin  = (string)($j['requester']['admin_uid'] ?? ($meta['requester']['admin_uid'] ?? 'an administrator'));
    $host   = $_SERVER['HTTP_HOST'] ?? (php_uname('n') ?: 'host');
    $when   = date('Y-m-d H:i:s T');

    // Human-friendly name
    $type  = ($op === 'totp.delete') ? 'TOTP reset'
           : (($op === 'webauthn.delete') ? 'WebAuthn device reset' : 'MFA change');
    if ($op === 'webauthn.delete') {
      $scope = (string)($j['target']['scope'] ?? ($meta['target']['scope'] ?? ''));
      if ($scope === 'all') $type = 'WebAuthn devices (all) reset';
    }

    // Look up user email + display name
    $toEmail = '';
    $toName  = $userId;
    try {
      $ldap = open_ldap_connection();
      global $LDAP; // ensure $LDAP is visible
      $filter = "({$LDAP['account_attribute']}=" . ldap_escape($userId, "", LDAP_ESCAPE_FILTER) . ")";
      $sr = @ldap_search($ldap, $LDAP['user_dn'], $filter, ['mail','givenName','sn']);
      if ($sr) {
        $en = @ldap_get_entries($ldap, $sr);
        if (is_array($en) && ($en['count'] ?? 0) > 0) {
          $toEmail = (string)($en[0]['mail'][0] ?? '');
          $gn = (string)($en[0]['givenname'][0] ?? ($en[0]['givenName'][0] ?? ''));
          $sn = (string)($en[0]['sn'][0] ?? '');
          $name = trim($gn . ' ' . $sn);
          if ($name !== '') $toName = $name;
        }
      }
    } catch (\Throwable $e) {
      // Ignore lookup errors; we'll just skip email if no address.
    }

    // Compose email
    $site    = site_name_guess();
    $support = support_email_guess();
    $safeUser  = htmlspecialchars($userId, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeAdmin = htmlspecialchars($admin,  ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeHost  = htmlspecialchars($host,   ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    $subject = "{$site} security alert: {$type}";
    $body = '<div style="font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#d7e7ff;background:#0b0f14;padding:16px;">
      <div style="max-width:640px;margin:0 auto;border:1px solid #1f2a44;border-radius:12px;overflow:hidden;background:#0f1522;">
        <div style="height:4px;background:linear-gradient(90deg,#00e5ff,#8a2be2,#ff00cc,#00e5ff);"></div>
        <div style="padding:18px 22px 10px;">
          <div style="font-size:12px;letter-spacing:2px;color:#7adfff;text-transform:uppercase;">Security notice</div>
          <h2 style="margin:6px 0 0 0;font-size:20px;color:#e8f3ff;">' . htmlspecialchars($type, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</h2>
          <p style="margin:10px 0 0 0;color:#a9b8d0;font-size:14px;line-height:1.7;">
            The ' . htmlspecialchars($type, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . ' for your account
            <strong>' . $safeUser . '</strong> was performed on <strong>' . $when . '</strong>
            by <strong>' . $safeAdmin . '</strong> on <code>' . $safeHost . '</code>.
          </p>
          <p style="margin:10px 0 0 0;color:#a9b8d0;font-size:14px;line-height:1.7;">
            If you didn’t request or expect this change, reply to this email or contact
            <a style="color:#7adfff;text-decoration:none;" href="mailto:' . htmlspecialchars($support, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($support, ENT_QUOTES, 'UTF-8') . '</a> immediately.
          </p>
        </div>
      </div>
    </div>';

    // Send email if we have an address
    if ($toEmail !== '') {
      include_once "mail_functions.inc.php";
      @send_email($toEmail, $toName, $subject, $body);
    }

    // Apprise alert (styled like your mTLS message)
    $appriseBody = '🔐 `' . $safeHost . '` **MFA Change**:<br />'
                 . 'User: <code>' . $safeUser  . '</code><br />'
                 . 'Type: <code>' . htmlspecialchars($type, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
                 . 'By: <code>'   . $safeAdmin . '</code><br />'
                 . 'Action: <code>' . htmlspecialchars($id, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</code>';
    mtls_apprise_notify($appriseBody);

    // Mark as notified so we don't double-send
    @file_put_contents($notifiedPath, '1');
    @chmod($notifiedPath, 0640);
  }

  // Return original result JSON
  echo $raw; exit;
}

/* ----------------------------- POST (queue) --------------------------------- */

if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(['ok'=>false,'error'=>'method'], 405);

$op   = $_POST['op']   ?? '';
$user = $_POST['user'] ?? '';
if (!preg_match('/^[A-Za-z0-9._@+-]{1,128}$/', $user)) out(['ok'=>false,'error'=>'bad user'], 400);
if (!in_array($op, ['totp.delete','webauthn.delete'], true)) out(['ok'=>false,'error'=>'bad op'], 400);

$target = null;
if ($op === 'webauthn.delete') {
  $scope = $_POST['scope'] ?? '';
  if ($scope === 'all') {
    $target = ['scope'=>'all'];
  } else {
    $masked = $_POST['masked'] ?? '';
    $index  = isset($_POST['index']) ? intval($_POST['index']) : null;
    if ($masked !== '')      $target = ['scope'=>'one','masked'=>$masked];
    elseif ($index !== null) $target = ['scope'=>'one','index'=>$index];
    else out(['ok'=>false,'error'=>'missing target'], 400);
  }
}

// ---- Block MFA ops if target is in the admin group ---------------------------
$ADMIN_GROUP_NAME = getenv('ADMIN_GROUP_NAME') ?: 'admin';
$ldap = open_ldap_connection();
$groups = ldap_user_group_membership($ldap, $user);
$blocked = false;
foreach ($groups as $g) {
  if (strcasecmp($g, $ADMIN_GROUP_NAME) === 0) { $blocked = true; break; }
}
if ($blocked) out(['ok'=>false,'error'=>'MFA actions disabled for admin-group users'], 403);

// ---- Build queued action -----------------------------------------------------
$admin_uid = $GLOBALS['USER_ID'] ?? ($_SESSION['user_id'] ?? 'unknown');
$ts        = gmdate('Ymd\THis\Z');
$rand      = bin2hex(random_bytes(4));
$action_id = $ts . '-' . $rand;

$payload = [
  'schema'     => 'authelia-action@v1',
  'action_id'  => $action_id,
  'request_ts' => time(),
  'requester'  => [
    'admin_uid' => $admin_uid,
    'ip'        => $_SERVER['REMOTE_ADDR']      ?? '',
    'ua'        => $_SERVER['HTTP_USER_AGENT']  ?? '',
  ],
  'op'   => $op,
  'user' => $user,
];
if ($target) $payload['target'] = $target;

if (!is_dir($Q) && !@mkdir($Q, 0770, true)) out(['ok'=>false,'error'=>'queue dir missing'], 500);

$tmp   = $Q . '/' . $action_id . '.json.tmp';
$final = $Q . '/' . $action_id . '.json';

if (@file_put_contents($tmp, json_encode($payload, JSON_UNESCAPED_SLASHES), LOCK_EX) === false)
  out(['ok'=>false,'error'=>'write failed'], 500);

@chmod($tmp, 0640);
if (!@rename($tmp, $final)) { @unlink($tmp); out(['ok'=>false,'error'=>'rename failed'], 500); }

/* Persist a tiny meta file so the result endpoint can include initiator context */
if (!is_dir($R)) { @mkdir($R, 0770, true); }
$meta = [
  'action_id' => $action_id,
  'op'        => $op,
  'user'      => $user,
  'requester' => $payload['requester'],
];
@file_put_contents($R . '/' . $action_id . '.meta.json', json_encode($meta, JSON_UNESCAPED_SLASHES), LOCK_EX);
@chmod($R . '/' . $action_id . '.meta.json', 0640);

out(['ok'=>true, 'action_id'=>$action_id]);
