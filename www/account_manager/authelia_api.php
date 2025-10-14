<?php
declare(strict_types=1);

set_include_path(".:" . __DIR__ . "/../includes/");
require_once "web_functions.inc.php";
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

// ---- GET helpers -------------------------------------------------------------
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
  echo $raw; exit;
}

// ---- POST: queue an action ---------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(['ok'=>false,'error'=>'method'], 405);

$op   = $_POST['op']   ?? '';
$user = $_POST['user'] ?? '';
if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $user)) out(['ok'=>false,'error'=>'bad user'], 400);
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

out(['ok'=>true, 'action_id'=>$action_id]);
