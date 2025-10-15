<?php
declare(strict_types=1);

// Prefer CF header, then X-Forwarded-For (right-most), then X-Real-IP, then REMOTE_ADDR
function apprise_client_ip(): string {
  if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
    return $_SERVER['HTTP_CF_CONNECTING_IP'];
  }
  if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
    $cand  = end($parts);
    if ($cand && filter_var($cand, FILTER_VALIDATE_IP)) return $cand;
  }
  if (!empty($_SERVER['HTTP_X_REAL_IP']) && filter_var($_SERVER['HTTP_X_REAL_IP'], FILTER_VALIDATE_IP)) {
    return $_SERVER['HTTP_X_REAL_IP'];
  }
  return $_SERVER['REMOTE_ADDR'] ?? '';
}

// Fire-and-forget multipart POST (matches your working style)
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

// Convenience wrapper for “User Deleted” events
function apprise_notify_user_deleted(string $uid, string $admin_uid, array $pre_groups = []): void {
  $host = $_SERVER['HTTP_HOST'] ?? php_uname('n') ?? 'host';
  $ip   = apprise_client_ip();
  $grp  = trim(implode(', ', $pre_groups));
  $grp  = $grp === '' ? 'none' : $grp;

  $body = '🔐 `' . htmlspecialchars($host, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '` **User Deleted**:<br />'
        . 'User: <code>' . htmlspecialchars($uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'By: <code>'   . htmlspecialchars($admin_uid, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'IP: <code>'   . htmlspecialchars($ip, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code><br />'
        . 'Groups: <code>' . htmlspecialchars($grp, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8') . '</code>';

  mtls_apprise_notify($body);
}
