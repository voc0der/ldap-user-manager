<?php

/**
 * Supplementary helpers + submenu renderer for Account Manager.
 * - Adds an "MFA Orphans" tab only when orphans exist (based on authelia/status.json).
 * - Keeps Bootstrap 3 markup you already use elsewhere.
 */

function _am_authelia_status_path(): string {
  // Resolve like account_manager/authelia.php does (relative to this file)
  $AUTHELIA_DIR = getenv('AUTHELIA_DIR')
    ?: (realpath(__DIR__ . '/../data/authelia') ?: (__DIR__ . '/../data/authelia'));
  return $AUTHELIA_DIR . '/status.json';
}

/**
 * Count MFA orphans from status.json against current LDAP users.
 * Returns: ['subjects' => int, 'totp' => int, 'web' => int]
 */
function get_mfa_orphan_counts(): array {
  $STATUS = _am_authelia_status_path();
  if (!is_file($STATUS)) return ['subjects'=>0,'totp'=>0,'web'=>0];

  $raw = @file_get_contents($STATUS);
  if ($raw === false) return ['subjects'=>0,'totp'=>0,'web'=>0];
  $j = json_decode($raw, true);
  if (!is_array($j))   return ['subjects'=>0,'totp'=>0,'web'=>0];

  $totp = is_array($j['totp'] ?? null) ? $j['totp'] : [];
  $web  = is_array($j['webauthn'] ?? null) ? $j['webauthn'] : [];

  // Build valid LDAP uid + email sets
  if (!function_exists('open_ldap_connection')) {
    @include_once "ldap_functions.inc.php";
  }
  try { $ldap = open_ldap_connection(); }
  catch (\Throwable $e) { $ldap = null; }

  $uidsLC = []; $emailsLC = [];
  if ($ldap) {
    $people = ldap_get_user_list($ldap);
    foreach ($people as $uid => $attribs) {
      $uidsLC[strtolower($uid)] = true;
      $mail = '';
      if (isset($attribs['mail'])) {
        $mail = is_array($attribs['mail']) ? ($attribs['mail'][0] ?? '') : $attribs['mail'];
      }
      if ($mail) $emailsLC[strtolower($mail)] = true;
    }
  }

  $subjects = [];
  $totpN = 0; $webN = 0;

  $is_orphan = function(string $s) use ($uidsLC, $emailsLC): bool {
    $sl = strtolower(trim($s));
    if (isset($uidsLC[$sl])) return false;
    if (strpos($sl,'@') !== false) {
      // normalize plus-addressing: user+tag@domain → user@domain
      $slx = preg_replace('/^([^+@]+)\+[^@]+(@.+)$/', '$1$2', $sl) ?: $sl;
      if (isset($emailsLC[$sl]) || isset($emailsLC[$slx])) return false;
    }
    return true;
  };

  foreach ($totp as $subject => $present) {
    if (!$present) continue;
    if ($is_orphan((string)$subject)) {
      $subjects[(string)$subject] = true;
      $totpN++;
    }
  }
  foreach ($web as $subject => $count) {
    if ((int)$count <= 0) continue;
    if ($is_orphan((string)$subject)) {
      $subjects[(string)$subject] = true;
      $webN++;
    }
  }

  return ['subjects'=>count($subjects), 'totp'=>$totpN, 'web'=>$webN];
}

function render_submenu() {
  global $THIS_MODULE_PATH;

  $submodules = array(
    'users'  => 'index.php',
    'groups' => 'groups.php'
  );

  // If orphans exist, expose the tab
  $oc = get_mfa_orphan_counts();
  if (($oc['subjects'] ?? 0) > 0) {
    $submodules['mfa_orphans'] = 'orphans.php';
  }
  ?>
  <nav class="navbar navbar-default">
    <div class="container-fluid">
      <ul class="nav navbar-nav">
        <?php foreach ($submodules as $key => $path):
          $isActive = (basename($_SERVER['SCRIPT_FILENAME']) == $path);
          $label = ($key === 'mfa_orphans')
            ? 'MFA Orphans <span class="badge" style="margin-left:6px;">'.(int)$oc['subjects'].'</span>'
            : ucwords($key);
        ?>
          <li class="<?php echo $isActive ? 'active' : ''; ?>">
            <a href="<?php echo $THIS_MODULE_PATH . '/' . $path; ?>"><?php echo $label; ?></a>
          </li>
        <?php endforeach; ?>
      </ul>
    </div>
  </nav>
  <?php
}
