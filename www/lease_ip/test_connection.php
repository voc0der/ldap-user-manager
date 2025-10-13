<?php
declare(strict_types=1);
require_once __DIR__ . '/../includes/web_functions.inc.php';
set_page_access('auth');

@session_start();
global $IS_ADMIN, $USER_ID;
$isAdmin  = !empty($IS_ADMIN);
$username = $USER_ID ?? ($_SESSION['user_id'] ?? 'unknown');

/* -------------------- helpers -------------------- */
function h(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function canon_ip(?string $ip): ?string {
    if (!$ip) return null;
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) return null;
    $bin = @inet_pton($ip);
    return $bin === false ? null : @inet_ntop($bin);
}
function get_client_ip(): ?string {
    $candidates = [];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) $candidates[] = trim($p);
    }
    if (!empty($_SERVER['HTTP_X_REAL_IP'])) $candidates[] = trim($_SERVER['HTTP_X_REAL_IP']);
    if (!empty($_SERVER['REMOTE_ADDR']))    $candidates[] = trim($_SERVER['REMOTE_ADDR']);
    foreach ($candidates as $v) if ($v = canon_ip($v)) return $v;
    return null;
}
function ip_in_cidr(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) return $ip === $cidr;
    [$sub, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ipBin  = @inet_pton($ip);
    $subBin = @inet_pton($sub);
    if ($ipBin === false || $subBin === false) return false;
    $len = strlen($ipBin);
    if ($len !== strlen($subBin)) return false; // v4 vs v6 mismatch
    $bytes = intdiv($bits, 8);
    $rem   = $bits % 8;
    if ($bytes && substr($ipBin, 0, $bytes) !== substr($subBin, 0, $bytes)) return false;
    if ($rem) {
        $mask = chr((0xFF00 >> $rem) & 0xFF);
        if ((ord($ipBin[$bytes]) & ord($mask)) !== (ord($subBin[$bytes]) & ord($mask))) return false;
    }
    return true;
}
function ip_in_any_cidr(string $ip, array $cidrs): bool {
    foreach ($cidrs as $c) {
        $c = trim($c);
        if ($c !== '' && ip_in_cidr($ip, $c)) return true;
    }
    return false;
}
function parse_cidr_list(string $spec): array {
    // comma, semicolon, or whitespace separated
    $spec = trim($spec);
    if ($spec === '') return [];
    $parts = preg_split('/[,\s;]+/', $spec, -1, PREG_SPLIT_NO_EMPTY);
    return array_values(array_unique(array_map('trim', $parts)));
}
function fetch_json(string $url): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_USERAGENT      => 'LUM-ConnTest/1.1',
        CURLOPT_HTTPHEADER     => ['Accept: application/json'],
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
    $err  = curl_error($ch);
    curl_close($ch);
    if ($body === false || $code < 200 || $code >= 300) return [false, null, $code, $err ?: 'http_error'];
    $data = json_decode($body, true);
    if (!is_array($data)) return [false, null, $code, 'invalid_json'];
    return [true, $data, $code, ''];
}
function current_host_url(): string {
    $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443');
    return ($https ? 'https://' : 'http://') . $host;
}

/* -------------------- inputs + detection -------------------- */
$format = (strtolower((string)($_GET['format'] ?? 'html')) === 'json') ? 'json' : 'html';

$clientIp = get_client_ip() ?: '0.0.0.0';
$isV4     = (bool)filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

/* LAN = any RFC1918 IPv4 + localhost (independent flag) */
$lanCidrs = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.1/32'];
$inLan    = $isV4 && ip_in_any_cidr($clientIp, $lanCidrs);

/* VPN CIDR(s) from env (independent flag). Default to 10.2.4.0/24. */
$vpnSpec = getenv('VPN_CIDR') ?: '10.2.4.0/24';
$vpnCidrs = parse_cidr_list($vpnSpec);
$onVpn    = $isV4 && !empty($vpnCidrs) && ip_in_any_cidr($clientIp, $vpnCidrs);

/* mTLS (independent flag): prefer explicit header from nginx location / */
$mtlsHeader   = strtolower((string)($_SERVER['HTTP_X_MTLS'] ?? ''));
$mtlsDetected = in_array($mtlsHeader, ['on','1','true'], true);

/* Whitelist (independent flag) via lease API */
$base = (string)($_GET['lease_url'] ?? (getenv('LEASE_API_BASE') ?: (rtrim(current_host_url(), '/') . '/endpoints/lease_ip.php')));
$leaseUrl = (function($u){$q=parse_url($u,PHP_URL_QUERY);return ($q && preg_match('/(?:^|&)list=1(?:&|$)/',(string)$q))?$u:$u.(strpos($u,'?')!==false?'&':'?').'list=1';})($base);

$isWhitelisted = false;
$wlMatch = null;
list($wlOk, $wlPayload, $wlHttp, $wlErr) = fetch_json($leaseUrl);
if ($wlOk && isset($wlPayload['entries']) && is_array($wlPayload['entries'])) {
    foreach ($wlPayload['entries'] as $e) {
        if (!isset($e['ip'])) continue;
        if ((string)$e['ip'] === $clientIp) {
            $isWhitelisted = true;
            $wlMatch = [
                'label'     => $e['label'] ?? null,
                'timestamp' => $e['timestamp'] ?? null,
                'source'    => $e['source'] ?? null,
                'static'    => (bool)($e['static'] ?? false),
            ];
            break;
        }
    }
}

/* Conservative inference: only if external + not VPN + not whitelisted and no header */
$mtlsAssumed = (!$mtlsDetected && !$inLan && !$onVpn && !$isWhitelisted);
$usingMtls   = $mtlsDetected || $mtlsAssumed;

/* -------------------- render -------------------- */
if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ok' => true,
        'user' => $username,
        'client_ip' => $clientIp,
        'flags' => [
            'in_lan'               => $inLan,
            'on_vpn'               => $onVpn,
            'using_whitelisted_ip' => $isWhitelisted,
            'using_mtls'           => $usingMtls,
        ],
        'mtls' => [
            'header'     => $mtlsHeader ?: null,
            'detected'   => $mtlsDetected,
            'assumed'    => $mtlsAssumed,
            'explanation'=> $mtlsDetected ? 'X-MTLS:on' : ($mtlsAssumed ? 'External & not VPN & not whitelisted' : 'Not detected'),
        ],
        'lease_api' => [
            'url' => $leaseUrl,
            'ok'  => $wlOk,
            'http'=> $wlHttp,
            'err' => $wlOk ? null : $wlErr,
            'match'=> $wlMatch,
        ],
        'vpn_cidrs' => $vpnCidrs,
        'ts' => date('Y-m-d H:i:s T'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

render_header('Test Connection');
?>
<style>
/* ---------- Cyberpunk-ish chrome (Bootstrap 3 friendly) ---------- */
.conn-wrap { max-width: 860px; margin: 18px auto 40px; }
.panel-modern { background:#0b0f13; border:1px solid rgba(255,255,255,.08); border-radius:12px; overflow:hidden; }
.panel-modern .panel-heading {
  background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.02));
  color:#cfe9ff; font-weight:600; letter-spacing:.4px; text-transform:uppercase;
  padding:10px 14px; border-bottom:1px solid rgba(255,255,255,.08);
}
.panel-modern .panel-body { padding:14px; }

.table-modern { margin:0; }
.table-modern>thead>tr>th,
.table-modern>tbody>tr>td,
.table-modern tfoot td { border-color: rgba(255,255,255,.08); }

.table-modern>thead>tr>th {
  color:#9fb6c9; font-size:12px; text-transform:uppercase; letter-spacing:.35px; border-bottom-width:1px;
}
.table-modern.table-striped>tbody>tr:nth-of-type(odd)  { background: rgba(255,255,255,.03); }
.table-modern.table-striped>tbody>tr:nth-of-type(even) { background: rgba(255,255,255,.015); }
.table-modern>tbody>tr:hover td { background: rgba(255,255,255,.06); }

.badge-chip { display:inline-block; padding:2px 8px; border-radius:10px; font-family:monospace; font-size:.95em;
  background:#1a2b3a; color:#a9e1ff; border:1px solid rgba(127,209,255,.35); }
.smallprint { color:#8aa0b2; font-size:12px; }
.flag-yes { color:#10b981; font-weight:700; }
.flag-no  { color:#ef4444; font-weight:700; }
.kv { display:flex; justify-content:space-between; align-items:center; padding:10px 12px; border-radius:10px; }
.kv + .kv { margin-top:8px; }
.hint { margin-top:10px; }
hr.soft { border:0; border-top:1px solid rgba(255,255,255,.08); margin:12px 0; }
</style>

<div class="container conn-wrap">

  <div class="panel panel-modern">
    <div class="panel-heading text-center">CONNECTION CHECK</div>
    <div class="panel-body">
      <div class="table-responsive">
        <table class="table table-modern">
          <tbody>
          <tr>
            <td>Signed in as</td>
            <td><span class="badge-chip"><?php echo h($username); ?></span></td>
          </tr>
          <tr>
            <td>Detected client IP</td>
            <td><span class="badge-chip"><?php echo h($clientIp); ?></span></td>
          </tr>
          </tbody>
        </table>
      </div>

      <hr class="soft" />

      <!-- Independent flags (multiple ✅ can be true) -->
      <div class="kv">
        <span>Your device is inside the LAN (RFC1918).</span>
        <span class="<?php echo $inLan ? 'flag-yes':'flag-no'; ?>"><?php echo $inLan ? '✅' : '❌'; ?></span>
      </div>
      <div class="kv">
        <span>Your device is on the VPN.</span>
        <span class="<?php echo $onVpn ? 'flag-yes':'flag-no'; ?>"><?php echo $onVpn ? '✅' : '❌'; ?></span>
      </div>
      <div class="kv">
        <span>Your device is using a whitelisted IP.</span>
        <span class="<?php echo $isWhitelisted ? 'flag-yes':'flag-no'; ?>"><?php echo $isWhitelisted ? '✅' : '❌'; ?></span>
      </div>
      <div class="kv">
        <span>Your device is pinning a mTLS certificate.</span>
        <span class="<?php echo $usingMtls ? 'flag-yes':'flag-no'; ?>"><?php echo $usingMtls ? '✅' : '❌'; ?></span>
      </div>

      <div class="smallprint hint">
        <?php if ($mtlsDetected): ?>
          mTLS <b>detected</b> via header <code>X-MTLS</code>=<code>on</code>.
        <?php elseif ($mtlsAssumed): ?>
          mTLS <b>assumed</b> because the client appears external, not on VPN, and not whitelisted.
        <?php else: ?>
          mTLS not detected on this path.
        <?php endif; ?>
        &nbsp;•&nbsp; VPN CIDR(s): <code><?php echo h(implode(', ', $vpnCidrs) ?: '—'); ?></code>
        &nbsp;•&nbsp; Lease API: <code><?php echo h($leaseUrl); ?></code>
      </div>

      <?php if ($isWhitelisted && $wlMatch): ?>
        <hr class="soft" />
        <div class="smallprint">
          Whitelist match:
          <?php if (!empty($wlMatch['label'])): ?> label <code><?php echo h((string)$wlMatch['label']); ?></code><?php endif; ?>
          <?php if (!empty($wlMatch['source'])): ?> • source <code><?php echo h((string)$wlMatch['source']); ?></code><?php endif; ?>
          <?php if (!empty($wlMatch['timestamp'])): ?> • since <code><?php echo h((string)$wlMatch['timestamp']); ?></code><?php endif; ?>
          <?php if (array_key_exists('static',$wlMatch) && $wlMatch['static']): ?> • <code>static</code><?php endif; ?>
        </div>
      <?php endif; ?>

      <?php if (!$wlOk): ?>
        <div class="smallprint" style="margin-top:8px;">
          Lease API lookup: <b>unavailable</b> (HTTP <?php echo (int)$wlHttp; ?><?php echo $wlErr ? ', ' . h($wlErr) : ''; ?>).
          Status shown without whitelist info.
        </div>
      <?php endif; ?>

    </div>
  </div>
</div>

<?php render_footer();
