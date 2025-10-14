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
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) foreach (explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']) as $p) $candidates[] = trim($p);
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
    if (strlen($ipBin) !== strlen($subBin)) return false;
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
    $spec = trim($spec);
    if ($spec === '') return [];
    $parts = preg_split('/[,\s;]+/', $spec, -1, PREG_SPLIT_NO_EMPTY);
    return array_values(array_unique(array_map('trim', $parts)));
}
function http_request(string $url, string $method='GET', ?string $body=null, array $headers=[]): array {
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 4,
        CURLOPT_USERAGENT      => 'LUM-ConnTest/1.2',
        CURLOPT_HEADER         => false,
    ];
    if ($method !== 'GET') {
        $opts[CURLOPT_CUSTOMREQUEST] = $method;
        if ($body !== null) $opts[CURLOPT_POSTFIELDS] = $body;
    }
    if ($headers) $opts[CURLOPT_HTTPHEADER] = $headers;
    curl_setopt_array($ch, $opts);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
    $err  = curl_error($ch);
    curl_close($ch);
    return [$code >= 200 && $code < 300, $code, $err, (string)$resp];
}
function current_host_url(): string {
    $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443');
    return ($https ? 'https://' : 'http://') . $host;
}

/* -------------------- inputs + detection -------------------- */
$format = strtolower((string)($_GET['format'] ?? 'html'));
if (!in_array($format, ['html','json','iframe'], true)) $format = 'html';
$showMenu = !in_array(strtolower((string)($_GET['render_menu'] ?? '1')), ['0','no','false'], true);

$clientIp = get_client_ip() ?: '0.0.0.0';
$isV4     = (bool)filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

/* LAN = any RFC1918 IPv4 + localhost */
$lanCidrs = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.1/32'];
$inLan    = $isV4 && ip_in_any_cidr($clientIp, $lanCidrs);

/* VPN CIDR(s) */
$vpnSpec  = getenv('VPN_CIDR') ?: '10.2.4.0/24';
$vpnCidrs = parse_cidr_list($vpnSpec);
$onVpn    = $isV4 && !empty($vpnCidrs) && ip_in_any_cidr($clientIp, $vpnCidrs);

/* mTLS header */
$mtlsHeader   = strtolower((string)($_SERVER['HTTP_X_MTLS'] ?? ''));
$usingMtls    = in_array($mtlsHeader, ['on','1','true'], true);

/* --- Lease API base: prefer env/lease_url; else default to APEX of current host (keep scheme) --- */
$hostNow = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
$labels  = explode('.', $hostNow);
$apex    = (count($labels) >= 3) ? implode('.', array_slice($labels, -3)) : $hostNow; // users.app.gg.no.re -> gg.no.re
$scheme  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443') ? 'https' : 'http';
$defaultApexBase = $scheme . '://' . $apex . '/endpoints/lease_ip.php';

$base = (string)($_GET['lease_url'] ?? (getenv('LEASE_API_BASE') ?: $defaultApexBase));

/* Build list URL: MUST be exactly one op (?list=1) */
$leaseUrl = (function($u){
    $q = parse_url($u, PHP_URL_QUERY);
    return ($q && preg_match('/(?:^|&)list=1(?:&|$)/', (string)$q))
        ? $u
        : $u . (strpos($u,'?')!==false ? '&' : '?') . 'list=1';
})($base);

/* -------- Resolve whitelist (list) -------- */
$isWhitelisted = false;
$wlMatch = null;
list($wlOk, $wlPayload, $wlHttp, $wlErr) = (function($url){
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_USERAGENT      => 'LUM-ConnTest/1.2',
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
})($leaseUrl);

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

/* ---- Inline Lease action (for iframe) ---- */
$allNo     = (!$inLan && !$onVpn && !$usingMtls && !$isWhitelisted);
$sourceTag = 'LUM Iframe';

/* ---- Same-origin proxy: must call GET ?add=<IP> with headers (no extra params!) ---- */
if (isset($_GET['do']) && $_GET['do'] === 'lease') {
    // EXACTLY one op key: add=<ip>
    $target = $base . (strpos($base,'?')!==false ? '&' : '?') . 'add=' . rawurlencode($clientIp);

    // Required headers for your endpoint
    $headers = [
        'Accept: application/json',
        'X-IP-Lease-Label: '  . $username,  // label
        'X-IP-Lease-Source: ' . $sourceTag, // source
        // optional helpers:
        'X-Forwarded-For: '   . $clientIp,
    ];

    [$ok, $code, $err, $body] = http_request($target, 'GET', null, $headers);
    error_log(sprintf('LUM-ConnTest: lease GET %s http=%d ok=%d', $target, (int)$code, $ok?1:0));

    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ok'     => $ok,
        'http'   => $code,
        'err'    => $ok ? null : $err,
        'target' => $target,
        'body'   => substr($body ?? '', 0, 256),
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

/* -------------------- render -------------------- */
if ($format === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'ok'        => true,
        'user'      => $username,
        'client_ip' => $clientIp,
        'flags'     => [
            'in_lan'               => $inLan,
            'on_vpn'               => $onVpn,
            'using_whitelisted_ip' => $isWhitelisted,
            'using_mtls'           => $usingMtls,
        ],
        'mtls' => [
            'header'   => $mtlsHeader ?: null,
            'detected' => $usingMtls,
        ],
        'lease_api' => [
            'url'   => $leaseUrl,
            'ok'    => $wlOk,
            'http'  => $wlHttp,
            'err'   => $wlOk ? null : $wlErr,
            'match' => $wlMatch,
        ],
        'vpn_cidrs' => $vpnCidrs,
        'ts' => date('Y-m-d H:i:s T'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
elseif ($format === 'iframe') {
    header('Content-Type: text/html; charset=utf-8');
    // Preserve resolved lease base for proxy
    $selfLeaseUrl = $_SERVER['PHP_SELF']
                  . '?format=iframe&do=lease&lease_url='
                  . rawurlencode($base);
    ?>
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
        :root { --fg:#0a0a0a; --muted:#6b7280; --card:#ffffff; --border:rgba(0,0,0,.08); }
        @media (prefers-color-scheme: dark) {
          :root { --fg:#e5e7eb; --muted:#94a3b8; --card:#0b0f13; --border:rgba(255,255,255,.08); }
        }
        *{box-sizing:border-box}
        body{margin:0; background:transparent; color:var(--fg); font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Arial}
        .micro{padding:10px 12px; border-radius:12px; background:var(--card); border:1px solid var(--border)}
        .row{display:flex; justify-content:space-between; align-items:center; padding:8px 0}
        .row+.row{border-top:1px solid var(--border)}
        .label{font-weight:600; letter-spacing:.2px}
        .yes{font-weight:700}
        .no{font-weight:700}
        .val{display:inline-flex; align-items:center; gap:8px;}
        .btn{display:inline-block; text-decoration:none; line-height:1; padding:8px 12px; border-radius:9px; font-weight:700; cursor:pointer; user-select:none; -webkit-tap-highlight-color:transparent;}
        @media (prefers-color-scheme: dark){
          .btn{ background:rgba(127,209,255,.18); color:#d6f1ff; border:1px solid rgba(127,209,255,.55); }
          .btn:hover,.btn:active{ background:rgba(127,209,255,.26); }
        }
        @media (prefers-color-scheme: light){
          .btn{ background:rgba(0,123,255,.14); color:#0b63c7; border:1px solid rgba(0,123,255,.50); }
          .btn:hover,.btn:active{ background:rgba(0,123,255,.22); }
        }
        .btn[aria-busy="true"]{opacity:.7; pointer-events:none}
      </style>
    </head>
    <body>
      <div class="micro">
        <div class="row"><span class="label">Inside LAN</span>
          <span class="<?php echo $inLan ? 'yes' : 'no'; ?>"><?php echo $inLan ? '✅' : '❌'; ?></span>
        </div>
        <div class="row"><span class="label">On VPN</span>
          <span class="<?php echo $onVpn ? 'yes' : 'no'; ?>"><?php echo $onVpn ? '✅' : '❌'; ?></span>
        </div>
        <div class="row"><span class="label">mTLS</span>
          <span class="<?php echo $usingMtls ? 'yes' : 'no'; ?>"><?php echo $usingMtls ? '✅' : '❌'; ?></span>
        </div>
        <div class="row">
          <span class="label">Leased IP</span>
          <span class="val">
            <?php if ($allNo && $isV4): ?>
              <a id="leaseBtn" class="btn" href="<?php echo h($selfLeaseUrl); ?>" role="button" aria-label="Lease this IP">Lease this IP</a>
            <?php endif; ?>
            <span class="<?php echo $isWhitelisted ? 'yes' : 'no'; ?>"><?php echo $isWhitelisted ? '✅' : '❌'; ?></span>
          </span>
        </div>
      </div>

      <?php if ($allNo && $isV4): ?>
      <script>
        (function(){
          var btn = document.getElementById('leaseBtn');
          if (!btn) return;
          var url = btn.getAttribute('href');
          btn.addEventListener('click', function(ev){
            ev.preventDefault();
            btn.setAttribute('aria-busy', 'true');
            btn.textContent = 'Leasing…';
            var finish = function(){ setTimeout(function(){ location.reload(); }, 800); };
            try {
              fetch(url, { credentials:'include' })
                .then(function(r){ return r.json().catch(function(){return {};}); })
                .then(function(j){
                  // If you want to inspect once, uncomment:
                  // console.log('lease proxy', j);
                })
                .catch(function(){ /* ignore */ })
                .finally(finish);
            } catch (_){ finish(); }
          });
        })();
      </script>
      <?php endif; ?>
    </body>
    </html>
    <?php
    exit;
}

render_header('Test Connection');

/* Hide the top menu/nav when render_menu=0 (useful for iframes) */
if (!$showMenu) {
    echo '<style>.navbar, .breadcrumb, .page-header{display:none!important;} body{padding-top:0!important;}</style>';
}
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

/* Readability for first-column labels */
.key { color:#e2f1ff; font-weight:700; letter-spacing:.2px; }
.badge-chip { display:inline-block; padding:2px 8px; border-radius:10px; font-family:monospace; font-size:.98em;
  background:#1a2b3a; color:#a9e1ff; border:1px solid rgba(127,209,255,.35); }

.smallprint { color:#8aa0b2; font-size:12px; }
.flag-yes { color:#10b981; font-weight:700; }
.flag-no  { color:#ef4444; font-weight:700; }
.kv { display:flex; justify-content:space-between; align-items:center; padding:10px 12px; border-radius:10px; }
.kv + .kv { margin-top:8px; }
.hint { margin-top:10px; }
hr.soft { border:0; border-top:1px solid rgba(255,255,255,.08); margin:12px 0; }

/* Mobile tweaks: larger label text & spacing */
@media (max-width: 768px) {
  .panel-modern .panel-body { padding:12px; }
  .table-modern>tbody>tr>td { padding:10px 8px; }
  .key { font-size:14px; }
  .badge-chip { font-size:1.05em; }
}
</style>

<div class="container conn-wrap">

  <div class="panel panel-modern">
    <div class="panel-heading text-center">CONNECTION CHECK</div>
    <div class="panel-body">
      <div class="table-responsive">
        <table class="table table-modern">
          <tbody>
          <tr>
            <td class="key">Signed in as</td>
            <td><span class="badge-chip"><?php echo h($username); ?></span></td>
          </tr>
          <tr>
            <td class="key">Detected client IP</td>
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
        <span>Your device is using a Leased IP.</span>
        <span class="<?php echo $isWhitelisted ? 'flag-yes':'flag-no'; ?>"><?php echo $isWhitelisted ? '✅' : '❌'; ?></span>
      </div>
      <div class="kv">
        <span>Your device is pinning a mTLS certificate.</span>
        <span class="<?php echo $usingMtls ? 'flag-yes':'flag-no'; ?>"><?php echo $usingMtls ? '✅' : '❌'; ?></span>
      </div>

      <!-- Hint line: simplified for non-admins; detailed for admins -->
      <div class="smallprint hint">
        <?php if ($usingMtls): ?>
          mTLS <b>detected</b> via header <code>X-MTLS</code>=<code>on</code>.
        <?php else: ?>
          mTLS not detected on this path.
        <?php endif; ?>
        <?php if ($isAdmin): ?>
          &nbsp;•&nbsp; VPN CIDR(s): <code><?php echo h(implode(', ', $vpnCidrs) ?: '—'); ?></code>
          &nbsp;•&nbsp; Lease API: <code><?php echo h($leaseUrl); ?></code>
        <?php endif; ?>
      </div>

      <?php if ($isAdmin && $isWhitelisted && $wlMatch): ?>
        <hr class="soft" />
        <div class="smallprint">
          Lease match:
          <?php if (!empty($wlMatch['label'])): ?> label <code><?php echo h((string)$wlMatch['label']); ?></code><?php endif; ?>
          <?php if (!empty($wlMatch['source'])): ?> • source <code><?php echo h((string)$wlMatch['source']); ?></code><?php endif; ?>
          <?php if (!empty($wlMatch['timestamp'])): ?> • since <code><?php echo h((string)$wlMatch['timestamp']); ?></code><?php endif; ?>
          <?php if (array_key_exists('static',$wlMatch) && $wlMatch['static']): ?> • <code>static</code><?php endif; ?>
        </div>
      <?php endif; ?>

      <?php if ($isAdmin && !$wlOk): ?>
        <div class="smallprint" style="margin-top:8px;">
          Lease API lookup: <b>unavailable</b> (HTTP <?php echo (int)$wlHttp; ?><?php echo $wlErr ? ', ' . h($wlErr) : ''; ?>).
          Status shown without whitelist info.
        </div>
      <?php endif; ?>

    </div>
  </div>
</div>

<?php render_footer();