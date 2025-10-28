<?php
declare(strict_types=1);
/*
  LUM Connection Tester (drop-in)
  - Base AllowedIPs from env WG_ALLOWEDIPS
  - External/WAN IPv4 autodetect (env override WG_EXTERNAL_IPV4), cached 15m in /tmp/lum_public_ipv4.json
*/
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
function is_public_ipv4(string $ip): bool {
    return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}
function curl_quick_text(string $url, int $connectTO=2, int $totalTO=3): ?string {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => $connectTO,
        CURLOPT_TIMEOUT        => $totalTO,
        CURLOPT_USERAGENT      => 'LUM-ConnTest/1.2',
        CURLOPT_HEADER         => false,
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE) ?: 0;
    curl_close($ch);
    if ($resp === false || $code < 200 || $code >= 300) return null;
    return (string)$resp;
}
function detect_public_ipv4(?string $hostForDns = null): ?string {
    foreach (['WG_EXTERNAL_IPV4','PUBLIC_IPV4','SERVER_PUBLIC_IP'] as $k) {
        $v = getenv($k);
        if ($v && is_public_ipv4($v)) return $v;
    }
    $cacheFile = '/tmp/lum_public_ipv4.json';
    $now = time();
    if (is_readable($cacheFile)) {
        $raw = @file_get_contents($cacheFile);
        if ($raw) {
            $j = @json_decode($raw, true);
            if (is_array($j) && !empty($j['ip']) && !empty($j['ts']) && ($now - (int)$j['ts'] < 900)) {
                if (is_public_ipv4($j['ip'])) return $j['ip'];
            }
        }
    }
    $candidates = [];
    $t = curl_quick_text('https://1.1.1.1/cdn-cgi/trace');
    if ($t && preg_match('/^ip=([0-9.]+)$/m', $t, $m) && is_public_ipv4($m[1])) $candidates[] = $m[1];
    $r = curl_quick_text('https://api.ipify.org'); if ($r && is_public_ipv4(trim($r))) $candidates[] = trim($r);
    $r = curl_quick_text('https://ipv4.icanhazip.com'); if ($r && is_public_ipv4(trim($r))) $candidates[] = trim($r);
    $r = curl_quick_text('https://ifconfig.me/ip'); if ($r && is_public_ipv4(trim($r))) $candidates[] = trim($r);
    if ($hostForDns) { $a = @gethostbyname($hostForDns); if ($a && $a !== $hostForDns && is_public_ipv4($a)) $candidates[] = $a; }
    $ip = $candidates[0] ?? null;
    if ($ip) @file_put_contents($cacheFile, json_encode(['ip'=>$ip, 'ts'=>$now]));
    return $ip ?: null;
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
function parse_filter_keys(string $spec): array {
    $spec = strtolower(trim($spec));
    if ($spec === '') return [];
    $out = [];
    foreach (preg_split('/[,\s;]+/', $spec, -1, PREG_SPLIT_NO_EMPTY) as $p) {
        $p = trim($p);
        if (in_array($p, ['lan','vpn','mtls','leased'], true)) $out[$p] = true;
    }
    return $out;
}

/* -------------------- inputs + detection -------------------- */
$format = strtolower((string)($_GET['format'] ?? 'html'));
if (!in_array($format, ['html','json','iframe'], true)) $format = 'html';
$showMenu = !in_array(strtolower((string)($_GET['render_menu'] ?? '1')), ['0','no','false'], true);

$clientIp = get_client_ip() ?: '0.0.0.0';
$isV4     = (bool)filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

$lanCidrs = ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.1/32'];
$inLan    = $isV4 && ip_in_any_cidr($clientIp, $lanCidrs);

$vpnSpec  = getenv('VPN_CIDR') ?: '10.2.4.0/24';
$vpnCidrs = parse_cidr_list($vpnSpec);
$onVpn    = $isV4 && !empty($vpnCidrs) && ip_in_any_cidr($clientIp, $vpnCidrs);

$mtlsHeader   = strtolower((string)($_SERVER['HTTP_X_MTLS'] ?? ''));
$usingMtls    = in_array($mtlsHeader, ['on','1','true'], true);

$hostNow = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'localhost');
$labels  = explode('.', $hostNow);
$apex    = (count($labels) >= 3) ? implode('.', array_slice($labels, -3)) : $hostNow;
$scheme  = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['SERVER_PORT'] ?? '') === '443') ? 'https' : 'http';
$defaultApexBase = $scheme . '://' . $apex . '/endpoints/lease_ip.php';

$base = (string)($_GET['lease_url'] ?? (getenv('LEASE_API_BASE') ?: $defaultApexBase));

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

$allNo     = (!$inLan && !$onVpn && !$usingMtls && !$isWhitelisted);
$sourceTag = 'LUM Iframe';

/* -------- AllowedIPs base + external -------- */
$wgBaseSpec = getenv('WG_ALLOWEDIPS')
  ?: '10.2.4.1/32, 10.2.4.2/32, 10.2.10.10/32, 10.2.10.20/32';
$wgBaseList = parse_cidr_list($wgBaseSpec);

$extIPv4   = detect_public_ipv4($hostNow);
$extCIDR   = $extIPv4 ? ($extIPv4 . '/32') : null;

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
        'mtls' => ['header'=>$mtlsHeader ?: null, 'detected'=>$usingMtls],
        'lease_api' => ['url'=>$leaseUrl, 'ok'=>$wlOk, 'http'=>$wlHttp, 'err'=>$wlOk?null:$wlErr, 'match'=>$wlMatch],
        'vpn_cidrs' => $vpnCidrs,
        'allowedips_base' => $wgBaseList,
        'external_ipv4'   => $extIPv4,
        'ts' => date('Y-m-d H:i:s T'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}
elseif ($format === 'iframe') {
    $filterKeys     = parse_filter_keys((string)($_GET['filter'] ?? ''));
    $showLanRow     = empty($filterKeys) || isset($filterKeys['lan']);
    $showVpnRow     = empty($filterKeys) || isset($filterKeys['vpn']);
    $showMtlsRow    = empty($filterKeys) || isset($filterKeys['mtls']);
    $showLeasedRow  = empty($filterKeys) || isset($filterKeys['leased']);

    $flagsRendered = 0; $flagsNo = 0;
    if ($showLanRow)    { $flagsRendered++; if (!$inLan)         $flagsNo++; }
    if ($showVpnRow)    { $flagsRendered++; if (!$onVpn)         $flagsNo++; }
    if ($showMtlsRow)   { $flagsRendered++; if (!$usingMtls)     $flagsNo++; }
    if ($showLeasedRow) { $flagsRendered++; if (!$isWhitelisted) $flagsNo++; }
    $allRenderedNo = ($flagsRendered > 0 && $flagsRendered === $flagsNo);

    header('Content-Type: text/html; charset=utf-8');
    $selfLeaseUrl = $_SERVER['PHP_SELF'] . '?format=iframe&do=lease&lease_url=' . rawurlencode($base);

    // Prebuild compact HTML chunks
    $baseHtml = implode(', ', array_map(fn($c)=>'<code>'.h($c).'</code>', $wgBaseList));
    $appendHtml = $extCIDR ? ', <code><u>'.h($extCIDR).'</u></code>' : ', <code><u>x.x.x.x/32</u></code>';
    $wanHtml = $extIPv4 ? '<code>'.h($extIPv4).'</code>' : '<em>unknown</em>';
    ?>
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
        :root { --fg:#e5e7eb; --card:#0b0f13; --border:rgba(255,255,255,.08); --glow:rgba(127,209,255,.35); --line:rgba(127,209,255,.45); }
        @media (prefers-color-scheme: light) { :root { --fg:#0a0a0a; --card:#ffffff; --border:rgba(0,0,0,.08); --glow:rgba(0,123,255,.25); --line:rgba(0,123,255,.45);} }
        *{box-sizing:border-box}
        body{margin:0; background:transparent; color:var(--fg); font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Arial}
        .micro{padding:10px 12px; border-radius:12px; background:var(--card); border:1px solid var(--border); overflow:visible;}
        .row{display:flex; justify-content:space-between; align-items:center; padding:8px 0}
        .row+.row{border-top:1px solid var(--border)}
        .label{font-weight:600; letter-spacing:.2px; display:inline-flex; align-items:center; gap:6px;}
        .yes,.no{font-weight:700}
        .val{display:inline-flex; align-items:center; gap:6px;}
        .btn{display:inline-block; text-decoration:none; line-height:1; padding:8px 12px; border-radius:9px; font-weight:700; cursor:pointer; user-select:none; -webkit-tap-highlight-color:transparent;}
        .btn{ background:rgba(127,209,255,.18); color:#d6f1ff; border:1px solid var(--line); }
        .btn[aria-busy="true"]{opacity:.7; pointer-events:none}
        .tip{
          position:relative; display:inline-flex; align-items:center; justify-content:center;
          min-width:16px; height:16px; border-radius:50%; font-size:11px; line-height:1; font-weight:800;
          background: radial-gradient(circle at 30% 30%, rgba(127,209,255,.22), rgba(127,209,255,.06) 60%), rgba(15,20,28,.72);
          color:#d6f1ff; border:1px solid var(--line);
          box-shadow: 0 0 6px var(--glow), inset 0 0 6px rgba(127,209,255,.15);
          cursor:pointer; outline:none; user-select:none; touch-action:manipulation;
        }
        .mini{min-width:14px; height:14px; font-size:10px; margin-left:4px;}
        #tipBubble, #tipArrow{ position:fixed; z-index:2147483646; }
        #tipBubble{
          max-width:min(90vw, 260px); padding:8px 9px; border-radius:10px;
          background: rgba(11,15,19,.98); color:#cfe9ff; border:1px solid var(--line);
          box-shadow: 0 10px 22px var(--glow), 0 0 12px rgba(0,180,255,.16);
          font-size:12px; letter-spacing:.2px; white-space:normal; text-align:left;
        }
        #tipArrow{ width:0; height:0; filter: drop-shadow(0 0 4px var(--glow)); }
        .hidden{ display:none !important; }
      </style>
    </head>
    <body>
      <div class="micro">
        <?php if ($showLanRow): ?>
        <div class="row">
          <span class="label">
            Inside LAN
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if your client IP is private (RFC1918: 10/8, 172.16–31/12, 192.168/16) or localhost.'); ?>">i</span>
          </span>
          <span class="<?php echo $inLan ? 'yes' : 'no'; ?>"><?php echo $inLan ? '✅' : '❌'; ?></span>
        </div>
        <?php endif; ?>

        <?php if ($showVpnRow): ?>
        <div class="row">
          <span class="label">
            On VPN
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if your client IP is within VPN_CIDR range(s).'); ?>">i</span>
          </span>
          <span class="val">
            <span class="<?php echo $onVpn ? 'yes' : 'no'; ?>"><?php echo $onVpn ? '✅' : '❌'; ?></span>
            <?php if (!$onVpn && $allRenderedNo): ?>
              <!-- Inline mini help next to the status icon -->
              <button type="button" class="tip mini" aria-label="Fix VPN" data-tip-template="vpnHelpTpl">?</button>
              <template id="vpnHelpTpl">
                <div>
                  <b>Fix “On VPN” = ❌</b><br/>
                  AllowedIPs → <?php echo $baseHtml; ?><?php echo $appendHtml; ?><br/>
                  WAN: <?php echo $wanHtml; ?>
                </div>
              </template>
            <?php endif; ?>
          </span>
        </div>
        <?php endif; ?>

        <?php if ($showMtlsRow): ?>
        <div class="row">
          <span class="label">
            mTLS
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if the reverse proxy verified a client certificate (X-MTLS: on).'); ?>">i</span>
          </span>
          <span class="<?php echo $usingMtls ? 'yes' : 'no'; ?>"><?php echo $usingMtls ? '✅' : '❌'; ?></span>
        </div>
        <?php endif; ?>

        <?php if ($showLeasedRow): ?>
        <div class="row">
          <span class="label">
            Leased IP
            <span class="tip" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false"
              data-tip="<?php echo h('True if your current IP is on the Lease IP allowlist.'); ?>">i</span>
          </span>
          <span class="val">
            <?php if ($allNo && $isV4): ?>
              <a id="leaseBtn" class="btn" href="<?php echo h($selfLeaseUrl); ?>" role="button" aria-label="Lease this IP">Lease this IP</a>
            <?php endif; ?>
            <span class="<?php echo $isWhitelisted ? 'yes' : 'no'; ?>"><?php echo $isWhitelisted ? '✅' : '❌'; ?></span>
          </span>
        </div>
        <?php endif; ?>
      </div>

      <?php if ($allNo && $isV4 && $showLeasedRow): ?>
      <script>
        (function(){
          var btn = document.getElementById('leaseBtn'); if (!btn) return;
          var url = btn.getAttribute('href');
          btn.addEventListener('click', function(ev){
            ev.preventDefault(); btn.setAttribute('aria-busy','true'); btn.textContent='Leasing…';
            var finish = function(){ setTimeout(function(){ location.reload(); }, 800); };
            try { fetch(url,{credentials:'include'}).finally(finish); } catch(_){ finish(); }
          });
        })();
      </script>
      <?php endif; ?>

      <div id="tipBubble" class="hidden" role="dialog" aria-live="polite"></div>
      <div id="tipArrow"  class="hidden" aria-hidden="true"></div>

      <script>
        (function(){
          var openEl=null, bubble=document.getElementById('tipBubble'), arrow=document.getElementById('tipArrow');
          var margin=8, gap=8, aSize=7, hoverTO=null;
          function clamp(v,min,max){ return Math.max(min,Math.min(max,v)); }
          function place(el){
            var r=el.getBoundingClientRect(), vw=Math.max(document.documentElement.clientWidth,window.innerWidth||0);
            var vh=Math.max(document.documentElement.clientHeight,window.innerHeight||0);
            var html='', tplId=el.getAttribute('data-tip-template');
            if (tplId){ var tpl=document.getElementById(tplId); html=tpl?tpl.innerHTML:''; }
            else if (el.hasAttribute('data-tip-html')){ html=el.getAttribute('data-tip-html')||''; }
            if (html) bubble.innerHTML=html; else bubble.textContent=el.getAttribute('data-tip')||'';
            bubble.classList.remove('hidden'); arrow.classList.remove('hidden');
            var bw=bubble.offsetWidth, bh=bubble.offsetHeight, cx=r.left+r.width/2;
            var top=r.top-gap-bh, placeTop=true; if (top<margin){ top=r.bottom+gap; placeTop=false; }
            var left=clamp(cx-bw/2, margin, vw-bw-margin);
            bubble.style.top=Math.round(top)+'px'; bubble.style.left=Math.round(left)+'px';
            var ax=clamp(cx, left+aSize+2, left+bw-aSize-2);
            if (placeTop){ arrow.style.borderLeft=aSize+'px solid transparent'; arrow.style.borderRight=aSize+'px solid transparent';
              arrow.style.borderBottom='0'; arrow.style.borderTop=aSize+'px solid var(--line)';
              arrow.style.top=Math.round(top+bh)+'px'; arrow.style.left=Math.round(ax-aSize)+'px'; }
            else { arrow.style.borderLeft=aSize+'px solid transparent'; arrow.style.borderRight=aSize+'px solid transparent';
              arrow.style.borderTop='0'; arrow.style.borderBottom=aSize+'px solid var(--line)';
              arrow.style.top=Math.round(top-aSize)+'px'; arrow.style.left=Math.round(ax-aSize)+'px'; }
            el.setAttribute('aria-expanded','true');
          }
          function close(){ if(!openEl) return; openEl.setAttribute('aria-expanded','false'); openEl=null; bubble.classList.add('hidden'); arrow.classList.add('hidden'); }
          function open(el){ if (openEl===el){ close(); } else { openEl=el; place(el); } }
          function handleOpen(ev){
            var tip=ev.target.closest('.tip'); if(!tip){ var label=ev.target.closest('.label'); if(label) tip=label.querySelector('.tip'); }
            if (tip){ ev.preventDefault(); open(tip); } else { close(); }
          }
          document.addEventListener('pointerup', handleOpen, {passive:false});
          document.addEventListener('touchend',  handleOpen, {passive:false});
          document.addEventListener('click',     handleOpen, {passive:false});
          document.addEventListener('mouseover', function(ev){ var t=ev.target.closest('.tip'); if(!t) return; clearTimeout(hoverTO); open(t); });
          document.addEventListener('mouseout',  function(ev){ if (ev.target && ev.target.closest && ev.target.closest('.tip')) hoverTO=setTimeout(close,120); });
          document.addEventListener('keydown',   function(ev){ if(ev.key==='Escape') close(); if((ev.key==='Enter'||ev.key===' ')&&document.activeElement&&document.activeElement.classList&&document.activeElement.classList.contains('tip')){ ev.preventDefault(); open(document.activeElement); } });
          window.addEventListener('resize', function(){ if(openEl) place(openEl); });
          window.addEventListener('scroll', function(){ if(openEl) place(openEl); }, {passive:true});
          window.addEventListener('blur', close);
        })();
      </script>
    </body>
    </html>
    <?php
    exit;
}

render_header('Test Connection');

if (!$showMenu) {
    echo '<style>.navbar, .breadcrumb, .page-header{display:none!important;} body{padding-top:0!important;}</style>';
}
?>
<style>
/* ---------- Desktop page chrome (unchanged) ---------- */
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
.table-modern>thead>tr>th { color:#9fb6c9; font-size:12px; text-transform:uppercase; letter-spacing:.35px; border-bottom-width:1px; }
.table-modern.table-striped>tbody>tr:nth-of-type(odd)  { background: rgba(255,255,255,.03); }
.table-modern.table-striped>tbody>tr:nth-of-type(even) { background: rgba(255,255,255,.015); }
.table-modern>tbody>tr:hover td { background: rgba(255,255,255,.06); }
.key { color:#e2f1ff; font-weight:700; letter-spacing:.2px; }
.badge-chip { display:inline-block; padding:2px 8px; border-radius:10px; font-family:monospace; font-size:.98em; background:#1a2b3a; color:#a9e1ff; border:1px solid rgba(127,209,255,.35); }
.smallprint { color:#8aa0b2; font-size:12px; }
.flag-yes { color:#10b981; font-weight:700; }
.flag-no  { color:#ef4444; font-weight:700; }
.kv { display:flex; justify-content:space-between; align-items:center; padding:10px 12px; border-radius:10px; }
.kv + .kv { margin-top:8px; }
hr.soft { border:0; border-top:1px solid rgba(255,255,255,.08); margin:12px 0; }
@media (max-width: 768px) { .panel-modern .panel-body { padding:12px; } .table-modern>tbody>tr>td { padding:10px 8px; } .key { font-size:14px; } .badge-chip { font-size:1.05em; } }
</style>

<div class="container conn-wrap">
  <div class="panel panel-modern">
    <div class="panel-heading text-center">CONNECTION CHECK</div>
    <div class="panel-body">
      <div class="table-responsive">
        <table class="table table-modern">
          <tbody>
          <tr><td class="key">Signed in as</td><td><span class="badge-chip"><?php echo h($username); ?></span></td></tr>
          <tr><td class="key">Detected client IP</td><td><span class="badge-chip"><?php echo h($clientIp); ?></span></td></tr>
          </tbody>
        </table>
      </div>

      <hr class="soft" />

      <div class="kv"><span>Your device is inside the LAN (RFC1918).</span><span class="<?php echo $inLan ? 'flag-yes':'flag-no'; ?>"><?php echo $inLan ? '✅' : '❌'; ?></span></div>
      <div class="kv"><span>Your device is on the VPN.</span><span class="<?php echo $onVpn ? 'flag-yes':'flag-no'; ?>"><?php echo $onVpn ? '✅' : '❌'; ?></span></div>
      <div class="kv"><span>Your device is using a Leased IP.</span><span class="<?php echo $isWhitelisted ? 'flag-yes':'flag-no'; ?>"><?php echo $isWhitelisted ? '✅' : '❌'; ?></span></div>
      <div class="kv"><span>Your device is pinning a mTLS certificate.</span><span class="<?php echo $usingMtls ? 'flag-yes':'flag-no'; ?>"><?php echo $usingMtls ? '✅' : '❌'; ?></span></div>

      <div class="smallprint">
        <?php if ($usingMtls): ?>mTLS <b>detected</b> via header <code>X-MTLS</code>=<code>on</code>.<?php else: ?>mTLS not detected on this path.<?php endif; ?>
        <?php if ($isAdmin): ?>
          &nbsp;•&nbsp; VPN CIDR(s): <code><?php echo h(implode(', ', $vpnCidrs) ?: '—'); ?></code>
          &nbsp;•&nbsp; Lease API: <code><?php echo h($leaseUrl); ?></code>
          &nbsp;•&nbsp; Ext IPv4: <code><?php echo h($extIPv4 ?: 'n/a'); ?></code>
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
