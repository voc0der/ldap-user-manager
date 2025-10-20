(function () {
  const clientIp = window.LEASE_IP?.clientIp || null;
  const isAdmin  = !!window.LEASE_IP?.isAdmin;
  const API      = '/lease_ip/api.php';

  // === Generic fetch helper (existing pattern) =================================
  const callOne = async (name, value, extraHeaders) => {
    const url = API + '?' + encodeURIComponent(name) + '=' + encodeURIComponent(value ?? '');
    const res = await fetch(url, {
      credentials: 'include',
      headers: Object.assign({ 'Cache-Control': 'no-store' }, (extraHeaders || {})),
    });
    let data;
    try { data = await res.json(); } catch { data = { ok: false, error: 'Invalid JSON from API' }; }
    if (!res.ok || data.ok === false) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  };

  // === Small utils =============================================================
  const nowMs = () => Date.now();

  const getTimestampMs = (ent) => {
    if (ent.ts !== undefined && ent.ts !== null) {
      const n = Number(ent.ts);
      if (Number.isFinite(n)) {
        return (n > 2e12 ? n : (n > 2e9 ? n : n * 1000));
      }
      const d1 = Date.parse(ent.ts);
      if (!Number.isNaN(d1)) return d1;
    }
    if (ent.timestamp) {
      const d2 = Date.parse(ent.timestamp);
      if (!Number.isNaN(d2)) return d2;
    }
    return NaN;
  };

  const fmtRemaining = (ms) => {
    if (!Number.isFinite(ms)) return '—';
    if (ms <= 0) return 'expired';
    const totalMin = Math.floor(ms / 60000);
    const d = Math.floor(totalMin / 1440);
    const h = Math.floor((totalMin - d * 1440) / 60);
    const m = totalMin - d * 1440 - h * 60;
    let out = '';
    if (d) out += d + 'd ';
    if (h || d) out += h + 'h ';
    out += m + 'm';
    return out.trim();
  };

  // === Cyberpunk Geo Popover (admin-only attach, safe no-op for users) =========
  const GeoUI = (() => {
    // Config
    const FRONT_TTL_MS = 600_000;   // 10 min (matches server cache)
    const HOVER_DELAY  = 220;       // ms before opening on hover
    const CLOSE_DELAY  = 180;       // ms after mouse leaves to close (if not pinned)

    // State
    const cache = new Map(); // ip -> { t:number, data:object } or { pending:Promise }
    let styleInjected = false;
    let popEl = null;
    let arrowEl = null;
    let pinned = false;
    let hoverTimer = null;
    let closeTimer = null;
    let currentAnchor = null;
    let currentIp = '';

    // Utilities
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => (
      { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]
    ));

    const injectStyle = () => {
      if (styleInjected) return;
      styleInjected = true;
      const css = `
#lum-geo-pop {
  position: fixed; z-index: 99999; min-width: 280px; max-width: 520px;
  background: radial-gradient(120% 140% at 0% 0%, rgba(42,139,220,0.25), rgba(18,24,32,0.96));
  backdrop-filter: blur(2px);
  border: 1px solid rgba(127,209,255,0.35);
  box-shadow: 0 0 24px rgba(42,139,220,0.35), inset 0 0 20px rgba(255,255,255,0.04);
  border-radius: 14px; padding: 10px 12px 12px 12px; color: #cfe9ff;
}
#lum-geo-pop .cg-head {
  display:flex; align-items:center; gap:8px; margin-bottom:6px;
  text-transform:uppercase; letter-spacing: .45px; font-size: 12px; color:#9fd1ff;
}
#lum-geo-pop .cg-ip { font-family: monospace; background:#102030; padding:2px 6px; border-radius: 8px; border:1px solid rgba(127,209,255,.35); color:#a9e1ff; }
#lum-geo-pop .cg-grid {
  display:grid; grid-template-columns: 128px 1fr; gap:6px 12px; font-size: 12.5px;
}
#lum-geo-pop .cg-key { color:#9fb6c9; text-transform:uppercase; letter-spacing:.3px; }
#lum-geo-pop .cg-val { color:#e5f4ff; overflow-wrap:anywhere; }
#lum-geo-pop .cg-bad { color:#ffb3b3; }
#lum-geo-pop .cg-warn { color:#ffdf9a; }
#lum-geo-pop .cg-flags { display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; }
#lum-geo-pop .chip {
  font-size: 11px; border-radius: 999px; padding:2px 8px; border:1px solid rgba(255,255,255,.18);
  background: rgba(255,255,255,.04); color:#bfe9ff;
}
#lum-geo-pop .chip.negative { background: rgba(255,80,80,.12); border-color: rgba(255,80,80,.35); color:#ffdcdc; }
#lum-geo-pop .chip.warn { background: rgba(255,200,60,.10); border-color: rgba(255,200,60,.35); color:#fff0cc; }
#lum-geo-pop .cg-foot { margin-top:8px; display:flex; gap:8px; justify-content:flex-end; }
#lum-geo-pop .btn-mini {
  font-size: 11px; padding: 4px 8px; border-radius: 10px; background:#121820; color:#cfe9ff;
  border:1px solid rgba(255,255,255,.12); cursor:pointer;
}
#lum-geo-pop .btn-mini:hover { background:#17202b; }
.lum-ip-geo {
  cursor: help; border-bottom: 1px dotted rgba(127,209,255,.65); color:#a9e1ff; text-decoration:none;
}
.lum-ip-geo:hover { color:#e9f7ff; }
#lum-geo-arrow {
  position: fixed; width: 0; height: 0; border: 8px solid transparent; z-index: 99998;
  border-right-color: rgba(127,209,255,0.35);
}
@media (max-width: 480px) {
  #lum-geo-pop { max-width: 90vw; }
  #lum-geo-pop .cg-grid { grid-template-columns: 100px 1fr; }
}`;
      const style = document.createElement('style');
      style.id = 'lum-geo-style';
      style.textContent = css;
      document.head.appendChild(style);
    };

    const ensureElems = () => {
      if (popEl && arrowEl) return;
      popEl = document.createElement('div');
      popEl.id = 'lum-geo-pop';
      popEl.style.display = 'none';
      arrowEl = document.createElement('div');
      arrowEl.id = 'lum-geo-arrow';
      arrowEl.style.display = 'none';
      document.body.appendChild(popEl);
      document.body.appendChild(arrowEl);

      // Global close handlers
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') hide(true);
      });
      document.addEventListener('click', (e) => {
        if (!pinned) return;
        if (popEl && !popEl.contains(e.target) && currentAnchor && !currentAnchor.contains(e.target)) {
          hide(true);
        }
      });
      window.addEventListener('scroll', () => pinned ? positionTo(currentAnchor) : hide(false), true);
      window.addEventListener('resize', () => pinned ? positionTo(currentAnchor) : hide(false));
    };

    const renderContent = (ip, payload) => {
      const g = payload?.geo || {};
      if (g.status && g.status !== 'success') {
        popEl.innerHTML = `
          <div class="cg-head"><span class="cg-ip">${esc(ip)}</span><span class="cg-bad">lookup failed</span></div>
          <div class="cg-grid">
            <div class="cg-key">Message</div><div class="cg-val cg-bad">${esc(g.message || 'Unknown error')}</div>
          </div>
        `;
        return;
      }

      const locParts = [
        g.city, g.regionName, g.countryCode ? `${g.country} (${g.countryCode})` : g.country, g.zip
      ].filter(Boolean).join(' · ');
      const asn = (g.asname || g.as || '').toString();

      popEl.innerHTML = `
        <div class="cg-head">
          <span class="cg-ip">${esc(ip)}</span>
          ${payload.cached ? '<span class="chip">cached</span>' : ''}
        </div>
        <div class="cg-grid">
          <div class="cg-key">Location</div><div class="cg-val">${esc(locParts || '—')}</div>
          <div class="cg-key">ISP</div><div class="cg-val">${esc(g.isp || '—')}</div>
          <div class="cg-key">Org</div><div class="cg-val">${esc(g.org || '—')}</div>
          <div class="cg-key">ASN</div><div class="cg-val">${esc(asn || '—')}</div>
          <div class="cg-key">Timezone</div><div class="cg-val">${esc(g.timezone || '—')}</div>
          <div class="cg-key">Reverse</div><div class="cg-val">${esc(g.reverse || '—')}</div>
          <div class="cg-key">Coords</div><div class="cg-val">${(g.lat!=null&&g.lon!=null)? esc(g.lat+', '+g.lon) : '—'}</div>
        </div>
        <div class="cg-flags">
          ${g.proxy ? '<span class="chip negative">proxy</span>' : ''}
          ${g.hosting ? '<span class="chip warn">hosting/DC</span>' : ''}
          ${g.mobile ? '<span class="chip warn">mobile</span>' : ''}
          ${g.continent ? `<span class="chip">${esc(g.continentCode || '')} ${esc(g.continent)}</span>` : ''}
          ${g.country ? `<span class="chip">${esc(g.country)}</span>` : ''}
        </div>
        <div class="cg-foot">
          <button class="btn-mini" data-act="copy">Copy IP</button>
          <button class="btn-mini" data-act="unpin">Close</button>
        </div>
      `;

      // Footer actions
      const copyBtn = popEl.querySelector('[data-act="copy"]');
      const unpinBtn = popEl.querySelector('[data-act="unpin"]');
      copyBtn?.addEventListener('click', async (e) => {
        try { await navigator.clipboard.writeText(ip); copyBtn.textContent = 'Copied'; setTimeout(()=>copyBtn.textContent='Copy IP', 1200); } catch {}
      });
      unpinBtn?.addEventListener('click', () => hide(true));
    };

    const positionTo = (anchor) => {
      if (!anchor || !popEl) return;
      const r = anchor.getBoundingClientRect();
      const vw = window.innerWidth, vh = window.innerHeight;

      const pad = 10;
      let left = r.right + 10;
      let top  = r.top;

      // If not enough space on right, show above/below or to the left
      const preferredWidth = Math.min(popEl.offsetWidth || 420, 520);
      if (left + preferredWidth + 16 > vw) {
        // Try left
        left = Math.max(pad, r.left - (preferredWidth + 18));
        if (left < pad) left = Math.max(pad, vw - preferredWidth - pad);
      }
      if (top + (popEl.offsetHeight || 240) + 16 > vh) {
        top = Math.max(pad, vh - (popEl.offsetHeight || 240) - pad);
      }

      popEl.style.left = Math.round(left) + 'px';
      popEl.style.top  = Math.round(top)  + 'px';

      // Arrow
      const ar = 8;
      arrowEl.style.top  = Math.round(r.top + Math.min(r.height/2, Math.max(ar+2, (popEl.offsetHeight||0)/3))) + 'px';
      arrowEl.style.left = Math.round(Math.min(r.right + 2, left - ar)) + 'px';
    };

    const show = (anchor, ip, payloadPromise) => {
      clearTimeout(closeTimer);
      ensureElems();
      currentAnchor = anchor;
      currentIp = ip;
      injectStyle();

      popEl.style.display = 'block';
      arrowEl.style.display = 'block';
      positionTo(anchor);

      payloadPromise.then((payload) => {
        // Still same anchor/ip?
        if (anchor !== currentAnchor || ip !== currentIp) return;
        renderContent(ip, payload);
        positionTo(anchor);
      }).catch((err) => {
        if (anchor !== currentAnchor || ip !== currentIp) return;
        popEl.innerHTML = `
          <div class="cg-head"><span class="cg-ip">${esc(ip)}</span><span class="cg-bad">lookup failed</span></div>
          <div class="cg-grid"><div class="cg-key">Error</div><div class="cg-val cg-bad">${esc(err.message || 'Request error')}</div></div>`;
      });
    };

    const hide = (force) => {
      clearTimeout(closeTimer);
      if (force) pinned = false;
      if (pinned) return;
      if (popEl) popEl.style.display = 'none';
      if (arrowEl) arrowEl.style.display = 'none';
      currentAnchor = null;
      currentIp = '';
    };

    const callGeo = async (ip) => {
      const hit = cache.get(ip);
      const now = nowMs();
      if (hit && hit.data && (now - hit.t < FRONT_TTL_MS)) {
        return hit.data;
      }
      if (hit && hit.pending) return hit.pending;

      const pending = fetch(API + '?geo=' + encodeURIComponent(ip), {
        credentials: 'include',
        headers: { 'Cache-Control': 'no-store' },
      })
        .then(async (res) => {
          let j;
          try { j = await res.json(); } catch { j = { ok:false, error:'Invalid JSON' }; }
          if (!res.ok || j.ok === false) throw new Error(j.error || ('HTTP ' + res.status));
          const payload = { cached: !!j.cached, geo: j.geo || {} };
          cache.set(ip, { t: now, data: payload });
          return payload;
        })
        .finally(() => {
          const h = cache.get(ip);
          if (h && h.pending) cache.delete(ip); // clean pending marker; data write happens in then()
        });

      cache.set(ip, { pending });
      return pending;
    };

    const attach = (el, ip) => {
      if (!el || !ip) return;

      // Styling for the anchor
      el.classList.add('lum-ip-geo');

      // Hover open (not pinned)
      el.addEventListener('mouseenter', () => {
        if (pinned) return;
        clearTimeout(hoverTimer);
        hoverTimer = setTimeout(() => show(el, ip, callGeo(ip)), HOVER_DELAY);
      });

      // Hover leave -> schedule close
      el.addEventListener('mouseleave', () => {
        if (pinned) return;
        clearTimeout(hoverTimer);
        closeTimer = setTimeout(() => hide(false), CLOSE_DELAY);
      });

      // Click -> pin/unpin
      el.addEventListener('click', (e) => {
        e.preventDefault();
        if (pinned && currentAnchor === el) {
          hide(true);
          return;
        }
        pinned = true;
        show(el, ip, callGeo(ip));
      });
    };

    return { attach, hide };
  })();

  // === User quick actions (unchanged) ==========================================
  const userStatus = document.getElementById('user-status');
  const btnAdd = document.getElementById('btn-add');
  const btnDel = document.getElementById('btn-del');
  const setBusy = (el, busy) => el && (el.disabled = !!busy);

  let refreshMine = null;
  let adminSoftRefresh = null;

  btnAdd?.addEventListener('click', async () => {
    setBusy(btnAdd, true);
    try {
      const r = await callOne('add', clientIp || '');
      userStatus.textContent = (r.result === 'exists') ? `Already present: ${r.ip}` : `Added: ${r.ip}`;
      if (typeof refreshMine === 'function') refreshMine({ force: true });
      if (typeof adminSoftRefresh === 'function') adminSoftRefresh({ force: true });
    } catch (e) {
      userStatus.textContent = 'Add failed: ' + e.message;
    } finally { setBusy(btnAdd, false); }
  });

  btnDel?.addEventListener('click', async () => {
    setBusy(btnDel, true);
    try {
      const r = await callOne('delete', clientIp || '');
      userStatus.textContent = (r.result === 'not_found') ? `Not present: ${r.ip}` : `Deleted: ${r.ip}`;
      if (typeof refreshMine === 'function') refreshMine({ force: true });
      if (typeof adminSoftRefresh === 'function') adminSoftRefresh({ force: true });
    } catch (e) {
      userStatus.textContent = 'Delete failed: ' + e.message;
    } finally { setBusy(btnDel, false); }
  });

  // === "MY LEASES" (non-admins) ===============================================
  (function initMyLeasesIfPresent() {
    const myTbody = document.getElementById('my-tbody');
    if (!myTbody) return;
    const myCount = document.getElementById('my-count');
    const myRefreshBtn = document.getElementById('my-refresh');
    const myStatus = document.getElementById('my-status');

    let myEtag = '';
    let myHash = '';
    let myPoll = null;

    const renderRows = (entries) => {
      myTbody.innerHTML = '';
      const ttlHrs = 96;
      const now = nowMs();
      for (const ent of entries) {
        const tr = document.createElement('tr');

        const tdUser = document.createElement('td');
        tdUser.textContent = ent.user || ent.label || ent.host || 'unknown';

        const tdSource = document.createElement('td');
        tdSource.textContent = (ent.source && String(ent.source).trim()) ? ent.source : '—';

        const tdTs = document.createElement('td');
        tdTs.textContent = ent.timestamp || '';

        const tdIp = document.createElement('td');
        // Show IP; for admins only we attach geo. For non-admin table we leave plain.
        tdIp.textContent = ent.ip || '';
        if (ent.static === true) tdIp.textContent += ' (static)';

        const tdExp = document.createElement('td');
        let expText = '—';
        let expTitle = '';
        if (ent.static === true) {
          expText = 'static';
        } else {
          const tsms = getTimestampMs(ent);
          if (Number.isFinite(tsms)) {
            const expAt = tsms + ttlHrs * 3600000;
            expText = fmtRemaining(expAt - now);
            expTitle = new Date(expAt).toLocaleString();
          }
        }
        tdExp.textContent = expText;
        if (expTitle) tdExp.title = expTitle;

        const tdAct = document.createElement('td');
        tdAct.className = 'text-right';

        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete';
        delBtn.className = 'btn btn-default btn-sm';
        delBtn.addEventListener('click', async () => {
          delBtn.disabled = true;
          try {
            await callOne('delete', ent.ip);
            await refreshMine({ force: true });
            myStatus.textContent = `Deleted ${ent.ip}`;
          } catch (e) {
            myStatus.textContent = 'Delete failed: ' + e.message;
          } finally { delBtn.disabled = false; }
        });

        const staticBtn = document.createElement('button');
        staticBtn.textContent = (ent.static === true) ? 'Unset Static' : 'Set Static';
        staticBtn.className = 'btn btn-default btn-sm';
        staticBtn.style.marginLeft = '0.5rem';
        staticBtn.addEventListener('click', async () => {
          staticBtn.disabled = true;
          try {
            const makeStatic = !(ent.static === true);
            await callOne('add', ent.ip, { 'X-LUM-Static': makeStatic ? '1' : '0' });
            await refreshMine({ force: true });
            myStatus.textContent = makeStatic ? `Marked static: ${ent.ip}` : `Unmarked static: ${ent.ip}`;
          } catch (e) {
            myStatus.textContent = 'Static toggle failed: ' + e.message;
          } finally {
            staticBtn.disabled = false;
          }
        });

        tdAct.appendChild(delBtn);
        tdAct.appendChild(staticBtn);

        tr.appendChild(tdUser);
        tr.appendChild(tdSource);
        tr.appendChild(tdTs);
        tr.appendChild(tdIp);
        tr.appendChild(tdExp);
        tr.appendChild(tdAct);
        myTbody.appendChild(tr);
      }
      myCount.textContent = String(entries.length);
    };

    const hashEntries = (entries) => {
      try { return JSON.stringify(entries); } catch { return String(entries?.length || 0); }
    };

    refreshMine = async function ({ force = false } = {}) {
      const headers = { 'Cache-Control': 'no-store' };
      if (!force && myEtag) headers['If-None-Match'] = myEtag;

      const res = await fetch(API + '?list=1', { credentials: 'include', headers });
      if (res.status === 304) {
        myStatus.textContent = `Up to date · ${new Date().toLocaleTimeString()}`;
        return;
      }
      if (!res.ok) { myStatus.textContent = `HTTP ${res.status}`; return; }

      let data;
      try { data = await res.json(); } catch { myStatus.textContent = 'Invalid JSON from API'; return; }
      if (data.ok === false) { myStatus.textContent = data.error || 'API error'; return; }

      const et = res.headers.get('ETag') || '';
      if (et) myEtag = et;

      const entries = (data.entries || []);
      const h = hashEntries(entries);
      if (force || h !== myHash) {
        renderRows(entries);
        myHash = h;
        myStatus.textContent = `Updated · ${new Date().toLocaleTimeString()}`;
      } else {
        myStatus.textContent = `No changes · ${new Date().toLocaleTimeString()}`;
      }
    };

    function startMyPoller() {
      if (myPoll) clearInterval(myPoll);
      myPoll = setInterval(() => refreshMine({ force: false }), document.hidden ? 60000 : 20000);
    }

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) refreshMine({ force: true });
    });
    myRefreshBtn?.addEventListener('click', () => refreshMine({ force: true }));

    refreshMine({ force: true });
    startMyPoller();
  })();

  // === Admin live list (adds GeoUI on IP cells) ================================
  (function initAdminIfPresent() {
    const tbody = document.getElementById('tbody');
    if (!tbody) return;

    const count = document.getElementById('count');
    const btnRefresh = document.getElementById('btn-refresh');
    const btnClear = document.getElementById('btn-clear');
    const btnPrune = document.getElementById('btn-prune');
    const pruneHours = document.getElementById('prune-hours');
    const adminStatus = document.getElementById('admin-status');
    const manualIp = document.getElementById('manual-ip');
    const manualStatic = document.getElementById('manual-static');
    const btnAddManual = document.getElementById('btn-add-manual');

    let currentEntries = [];
    let lastHash = '';
    let lastEtag = '';
    let pollTimer = null;
    let countdownTimer = null;
    let inFlight = null;
    let backoffMs = 0;

    const POLL_VISIBLE_MS = 15000;
    const POLL_HIDDEN_MS  = 60000;
    const COUNTDOWN_TICK_MS = 10000;

    const setStatus = (msg) => { adminStatus.textContent = msg || ''; };

    const renderRows = (entries) => {
      tbody.innerHTML = '';
      const ttlHrs = parseFloat(pruneHours?.value || '96');
      const now = nowMs();

      for (const ent of entries) {
        const tr = document.createElement('tr');

        const tdUser = document.createElement('td');
        tdUser.textContent = ent.user || ent.label || ent.host || 'unknown';

        const tdSource = document.createElement('td');
        tdSource.textContent = (ent.source && String(ent.source).trim()) ? ent.source : '—';

        const tdTs = document.createElement('td');
        tdTs.textContent = ent.timestamp || '';

        const tdIp = document.createElement('td');
        // Make the IP clickable with geo popup for admins
        if (ent.ip) {
          const ipSpan = document.createElement('a');
          ipSpan.href = '#';
          ipSpan.textContent = ent.ip + (ent.static === true ? ' (static)' : '');
          // Keep the "(static)" text but only attach geo on the IP part
          if (ent.static === true) {
            // Slightly better: split into two spans so the underline applies to the IP only
            const ipOnly = document.createElement('a');
            ipOnly.href = '#';
            ipOnly.textContent = ent.ip;
            ipOnly.style.marginRight = '4px';
            tdIp.appendChild(ipOnly);
            const st = document.createElement('span');
            st.textContent = '(static)';
            st.style.opacity = '0.8';
            st.style.marginLeft = '2px';
            if (isAdmin) GeoUI.attach(ipOnly, ent.ip);
          } else {
            tdIp.appendChild(ipSpan);
            if (isAdmin) GeoUI.attach(ipSpan, ent.ip);
          }
        } else {
          tdIp.textContent = '';
        }

        const tdExp = document.createElement('td');
        let expText = '—';
        let expTitle = '';
        if (ent.static === true) {
          expText = 'static';
        } else {
          const tsms = getTimestampMs(ent);
          if (Number.isFinite(tsms)) {
            const expAt = tsms + ttlHrs * 3600000;
            expText = fmtRemaining(expAt - now);
            expTitle = new Date(expAt).toLocaleString();
          }
        }
        tdExp.textContent = expText;
        if (expTitle) tdExp.title = expTitle;

        const tdAct = document.createElement('td');
        tdAct.className = 'text-right';

        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete';
        delBtn.className = 'btn btn-default btn-sm';
        delBtn.addEventListener('click', async () => {
          delBtn.disabled = true;
          try {
            await callOne('delete', ent.ip);
            await adminSoftRefresh({ force: true });
            setStatus(`Deleted ${ent.ip}`);
          } catch (e) {
            setStatus('Delete failed: ' + e.message);
          } finally {
            delBtn.disabled = false;
          }
        });

        const staticBtn = document.createElement('button');
        staticBtn.textContent = (ent.static === true) ? 'Unset Static' : 'Set Static';
        staticBtn.className = 'btn btn-default btn-sm';
        staticBtn.style.marginLeft = '0.5rem';
        staticBtn.addEventListener('click', async () => {
          staticBtn.disabled = true;
          try {
            const makeStatic = !(ent.static === true);
            await callOne('add', ent.ip, { 'X-LUM-Static': makeStatic ? '1' : '0' });
            await adminSoftRefresh({ force: true });
            setStatus(makeStatic ? `Marked static: ${ent.ip}` : `Unmarked static: ${ent.ip}`);
          } catch (e) {
            setStatus('Static toggle failed: ' + e.message);
          } finally {
            staticBtn.disabled = false;
          }
        });

        tdAct.appendChild(delBtn);
        tdAct.appendChild(staticBtn);

        tr.appendChild(tdUser);
        tr.appendChild(tdSource);
        tr.appendChild(tdTs);
        tr.appendChild(tdIp);
        tr.appendChild(tdExp);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
      count.textContent = String(entries.length);
    };

    const hashEntries = (entries) => {
      try { return JSON.stringify(entries); } catch { return String(entries?.length || 0); }
    };

    const fetchList = async (opts = {}) => {
      const { signal } = opts;
      const url = API + '?list=1';
      const headers = { 'Cache-Control': 'no-store' };
      if (lastEtag) headers['If-None-Match'] = lastEtag;

      const res = await fetch(url, { credentials: 'include', headers, signal });
      if (res.status === 304) {
        return { entries: null, etag: lastEtag, notModified: true };
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      let data;
      try { data = await res.json(); } catch { throw new Error('Invalid JSON from API'); }
      if (data.ok === false) throw new Error(data.error || 'API error');

      const etag = res.headers.get('ETag') || '';
      return { entries: (data.entries || []), etag, notModified: false };
    };

    const applyEntriesIfChanged = (entries, { force = false } = {}) => {
      if (!entries) return false;
      const h = hashEntries(entries);
      if (!force && h === lastHash) return false;
      currentEntries = entries;
      lastHash = h;
      renderRows(currentEntries);
      return true;
    };

    async function softRefresh({ force = false } = {}) {
      try { inFlight?.abort(); } catch {}
      inFlight = new AbortController();

      if (force) setStatus('Updating...'); else setStatus('');
      try {
        const { entries, etag, notModified } = await fetchList({ signal: inFlight.signal });
        if (etag) lastEtag = etag;

        if (notModified) {
          setStatus(`Up to date · ${new Date().toLocaleTimeString()}`);
        } else {
          const changed = applyEntriesIfChanged(entries, { force });
          setStatus(`Updated ${changed ? '' : '(no changes)'} · ${new Date().toLocaleTimeString()}`);
        }
        backoffMs = 0;
      } catch (e) {
        backoffMs = Math.min((backoffMs ? backoffMs * 2 : 2000), 60000);
        setStatus(`Connection issue: ${e.message}. Retrying in ${Math.round(backoffMs / 1000)}s…`);
        scheduleNextPoll(backoffMs);
      }
    }
    adminSoftRefresh = softRefresh;

    function pollIntervalMs() { return document.hidden ? POLL_HIDDEN_MS : POLL_VISIBLE_MS; }
    function clearPoller() { if (pollTimer) { clearTimeout(pollTimer); clearInterval(pollTimer); pollTimer = null; } }
    function startPoller() { clearPoller(); pollTimer = setInterval(() => softRefresh({ force: false }), pollIntervalMs()); }
    function scheduleNextPoll(ms) { clearPoller(); pollTimer = setTimeout(() => { softRefresh({ force: false }).finally(() => startPoller()); }, ms); }

    function startCountdownTicker() {
      if (countdownTimer) clearInterval(countdownTimer);
      countdownTimer = setInterval(() => {
        if (currentEntries && currentEntries.length) renderRows(currentEntries);
      }, COUNTDOWN_TICK_MS);
    }

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) { softRefresh({ force: true }).finally(startPoller); }
      else { startPoller(); }
    });

    window.addEventListener('online', () => softRefresh({ force: true }));
    window.addEventListener('offline', () => setStatus('Offline'));

    btnRefresh?.setAttribute('title', 'Manual refresh (auto-refresh is on)');
    btnRefresh?.addEventListener('click', () => softRefresh({ force: true }));

    btnClear?.addEventListener('click', async () => {
      if (!confirm('Clear ALL entries?')) return;
      btnClear.disabled = true;
      try {
        await callOne('clear', '1');
        await softRefresh({ force: true });
        setStatus('Cleared all');
      } catch (e) {
        setStatus('Clear failed: ' + e.message);
      } finally {
        btnClear.disabled = false;
      }
    });

    btnPrune?.addEventListener('click', async () => {
      const n = parseInt(pruneHours.value, 10);
      if (!(n > 0)) return setStatus('Enter a positive hour count.');
      btnPrune.disabled = true;
      try {
        await callOne('prune', String(n));
        await softRefresh({ force: true });
        setStatus(`Pruned entries older than ${n} hours`);
      } catch (e) {
        setStatus('Prune failed: ' + e.message);
      } finally {
        btnPrune.disabled = false;
      }
    });

    manualIp?.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') { ev.preventDefault(); btnAddManual?.click(); }
    });

    btnAddManual?.addEventListener('click', async () => {
      const ip = (manualIp?.value || '').trim();
      if (!ip) { setStatus('Enter an IP address.'); return; }
      btnAddManual.disabled = true;
      try {
        const hdrs = manualStatic?.checked ? { 'X-LUM-Static': '1' } : undefined;
        const r = await callOne('add', ip, hdrs);
        await softRefresh({ force: true });
        setStatus((r.result === 'exists') ? `Already present: ${r.ip}` : `Added: ${r.ip}`);
        manualIp.value = '';
        if (manualStatic) manualStatic.checked = false;
      } catch (e) {
        setStatus('Add failed: ' + e.message);
      } finally {
        btnAddManual.disabled = false;
      }
    });

    // Kickoff admin list
    softRefresh({ force: true });
    startPoller();
    startCountdownTicker();
  })();
})();
