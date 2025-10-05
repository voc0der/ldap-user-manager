(function () {
  const clientIp = window.LEASE_IP.clientIp || null;
  const isAdmin = !!window.LEASE_IP.isAdmin;
  const API = '/lease_ip/api.php';

  // === Fetch helpers =========================================================
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

  // === User actions (always-on) ==============================================
  const userStatus = document.getElementById('user-status');
  const btnAdd = document.getElementById('btn-add');
  const btnDel = document.getElementById('btn-del');

  const setBusy = (el, busy) => el && (el.disabled = !!busy);

  btnAdd?.addEventListener('click', async () => {
    setBusy(btnAdd, true);
    try {
      const r = await callOne('add', clientIp || '');
      userStatus.textContent = (r.result === 'exists') ? `Already present: ${r.ip}` : `Added: ${r.ip}`;
      if (isAdmin) softRefresh({ force: true }); // reflect instantly in list if admin is viewing
    } catch (e) {
      userStatus.textContent = 'Add failed: ' + e.message;
    } finally { setBusy(btnAdd, false); }
  });

  btnDel?.addEventListener('click', async () => {
    setBusy(btnDel, true);
    try {
      const r = await callOne('delete', clientIp || '');
      userStatus.textContent = (r.result === 'not_found') ? `Not present: ${r.ip}` : `Deleted: ${r.ip}`;
      if (isAdmin) softRefresh({ force: true });
    } catch (e) {
      userStatus.textContent = 'Delete failed: ' + e.message;
    } finally { setBusy(btnDel, false); }
  });

  // === Admin live list =======================================================
  if (isAdmin) {
    const tbody = document.getElementById('tbody');
    const count = document.getElementById('count');
    const btnRefresh = document.getElementById('btn-refresh');
    const btnClear = document.getElementById('btn-clear');
    const btnPrune = document.getElementById('btn-prune');
    const pruneHours = document.getElementById('prune-hours');
    const adminStatus = document.getElementById('admin-status');
    const manualIp = document.getElementById('manual-ip');
    const manualStatic = document.getElementById('manual-static');
    const btnAddManual = document.getElementById('btn-add-manual');

    // --- State
    let currentEntries = [];
    let lastHash = '';
    let lastEtag = '';
    let lastUpdatedMs = 0;
    let pollTimer = null;
    let countdownTimer = null;
    let inFlight = null;  // AbortController for list fetch
    let backoffMs = 0;

    const POLL_VISIBLE_MS = 15000; // 15s when tab visible
    const POLL_HIDDEN_MS  = 60000; // 60s when tab hidden
    const COUNTDOWN_TICK_MS = 10000; // re-render remaining time every 10s

    // --- Utilities -----------------------------------------------------------
    const nowMs = () => Date.now();

    const hashEntries = (entries) => {
      // Stable-ish string for change detection; avoid huge cost if list is big
      try { return JSON.stringify(entries); } catch { return String(entries?.length || 0); }
    };

    const getTtlHours = () => {
      const n = parseFloat(pruneHours?.value || '24');
      return (n > 0) ? n : 24;
    };

    const getTimestampMs = (ent) => {
      if (ent.ts !== undefined && ent.ts !== null) {
        const n = Number(ent.ts);
        if (Number.isFinite(n)) {
          // heuristic: seconds vs ms
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

    const setStatus = (msg) => { adminStatus.textContent = msg || ''; };

    // --- Rendering -----------------------------------------------------------
    const renderRows = (entries) => {
      tbody.innerHTML = '';
      const ttlHrs = getTtlHours();
      const now = nowMs();

      for (const ent of entries) {
        const tr = document.createElement('tr');

        const tdLabel = document.createElement('td');
        tdLabel.textContent = ent.host || ent.label || 'unknown';

        const tdTs = document.createElement('td');
        tdTs.textContent = ent.timestamp || '';

        const tdIp = document.createElement('td');
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
            await softRefresh({ force: true });
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
            await softRefresh({ force: true });
            setStatus(makeStatic ? `Marked static: ${ent.ip}` : `Unmarked static: ${ent.ip}`);
          } catch (e) {
            setStatus('Static toggle failed: ' + e.message);
          } finally {
            staticBtn.disabled = false;
          }
        });

        tdAct.appendChild(delBtn);
        tdAct.appendChild(staticBtn);

        tr.appendChild(tdLabel);
        tr.appendChild(tdTs);
        tr.appendChild(tdIp);
        tr.appendChild(tdExp);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
      count.textContent = String(entries.length);
    };

    // --- List fetch with ETag / backoff -------------------------------------
    const fetchList = async (opts = {}) => {
      const { signal } = opts;
      const url = API + '?list=1';
      const headers = { 'Cache-Control': 'no-store' };
      if (lastEtag) headers['If-None-Match'] = lastEtag;

      const res = await fetch(url, { credentials: 'include', headers, signal });
      if (res.status === 304) {
        // Not modified
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
      if (!entries) return false; // no change
      const h = hashEntries(entries);
      if (!force && h === lastHash) return false;
      currentEntries = entries;
      lastHash = h;
      renderRows(currentEntries);
      lastUpdatedMs = nowMs();
      return true;
    };

    // Soft refresh: only re-render if changed (ETag / hash)
    async function softRefresh({ force = false } = {}) {
      // Cancel any in-flight fetch to avoid overlap
      try { inFlight?.abort(); } catch {}
      inFlight = new AbortController();

      if (!force) setStatus(''); else setStatus('Updating...');
      try {
        const { entries, etag, notModified } = await fetchList({ signal: inFlight.signal });
        if (etag) lastEtag = etag;

        if (notModified) {
          // Touch timestamp so “last updated” stays fresh, but skip re-render
          lastUpdatedMs = nowMs();
          setStatus(`Up to date · ${new Date(lastUpdatedMs).toLocaleTimeString()}`);
        } else {
          const changed = applyEntriesIfChanged(entries, { force });
          setStatus(`Updated ${changed ? '' : '(no changes)'} · ${new Date(lastUpdatedMs).toLocaleTimeString()}`);
        }

        // Reset backoff on success
        backoffMs = 0;
      } catch (e) {
        // Exponential backoff up to 60s
        backoffMs = Math.min((backoffMs ? backoffMs * 2 : 2000), 60000);
        setStatus(`Connection issue: ${e.message}. Retrying in ${Math.round(backoffMs / 1000)}s…`);
        // Schedule a one-off retry respecting backoff
        scheduleNextPoll(backoffMs);
      }
    }

    // --- Polling & visibility management ------------------------------------
    function pollIntervalMs() {
      return document.hidden ? POLL_HIDDEN_MS : POLL_VISIBLE_MS;
    }

    function clearPoller() {
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    function startPoller() {
      clearPoller();
      pollTimer = setInterval(() => softRefresh({ force: false }), pollIntervalMs());
    }

    function scheduleNextPoll(ms) {
      clearPoller();
      pollTimer = setTimeout(() => {
        softRefresh({ force: false }).finally(() => startPoller());
      }, ms);
    }

    function startCountdownTicker() {
      if (countdownTimer) clearInterval(countdownTimer);
      countdownTimer = setInterval(() => {
        if (currentEntries.length) renderRows(currentEntries);
      }, COUNTDOWN_TICK_MS);
    }

    document.addEventListener('visibilitychange', () => {
      // On return to tab, do an immediate refresh and restart poller at fast cadence
      if (!document.hidden) {
        softRefresh({ force: true }).finally(startPoller);
      } else {
        // Slow cadence will be picked on next startPoller call
        startPoller();
      }
    });

    window.addEventListener('online', () => softRefresh({ force: true }));
    window.addEventListener('offline', () => setStatus('Offline'));

    // --- Buttons / inputs ----------------------------------------------------
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

    // Enter to add manual
    manualIp?.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        btnAddManual?.click();
      }
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

    // TTL change only needs a re-render (no refetch)
    pruneHours?.addEventListener('input', () => {
      if (currentEntries.length) renderRows(currentEntries);
    });

    // --- Kickoff -------------------------------------------------------------
    startCountdownTicker();          // live remaining-time updates
    softRefresh({ force: true });    // initial load
    startPoller();                   // background polling
  }
})();
