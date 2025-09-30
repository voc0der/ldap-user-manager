(function() {
  const clientIp = window.LEASE_IP.clientIp || null;
  const isAdmin = !!window.LEASE_IP.isAdmin;
  const API = '/lease_ip/api.php';

  const qs = (o) => Object.entries(o)
    .map(([k,v]) => v === undefined || v === null ? '' : encodeURIComponent(k)+'='+encodeURIComponent(String(v)))
    .filter(Boolean).join('&');

  const call = async (params) => {
    const url = API + '?' + qs(params);
    const res = await fetch(url, { credentials: 'include' });
    let data;
    try { data = await res.json(); } catch { data = { ok:false, error:'Invalid JSON from API' }; }
    if (!res.ok || data.ok === false) throw new Error(data.error || ('HTTP '+res.status));
    return data;
  };

  // User actions
  const userStatus = document.getElementById('user-status');
  const btnAdd = document.getElementById('btn-add');
  const btnDel = document.getElementById('btn-del');

  const setBusy = (el, busy) => el && (el.disabled = !!busy);

  btnAdd?.addEventListener('click', async () => {
    if (!clientIp) return userStatus.textContent = 'Cannot detect client IP.';
    setBusy(btnAdd, true);
    try {
      const r = await call({ action: 'add' });
      userStatus.textContent = (r.result === 'exists') ? `Already present: ${r.ip}` : `Added: ${r.ip}`;
    } catch (e) {
      userStatus.textContent = 'Add failed: ' + e.message;
    } finally { setBusy(btnAdd, false); }
  });

  btnDel?.addEventListener('click', async () => {
    if (!clientIp) return userStatus.textContent = 'Cannot detect client IP.';
    setBusy(btnDel, true);
    try {
      const r = await call({ action: 'delete' });
      userStatus.textContent = (r.result === 'not_found') ? `Not present: ${r.ip}` : `Deleted: ${r.ip}`;
    } catch (e) {
      userStatus.textContent = 'Delete failed: ' + e.message;
    } finally { setBusy(btnDel, false); }
  });

  // Admin section
  if (isAdmin) {
    const tbody = document.getElementById('tbody');
    const count = document.getElementById('count');
    const btnRefresh = document.getElementById('btn-refresh');
    const btnClear = document.getElementById('btn-clear');
    const btnPrune = document.getElementById('btn-prune');
    const pruneHours = document.getElementById('prune-hours');
    const adminStatus = document.getElementById('admin-status');
    const manualIp = document.getElementById('manual-ip');
    const btnAddManual = document.getElementById('btn-add-manual');

    const renderRows = (entries) => {
      tbody.innerHTML = '';
      for (const ent of entries) {
        const tr = document.createElement('tr');

        const tdLabel = document.createElement('td');
        tdLabel.textContent = ent.host || ent.label || 'unknown';

        const tdTs = document.createElement('td');
        tdTs.textContent = ent.timestamp || '';

        const tdIp = document.createElement('td');
        tdIp.textContent = ent.ip || '';
        if (ent.static === true) {
          tdIp.textContent += ' (static)';
        }

        const tdAct = document.createElement('td');
        tdAct.className = 'text-right';

        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete';
        delBtn.className = 'btn btn-default btn-sm';
        delBtn.addEventListener('click', async () => {
          delBtn.disabled = true;
          try {
            await call({ action: 'delete', ip: ent.ip });
            await refresh();
            adminStatus.textContent = `Deleted ${ent.ip}`;
          } catch (e) {
            adminStatus.textContent = 'Delete failed: ' + e.message;
          } finally {
            delBtn.disabled = false;
          }
        });

        // NEW: Static toggle
        const staticBtn = document.createElement('button');
        staticBtn.textContent = (ent.static === true) ? 'Unset Static' : 'Set Static';
        staticBtn.className = 'btn btn-default btn-sm';
        staticBtn.style.marginLeft = '0.5rem';
        staticBtn.addEventListener('click', async () => {
          staticBtn.disabled = true;
          try {
            const action = (ent.static === true) ? 'unstatic' : 'static';
            await call({ action, ip: ent.ip });
            await refresh();
            adminStatus.textContent = (action === 'static')
              ? `Marked static: ${ent.ip}`
              : `Unmarked static: ${ent.ip}`;
          } catch (e) {
            adminStatus.textContent = 'Static toggle failed: ' + e.message;
          } finally {
            staticBtn.disabled = false;
          }
        });

        tdAct.appendChild(delBtn);
        tdAct.appendChild(staticBtn);

        tr.appendChild(tdLabel);
        tr.appendChild(tdTs);
        tr.appendChild(tdIp);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
      count.textContent = String(entries.length);
    };

    const refresh = async () => {
      adminStatus.textContent = 'Loading...';
      try {
        const r = await call({ action: 'list' });
        adminStatus.textContent = '';
        renderRows(r.entries || []);
      } catch (e) {
        adminStatus.textContent = 'List failed: ' + e.message;
        tbody.innerHTML = '';
        count.textContent = '0';
      }
    };

    btnRefresh?.addEventListener('click', refresh);

    btnClear?.addEventListener('click', async () => {
      if (!confirm('Clear ALL entries?')) return;
      btnClear.disabled = true;
      try {
        await call({ action: 'clear' });
        await refresh();
        adminStatus.textContent = 'Cleared all';
      } catch (e) {
        adminStatus.textContent = 'Clear failed: ' + e.message;
      } finally {
        btnClear.disabled = false;
      }
    });

    btnPrune?.addEventListener('click', async () => {
      const n = parseInt(pruneHours.value, 10);
      if (!(n > 0)) return adminStatus.textContent = 'Enter a positive hour count.';
      btnPrune.disabled = true;
      try {
        await call({ action: 'prune', hours: n });
        await refresh();
        adminStatus.textContent = `Pruned entries older than ${n} hours`;
      } catch (e) {
        adminStatus.textContent = 'Prune failed: ' + e.message;
      } finally {
        btnPrune.disabled = false;
      }
    });

    // Manual add (admin)
    btnAddManual?.addEventListener('click', async () => {
      const ip = (manualIp?.value || '').trim();
      if (!ip) {
        adminStatus.textContent = 'Enter an IP address.';
        return;
      }
      btnAddManual.disabled = true;
      try {
        const r = await call({ action: 'add', ip });
        await refresh();
        adminStatus.textContent = (r.result === 'exists') ? `Already present: ${r.ip}` : `Added: ${r.ip}`;
        manualIp.value = '';
      } catch (e) {
        adminStatus.textContent = 'Add failed: ' + e.message;
      } finally {
        btnAddManual.disabled = false;
      }
    });

    // initial load
    refresh();
  }
})();
