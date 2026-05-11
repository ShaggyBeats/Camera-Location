/**
 * app.js — Camera Discovery Octopus
 * Frontend dashboard: SSE live updates, scan control, device table,
 * detail panel, filtering, and export.
 */

(function() {
  'use strict';

  // ─── State ──────────────────────────────────────────────────────────
  let devices = [];
  let selectedDeviceIp = null;
  let currentMode = 'listen';
  let isScanning = false;
  let scanStartTime = null;
  let scanTimer = null;
  let sortField = 'ip';
  let sortDir = 'asc';
  let eventSource = null;
  let activityEvents = [];

  // ─── DOM refs ───────────────────────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const app = $('#app');
  const ifaceSelect = $('#iface-select');
  const modeTabs = $$('.cam__mode-tab');
  const scanBtn = $('#scan-btn');
  const exportCsv = $('#export-csv');
  const exportJson = $('#export-json');
  const deviceCount = $('#device-count');
  const deviceCountNum = deviceCount.querySelector('.cam__device-count__num');
  const scanStatus = $('#scan-status');
  const statusIcon = scanStatus.querySelector('.cam__status-dot__icon');
  const statusLabel = scanStatus.querySelector('.cam__status-dot__label');
  const progressBar = $('#progress-bar');
  const progressFill = $('#progress-fill');
  const progressText = $('#progress-text');
  const searchInput = $('#search-input');
  const tableBody = $('#device-tbody');
  const detailPanel = $('#detail-panel');
  const detailTitle = $('#detail-title');
  const detailBody = $('#detail-body');
  const detailClose = $('#detail-close');
  const sidebarEl = $('#sidebar');
  const sidebarCollapse = $('#sidebar-collapse');
  const confidenceFilter = $('#confidence-filter');
  const confidenceVal = $('#confidence-val');
  const vendorFilters = $('#vendor-filters');
  const protocolFilters = $$('#protocol-filters input[type="checkbox"]');
  const subnetFilters = $('#subnet-filters');
  const tickerInner = $('#ticker-inner');
  const scanTime = $('#scan-time');
  const expandAllBtn = $('#btn-expand-all');
  const collapseAllBtn = $('#btn-collapse-all');

  // ─── Init ───────────────────────────────────────────────────────────
  async function init() {
    await loadInterfaces();
    bindEvents();
    connectSSE();
    await loadExistingDevices();
  }

  async function loadInterfaces() {
    try {
      const resp = await fetch('/api/interfaces');
      const ifaces = await resp.json();
      ifaceSelect.innerHTML = '<option value="">Auto-detect</option>';
      ifaces.forEach(i => {
        const opt = document.createElement('option');
        opt.value = i.name;
        opt.textContent = `${i.name} (${i.ip}) — ${i.iface_type}`;
        if (i.iface_type === 'ethernet') opt.selected = true;
        ifaceSelect.appendChild(opt);
      });
    } catch(e) {
      console.error('Failed to load interfaces:', e);
    }
  }

  async function loadExistingDevices() {
    try {
      const resp = await fetch('/api/devices');
      devices = await resp.json();
      renderTable();
      updateStats();
    } catch(e) { /* no existing devices */ }
  }

  // ─── SSE ────────────────────────────────────────────────────────────
  function connectSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/api/events');

    eventSource.addEventListener('message', (e) => {
      try {
        const msg = JSON.parse(e.data);
        handleEvent(msg);
      } catch(err) { /* heartbeat or parse error */ }
    });

    eventSource.onerror = () => {
      // Reconnect after delay
      setTimeout(connectSSE, 3000);
    };
  }

  function handleEvent(msg) {
    const { type, data } = msg;

    switch(type) {
      case 'device_found':
        devices.push(data);
        addActivityEvent('found', `Found ${data.ip} — ${data.vendor}`);
        renderTable();
        updateStats();
        break;

      case 'device_updated':
        const idx = devices.findIndex(d => d.ip === data.ip);
        if (idx >= 0) {
          devices[idx] = data;
        } else {
          devices.push(data);
        }
        renderTable();
        updateStats();
        break;

      case 'progress':
        updateProgress(data);
        break;

      case 'scan_complete':
        setScanning(false);
        addActivityEvent('found', `Scan complete — ${data.device_count} devices found`);
        break;

      case 'error':
        addActivityEvent('error', data.message);
        break;
    }
  }

  // ─── Scan control ───────────────────────────────────────────────────
  function bindEvents() {
    // Mode tabs
    modeTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        modeTabs.forEach(t => t.classList.remove('cam__mode-tab--active'));
        tab.classList.add('cam__mode-tab--active');
        currentMode = tab.dataset.mode;
        app.dataset.mode = currentMode;
      });
    });

    // Scan button
    scanBtn.addEventListener('click', () => {
      if (isScanning) {
        stopScan();
      } else {
        startScan();
      }
    });

    // Export
    exportCsv.addEventListener('click', () => window.open('/api/export/csv', '_blank'));
    exportJson.addEventListener('click', () => window.open('/api/export/json', '_blank'));

    // Search
    searchInput.addEventListener('input', debounce(renderTable, 200));

    // Sidebar collapse
    sidebarCollapse.addEventListener('click', () => {
      sidebarEl.classList.toggle('cam__sidebar--collapsed');
      const isCollapsed = sidebarEl.classList.contains('cam__sidebar--collapsed');
      sidebarCollapse.textContent = isCollapsed ? '\u25B6' : '\u25C0';
    });

    // Confidence filter
    confidenceFilter.addEventListener('input', () => {
      confidenceVal.textContent = confidenceFilter.value + '%+';
      renderTable();
    });

    // Protocol filters
    protocolFilters.forEach(cb => cb.addEventListener('change', renderTable));

    // Sort
    $$('.cam__th[data-sort]').forEach(th => {
      th.addEventListener('click', () => {
        const field = th.dataset.sort;
        if (sortField === field) {
          sortDir = sortDir === 'asc' ? 'desc' : 'asc';
        } else {
          sortField = field;
          sortDir = 'asc';
        }
        renderTable();
      });
    });

    // Detail panel close
    detailClose.addEventListener('click', closeDetail);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeDetail();
    });

    // Expand/collapse all
    expandAllBtn.addEventListener('click', () => {
      $$('.cam__expand-btn').forEach(b => b.classList.add('cam__expand-btn--open'));
      $$('.cam__detail-row').forEach(r => r.style.display = '');
    });
    collapseAllBtn.addEventListener('click', () => {
      $$('.cam__expand-btn').forEach(b => b.classList.remove('cam__expand-btn--open'));
      $$('.cam__detail-row').forEach(r => r.style.display = 'none');
    });
  }

  async function startScan() {
    setScanning(true);
    devices = [];
    renderTable();
    updateStats();

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: currentMode,
          interface: ifaceSelect.value,
        }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        addActivityEvent('error', err.error || 'Scan failed');
        setScanning(false);
      }
    } catch(e) {
      addActivityEvent('error', 'Network error starting scan');
      setScanning(false);
    }
  }

  async function stopScan() {
    try {
      await fetch('/api/scan/stop', { method: 'POST' });
      setScanning(false);
    } catch(e) { /* ignore */ }
  }

  function setScanning(state) {
    isScanning = state;
    if (state) {
      scanBtn.className = 'cam__scan-btn cam__scan-btn--stop';
      scanBtn.innerHTML = '<span class="cam__scan-btn__icon">\u25A0</span> Stop';
      statusIcon.className = 'cam__status-dot__icon cam__status-dot__icon--active';
      statusLabel.textContent = 'Scanning';
      progressBar.style.display = '';
      scanStartTime = Date.now();
      scanTimer = setInterval(updateScanTime, 1000);
    } else {
      scanBtn.className = 'cam__scan-btn cam__scan-btn--start';
      scanBtn.innerHTML = '<span class="cam__scan-btn__icon">\u25B6</span> Start Scan';
      statusIcon.className = 'cam__status-dot__icon cam__status-dot__icon--idle';
      statusLabel.textContent = 'Idle';
      progressBar.style.display = 'none';
      if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
    }
  }

  function updateScanTime() {
    if (!scanStartTime) return;
    const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
    const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const secs = String(elapsed % 60).padStart(2, '0');
    scanTime.textContent = `${mins}:${secs}`;
  }

  function updateProgress(data) {
    if (data.total > 0) {
      const pct = Math.round((data.current / data.total) * 100);
      progressFill.style.width = pct + '%';
    }
    progressText.textContent = data.message || '';
  }

  // ─── Rendering ──────────────────────────────────────────────────────
  function renderTable() {
    const filtered = getFilteredDevices();
    const sorted = sortDevices(filtered);

    if (sorted.length === 0) {
      tableBody.innerHTML = `
        <tr class="cam__empty-row">
          <td colspan="10">
            <div class="cam__empty-state">
              <div class="cam__empty-icon">&#9673;</div>
              <div class="cam__empty-text">${devices.length === 0 ? 'No devices discovered yet' : 'No devices match filters'}</div>
              <div class="cam__empty-hint">${devices.length === 0 ? 'Select an interface and start a scan' : 'Adjust sidebar filters'}</div>
            </div>
          </td>
        </tr>`;
      return;
    }

    let html = '';
    sorted.forEach(device => {
      const isSelected = device.ip === selectedDeviceIp;
      const vendorClass = getVendorClass(device.vendor);
      const portTags = renderPortTags(device.open_ports);
      const onvifStatus = renderStatusIndicator(device.onvif_status);
      const rtspStatus = renderStatusIndicator(device.rtsp_status);
      const confidenceHtml = renderConfidence(device.confidence);
      const actionLinks = renderActionLinks(device);

      html += `
        <tr class="cam__tr ${isSelected ? 'cam__tr--selected' : ''} cam__tr--new"
            data-ip="${esc(device.ip)}" onclick="window._selectDevice('${esc(device.ip)}')">
          <td class="cam__td">
            <button class="cam__expand-btn" onclick="event.stopPropagation(); window._toggleExpand('${esc(device.ip)}')">&#9654;</button>
          </td>
          <td class="cam__td cam__td--ip">${esc(device.ip)}</td>
          <td class="cam__td cam__td--mac">${esc(device.mac || '—')}</td>
          <td class="cam__td cam__td--vendor">
            <span class="cam__vendor-badge ${vendorClass}">${esc(device.vendor)}</span>
          </td>
          <td class="cam__td">${esc(device.model || '—')}</td>
          <td class="cam__td cam__td--ports">${portTags}</td>
          <td class="cam__td">${onvifStatus}</td>
          <td class="cam__td">${rtspStatus}</td>
          <td class="cam__td">${confidenceHtml}</td>
          <td class="cam__td">${actionLinks}</td>
        </tr>
        <tr class="cam__detail-row" data-detail-ip="${esc(device.ip)}" style="display:none;">
          <td colspan="10">
            <div class="cam__detail-expand">
              ${renderInlineDetail(device)}
            </div>
          </td>
        </tr>`;
    });

    tableBody.innerHTML = html;
    deviceCountNum.textContent = devices.length;
  }

  function renderInlineDetail(device) {
    const fields = [
      ['IP Address', device.ip],
      ['MAC Address', device.mac || '—'],
      ['Vendor', device.vendor],
      ['Model', device.model || '—'],
      ['Hostname', device.hostname || '—'],
      ['Subnet', device.subnet || '—'],
      ['ONVIF URL', device.onvif_url ? `<a href="${esc(device.onvif_url)}" target="_blank">${esc(device.onvif_url)}</a>` : '—'],
      ['RTSP URL', device.rtsp_url ? `<a href="${esc(device.rtsp_url)}" target="_blank">${esc(device.rtsp_url)}</a>` : '—'],
      ['Web URL', device.web_url ? `<a href="${esc(device.web_url)}" target="_blank">${esc(device.web_url)}</a>` : '—'],
      ['Confidence', device.confidence + '%'],
      ['Discovery', (device.discovery_methods || []).join(', ')],
      ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleTimeString() : '—'],
    ];

    let html = '<div class="cam__detail-grid">';
    fields.forEach(([label, value]) => {
      html += `
        <div class="cam__detail-field">
          <span class="cam__detail-field__label">${label}</span>
          <span class="cam__detail-field__value">${value}</span>
        </div>`;
    });
    html += '</div>';
    return html;
  }

  function renderPortTags(ports) {
    if (!ports || !ports.length) return '<span style="color:var(--text-label)">—</span>';
    return ports.map(p => {
      let cls = 'other';
      if (p === 80 || p === 8080) cls = 'http';
      else if (p === 443) cls = 'https';
      else if (p === 554) cls = 'rtsp';
      else if (p === 3702 || p === 8899) cls = 'onvif';
      else if (p === 37777 || p === 37778) cls = 'dahua';
      else if (p === 8000) cls = 'hik';
      return `<span class="cam__port-tag cam__port-tag--${cls}">${p}</span>`;
    }).join('');
  }

  function renderStatusIndicator(status) {
    if (status === 'found') return '<span class="cam__status-indicator cam__status-indicator--found">&#10003;</span>';
    if (status === 'error') return '<span class="cam__status-indicator cam__status-indicator--error">&#10007;</span>';
    return '<span class="cam__status-indicator cam__status-indicator--unchecked">—</span>';
  }

  function renderConfidence(score) {
    const cls = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
    return `
      <div class="cam__confidence-bar">
        <div class="cam__confidence-fill">
          <div class="cam__confidence-fill__inner cam__confidence-fill__inner--${cls}" style="width:${score}%"></div>
        </div>
        <span class="cam__confidence-val cam__confidence-val--${cls}">${score}%</span>
      </div>`;
  }

  function renderActionLinks(device) {
    let html = '<div class="cam__action-links">';
    if (device.web_url) {
      html += `<a class="cam__action-link cam__action-link--web" href="${esc(device.web_url)}" target="_blank" title="Open Web UI">&#127760;</a>`;
    }
    if (device.rtsp_url) {
      html += `<a class="cam__action-link cam__action-link--rtsp" href="${esc(device.rtsp_url)}" title="Copy RTSP URL" onclick="event.preventDefault(); navigator.clipboard.writeText('${esc(device.rtsp_url)}')">&#9654;</a>`;
    }
    if (device.onvif_url) {
      html += `<a class="cam__action-link cam__action-link--onvif" href="${esc(device.onvif_url)}" target="_blank" title="ONVIF Endpoint">&#9881;</a>`;
    }
    html += '</div>';
    return html;
  }

  function getVendorClass(vendor) {
    const v = (vendor || '').toLowerCase();
    if (v.includes('hikvision')) return 'cam__vendor-badge--hikvision';
    if (v.includes('dahua')) return 'cam__vendor-badge--dahua';
    if (v.includes('amcrest')) return 'cam__vendor-badge--amcrest';
    if (v.includes('axis')) return 'cam__vendor-badge--axis';
    if (v.includes('hanwha') || v.includes('wisenet')) return 'cam__vendor-badge--hanwha';
    if (v.includes('bosch')) return 'cam__vendor-badge--bosch';
    if (v.includes('reolink')) return 'cam__vendor-badge--reolink';
    if (v.includes('uniview')) return 'cam__vendor-badge--uniview';
    if (v.includes('vivotek')) return 'cam__vendor-badge--vivotek';
    if (v.includes('avigilon')) return 'cam__vendor-badge--avigilon';
    if (v.includes('lorex')) return 'cam__vendor-badge--lorex';
    if (v.includes('generic') || v.includes('onvif')) return 'cam__vendor-badge--generic';
    return 'cam__vendor-badge--unknown';
  }

  // ─── Filtering ──────────────────────────────────────────────────────
  function getFilteredDevices() {
    const query = searchInput.value.toLowerCase().trim();
    const minConfidence = parseInt(confidenceFilter.value, 10);

    // Get active protocol filters
    const activeProtocols = [];
    protocolFilters.forEach(cb => {
      if (cb.checked) activeProtocols.push(cb.value);
    });

    // Get active vendor filters
    const activeVendors = [];
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeVendors.push(cb.value);
    });

    // Get active subnet filters
    const activeSubnets = [];
    subnetFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeSubnets.push(cb.value);
    });

    return devices.filter(d => {
      // Search filter
      if (query) {
        const haystack = `${d.ip} ${d.mac} ${d.vendor} ${d.model} ${d.hostname}`.toLowerCase();
        if (!haystack.includes(query)) return false;
      }

      // Confidence filter
      if (d.confidence < minConfidence) return false;

      // Protocol filter
      if (activeProtocols.length > 0 && activeProtocols.length < 4) {
        const dProtos = (d.protocols || []).map(p => p.toUpperCase());
        const hasMatch = dProtos.some(p => activeProtocols.includes(p));
        if (!hasMatch && dProtos.length > 0) return false;
      }

      // Vendor filter
      if (activeVendors.length > 0) {
        if (!activeVendors.some(v => d.vendor === v)) return false;
      }

      // Subnet filter
      if (activeSubnets.length > 0) {
        if (!activeSubnets.some(s => d.subnet === s)) return false;
      }

      return true;
    });
  }

  function sortDevices(list) {
    return list.sort((a, b) => {
      let va, vb;
      switch(sortField) {
        case 'ip':
          va = a.ip.split('.').map(n => n.padStart(3, '0')).join('');
          vb = b.ip.split('.').map(n => n.padStart(3, '0')).join('');
          break;
        case 'mac': va = a.mac || ''; vb = b.mac || ''; break;
        case 'vendor': va = a.vendor || ''; vb = b.vendor || ''; break;
        case 'model': va = a.model || ''; vb = b.model || ''; break;
        case 'ports': va = (a.open_ports || []).length; vb = (b.open_ports || []).length; break;
        case 'confidence': va = a.confidence; vb = b.confidence; break;
        default: va = a.ip; vb = b.ip;
      }
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  // ─── Detail panel ───────────────────────────────────────────────────
  function selectDevice(ip) {
    selectedDeviceIp = ip;
    const device = devices.find(d => d.ip === ip);
    if (!device) return;

    detailTitle.textContent = device.ip;
    detailBody.innerHTML = renderDetailPanelContent(device);
    detailPanel.classList.add('cam__detail-panel--open');

    // Highlight row
    $$('.cam__tr').forEach(tr => tr.classList.remove('cam__tr--selected'));
    const row = document.querySelector(`.cam__tr[data-ip="${ip}"]`);
    if (row) row.classList.add('cam__tr--selected');
  }

  function closeDetail() {
    selectedDeviceIp = null;
    detailPanel.classList.remove('cam__detail-panel--open');
    $$('.cam__tr').forEach(tr => tr.classList.remove('cam__tr--selected'));
  }

  function renderDetailPanelContent(device) {
    const sections = [];

    // Identity
    sections.push({
      title: 'Identity',
      fields: [
        ['IP Address', device.ip],
        ['MAC Address', device.mac || '—'],
        ['Vendor', device.vendor],
        ['Model', device.model || '—'],
        ['Hostname', device.hostname || '—'],
        ['Firmware', device.firmware || '—'],
      ]
    });

    // Network
    sections.push({
      title: 'Network',
      fields: [
        ['Subnet', device.subnet || '—'],
        ['Open Ports', (device.open_ports || []).join(', ') || '—'],
        ['Discovery', (device.discovery_methods || []).join(', ')],
        ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleString() : '—'],
      ]
    });

    // Protocols
    sections.push({
      title: 'Protocols',
      fields: [
        ['ONVIF', `${device.onvif_status}${device.onvif_url ? ' — <a href="'+esc(device.onvif_url)+'" target="_blank">'+esc(device.onvif_url)+'</a>' : ''}`],
        ['RTSP', `${device.rtsp_status}${device.rtsp_url ? ' — <a href="'+esc(device.rtsp_url)+'" target="_blank">'+esc(device.rtsp_url)+'</a>' : ''}`],
        ['Web UI', device.web_url ? `<a href="${esc(device.web_url)}" target="_blank">${esc(device.web_url)}</a>` : '—'],
        ['Protocols', (device.protocols || []).join(', ')],
      ]
    });

    // Fingerprint
    sections.push({
      title: 'Fingerprint',
      fields: [
        ['Confidence', `${device.confidence}%`],
        ['Vendor Match', device.vendor],
      ]
    });

    let html = '';
    sections.forEach(s => {
      html += `<div class="cam__detail-section">
        <div class="cam__detail-section-title">${s.title}</div>
        <dl class="cam__detail-kv">`;
      s.fields.forEach(([label, value]) => {
        html += `<dt>${label}</dt><dd>${value}</dd>`;
      });
      html += '</dl></div>';
    });

    // Raw responses
    if (device.raw_responses && Object.keys(device.raw_responses).length) {
      html += `<div class="cam__detail-section">
        <div class="cam__detail-section-title">Raw Responses</div>
        <div class="cam__detail-raw"><pre>${esc(JSON.stringify(device.raw_responses, null, 2))}</pre></div>
      </div>`;
    }

    return html;
  }

  // ─── Stats & filters ────────────────────────────────────────────────
  function updateStats() {
    const total = devices.length;
    const cameras = devices.filter(d => d.confidence >= 40).length;
    const onvif = devices.filter(d => d.onvif_status === 'found').length;
    const rtsp = devices.filter(d => d.rtsp_status === 'found').length;

    $('#stat-total').textContent = total;
    $('#stat-cameras').textContent = cameras;
    $('#stat-onvif').textContent = onvif;
    $('#stat-rtsp').textContent = rtsp;

    updateVendorFilters();
    updateSubnetFilters();
    updateProtocolCounts();
  }

  function updateVendorFilters() {
    const vendors = {};
    devices.forEach(d => {
      vendors[d.vendor] = (vendors[d.vendor] || 0) + 1;
    });

    const existing = new Set();
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => existing.add(cb.value));

    let html = '';
    Object.entries(vendors).sort((a,b) => b[1] - a[1]).forEach(([vendor, count]) => {
      const checked = existing.has(vendor) ? 'checked' : (existing.size === 0 ? 'checked' : '');
      html += `
        <label class="cam__filter-item">
          <input type="checkbox" value="${esc(vendor)}" ${checked}> ${esc(vendor)}
          <span class="cam__filter-count">${count}</span>
        </label>`;
    });
    vendorFilters.innerHTML = html;

    // Rebind events
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', renderTable);
    });
  }

  function updateSubnetFilters() {
    const subnets = {};
    devices.forEach(d => {
      if (d.subnet) subnets[d.subnet] = (subnets[d.subnet] || 0) + 1;
    });

    let html = '';
    Object.entries(subnets).sort((a,b) => b[1] - a[1]).forEach(([subnet, count]) => {
      html += `
        <label class="cam__filter-item">
          <input type="checkbox" value="${esc(subnet)}" checked> ${esc(subnet)}
          <span class="cam__filter-count">${count}</span>
        </label>`;
    });
    subnetFilters.innerHTML = html;

    subnetFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      cb.addEventListener('change', renderTable);
    });
  }

  function updateProtocolCounts() {
    const counts = { ONVIF: 0, RTSP: 0, HTTP: 0, SSDP: 0 };
    devices.forEach(d => {
      (d.protocols || []).forEach(p => {
        const key = p.toUpperCase();
        if (key.includes('ONVIF')) counts.ONVIF++;
        if (key.includes('RTSP')) counts.RTSP++;
        if (key.includes('HTTP')) counts.HTTP++;
        if (key.includes('SSDP') || key.includes('UPNP')) counts.SSDP++;
      });
    });

    $$('.cam__filter-count[data-protocol]').forEach(el => {
      const proto = el.dataset.protocol;
      el.textContent = counts[proto] || 0;
    });
  }

  // ─── Activity ticker ────────────────────────────────────────────────
  function addActivityEvent(type, message) {
    const dotClass = type === 'found' ? 'cam__activity-event__dot--found'
                   : type === 'error' ? 'cam__activity-event__dot--error'
                   : type === 'warn' ? 'cam__activity-event__dot--warn'
                   : 'cam__activity-event__dot--idle';

    const time = new Date().toLocaleTimeString();
    activityEvents.push({ type, message, time, dotClass });

    // Keep last 50
    if (activityEvents.length > 50) activityEvents.shift();

    // Render
    let html = '';
    activityEvents.forEach(e => {
      html += `<span class="cam__activity-event">
        <span class="cam__activity-event__dot ${e.dotClass}"></span>
        ${esc(e.time)} ${esc(e.message)}
      </span>`;
    });
    // Duplicate for seamless scroll
    html += html;
    tickerInner.innerHTML = html;
  }

  // ─── Row expand/collapse ────────────────────────────────────────────
  window._toggleExpand = function(ip) {
    const btn = document.querySelector(`.cam__tr[data-ip="${ip}"] .cam__expand-btn`);
    const detailRow = document.querySelector(`.cam__detail-row[data-detail-ip="${ip}"]`);
    if (!btn || !detailRow) return;

    const isOpen = btn.classList.toggle('cam__expand-btn--open');
    detailRow.style.display = isOpen ? '' : 'none';
  };

  window._selectDevice = function(ip) {
    selectDevice(ip);
  };

  // ─── Utilities ──────────────────────────────────────────────────────
  function esc(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  function debounce(fn, ms) {
    let timer;
    return function(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  // ─── Boot ───────────────────────────────────────────────────────────
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
