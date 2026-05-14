/**
 * app.js — Camera Discovery Octopus
 * Frontend dashboard: SSE live updates, scan control, device table,
 * DPI protocol-stage validation, subnet zones, capture position,
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
  let subnetZones = [];
  let capturePosition = { position: 'ethernet_same', can_see_unicast: true, can_see_rtsp: true };
  let isWatching = false;
  let sniffedSubnets = [];   // subnets detected by the sniffer

  // DPI stage order for display
  const DPI_STAGES = ['link','dhcp','discovery','auth','rtsp','onvif_ctrl','ntp','dns','cloud','recording'];
  const DPI_LABELS = {
    link:'L2',dhcp:'DHCP',discovery:'Disc',auth:'Auth',rtsp:'RTSP',
    onvif_ctrl:'ONVIF',ntp:'NTP',dns:'DNS',cloud:'Cloud',recording:'Rec'
  };

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
  const capturePosEl = $('#capture-pos');
  const capturePosIcon = $('#capture-pos-icon');
  const capturePosLabel = $('#capture-pos-label');
  const addSubnetBtn = $('#add-subnet-btn');
  const watchBtn = $('#watch-btn');

  // ─── Init ───────────────────────────────────────────────────────────
  async function init() {
    detectElectron();
    await loadInterfaces();
    await loadCapturePosition();
    await loadSubnetZones();
    bindEvents();
    connectSSE();
    await loadExistingDevices();
  }

  function detectElectron() {
    const isElectron = !!(window.electronAPI && window.electronAPI.isElectron);
    if (isElectron) {
      document.body.classList.add('is-electron');

      // Wire up title bar controls
      const btnMin = document.getElementById('btn-minimize');
      const btnMax = document.getElementById('btn-maximize');
      const btnClose = document.getElementById('btn-close');

      if (btnMin) btnMin.addEventListener('click', () => window.electronAPI.minimize());
      if (btnMax) btnMax.addEventListener('click', () => window.electronAPI.maximize());
      if (btnClose) btnClose.addEventListener('click', () => window.electronAPI.close());
    }
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

  async function loadCapturePosition() {
    try {
      const resp = await fetch('/api/capture-position');
      capturePosition = await resp.json();
      renderCapturePosition();
    } catch(e) { /* ignore */ }
  }

  async function loadSubnetZones() {
    try {
      const resp = await fetch('/api/subnets');
      subnetZones = await resp.json();
      renderSubnetZones();
    } catch(e) { /* ignore */ }
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

      case 'subnet_sniffed':
        handleSubnetSniffed(data);
        break;

      case 'subnet_added':
        loadSubnetZones();
        break;

      case 'subnet_removed':
        loadSubnetZones();
        break;

      case 'capture_position_changed':
        capturePosition = data;
        renderCapturePosition();
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
      if (isScanning) stopScan();
      else startScan();
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
      if (e.key === 'Escape') {
        closeDetail();
        closeAnyDialog();
      }
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

    // Capture position click
    capturePosEl.addEventListener('click', showCapturePositionDialog);

    // Add subnet button
    addSubnetBtn.addEventListener('click', showAddSubnetDialog);

    // Subnet watch toggle
    watchBtn.addEventListener('click', toggleWatch);
  }

  async function toggleWatch() {
    if (isWatching) {
      await fetch('/api/subnet-watch/stop', { method: 'POST' });
      isWatching = false;
      watchBtn.classList.remove('cam__watch-btn--active');
      addActivityEvent('warn', 'Subnet watch stopped');
    } else {
      await fetch('/api/subnet-watch/start', { method: 'POST' });
      isWatching = true;
      watchBtn.classList.add('cam__watch-btn--active');
      addActivityEvent('found', 'Subnet watch started — sniffing for new subnets...');
    }
  }

  function handleSubnetSniffed(data) {
    const { subnet, first_seen_ip, source } = data;
    if (!sniffedSubnets.includes(subnet)) {
      sniffedSubnets.push(subnet);
    }
    addActivityEvent('found',
      `Subnet sniffed: ${subnet} (${source}, first host ${first_seen_ip}) — auto-scanning`);
    // Refresh subnet zones after a short delay to pick up the auto-added zone
    setTimeout(loadSubnetZones, 1500);
    // Flash a visual badge on the subnet section
    const subnetSection = $('#subnet-filters');
    if (subnetSection) {
      subnetSection.closest('.cam__sidebar-section').classList.add('cam__sidebar-section--flash');
      setTimeout(() => {
        subnetSection.closest('.cam__sidebar-section').classList.remove('cam__sidebar-section--flash');
      }, 2000);
    }
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
          <td colspan="11">
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
      const dpiBar = renderDPIBar(device.dpi_stages, device.dpi_score);
      const confidenceHtml = renderConfidence(device.confidence);
      const actionLinks = renderActionLinks(device);

      html += `
        <tr class="cam__tr ${isSelected ? 'cam__tr--selected' : ''} cam__tr--new"
            data-ip="${esc(device.ip)}" onclick="window._selectDevice('${esc(device.ip)}')">
          <td class="cam__td">
            <button class="cam__expand-btn" onclick="event.stopPropagation(); window._toggleExpand('${esc(device.ip)}')">&#9654;</button>
          </td>
          <td class="cam__td cam__td--ip">${esc(device.ip)}</td>
          <td class="cam__td cam__td--mac">${esc(device.mac || '\u2014')}</td>
          <td class="cam__td cam__td--vendor">
            <span class="cam__vendor-badge ${vendorClass}">${esc(device.vendor)}</span>
          </td>
          <td class="cam__td">${esc(device.model || '\u2014')}</td>
          <td class="cam__td cam__td--ports">${portTags}</td>
          <td class="cam__td">${onvifStatus}</td>
          <td class="cam__td">${rtspStatus}</td>
          <td class="cam__td">${dpiBar}</td>
          <td class="cam__td">${confidenceHtml}</td>
          <td class="cam__td">${actionLinks}</td>
        </tr>
        <tr class="cam__detail-row" data-detail-ip="${esc(device.ip)}" style="display:none;">
          <td colspan="11">
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
      ['MAC Address', device.mac || '\u2014'],
      ['Vendor', device.vendor],
      ['Model', device.model || '\u2014'],
      ['Hostname', device.hostname || '\u2014'],
      ['Subnet', device.subnet || '\u2014'],
      ['Subnet Zone', device.subnet_zone || '\u2014'],
      ['ONVIF URL', device.onvif_url ? `<a href="${esc(device.onvif_url)}" target="_blank">${esc(device.onvif_url)}</a>` : '\u2014'],
      ['RTSP URL', device.rtsp_url ? `<a href="${esc(device.rtsp_url)}" target="_blank">${esc(device.rtsp_url)}</a>` : '\u2014'],
      ['Web URL', device.web_url ? `<a href="${esc(device.web_url)}" target="_blank">${esc(device.web_url)}</a>` : '\u2014'],
      ['Confidence', device.confidence + '%'],
      ['DPI Score', (device.dpi_score != null ? device.dpi_score + '%' : '\u2014')],
      ['Discovery', (device.discovery_methods || []).join(', ')],
      ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleTimeString() : '\u2014'],
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

    // DPI stage detail grid
    if (device.dpi_stages && Object.keys(device.dpi_stages).length > 0) {
      html += '<div class="cam__dpi-stage-grid">';
      DPI_STAGES.forEach(stage => {
        const r = device.dpi_stages[stage];
        if (!r) return;
        html += `
          <div class="cam__dpi-stage-item">
            <span class="cam__dpi-stage-item__icon cam__dpi-stage-item__icon--${r.status}"></span>
            <span class="cam__dpi-stage-item__label">${DPI_LABELS[stage] || stage}</span>
            <span class="cam__dpi-stage-item__detail">${esc(r.detail || '')}</span>
          </div>`;
      });
      html += '</div>';
    }

    return html;
  }

  function renderPortTags(ports) {
    if (!ports || !ports.length) return '<span style="color:var(--text-label)">\u2014</span>';
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
    return '<span class="cam__status-indicator cam__status-indicator--unchecked">\u2014</span>';
  }

  function renderDPIBar(stages, score) {
    if (!stages || Object.keys(stages).length === 0) {
      return '<span style="color:var(--text-label);font-size:10px">\u2014</span>';
    }
    let html = '<div class="cam__dpi-bar">';
    DPI_STAGES.forEach(stage => {
      const s = stages[stage];
      if (!s) return;
      html += `<span class="cam__dpi-stage-dot cam__dpi-stage-dot--${s.status}" title="${DPI_LABELS[stage]}: ${s.detail}"></span>`;
    });
    if (score != null) {
      const cls = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low';
      html += `<span class="cam__dpi-score cam__dpi-score--${cls}">${score}%</span>`;
    }
    html += '</div>';
    return html;
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
    // View camera (snapshot / RTSP)
    html += `<a class="cam__action-link cam__action-link--view" title="View camera" onclick="event.preventDefault(); event.stopPropagation(); window._viewCamera('${esc(device.ip)}')">&#128247;</a>`;
    // Change IP
    html += `<a class="cam__action-link cam__action-link--setip" title="Change IP address" onclick="event.preventDefault(); event.stopPropagation(); window._showSetIPDialog('${esc(device.ip)}')">&#9998;</a>`;
    if (device.web_url) {
      html += `<a class="cam__action-link cam__action-link--web" href="${esc(device.web_url)}" target="_blank" title="Open Web UI">&#127760;</a>`;
    }
    if (device.rtsp_url) {
      html += `<a class="cam__action-link cam__action-link--rtsp" href="${esc(device.rtsp_url)}" title="Copy RTSP URL" onclick="event.preventDefault(); event.stopPropagation(); navigator.clipboard.writeText('${esc(device.rtsp_url)}').then(()=>addActivityEvent('found','RTSP URL copied'))">&#9654;</a>`;
    }
    if (device.onvif_url) {
      html += `<a class="cam__action-link cam__action-link--onvif" href="${esc(device.onvif_url)}" target="_blank" title="ONVIF Endpoint">&#9881;</a>`;
    }
    html += `<a class="cam__action-link" style="background:rgba(34,211,238,.1);color:#22d3ee" title="Run DPI validation" onclick="event.preventDefault(); event.stopPropagation(); window._validateDPI('${esc(device.ip)}')">&#128065;</a>`;
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

    const activeProtocols = [];
    protocolFilters.forEach(cb => { if (cb.checked) activeProtocols.push(cb.value); });

    const activeVendors = [];
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeVendors.push(cb.value);
    });

    const activeSubnets = [];
    subnetFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => {
      if (cb.checked) activeSubnets.push(cb.value);
    });

    return devices.filter(d => {
      if (query) {
        const haystack = `${d.ip} ${d.mac} ${d.vendor} ${d.model} ${d.hostname} ${d.subnet_zone || ''}`.toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      if (d.confidence < minConfidence) return false;
      if (activeProtocols.length > 0 && activeProtocols.length < 4) {
        const dProtos = (d.protocols || []).map(p => p.toUpperCase());
        const hasMatch = dProtos.some(p => activeProtocols.includes(p));
        if (!hasMatch && dProtos.length > 0) return false;
      }
      if (activeVendors.length > 0) {
        if (!activeVendors.some(v => d.vendor === v)) return false;
      }
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

    sections.push({
      title: 'Identity',
      fields: [
        ['IP Address', device.ip],
        ['MAC Address', device.mac || '\u2014'],
        ['Vendor', device.vendor],
        ['Model', device.model || '\u2014'],
        ['Hostname', device.hostname || '\u2014'],
        ['Firmware', device.firmware || '\u2014'],
      ]
    });

    sections.push({
      title: 'Network',
      fields: [
        ['Subnet', device.subnet || '\u2014'],
        ['Subnet Zone', device.subnet_zone || '\u2014'],
        ['Open Ports', (device.open_ports || []).join(', ') || '\u2014'],
        ['Discovery', (device.discovery_methods || []).join(', ')],
        ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleString() : '\u2014'],
      ]
    });

    sections.push({
      title: 'Protocols',
      fields: [
        ['ONVIF', `${device.onvif_status}${device.onvif_url ? ' \u2014 <a href="'+esc(device.onvif_url)+'" target="_blank">'+esc(device.onvif_url)+'</a>' : ''}`],
        ['RTSP', `${device.rtsp_status}${device.rtsp_url ? ' \u2014 <a href="'+esc(device.rtsp_url)+'" target="_blank">'+esc(device.rtsp_url)+'</a>' : ''}`],
        ['Web UI', device.web_url ? `<a href="${esc(device.web_url)}" target="_blank">${esc(device.web_url)}</a>` : '\u2014'],
        ['Protocols', (device.protocols || []).join(', ')],
      ]
    });

    // DPI section
    if (device.dpi_stages && Object.keys(device.dpi_stages).length > 0) {
      const dpiFields = [['DPI Score', (device.dpi_score != null ? device.dpi_score + '%' : '\u2014')]];
      DPI_STAGES.forEach(stage => {
        const r = device.dpi_stages[stage];
        if (r) {
          const icon = r.status === 'pass' ? '\u2713' : r.status === 'fail' ? '\u2717' : '?';
          dpiFields.push([DPI_LABELS[stage] || stage, `${icon} ${r.detail || r.status}`]);
        }
      });
      sections.push({ title: 'DPI Protocol Stages', fields: dpiFields });
    }

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

    // DPI stats
    const dpiValidated = devices.filter(d => d.dpi_stages && Object.keys(d.dpi_stages).length > 0).length;
    const dpiIssues = devices.filter(d => {
      if (!d.dpi_stages) return false;
      return Object.values(d.dpi_stages).some(s => s.status === 'fail');
    }).length;
    const dpiScores = devices.filter(d => d.dpi_score != null).map(d => d.dpi_score);
    const avgDpi = dpiScores.length ? Math.round(dpiScores.reduce((a,b) => a+b, 0) / dpiScores.length) : null;

    $('#stat-dpi-validated').textContent = dpiValidated;
    $('#stat-dpi-issues').textContent = dpiIssues;
    $('#stat-dpi-avg-score').textContent = avgDpi != null ? avgDpi + '%' : '\u2014';
    $('#stat-subnet-zones').textContent = subnetZones.length;

    updateVendorFilters();
    updateSubnetFilters();
    updateProtocolCounts();
  }

  function updateVendorFilters() {
    const vendors = {};
    devices.forEach(d => { vendors[d.vendor] = (vendors[d.vendor] || 0) + 1; });

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
    vendorFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', renderTable));
  }

  function updateSubnetFilters() {
    const subnets = {};
    devices.forEach(d => { if (d.subnet) subnets[d.subnet] = (subnets[d.subnet] || 0) + 1; });

    let html = '';
    // Show subnet zones as cards
    subnetZones.forEach(zone => {
      html += `
        <div class="cam__subnet-zone-card">
          <div class="cam__subnet-zone-card__header">
            <span class="cam__subnet-zone-card__subnet">${esc(zone.subnet)}</span>
            <button class="cam__subnet-zone-card__delete" onclick="window._removeSubnet('${esc(zone.subnet)}')">&times;</button>
          </div>
          ${zone.label ? `<div class="cam__subnet-zone-card__label">${esc(zone.label)}</div>` : ''}
          <div class="cam__subnet-zone-card__meta">
            <span>${zone.method}</span>
            <span>${zone.discoverable ? 'discoverable' : 'no discovery'}</span>
            <span>${zone.internet_blocked ? 'internet blocked' : 'internet open'}</span>
          </div>
        </div>`;
    });

    // Also add filter checkboxes for discovered subnets
    Object.entries(subnets).sort((a,b) => b[1] - a[1]).forEach(([subnet, count]) => {
      html += `
        <label class="cam__filter-item">
          <input type="checkbox" value="${esc(subnet)}" checked> ${esc(subnet)}
          <span class="cam__filter-count">${count}</span>
        </label>`;
    });
    subnetFilters.innerHTML = html;
    subnetFilters.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.addEventListener('change', renderTable));
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
      el.textContent = counts[el.dataset.protocol] || 0;
    });
  }

  // ─── Capture Position ───────────────────────────────────────────────
  function renderCapturePosition() {
    const pos = capturePosition.position || 'unknown';
    const labels = {
      wifi: 'Wi-Fi', ethernet_same: 'Ethernet', span_port: 'SPAN Port',
      inline_tap: 'Inline Tap', nvr_capture: 'NVR Capture', unknown: 'Unknown'
    };
    capturePosLabel.textContent = labels[pos] || pos;

    capturePosEl.classList.remove('cam__capture-pos--good', 'cam__capture-pos--limited', 'cam__capture-pos--unknown');
    if (capturePosition.can_see_unicast && capturePosition.can_see_rtsp) {
      capturePosEl.classList.add('cam__capture-pos--good');
    } else if (pos === 'wifi') {
      capturePosEl.classList.add('cam__capture-pos--limited');
    } else {
      capturePosEl.classList.add('cam__capture-pos--unknown');
    }
  }

  function showCapturePositionDialog() {
    const options = [
      { id: 'wifi', icon: '\u{1F4F6}', label: 'Wi-Fi Adapter', desc: 'Limited — broadcast/multicast only, cannot see unicast camera-to-NVR traffic', unicast: false, rtsp: false },
      { id: 'ethernet_same', icon: '\u{1F5A7}', label: 'Ethernet Same VLAN', desc: 'Can see unicast + broadcast if on same VLAN as cameras', unicast: true, rtsp: true },
      { id: 'span_port', icon: '\u{1F50D}', label: 'SPAN/Mirror Port', desc: 'Full visibility via managed switch port mirroring', unicast: true, rtsp: true },
      { id: 'inline_tap', icon: '\u{1F517}', label: 'Inline Tap', desc: 'Full visibility via network tap between switch and NVR', unicast: true, rtsp: true },
      { id: 'nvr_capture', icon: '\u{1F4BB}', label: 'NVR Interface Capture', desc: 'Capture directly on the NVR network interface', unicast: true, rtsp: true },
    ];

    const selected = capturePosition.position;
    let html = `<div class="cam__capture-dialog" onclick="if(event.target===this)this.remove()">
      <div class="cam__capture-dialog__inner">
        <div class="cam__capture-dialog__title">Capture Position</div>
        <p style="font-size:11px;color:var(--text-muted);margin:0 0 12px">Where are you capturing from? This affects what traffic you can see.</p>`;

    options.forEach(o => {
      html += `
        <div class="cam__capture-dialog__option ${o.id === selected ? 'cam__capture-dialog__option--selected' : ''}"
             onclick="window._setCapturePosition('${o.id}')">
          <span class="cam__capture-dialog__option__icon">${o.icon}</span>
          <div class="cam__capture-dialog__option__text">
            <div class="cam__capture-dialog__option__label">${o.label}</div>
            <div class="cam__capture-dialog__option__desc">${o.desc}</div>
          </div>
          <div class="cam__capture-dialog__option__vis">
            <span class="cam__capture-dialog__option__vis-tag ${o.unicast ? 'cam__capture-dialog__option__vis-tag--yes' : 'cam__capture-dialog__option__vis-tag--no'}">Unicast</span>
            <span class="cam__capture-dialog__option__vis-tag ${o.rtsp ? 'cam__capture-dialog__option__vis-tag--yes' : 'cam__capture-dialog__option__vis-tag--no'}">RTSP</span>
          </div>
        </div>`;
    });

    html += `<div class="cam__capture-dialog__actions">
        <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--cancel" onclick="this.closest('.cam__capture-dialog').remove()">Close</button>
      </div>
    </div></div>`;

    document.body.insertAdjacentHTML('beforeend', html);
  }

  // ─── Subnet Zone Dialog ─────────────────────────────────────────────
  function showAddSubnetDialog() {
    const html = `<div class="cam__subnet-dialog" onclick="if(event.target===this)this.remove()">
      <div class="cam__subnet-dialog__inner">
        <div class="cam__subnet-dialog__title">Add Subnet Zone</div>
        <div class="cam__subnet-dialog__field">
          <label>Subnet (CIDR)</label>
          <input type="text" id="new-subnet" placeholder="192.168.88.0/24">
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Label</label>
          <input type="text" id="new-subnet-label" placeholder="Legacy Camera Range">
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Gateway</label>
          <input type="text" id="new-subnet-gateway" placeholder="192.168.1.1">
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Method</label>
          <select id="new-subnet-method">
            <option value="auto">Auto (try secondary IP, then route)</option>
            <option value="secondary_ip">Secondary IP on this adapter</option>
            <option value="route">Static route via gateway</option>
            <option value="manual">Manual (no auto-configuration)</option>
          </select>
        </div>
        <div class="cam__subnet-dialog__field">
          <label>Notes</label>
          <input type="text" id="new-subnet-notes" placeholder="Previous installer range">
        </div>
        <div class="cam__subnet-dialog__actions">
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--cancel" onclick="this.closest('.cam__subnet-dialog').remove()">Cancel</button>
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--add" onclick="window._addSubnet()">Add Zone</button>
        </div>
      </div>
    </div>`;

    document.body.insertAdjacentHTML('beforeend', html);
  }

  // ─── Activity ticker ────────────────────────────────────────────────
  function addActivityEvent(type, message) {
    const dotClass = type === 'found' ? 'cam__activity-event__dot--found'
                   : type === 'error' ? 'cam__activity-event__dot--error'
                   : type === 'warn' ? 'cam__activity-event__dot--warn'
                   : 'cam__activity-event__dot--idle';

    const time = new Date().toLocaleTimeString();
    activityEvents.push({ type, message, time, dotClass });
    if (activityEvents.length > 50) activityEvents.shift();

    let html = '';
    activityEvents.forEach(e => {
      html += `<span class="cam__activity-event">
        <span class="cam__activity-event__dot ${e.dotClass}"></span>
        ${esc(e.time)} ${esc(e.message)}
      </span>`;
    });
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

  window._validateDPI = async function(ip) {
    addActivityEvent('found', `Running DPI validation on ${ip}...`);
    try {
      const resp = await fetch(`/api/dpi/validate/${ip}`);
      const result = await resp.json();
      // Update device in local state
      const idx = devices.findIndex(d => d.ip === ip);
      if (idx >= 0) {
        devices[idx].dpi_stages = result.dpi_stages;
        devices[idx].dpi_score = result.dpi_score;
        devices[idx].dpi_summary = result.dpi_summary;
      }
      renderTable();
      updateStats();
      addActivityEvent('found', `DPI validation complete for ${ip}: ${result.dpi_score}%`);
    } catch(e) {
      addActivityEvent('error', `DPI validation failed for ${ip}`);
    }
  };

  window._setCapturePosition = async function(position) {
    try {
      const resp = await fetch('/api/capture-position', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ position }),
      });
      capturePosition = await resp.json();
      renderCapturePosition();
    } catch(e) { /* ignore */ }
    closeAnyDialog();
  };

  window._addSubnet = async function() {
    const subnet = document.getElementById('new-subnet').value.trim();
    const label = document.getElementById('new-subnet-label').value.trim();
    const gateway = document.getElementById('new-subnet-gateway').value.trim();
    const method = document.getElementById('new-subnet-method').value;
    const notes = document.getElementById('new-subnet-notes').value.trim();

    if (!subnet) return;

    try {
      await fetch('/api/subnets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet, label, gateway, method, notes }),
      });
      await loadSubnetZones();
      addActivityEvent('found', `Added subnet zone: ${subnet}`);
    } catch(e) {
      addActivityEvent('error', `Failed to add subnet zone`);
    }
    closeAnyDialog();
  };

  window._removeSubnet = async function(subnet) {
    try {
      await fetch(`/api/subnets/${encodeURIComponent(subnet)}`, { method: 'DELETE' });
      await loadSubnetZones();
      addActivityEvent('warn', `Removed subnet zone: ${subnet}`);
    } catch(e) { /* ignore */ }
  };

  // ─── Camera Viewer ──────────────────────────────────────────────────
  window._viewCamera = function(ip) {
    const device = devices.find(d => d.ip === ip) || { ip };
    const snapshotUrl = `/api/devices/${encodeURIComponent(ip)}/snapshot`;

    const html = `<div class="cam__viewer-overlay" id="viewer-overlay" onclick="if(event.target===this)this.remove()">
      <div class="cam__viewer">
        <div class="cam__viewer__header">
          <span class="cam__viewer__title">&#128247; ${esc(ip)} &mdash; ${esc(device.vendor || 'Camera')}</span>
          <button class="cam__viewer__close" onclick="document.getElementById('viewer-overlay').remove()">&times;</button>
        </div>
        <div class="cam__viewer__snapshot-wrap" id="viewer-snap-wrap">
          <img id="viewer-img" class="cam__viewer__img" src="" alt="Loading snapshot...">
          <div class="cam__viewer__snap-error" id="viewer-snap-error" style="display:none">
            No snapshot available — camera may require authentication or use RTSP only.
          </div>
        </div>
        <div class="cam__viewer__controls">
          <button class="cam__viewer__btn" onclick="window._refreshSnapshot('${esc(ip)}')">&#8635; Snapshot</button>
          ${device.rtsp_url ? `<button class="cam__viewer__btn" onclick="navigator.clipboard.writeText('${esc(device.rtsp_url)}').then(()=>addActivityEvent('found','RTSP copied'))">&#9654; Copy RTSP</button>` : ''}
          ${device.web_url ? `<a class="cam__viewer__btn" href="${esc(device.web_url)}" target="_blank">&#127760; Web UI</a>` : ''}
          <button class="cam__viewer__btn" id="viewer-onvif-btn-${esc(ip)}" onclick="window._queryOnvifInfo('${esc(ip)}')">&#9881; ONVIF Info</button>
          <button class="cam__viewer__btn cam__viewer__btn--setip" onclick="document.getElementById('viewer-overlay').remove(); window._showSetIPDialog('${esc(ip)}')">&#9998; Change IP</button>
        </div>
        <div class="cam__viewer__info" id="viewer-info-${esc(ip)}">
          ${device.rtsp_url ? `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">RTSP</span><code>${esc(device.rtsp_url)}</code></div>` : ''}
          ${device.onvif_url ? `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">ONVIF</span><code>${esc(device.onvif_url)}</code></div>` : ''}
          <div class="cam__viewer__info-row"><span class="cam__viewer__info-label">MAC</span><code>${esc(device.mac || '—')}</code></div>
          <div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Ports</span><code>${(device.open_ports || []).join(', ') || '—'}</code></div>
          ${device.firmware ? `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">FW</span><code>${esc(device.firmware)}</code></div>` : ''}
        </div>
        <div class="cam__viewer__auth">
          <span class="cam__viewer__auth-label">Auth (for snapshot)</span>
          <input type="text" id="viewer-user" placeholder="username" value="admin" class="cam__viewer__auth-input">
          <input type="password" id="viewer-pass" placeholder="password" class="cam__viewer__auth-input">
          <button class="cam__viewer__btn" onclick="window._refreshSnapshot('${esc(ip)}')">Load</button>
        </div>
      </div>
    </div>`;

    closeAnyDialog();
    document.body.insertAdjacentHTML('beforeend', html);
    window._refreshSnapshot(ip);
  };

  window._queryOnvifInfo = async function(ip) {
    const btn = document.getElementById(`viewer-onvif-btn-${ip}`);
    const infoEl = document.getElementById(`viewer-info-${ip}`);
    if (btn) { btn.disabled = true; btn.textContent = 'Querying…'; }
    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';
    try {
      const resp = await fetch(`/api/devices/${encodeURIComponent(ip)}/onvif-info?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`);
      const info = await resp.json();
      if (info.error) {
        addActivityEvent('error', `ONVIF info failed for ${ip}: ${info.error}`);
      } else {
        // Update device in local state
        const d = devices.find(x => x.ip === ip);
        if (d) {
          if (info.model)    d.model    = info.model;
          if (info.firmware) d.firmware = info.firmware;
          if (info.stream_uris && info.stream_uris.length) d.rtsp_url = info.stream_uris[0];
          renderTable();
        }
        // Render into info panel
        if (infoEl) {
          let extra = '';
          if (info.manufacturer) extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Mfr</span><code>${esc(info.manufacturer)}</code></div>`;
          if (info.model)    extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Model</span><code>${esc(info.model)}</code></div>`;
          if (info.firmware) extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">FW</span><code>${esc(info.firmware)}</code></div>`;
          if (info.serial)   extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">S/N</span><code>${esc(info.serial)}</code></div>`;
          info.stream_uris.forEach((u, i) => {
            extra += `<div class="cam__viewer__info-row"><span class="cam__viewer__info-label">Stream ${i+1}</span><code>${esc(u)}</code> <button class="cam__viewer__btn" style="padding:1px 6px;font-size:10px" onclick="navigator.clipboard.writeText('${esc(u)}').then(()=>addActivityEvent('found','RTSP copied'))">Copy</button></div>`;
          });
          infoEl.insertAdjacentHTML('beforeend', extra);
        }
        addActivityEvent('found', `ONVIF info: ${ip} — ${info.manufacturer} ${info.model} FW:${info.firmware}`);
      }
    } catch(e) {
      addActivityEvent('error', `ONVIF info error for ${ip}`);
    }
    if (btn) { btn.disabled = false; btn.innerHTML = '&#9881; ONVIF Info'; }
  };

  window._refreshSnapshot = function(ip) {
    const img = document.getElementById('viewer-img');
    const errEl = document.getElementById('viewer-snap-error');
    if (!img) return;
    const user = (document.getElementById('viewer-user') || {}).value || 'admin';
    const pass = (document.getElementById('viewer-pass') || {}).value || '';
    const ts = Date.now();
    const url = `/api/devices/${encodeURIComponent(ip)}/snapshot?user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&_=${ts}`;
    img.style.opacity = '0.4';
    if (errEl) errEl.style.display = 'none';
    const tester = new Image();
    tester.onload = () => { img.src = url; img.style.opacity = '1'; };
    tester.onerror = () => {
      img.style.opacity = '0';
      if (errEl) errEl.style.display = '';
    };
    tester.src = url;
  };

  // ─── Set IP Dialog ──────────────────────────────────────────────────
  window._showSetIPDialog = function(ip) {
    const device = devices.find(d => d.ip === ip) || { ip };
    const subnet = device.subnet || '';
    const defaultGw = subnet ? subnet.replace(/\d+\/\d+$/, '1') : '';

    const html = `<div class="cam__setip-dialog" onclick="if(event.target===this)this.remove()">
      <div class="cam__setip-dialog__inner">
        <div class="cam__setip-dialog__title">&#9998; Change IP &mdash; ${esc(ip)}</div>
        <div class="cam__setip-info">
          <span class="cam__vendor-badge ${getVendorClass(device.vendor || '')}">${esc(device.vendor || 'Unknown')}</span>
          MAC: ${esc(device.mac || '—')}
        </div>
        <div class="cam__setip-field">
          <label>New IP Address</label>
          <input type="text" id="setip-newip" placeholder="192.168.1.50" value="${esc(ip)}" class="cam__setip-input">
        </div>
        <div class="cam__setip-field">
          <label>Subnet Mask</label>
          <input type="text" id="setip-mask" placeholder="255.255.255.0" value="255.255.255.0" class="cam__setip-input">
        </div>
        <div class="cam__setip-field">
          <label>Default Gateway</label>
          <input type="text" id="setip-gw" placeholder="192.168.1.1" value="${esc(defaultGw)}" class="cam__setip-input">
        </div>
        <div class="cam__setip-field">
          <label>Username</label>
          <input type="text" id="setip-user" placeholder="admin" value="admin" class="cam__setip-input">
        </div>
        <div class="cam__setip-field">
          <label>Password</label>
          <input type="password" id="setip-pass" placeholder="camera password" class="cam__setip-input">
        </div>
        <div class="cam__setip-result" id="setip-result" style="display:none"></div>
        <div class="cam__setip-actions">
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--cancel" onclick="this.closest('.cam__setip-dialog').remove()">Cancel</button>
          <button class="cam__subnet-dialog__btn cam__subnet-dialog__btn--add" id="setip-submit-btn" onclick="window._submitSetIP('${esc(ip)}')">Apply</button>
        </div>
      </div>
    </div>`;

    closeAnyDialog();
    document.body.insertAdjacentHTML('beforeend', html);
    document.getElementById('setip-newip').focus();
  };

  window._submitSetIP = async function(ip) {
    const newIp   = document.getElementById('setip-newip').value.trim();
    const netmask = document.getElementById('setip-mask').value.trim();
    const gateway = document.getElementById('setip-gw').value.trim();
    const username = document.getElementById('setip-user').value.trim();
    const password = document.getElementById('setip-pass').value;
    const resultEl = document.getElementById('setip-result');
    const btn = document.getElementById('setip-submit-btn');

    if (!newIp) { resultEl.textContent = 'New IP is required.'; resultEl.style.display = ''; return; }

    btn.disabled = true;
    btn.textContent = 'Applying...';
    resultEl.style.display = 'none';

    try {
      const resp = await fetch(`/api/devices/${encodeURIComponent(ip)}/set-ip`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_ip: newIp, netmask, gateway, username, password }),
      });
      const result = await resp.json();
      resultEl.style.display = '';
      if (result.success) {
        resultEl.className = 'cam__setip-result cam__setip-result--ok';
        resultEl.textContent = `✓ ${result.message || 'IP change sent. Camera may reboot.'}`;
        addActivityEvent('found', `IP change sent to ${ip} → ${newIp} (${result.method})`);
      } else {
        resultEl.className = 'cam__setip-result cam__setip-result--err';
        resultEl.textContent = `✗ ${result.message || 'Failed — check credentials and try again'}`;
        addActivityEvent('error', `IP change failed for ${ip}: ${result.message}`);
      }
    } catch(e) {
      resultEl.style.display = '';
      resultEl.className = 'cam__setip-result cam__setip-result--err';
      resultEl.textContent = 'Network error contacting server.';
    }
    btn.disabled = false;
    btn.textContent = 'Apply';
  };

  function closeAnyDialog() {
    document.querySelectorAll('.cam__subnet-dialog, .cam__capture-dialog, .cam__setip-dialog, .cam__viewer-overlay').forEach(d => d.remove());
  }

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
  async function safeInit() {
    try {
      await init();
    } catch(e) {
      console.error('CAM INIT FAILED:', e);
      document.body.insertAdjacentHTML('afterbegin',
        `<div style="position:fixed;top:0;left:0;right:0;z-index:9999;background:#ff3a3a;color:#fff;padding:10px 16px;font:13px monospace;">
          Init error: ${e.message} — open DevTools (F12) for details
        </div>`
      );
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', safeInit);
  } else {
    safeInit();
  }

})();
