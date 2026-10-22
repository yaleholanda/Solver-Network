// Solver Network - Gerenciador Inteligente de Redes
// Frontend Application Logic

let networkInfo = null;
let currentDevices = [];
let scanStats = null;
let activeCategory = 'all';
let searchQuery = '';
let viewMode = (window.innerWidth <= 768) ? 'cards' : 'table'; // Responsive: default to cards on mobile
let isPollingScan = false;
let pollInterval = null;
let currentSelectedSubBlock = null;
let currentClientIp = null;
let isRemoteClient = false;

// Multi-network state & cache
let availableScopes = [];
let selectedNetworkScope = null;
let scopeScanCache = {}; // cidr -> { stats, devices }

// Sorting state
let currentSortKey = 'ip';
let currentSortOrder = 'asc';

// DOM Elements - Header
const badgeIface = document.getElementById('badge-iface');
const badgeIp = document.getElementById('badge-ip');
const selectHeaderNetwork = document.getElementById('select-header-network');
const badgeGateway = document.getElementById('badge-gateway');

const btnStartScan = document.getElementById('btn-start-scan');
const btnScanLabel = document.getElementById('btn-scan-label');
const btnStopScan = document.getElementById('btn-stop-scan');
const btnConfigScope = document.getElementById('btn-config-scope');

const scanBanner = document.getElementById('scan-progress-banner');
const scanStatusText = document.getElementById('scan-status-text');
const scanProgressFill = document.getElementById('scan-progress-fill');



// DOM Elements - KPIs
const statTotalIps = document.getElementById('stat-total-ips');
const statSubnetMask = document.getElementById('stat-subnet-mask');
const statScopeDesc = document.getElementById('stat-scope-desc');
const statOccupiedIps = document.getElementById('stat-occupied-ips');
const statOccupancyRate = document.getElementById('stat-occupancy-rate');
const statOccupiedBar = document.getElementById('stat-occupied-bar');
const statFreeIps = document.getElementById('stat-free-ips');
const statFreePct = document.getElementById('stat-free-pct');
const statDevicesOnline = document.getElementById('stat-devices-online');
const statDuration = document.getElementById('stat-duration');
const statLastTime = document.getElementById('stat-last-time');

// IPAM Grid Elements
const ipamGrid = document.getElementById('ipam-grid');
const ipamTooltip = document.getElementById('ipam-tooltip');
const btnToggleIpam = document.getElementById('btn-toggle-ipam');
const ipamWrapper = document.getElementById('ipam-grid-wrapper');
const ipamBlockBar = document.getElementById('ipam-block-bar');
const selectIpamBlock = document.getElementById('select-ipam-block');
const ipamScopeStatsSummary = document.getElementById('ipam-scope-stats-summary');

const categoryTabs = document.getElementById('category-tabs');
const inventorySearch = document.getElementById('inventory-search');
const btnClearSearch = document.getElementById('btn-clear-search');
const resultsCount = document.getElementById('results-count');
const selectDeviceSort = document.getElementById('select-device-sort');

const viewBtnTable = document.getElementById('view-mode-table');
const viewBtnCards = document.getElementById('view-mode-cards');
const tableContainer = document.getElementById('devices-table-container');
const cardsContainer = document.getElementById('devices-cards-container');
const devicesTableBody = document.getElementById('devices-table-body');

// Scope Modal Elements
const modalScope = document.getElementById('modal-scope');
const btnCloseScopeModal = document.getElementById('btn-close-scope-modal');
const btnCancelScope = document.getElementById('btn-cancel-scope');
const btnSaveScope = document.getElementById('btn-save-scope');
const detectedScopesList = document.getElementById('detected-scopes-list');
const calcInputIp = document.getElementById('calc-input-ip');
const calcSelectMask = document.getElementById('calc-select-mask');
const calcCustomMaskInput = document.getElementById('calc-custom-mask-input');
const prevCidr = document.getElementById('prev-cidr');
const prevMask = document.getElementById('prev-mask');
const prevRange = document.getElementById('prev-range');
const prevUsable = document.getElementById('prev-usable');
const inputRangeStart = document.getElementById('input-range-start');
const inputRangeEnd = document.getElementById('input-range-end');
const checkDeepScan = document.getElementById('check-deep-scan');

// Edit Modal Elements
const modalEdit = document.getElementById('modal-edit-device');
const btnCloseEditModal = document.getElementById('btn-close-edit-modal');
const btnCancelEdit = document.getElementById('btn-cancel-edit');
const btnSaveDevice = document.getElementById('btn-save-device');
const editIp = document.getElementById('edit-device-ip');
const editMac = document.getElementById('edit-device-mac');
const editName = document.getElementById('edit-device-name');
const editCategory = document.getElementById('edit-device-category');
const editNotes = document.getElementById('edit-device-notes');

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  setupCalculatorListeners();
  fetchNetworkInfo();
  checkExistingScanStatus();
});

function setupEventListeners() {
  btnStartScan.addEventListener('click', () => startScan());
  btnStopScan.addEventListener('click', () => stopScan());
  btnConfigScope.addEventListener('click', () => openScopeModal());

  // Header network dropdown change
  if (selectHeaderNetwork) {
    selectHeaderNetwork.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === '__custom__') {
        if (selectedNetworkScope) {
          selectHeaderNetwork.value = selectedNetworkScope.cidr;
        }
        openScopeModal();
        return;
      }
      const matched = availableScopes.find(s => s.cidr === val);
      if (matched) {
        setSelectedScope(matched);
      }
    });
  }

  // Scope Modal
  btnCloseScopeModal.addEventListener('click', () => closeScopeModal());
  btnCancelScope.addEventListener('click', () => closeScopeModal());
  btnSaveScope.addEventListener('click', () => handleSaveScopeAndScan());

  // Edit Modal
  btnCloseEditModal.addEventListener('click', () => closeEditModal());
  btnCancelEdit.addEventListener('click', () => closeEditModal());
  btnSaveDevice.addEventListener('click', () => handleSaveDevice());

  // Search
  inventorySearch.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    btnClearSearch.style.display = searchQuery ? 'block' : 'none';
    renderDevices();
  });

  btnClearSearch.addEventListener('click', () => {
    inventorySearch.value = '';
    searchQuery = '';
    btnClearSearch.style.display = 'none';
    renderDevices();
  });

  // View Mode Toggle
  if (viewBtnTable && viewBtnCards) {
    if (viewMode === 'cards') {
      viewBtnCards.classList.add('active');
      viewBtnTable.classList.remove('active');
    } else {
      viewBtnTable.classList.add('active');
      viewBtnCards.classList.remove('active');
    }
    viewBtnTable.addEventListener('click', () => setViewMode('table'));
    viewBtnCards.addEventListener('click', () => setViewMode('cards'));
  }

  // Device Sorting Dropdown
  if (selectDeviceSort) {
    selectDeviceSort.addEventListener('change', (e) => {
      const parts = e.target.value.split('-');
      if (parts.length === 2) {
        setDeviceSort(parts[0], parts[1]);
      }
    });
  }

  // Interactive Clickable Table Headers Sorting
  document.querySelectorAll('.th-sortable').forEach(th => {
    th.addEventListener('click', () => {
      const sortKey = th.dataset.sort;
      if (!sortKey) return;
      let newOrder = 'asc';
      if (currentSortKey === sortKey) {
        newOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
      } else {
        newOrder = (sortKey === 'ports' || sortKey === 'status') ? 'desc' : 'asc';
      }
      setDeviceSort(sortKey, newOrder);
    });
  });

  // Toggle IPAM Map
  btnToggleIpam.addEventListener('click', () => {
    if (ipamWrapper.style.display === 'none') {
      ipamWrapper.style.display = 'block';
      btnToggleIpam.textContent = 'Recolher Mapa';
    } else {
      ipamWrapper.style.display = 'none';
      btnToggleIpam.textContent = 'Expandir Mapa';
    }
  });

  // IPAM Sub-block selector for /16 or large networks
  if (selectIpamBlock) {
    selectIpamBlock.addEventListener('change', (e) => {
      currentSelectedSubBlock = e.target.value;
      if (scanStats && currentDevices) {
        renderIpamGrid(scanStats, currentDevices);
      }
    });
  }

  // Category Tabs
  categoryTabs.querySelectorAll('.cat-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      categoryTabs.querySelectorAll('.cat-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeCategory = tab.dataset.category;
      renderDevices();
    });
  });
}

// --- Network Selection & Scope Management ---
function getScopeRange(scope) {
  if (!scope) return { first: '--', last: '--' };
  if (scope.first_usable_ip && scope.last_usable_ip && scope.first_usable_ip !== 'undefined' && scope.last_usable_ip !== 'undefined') {
    return { first: scope.first_usable_ip, last: scope.last_usable_ip };
  }
  if (scope.first && scope.last && scope.first !== 'undefined' && scope.last !== 'undefined') {
    return { first: scope.first, last: scope.last };
  }
  if (scope.ip) {
    const calc = calculateSubnetLocally(scope.ip, scope.netmask || '255.255.255.0');
    if (calc && calc.first && calc.last) {
      return { first: calc.first, last: calc.last };
    }
  }
  return { first: scope.ip || '--', last: scope.ip || '--' };
}

function setSelectedScope(scope) {
  if (!scope) return;
  selectedNetworkScope = scope;

  // 1. Ensure first and last usable IP are always populated and valid
  const range = getScopeRange(scope);
  scope.first_usable_ip = range.first;
  scope.last_usable_ip = range.last;

  // 2. Sync header dropdown
  if (selectHeaderNetwork) {
    selectHeaderNetwork.value = scope.cidr;
  }

  // 3. Update badges on the same line in header (Meu IP com sua máscara e o Gateway)
  if (badgeIp) {
    badgeIp.innerHTML = `<span class="badge-ip-text">${scope.ip}</span> <span class="badge-mask-text">(${scope.netmask})</span>`;
  }
  if (badgeGateway) {
    const gw = (scope.gateway && scope.gateway !== 'N/A')
      ? scope.gateway
      : (networkInfo && networkInfo.gateway && networkInfo.gateway !== 'N/A' ? networkInfo.gateway : 'N/A');
    badgeGateway.textContent = gw;
  }

  // 4. Update scan button text
  if (btnScanLabel) {
    btnScanLabel.textContent = `Escanear Rede (${scope.cidr})`;
  }

  // 5. Update KPI metrics for the selected network
  const usable = scope.usable_ips || scope.total_ips || 254;
  statTotalIps.textContent = usable.toLocaleString('pt-BR');
  statSubnetMask.textContent = `Máscara ${scope.netmask} (/${scope.prefix_len || 24})`;
  statScopeDesc.textContent = `Faixa: ${range.first} - ${range.last}`;

  // 6. Check if we already have scan results for this network
  const cached = scopeScanCache[scope.cidr];
  if (cached) {
    currentDevices = cached.devices || [];
    scanStats = cached.stats || null;
    updateDashboardKPIs(scanStats, currentDevices.length);
    renderCategoryCounts(scanStats ? scanStats.categories : null);
    renderDevices();
    renderIpamGrid(scanStats, currentDevices);
  } else {
    // Fresh state for this network
    currentDevices = [];
    scanStats = null;
    statOccupiedIps.textContent = "0";
    statOccupancyRate.textContent = "0% em uso";
    statOccupiedBar.style.width = "0%";
    statFreeIps.textContent = usable.toLocaleString('pt-BR');
    statFreePct.textContent = "100% livres";
    statDevicesOnline.textContent = "0";
    statDuration.textContent = "0.0s";
    statLastTime.textContent = "Nenhuma varredura recente nesta rede";
    renderCategoryCounts(null);
    renderDevices();
    
    if (ipamGrid) {
      ipamGrid.innerHTML = `
        <div class="ipam-empty-placeholder">
          Rede <strong>${scope.cidr}</strong> pronta para análise.<br>
          Clique em <strong>"Escanear Rede (${scope.cidr})"</strong> para mapear todos os ${usable.toLocaleString('pt-BR')} IPs disponíveis desta sub-rede.
        </div>
      `;
    }
  }

  // Pre-fill inputs for calculator and range
  if (calcInputIp) calcInputIp.value = scope.ip;
  if (inputRangeStart) inputRangeStart.value = range.first;
  if (inputRangeEnd) inputRangeEnd.value = range.last;
  updateCalculatorPreview();
}

function renderNetworkDropdown(scopes) {
  if (!selectHeaderNetwork) return;
  selectHeaderNetwork.innerHTML = '';

  if (!scopes || scopes.length === 0) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Nenhuma rede detectada';
    selectHeaderNetwork.appendChild(opt);
    return;
  }

  scopes.forEach((sc) => {
    const range = getScopeRange(sc);
    sc.first_usable_ip = range.first;
    sc.last_usable_ip = range.last;

    const opt = document.createElement('option');
    opt.value = sc.cidr;
    const isGw = sc.is_gateway_scope;
    const hostsCount = (sc.usable_ips || sc.total_ips || 254).toLocaleString('pt-BR');
    opt.textContent = `${sc.cidr} (${sc.first_usable_ip} - ${sc.last_usable_ip}) • IP: ${sc.ip} • ${hostsCount} hosts${isGw ? ' [Gateway]' : ''}`;
    selectHeaderNetwork.appendChild(opt);
  });

  // Custom option to configure other networks
  const customOpt = document.createElement('option');
  customOpt.value = '__custom__';
  customOpt.textContent = '⚙️ Outra Rede / Máscara personalizada...';
  selectHeaderNetwork.appendChild(customOpt);

  if (selectedNetworkScope) {
    selectHeaderNetwork.value = selectedNetworkScope.cidr;
  }
}

// --- Live Network Scope Calculator in Modal ---
function setupCalculatorListeners() {
  if (!calcInputIp || !calcSelectMask) return;

  const handleCalcChange = () => {
    if (calcSelectMask.value === 'custom') {
      calcCustomMaskInput.style.display = 'block';
    } else {
      calcCustomMaskInput.style.display = 'none';
    }
    updateCalculatorPreview();
  };

  calcInputIp.addEventListener('input', handleCalcChange);
  calcSelectMask.addEventListener('change', handleCalcChange);
  if (calcCustomMaskInput) {
    calcCustomMaskInput.addEventListener('input', handleCalcChange);
  }

  calcInputIp.addEventListener('focus', () => {
    const radio = document.querySelector('input[name="scope_mode"][value="by_mask"]');
    if (radio) radio.checked = true;
  });
  calcSelectMask.addEventListener('focus', () => {
    const radio = document.querySelector('input[name="scope_mode"][value="by_mask"]');
    if (radio) radio.checked = true;
  });
}

function updateCalculatorPreview() {
  const ip = calcInputIp.value.trim() || '192.168.0.1';
  let mask = calcSelectMask.value;
  if (mask === 'custom') {
    mask = calcCustomMaskInput.value.trim() || '255.255.255.0';
  }

  const calc = calculateSubnetLocally(ip, mask);
  if (calc) {
    prevCidr.textContent = calc.cidr;
    prevMask.textContent = `${calc.netmask} (/${calc.prefix})`;
    prevRange.textContent = `${calc.first} - ${calc.last}`;
    prevUsable.textContent = `${calc.usable.toLocaleString('pt-BR')} hosts utilizáveis`;
  } else {
    prevCidr.textContent = '--';
    prevMask.textContent = '--';
    prevRange.textContent = 'Parâmetros inválidos';
    prevUsable.textContent = '--';
  }
}

function calculateSubnetLocally(ipStr, maskStr) {
  try {
    const ipParts = ipStr.split('.').map(Number);
    const maskParts = maskStr.split('.').map(Number);
    if (ipParts.length !== 4 || maskParts.length !== 4) return null;
    if (ipParts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
    if (maskParts.some(p => isNaN(p) || p < 0 || p > 255)) return null;

    const ipInt = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
    const maskInt = ((maskParts[0] << 24) | (maskParts[1] << 16) | (maskParts[2] << 8) | maskParts[3]) >>> 0;

    let prefix = 0;
    for (let i = 31; i >= 0; i--) {
      if ((maskInt & (1 << i)) !== 0) prefix++;
      else break;
    }

    const netInt = (ipInt & maskInt) >>> 0;
    const bcastInt = (netInt | (~maskInt >>> 0)) >>> 0;

    const intToIp = (val) => [
      (val >>> 24) & 255,
      (val >>> 16) & 255,
      (val >>> 8) & 255,
      val & 255
    ].join('.');

    const total = Math.pow(2, 32 - prefix);
    const usable = prefix <= 30 ? Math.max(0, total - 2) : total;

    const first = prefix <= 30 ? intToIp(netInt + 1) : intToIp(netInt);
    const last = prefix <= 30 ? intToIp(bcastInt - 1) : intToIp(bcastInt);

    return {
      cidr: `${intToIp(netInt)}/${prefix}`,
      netmask: maskStr,
      prefix: prefix,
      network: intToIp(netInt),
      broadcast: intToIp(bcastInt),
      first: first,
      last: last,
      first_usable_ip: first,
      last_usable_ip: last,
      total: total,
      usable: usable
    };
  } catch (e) {
    return null;
  }
}

// --- Network Adapter Info & Scope Discovery ---
async function fetchNetworkInfo() {
  try {
    const res = await fetch('/api/network-info');
    const data = await res.json();
    if (data.status === 'success' && data.adapter) {
      networkInfo = data.adapter;
      currentClientIp = data.client_ip || (networkInfo ? networkInfo.ip : null);
      isRemoteClient = Boolean(data.is_remote_client);

      badgeIface.textContent = networkInfo.description || networkInfo.adapter_name || 'Conexão Local';

      availableScopes = networkInfo.all_scopes || networkInfo.scopes || [];
      renderNetworkDropdown(availableScopes);
      renderDetectedScopes(availableScopes, networkInfo.cidr);

      // Find primary gateway scope or first scope
      const defaultScope = availableScopes.find(s => s.is_gateway_scope) || availableScopes[0] || networkInfo;
      setSelectedScope(defaultScope);
    }
  } catch (err) {
    console.error('Erro ao buscar informações da rede:', err);
    showToast('Aviso: Não foi possível obter adaptador padrão', 'warning');
  }
}

function renderDetectedScopes(scopes, activeCidr) {
  if (!detectedScopesList) return;
  if (!scopes || scopes.length === 0) {
    detectedScopesList.innerHTML = '<div style="font-size:0.8rem;color:var(--text-dim);padding:8px;">Nenhuma sub-rede adicional detectada.</div>';
    return;
  }

  detectedScopesList.innerHTML = '';
  scopes.forEach((sc, idx) => {
    const isSelected = (activeCidr ? sc.cidr === activeCidr : idx === 0);
    const item = document.createElement('div');
    item.className = `scope-card-item ${isSelected ? 'selected' : ''}`;
    item.innerHTML = `
      <div class="scope-card-left">
        <input type="radio" name="detected_scope_select" class="scope-radio" value="${sc.cidr}" data-ip="${sc.ip}" data-mask="${sc.netmask}" ${isSelected ? 'checked' : ''}>
        <div>
          <div class="scope-info-title">
            <span class="scope-cidr-tag">${sc.cidr}</span>
            ${sc.is_gateway_scope ? '<span class="scope-badge-gw">Gateway / Principal</span>' : ''}
          </div>
          <div class="scope-info-sub">
            IP: <strong>${sc.ip}</strong> • Máscara: <strong>${sc.netmask}</strong> (/${sc.prefix_len}) • Faixa: ${sc.first_usable_ip} - ${sc.last_usable_ip}
          </div>
        </div>
      </div>
      <div class="scope-card-right">
        <span class="scope-ips-count">${sc.usable_ips.toLocaleString('pt-BR')}</span>
        <span class="scope-ips-label">IPs disponíveis</span>
      </div>
    `;

    item.addEventListener('click', () => {
      const radio = item.querySelector('input[type="radio"]');
      radio.checked = true;
      document.querySelectorAll('.scope-card-item').forEach(el => el.classList.remove('selected'));
      item.classList.add('selected');
      const modeRadio = document.querySelector('input[name="scope_mode"][value="detected"]');
      if (modeRadio) modeRadio.checked = true;
    });

    detectedScopesList.appendChild(item);
  });
}

// --- Scan Execution ---
async function startScan(customPayload = null) {
  try {
    btnStartScan.style.display = 'none';
    btnStopScan.style.display = 'inline-flex';
    scanBanner.style.display = 'block';

    const targetScopeName = (customPayload && customPayload.cidr) 
      ? customPayload.cidr 
      : (selectedNetworkScope ? selectedNetworkScope.cidr : 'local');

    scanStatusText.textContent = `Iniciando varredura ARP da rede ${targetScopeName}...`;
    scanProgressFill.style.width = '5%';

    // Build payload using chosen network scope
    let payload = customPayload;
    if (!payload) {
      payload = {
        deep_scan: true
      };
      if (selectedNetworkScope) {
        payload.cidr = selectedNetworkScope.cidr;
        payload.ip = selectedNetworkScope.ip;
        payload.netmask = selectedNetworkScope.netmask;
      }
    }

    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (data.status === 'started' || data.status === 'already_scanning') {
      startPollingScan();
    }
  } catch (err) {
    console.error('Erro ao iniciar varredura:', err);
    showToast('Erro ao iniciar varredura de rede', 'error');
    resetScanButtons();
  }
}

async function stopScan() {
  try {
    await fetch('/api/scan-stop', { method: 'POST' });
    showToast('Solicitação de parada enviada', 'info');
  } catch (err) {
    console.error(err);
  }
}

function startPollingScan() {
  if (isPollingScan) return;
  isPollingScan = true;

  pollInterval = setInterval(async () => {
    try {
      const res = await fetch('/api/scan-status');
      const data = await res.json();

      if (data.status === 'success') {
        scanProgressFill.style.width = `${Math.max(5, data.progress)}%`;
        scanStatusText.textContent = data.status_text || 'Escaneando dispositivos...';

        if (data.devices && data.devices.length > 0) {
          currentDevices = data.devices;
          scanStats = data.stats;

          // Save to scope cache
          const scopeKey = (scanStats && scanStats.scope) ? scanStats.scope : (selectedNetworkScope ? selectedNetworkScope.cidr : 'default');
          scopeScanCache[scopeKey] = { stats: scanStats, devices: currentDevices };

          updateDashboardKPIs(data.stats, data.devices.length);
          renderCategoryCounts(data.stats ? data.stats.categories : null);
          renderDevices();
          renderIpamGrid(data.stats, currentDevices);
        }

        if (!data.is_scanning) {
          stopPollingScan();
          scanProgressFill.style.width = '100%';
          setTimeout(() => {
            scanBanner.style.display = 'none';
            resetScanButtons();
          }, 800);
          showToast(`Varredura concluída! ${currentDevices.length} dispositivos ativos encontrados.`, 'success');
        }
      }
    } catch (err) {
      console.error('Erro no polling do scan:', err);
    }
  }, 600);
}

function stopPollingScan() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  isPollingScan = false;
}

function resetScanButtons() {
  btnStartScan.style.display = 'inline-flex';
  btnStopScan.style.display = 'none';
  scanBanner.style.display = 'none';
}

async function checkExistingScanStatus() {
  try {
    const res = await fetch('/api/scan-status');
    const data = await res.json();
    if (data.status === 'success') {
      if (data.is_scanning) {
        btnStartScan.style.display = 'none';
        btnStopScan.style.display = 'inline-flex';
        scanBanner.style.display = 'block';
        startPollingScan();
      } else if (data.devices && data.devices.length > 0) {
        currentDevices = data.devices;
        scanStats = data.stats;
        const scopeKey = (scanStats && scanStats.scope) ? scanStats.scope : 'default';
        scopeScanCache[scopeKey] = { stats: scanStats, devices: currentDevices };
        updateDashboardKPIs(data.stats, data.devices.length);
        renderCategoryCounts(data.stats ? data.stats.categories : null);
        renderDevices();
        renderIpamGrid(data.stats, currentDevices);
      }
    }
  } catch (err) {
    console.error(err);
  }
}

// --- KPI Metrics ---
function updateDashboardKPIs(stats, devicesCount) {
  if (!stats) return;

  const usableIps = stats.usable_ips || stats.total_ips;
  statTotalIps.textContent = usableIps.toLocaleString('pt-BR');
  statSubnetMask.textContent = stats.netmask ? `Máscara ${stats.netmask} (/${stats.prefix_len})` : `Escopo ${stats.scope}`;

  if (stats.first_usable_ip && stats.last_usable_ip) {
    statScopeDesc.textContent = `Faixa: ${stats.first_usable_ip} - ${stats.last_usable_ip}`;
  } else {
    statScopeDesc.textContent = `Escopo: ${stats.scope}`;
  }

  statOccupiedIps.textContent = stats.occupied_ips.toLocaleString('pt-BR');
  statOccupancyRate.textContent = `${stats.occupancy_rate}% em uso`;
  statOccupiedBar.style.width = `${Math.min(100, stats.occupancy_rate)}%`;

  statFreeIps.textContent = stats.free_ips.toLocaleString('pt-BR');
  const freePct = (100 - stats.occupancy_rate).toFixed(1);
  statFreePct.textContent = `${freePct}% livres`;

  statDevicesOnline.textContent = devicesCount.toLocaleString('pt-BR');
  statDuration.textContent = `${stats.duration_sec}s`;
  statLastTime.textContent = `Varredura: ${stats.scanned_at || 'Recente'}`;
}

// --- Category Counters ---
function renderCategoryCounts(counts) {
  document.getElementById('count-all').textContent = currentDevices.length;
  document.getElementById('count-computers').textContent = counts ? (counts.computers || 0) : 0;
  document.getElementById('count-phones').textContent = counts ? (counts.phones || 0) : 0;
  document.getElementById('count-printers').textContent = counts ? (counts.printers || 0) : 0;
  document.getElementById('count-network').textContent = counts ? (counts.network || 0) : 0;
  document.getElementById('count-media').textContent = counts ? (counts.media || 0) : 0;
  document.getElementById('count-iot').textContent = counts ? (counts.iot || 0) : 0;
  document.getElementById('count-unknown').textContent = counts ? (counts.unknown || 0) : 0;
}

// --- Render IPAM Matrix Grid ---
function renderIpamGrid(stats, devices) {
  if (!stats || !devices) return;
  ipamGrid.innerHTML = '';

  const occupiedMap = new Map();
  devices.forEach(d => occupiedMap.set(d.ip, d));

  const totalUsable = stats.usable_ips || stats.total_ips;

  // Handle large subnets (like /16 with 65k IPs) via Sub-block Navigator
  if (totalUsable > 1024 && stats.scope) {
    ipamBlockBar.style.display = 'flex';

    const blocksWithDevices = new Map();
    devices.forEach(d => {
      const parts = d.ip.split('.');
      if (parts.length === 4) {
        const blk = `${parts[0]}.${parts[1]}.${parts[2]}`;
        blocksWithDevices.set(blk, (blocksWithDevices.get(blk) || 0) + 1);
      }
    });

    const currentBlocks = Array.from(blocksWithDevices.keys()).sort();
    if (selectedNetworkScope && selectedNetworkScope.ip) {
      const localBlk = selectedNetworkScope.ip.split('.').slice(0, 3).join('.');
      if (!currentBlocks.includes(localBlk)) {
        currentBlocks.unshift(localBlk);
      }
    }

    selectIpamBlock.innerHTML = '';
    currentBlocks.forEach(blk => {
      const count = blocksWithDevices.get(blk) || 0;
      const opt = document.createElement('option');
      opt.value = blk;
      opt.textContent = `${blk}.x (${count} ativos)`;
      selectIpamBlock.appendChild(opt);
    });

    if (currentSelectedSubBlock && currentBlocks.includes(currentSelectedSubBlock)) {
      selectIpamBlock.value = currentSelectedSubBlock;
    } else if (currentBlocks.length > 0) {
      selectIpamBlock.value = currentBlocks[0];
      currentSelectedSubBlock = currentBlocks[0];
    }

    ipamScopeStatsSummary.textContent = `${stats.occupied_ips} ativos na rede ${stats.scope} (${totalUsable.toLocaleString('pt-BR')} IPs utilizáveis pela máscara ${stats.netmask})`;

    // Render 254 nodes of the selected /24 sub-block
    const activeBase = selectIpamBlock.value || (selectedNetworkScope ? selectedNetworkScope.ip.split('.').slice(0, 3).join('.') : '172.16.50');
    const ipList = [];
    for (let i = 1; i <= 254; i++) {
      ipList.push(`${activeBase}.${i}`);
    }
    renderIpNodes(ipList, occupiedMap);
    return;
  }

  // Standard subnet (<= 1024 IPs like /24, /23, /22)
  ipamBlockBar.style.display = 'none';

  let ipList = [];
  if (stats.scope && stats.scope.includes('/24')) {
    const base = stats.scope.split('/')[0].split('.').slice(0, 3).join('.');
    for (let i = 1; i <= 254; i++) {
      ipList.push(`${base}.${i}`);
    }
  } else if (stats.first_usable_ip && stats.last_usable_ip && totalUsable <= 1024) {
    const startInt = ipToInt(stats.first_usable_ip);
    const endInt = ipToInt(stats.last_usable_ip);
    for (let i = startInt; i <= endInt; i++) {
      ipList.push(intToIp(i));
    }
  } else if (selectedNetworkScope && selectedNetworkScope.ip) {
    const base = selectedNetworkScope.ip.split('.').slice(0, 3).join('.');
    for (let i = 1; i <= 254; i++) {
      ipList.push(`${base}.${i}`);
    }
  } else {
    ipList = devices.map(d => d.ip);
    if (stats.free_ips_sample) {
      ipList = ipList.concat(stats.free_ips_sample.slice(0, 254));
    }
  }

  renderIpNodes(ipList, occupiedMap);
}

function renderIpNodes(ipList, occupiedMap) {
  ipList.forEach(ip => {
    const lastOctet = ip.split('.').pop();
    const dev = occupiedMap.get(ip);
    const node = document.createElement('div');
    node.className = 'ipam-node';
    node.textContent = lastOctet;

    if (dev) {
      if (currentClientIp && dev.ip === currentClientIp) {
        node.classList.add('node-local');
      } else if (dev.is_local) {
        node.classList.add(isRemoteClient ? 'node-occupied' : 'node-local');
      } else if (dev.is_gateway) {
        node.classList.add('node-gateway');
      } else {
        node.classList.add('node-occupied');
      }

      node.addEventListener('mouseenter', (e) => {
        showIpamTooltip(e, `<strong>${dev.icon} ${escapeHtml(dev.display_name)}</strong><br>IP: ${dev.ip}<br>MAC: ${dev.mac}<br>Fabr: ${escapeHtml(dev.vendor)}`);
      });

      node.addEventListener('click', () => {
        highlightDeviceRow(dev.ip);
      });
    } else {
      node.classList.add('node-free');
      node.addEventListener('mouseenter', (e) => {
        showIpamTooltip(e, `<strong>⚪ IP Livre</strong><br>IP: ${ip}<br>Disponível para alocação`);
      });

      node.addEventListener('click', () => {
        navigator.clipboard.writeText(ip);
        showToast(`IP Livre ${ip} copiado para a área de transferência!`, 'info');
      });
    }

    node.addEventListener('mouseleave', () => hideIpamTooltip());
    ipamGrid.appendChild(node);
  });
}

function showIpamTooltip(e, html) {
  ipamTooltip.innerHTML = html;
  ipamTooltip.style.display = 'block';
  const rect = e.target.getBoundingClientRect();
  const wrapperRect = ipamWrapper.getBoundingClientRect();

  let left = rect.left - wrapperRect.left + (rect.width / 2) - 80;
  let top = rect.top - wrapperRect.top - 70;
  if (left < 0) left = 10;
  if (top < 0) top = rect.bottom - wrapperRect.top + 10;

  ipamTooltip.style.left = `${left}px`;
  ipamTooltip.style.top = `${top}px`;
}

function hideIpamTooltip() {
  ipamTooltip.style.display = 'none';
}

function highlightDeviceRow(ip) {
  const row = document.getElementById(`row-${ip.replace(/\./g, '-')}`);
  if (row) {
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
    row.style.background = 'rgba(0, 240, 255, 0.2)';
    setTimeout(() => {
      row.style.background = '';
    }, 2000);
  }
}

// --- Devices Sorting, Filtering & Rendering ---
function setDeviceSort(key, order) {
  currentSortKey = key;
  currentSortOrder = order;

  // 1. Sync dropdown
  if (selectDeviceSort) {
    selectDeviceSort.value = `${key}-${order}`;
  }

  // 2. Sync table header classes and arrows
  document.querySelectorAll('.th-sortable').forEach(th => {
    const icon = th.querySelector('.sort-icon');
    if (th.dataset.sort === key) {
      th.classList.remove('sorted-asc', 'sorted-desc');
      th.classList.add(order === 'asc' ? 'sorted-asc' : 'sorted-desc');
      if (icon) icon.textContent = order === 'asc' ? '▲' : '▼';
    } else {
      th.classList.remove('sorted-asc', 'sorted-desc');
      if (icon) icon.textContent = '↕';
    }
  });

  // 3. Re-render devices
  renderDevices();
}

function sortDevicesList(devices, key, order) {
  const mult = order === 'desc' ? -1 : 1;

  return [...devices].sort((a, b) => {
    let cmp = 0;

    switch (key) {
      case 'status': {
        const scoreA = (a.is_local ? 100 : 0) + (a.is_gateway ? 50 : 0) + (a.is_online ? 10 : 0);
        const scoreB = (b.is_local ? 100 : 0) + (b.is_gateway ? 50 : 0) + (b.is_online ? 10 : 0);
        cmp = scoreA - scoreB;
        break;
      }
      case 'name': {
        const nameA = (a.display_name || a.hostname || a.ip || '').toLowerCase();
        const nameB = (b.display_name || b.hostname || b.ip || '').toLowerCase();
        cmp = nameA.localeCompare(nameB, 'pt-BR', { numeric: true, sensitivity: 'base' });
        break;
      }
      case 'category': {
        const catA = (a.category_label || a.category || '').toLowerCase();
        const catB = (b.category_label || b.category || '').toLowerCase();
        cmp = catA.localeCompare(catB, 'pt-BR');
        break;
      }
      case 'ip': {
        cmp = ipToInt(a.ip) - ipToInt(b.ip);
        break;
      }
      case 'mac': {
        const macA = a.mac || '';
        const macB = b.mac || '';
        cmp = macA.localeCompare(macB);
        break;
      }
      case 'vendor': {
        const venA = (a.vendor || '').toLowerCase();
        const venB = (b.vendor || '').toLowerCase();
        cmp = venA.localeCompare(venB, 'pt-BR');
        break;
      }
      case 'latency': {
        const latA = (a.latency_ms !== undefined && a.latency_ms !== null) ? Number(a.latency_ms) : 99999;
        const latB = (b.latency_ms !== undefined && b.latency_ms !== null) ? Number(b.latency_ms) : 99999;
        cmp = latA - latB;
        break;
      }
      case 'ports': {
        const pA = a.open_ports ? a.open_ports.length : 0;
        const pB = b.open_ports ? b.open_ports.length : 0;
        cmp = pA - pB;
        break;
      }
      default:
        cmp = ipToInt(a.ip) - ipToInt(b.ip);
        break;
    }

    if (cmp !== 0) {
      return cmp * mult;
    }
    // Fallback tie-breaker: numeric IP ascending
    return ipToInt(a.ip) - ipToInt(b.ip);
  });
}

function getFilteredDevices() {
  const filtered = currentDevices.filter(d => {
    if (activeCategory !== 'all' && d.category !== activeCategory) {
      return false;
    }
    if (searchQuery) {
      const match =
        d.ip.toLowerCase().includes(searchQuery) ||
        (d.mac && d.mac.toLowerCase().includes(searchQuery)) ||
        (d.display_name && d.display_name.toLowerCase().includes(searchQuery)) ||
        (d.hostname && d.hostname.toLowerCase().includes(searchQuery)) ||
        (d.vendor && d.vendor.toLowerCase().includes(searchQuery)) ||
        (d.category_label && d.category_label.toLowerCase().includes(searchQuery)) ||
        (d.notes && d.notes.toLowerCase().includes(searchQuery));
      if (!match) return false;
    }
    return true;
  });

  return sortDevicesList(filtered, currentSortKey, currentSortOrder);
}

function setViewMode(mode) {
  viewMode = mode;
  if (viewBtnTable && viewBtnCards) {
    if (mode === 'table') {
      viewBtnTable.classList.add('active');
      viewBtnCards.classList.remove('active');
    } else {
      viewBtnCards.classList.add('active');
      viewBtnTable.classList.remove('active');
    }
  }
  renderDevices();
}

function renderDevices() {
  const filtered = getFilteredDevices();
  resultsCount.textContent = `${filtered.length} de ${currentDevices.length} dispositivos`;

  if (viewMode === 'table') {
    renderTable(filtered);
  } else {
    renderCards(filtered);
  }
}

function renderTable(devices) {
  tableContainer.style.display = 'block';
  cardsContainer.style.display = 'none';

  if (devices.length === 0) {
    const scopeLabel = selectedNetworkScope ? selectedNetworkScope.cidr : 'esta rede';
    devicesTableBody.innerHTML = `
      <tr>
        <td colspan="9" class="empty-state">
          <div class="empty-icon">📡</div>
          <h3>Nenhum dispositivo mapeado em ${scopeLabel}</h3>
          <p>Clique em <strong>"Escanear Rede"</strong> para iniciar a varredura completa dos IPs desta sub-rede.</p>
        </td>
      </tr>
    `;
    return;
  }

  devicesTableBody.innerHTML = devices.map(d => {
    const rowId = `row-${d.ip.replace(/\./g, '-')}`;
    const portsHtml = (d.open_ports && d.open_ports.length > 0)
      ? d.open_ports.map(p => `<span class="port-pill">${p}</span>`).join('')
      : '<span style="color: var(--text-dim); font-size: 0.72rem;">Nenhuma</span>';

    const isClientDevice = (currentClientIp && d.ip === currentClientIp);
    const hostTag = isClientDevice
      ? '<span class="tag-local" style="background: var(--accent-cyan); color: #020617; font-weight: 700;">SEU DISPOSITIVO</span>'
      : (d.is_local
          ? (isRemoteClient ? '<span class="tag-local" style="background: rgba(147, 51, 234, 0.2); color: #c084fc; border: 1px solid rgba(147, 51, 234, 0.4);">SERVIDOR</span>' : '<span class="tag-local">MEU PC</span>')
          : '');

    return `
      <tr id="${rowId}">
        <td><span class="status-online" title="Online (${d.latency_ms} ms)"></span></td>
        <td>
          <div class="device-ident">
            <span class="device-name">
              ${escapeHtml(d.display_name)}
              ${hostTag}
              ${d.is_gateway ? '<span class="tag-gateway">ROTEADOR</span>' : ''}
            </span>
            <span class="device-sub">${escapeHtml(d.hostname || d.web_title || 'Sem nome DNS')}</span>
          </div>
        </td>
        <td>
          <span class="badge-cat cat-${d.category}">
            ${d.icon} ${escapeHtml(d.category_label)}
          </span>
        </td>
        <td class="mono"><strong>${d.ip}</strong></td>
        <td class="mono" style="color: var(--text-muted); font-size: 0.8rem;">${d.mac || 'N/A'}</td>
        <td style="color: var(--text-muted); font-size: 0.82rem;">${escapeHtml(d.vendor)}</td>
        <td class="mono" style="color: var(--accent-cyan); font-size: 0.8rem;">${d.latency_ms} ms</td>
        <td><div class="ports-list">${portsHtml}</div></td>
        <td>
          <div class="table-actions">
            <button class="action-btn" title="Editar Nome/Categoria" onclick="openEditModal('${d.mac}', '${d.ip}')">
              ✏️
            </button>
            <button class="action-btn" title="Testar Latência (Ping)" onclick="pingDevice('${d.ip}')">
              ⚡
            </button>
            <button class="action-btn" title="Wake-on-LAN (Ligar Computador)" onclick="wolDevice('${d.mac}')">
              ⏰
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function renderCards(devices) {
  tableContainer.style.display = 'none';
  cardsContainer.style.display = 'grid';

  if (devices.length === 0) {
    cardsContainer.innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-icon">🔍</div>
        <h3>Nenhum dispositivo encontrado nesta visualização</h3>
      </div>
    `;
    return;
  }

  cardsContainer.innerHTML = devices.map(d => {
    const isClientDevice = (currentClientIp && d.ip === currentClientIp);
    const hostTag = isClientDevice
      ? '<span class="tag-local" style="background: var(--accent-cyan); color: #020617; font-weight: 700;">SEU DISPOSITIVO</span>'
      : (d.is_local
          ? (isRemoteClient ? '<span class="tag-local" style="background: rgba(147, 51, 234, 0.2); color: #c084fc; border: 1px solid rgba(147, 51, 234, 0.4);">SERVIDOR</span>' : '<span class="tag-local">MEU PC</span>')
          : '');

    return `
      <div class="device-card">
        <div class="device-card-header">
          <div class="device-ident">
            <span class="device-name">
              ${escapeHtml(d.display_name)}
              ${hostTag}
              ${d.is_gateway ? '<span class="tag-gateway">ROTEADOR</span>' : ''}
            </span>
            <span class="device-sub">${escapeHtml(d.hostname || 'Sem nome DNS')}</span>
          </div>
          <span class="badge-cat cat-${d.category}">
            ${d.icon} ${escapeHtml(d.category_label)}
          </span>
        </div>

        <div class="device-card-body">
          <div class="card-meta-row">
            <span>Endereço IP:</span>
            <span class="mono"><strong>${d.ip}</strong></span>
          </div>
          <div class="card-meta-row">
            <span>Endereço MAC:</span>
            <span class="mono">${d.mac || 'N/A'}</span>
          </div>
          <div class="card-meta-row">
            <span>Fabricante:</span>
            <span>${escapeHtml(d.vendor)}</span>
          </div>
          <div class="card-meta-row">
            <span>Latência:</span>
            <span class="mono" style="color: var(--accent-cyan);">${d.latency_ms} ms</span>
          </div>
        </div>

        <div class="device-card-footer">
          <span style="font-size: 0.72rem; color: var(--text-dim);">${d.open_ports.length} portas abertas</span>
          <div class="table-actions">
            <button class="action-btn" onclick="openEditModal('${d.mac}', '${d.ip}')">✏️ Editar</button>
            <button class="action-btn" onclick="pingDevice('${d.ip}')">⚡ Ping</button>
            <button class="action-btn" onclick="wolDevice('${d.mac}')">⏰ WOL</button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function setViewMode(mode) {
  viewMode = mode;
  if (mode === 'table') {
    viewBtnTable.classList.add('active');
    viewBtnCards.classList.remove('active');
  } else {
    viewBtnCards.classList.add('active');
    viewBtnTable.classList.remove('active');
  }
  renderDevices();
}

// --- Quick Device Actions (Ping, WOL, Edit) ---
async function pingDevice(ip) {
  showToast(`Enviando ping para ${ip}...`, 'info');
  try {
    const res = await fetch('/api/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.status === 'online') {
      showToast(`⚡ ${ip} respondeu em ${data.latency_ms} ms!`, 'success');
      const dev = currentDevices.find(d => d.ip === ip);
      if (dev) {
        dev.latency_ms = data.latency_ms;
        renderDevices();
      }
    } else {
      showToast(`❌ ${ip} não respondeu ao ping.`, 'warning');
    }
  } catch (err) {
    showToast(`Erro ao testar ping em ${ip}`, 'error');
  }
}

async function wolDevice(mac) {
  if (!mac || mac === 'N/A') {
    showToast('MAC address não disponível para este dispositivo', 'warning');
    return;
  }
  showToast(`Enviando Magic Packet WOL para ${mac}...`, 'info');
  try {
    const res = await fetch('/api/wol', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac })
    });
    const data = await res.json();
    if (data.status === 'success') {
      showToast(data.message, 'success');
    } else {
      showToast(data.message, 'error');
    }
  } catch (err) {
    showToast('Falha ao enviar Wake-on-LAN', 'error');
  }
}

// --- Device Edit Modal ---
function openEditModal(mac, ip) {
  const dev = currentDevices.find(d => d.ip === ip || d.mac === mac);
  if (!dev) return;

  editIp.value = dev.ip;
  editMac.value = dev.mac || '';
  editName.value = dev.display_name || '';
  editCategory.value = dev.category || 'unknown';
  editNotes.value = dev.notes || '';

  modalEdit.style.display = 'flex';
}

function closeEditModal() {
  modalEdit.style.display = 'none';
}

async function handleSaveDevice() {
  const mac = editMac.value;
  const ip = editIp.value;
  const custom_name = editName.value.trim();
  const custom_category = editCategory.value;
  const notes = editNotes.value.trim();

  try {
    const res = await fetch('/api/device/update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mac, custom_name, custom_category, notes })
    });

    const data = await res.json();
    if (data.status === 'success') {
      showToast('Dispositivo atualizado com sucesso!', 'success');
      const dev = currentDevices.find(d => d.ip === ip || d.mac === mac);
      if (dev) {
        dev.display_name = custom_name || dev.display_name;
        dev.category = custom_category;
        dev.notes = notes;
        dev.is_custom = true;
      }
      closeEditModal();
      renderDevices();
    }
  } catch (err) {
    showToast('Erro ao salvar customização do dispositivo', 'error');
  }
}

// --- Scope Config Modal & Triggering Complete Scan ---
function openScopeModal() {
  modalScope.style.display = 'flex';
  updateCalculatorPreview();
}

function closeScopeModal() {
  modalScope.style.display = 'none';
}

async function handleSaveScopeAndScan() {
  const selectedMode = document.querySelector('input[name="scope_mode"]:checked').value;
  const deepScan = checkDeepScan.checked;
  let payload = { deep_scan: deepScan };

  if (selectedMode === 'detected') {
    const selectedRadio = document.querySelector('input[name="detected_scope_select"]:checked');
    if (!selectedRadio) {
      showToast('Selecione uma das sub-redes detectadas', 'warning');
      return;
    }
    const cidr = selectedRadio.value;
    const sc = availableScopes.find(s => s.cidr === cidr);
    if (sc) {
      setSelectedScope(sc);
    }
    payload.cidr = cidr;
    payload.ip = selectedRadio.dataset.ip;
    payload.netmask = selectedRadio.dataset.mask;
  } else if (selectedMode === 'by_mask') {
    const ip = calcInputIp.value.trim();
    let mask = calcSelectMask.value;
    if (mask === 'custom') {
      mask = calcCustomMaskInput.value.trim();
    }
    if (!ip || !mask) {
      showToast('Informe o IP base e a máscara de sub-rede', 'warning');
      return;
    }

    // Calculate scope parameters
    const calc = calculateSubnetLocally(ip, mask);
    if (calc) {
      const customScope = {
        ip: ip,
        netmask: mask,
        prefix_len: calc.prefix,
        cidr: calc.cidr,
        network_ip: calc.network,
        broadcast_ip: calc.broadcast,
        first_usable_ip: calc.first,
        last_usable_ip: calc.last,
        total_ips: calc.total,
        usable_ips: calc.usable,
        gateway: 'N/A',
        is_gateway_scope: false
      };

      if (!availableScopes.some(s => s.cidr === calc.cidr)) {
        availableScopes.push(customScope);
        renderNetworkDropdown(availableScopes);
      }
      setSelectedScope(customScope);
    }

    payload.ip = ip;
    payload.netmask = mask;
    if (calc) payload.cidr = calc.cidr;
  } else if (selectedMode === 'custom_range') {
    const start = inputRangeStart.value.trim();
    const end = inputRangeEnd.value.trim();
    if (!start || !end) {
      showToast('Informe o IP de início e o IP de fim', 'warning');
      return;
    }
    payload.custom_range = [start, end];
  }

  closeScopeModal();
  startScan(payload);
}

// --- Toast Notifications ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';

  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'warning') icon = '⚠️';
  if (type === 'error') icon = '❌';

  toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => ((acc << 8) + parseInt(oct, 10)) >>> 0, 0);
}

function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.');
}
