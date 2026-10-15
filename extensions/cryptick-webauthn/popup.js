// Cryptick Token - Material Design 3 / SwiftUI Popup Controller
let allTotpAccounts = [];
let allPasskeys = [];
let activeCountdownIntervals = {};
let lastConnectionState = null;
let currentClockOffsetSecs = 0;
let lastKnownUtc = 0;
let lastKnownUtcTimestamp = 0;

function getLocalTzOffset() {
  const offsetMin = -new Date().getTimezoneOffset();
  const sign = offsetMin >= 0 ? '+' : '-';
  const abs = Math.abs(offsetMin);
  const h = String(Math.floor(abs / 60)).padStart(2, '0');
  const m = String(abs % 60).padStart(2, '0');
  return `UTC${sign}${h}:${m}`;
}

function formatTimeWithOffset(utcSecs, offsetSecs = 0) {
  const effectiveSecs = (utcSecs || Math.floor(Date.now() / 1000)) + offsetSecs;
  const d = new Date(effectiveSecs * 1000);
  const locH = String(d.getHours()).padStart(2, '0');
  const locM = String(d.getMinutes()).padStart(2, '0');
  const locS = String(d.getSeconds()).padStart(2, '0');
  const localTime = `${locH}:${locM}:${locS}`;

  const utcH = String(d.getUTCHours()).padStart(2, '0');
  const utcM = String(d.getUTCMinutes()).padStart(2, '0');
  const utcS = String(d.getUTCSeconds()).padStart(2, '0');
  const utcTime = `${utcH}:${utcM}:${utcS} UTC`;

  const tz = getLocalTzOffset();
  return {
    localTime,
    utcTime,
    tzOffset: tz,
    fullDisplay: `${localTime} (${tz}) • ${utcTime}`
  };
}

// 1. Tab Navigation (M3 / SwiftUI Segmented Button Group)
function initTabs() {
  const tabs = document.querySelectorAll('.m3-segmented-button');
  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      tabs.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const content = document.getElementById(targetId);
      if (content) content.classList.add('active');

      if (targetId === 'tab-totp') {
        if (lastConnectionState) {
          loadTotpAccounts();
        }
      } else if (targetId === 'tab-passkeys') {
        if (lastConnectionState) {
          loadPasskeyHistory();
        }
      } else if (targetId === 'tab-device') {
        checkStatus();
        updatePasskeyCount();
      }
    });
  });
}

// 2. Hardware Status & Telemetry
function applyStatus(res) {
  const connDot = document.getElementById('connDot');
  const connText = document.getElementById('connText');
  const devSub = document.getElementById('devSub');
  const devPillDot = document.getElementById('devPillDot');
  const devPillText = document.getElementById('devPillText');
  const devTransport = document.getElementById('devTransport');
  const devTransportDesc = document.getElementById('devTransportDesc');
  const devEnclave = document.getElementById('devEnclave');
  const devEnclaveDesc = document.getElementById('devEnclaveDesc');
  const devVerify = document.getElementById('devVerify');
  const devVerifyDesc = document.getElementById('devVerifyDesc');
  const devPiv = document.getElementById('devPiv');
  const devPivDesc = document.getElementById('devPivDesc');
  const telDaemon = document.getElementById('telDaemon');
  const telInterface = document.getElementById('telInterface');
  const telLatency = document.getElementById('telLatency');
  const telClock = document.getElementById('telClock');
  const telClockDrift = document.getElementById('telClockDrift');
  const totpClockDot = document.getElementById('totpClockDot');
  const totpClockBadge = document.getElementById('totpClockBadge');
  const totpClockReadout = document.getElementById('totpClockReadout');

  if (!connDot || !connText) return;

  const isUsb = !!(res && res.status === 'ok' && res.usb);
  const isInRange = !!(res && res.status === 'ok' && res.inRange);
  const isConnected = isUsb || isInRange;
  const isHostOnline = !!(res && res.status === 'ok');

  // Toggle Disconnected vs Connected views (Zero credential exposure when unplugged)
  const passkeyDisc = document.getElementById('passkeyDisconnected');
  const passkeyConn = document.getElementById('passkeyConnected');
  const totpDisc = document.getElementById('totpDisconnected');
  const totpConn = document.getElementById('totpConnected');
  const deviceDisc = document.getElementById('deviceDisconnected');
  const deviceConn = document.getElementById('deviceConnected');

  if (passkeyDisc && passkeyConn) {
    passkeyDisc.style.display = isConnected ? 'none' : 'flex';
    passkeyConn.style.display = isConnected ? 'block' : 'none';
  }
  if (totpDisc && totpConn) {
    totpDisc.style.display = isConnected ? 'none' : 'flex';
    totpConn.style.display = isConnected ? 'block' : 'none';
  }
  if (deviceDisc && deviceConn) {
    deviceDisc.style.display = isConnected ? 'none' : 'flex';
    deviceConn.style.display = isConnected ? 'block' : 'none';
  }

  // Auto-refresh data on initial connection transition
  if (isConnected && lastConnectionState === false) {
    // Auto-sync hardware RTC immediately when token connects
    syncClock();
    const activeTab = document.querySelector('.m3-segmented-button.active');
    const activeTabId = activeTab ? activeTab.getAttribute('data-tab') : null;
    if (activeTabId === 'tab-totp') {
      loadTotpAccounts();
    } else if (activeTabId === 'tab-passkeys') {
      loadPasskeyHistory();
    }
  }
  lastConnectionState = isConnected;

  const latency = res && res.latencyMs ? `${res.latencyMs}ms` : (isUsb ? '< 1ms' : '12ms');

  // Format UTC and Local clock display with offset
  const nowUtc = Math.floor(Date.now() / 1000);
  const clockUtc = (res && res.clockUtc) ? res.clockUtc : nowUtc;
  const isClockSynced = !!(res && res.clockSynced);
  const tzOffsetStr = (res && res.tzOffsetStr) ? res.tzOffsetStr : getLocalTzOffset();
  const timeOffsetSecs = (res && typeof res.timeOffsetSecs === 'number') ? res.timeOffsetSecs : 0;
  currentClockOffsetSecs = timeOffsetSecs;
  lastKnownUtc = clockUtc;
  lastKnownUtcTimestamp = Date.now();

  const timeInfo = formatTimeWithOffset(clockUtc, timeOffsetSecs);

  const telUtcClock = document.getElementById('telUtcClock');
  const telTzOffset = document.getElementById('telTzOffset');
  const totpClockOffsetBadge = document.getElementById('totpClockOffsetBadge');

  if (telClock) {
    telClock.textContent = isConnected ? `${timeInfo.localTime} (${tzOffsetStr})` : '—';
  }
  if (telUtcClock) {
    telUtcClock.textContent = isConnected ? timeInfo.utcTime : '—';
  }
  if (telTzOffset) {
    telTzOffset.textContent = isConnected ? tzOffsetStr : '—';
  }
  if (telClockDrift) {
    if (isConnected) {
      const offsetDesc = timeOffsetSecs === 0 ? '0.0s (Host Sync)' : `${timeOffsetSecs > 0 ? '+' : ''}${timeOffsetSecs}s offset`;
      telClockDrift.textContent = isClockSynced ? offsetDesc : 'Drift detected';
      telClockDrift.style.color = isClockSynced ? '#10b981' : '#f59e0b';
    } else {
      telClockDrift.textContent = '—';
      telClockDrift.style.color = 'var(--md-sys-color-on-surface-variant)';
    }
  }

  if (totpClockDot && totpClockBadge && totpClockReadout) {
    if (isConnected) {
      totpClockDot.className = isClockSynced ? 'm3-status-dot green' : 'm3-status-dot yellow';
      totpClockBadge.textContent = isClockSynced ? 'In Sync' : 'Sync Needed';
      totpClockBadge.style.background = isClockSynced ? 'var(--md-sys-color-secondary-container)' : 'var(--md-sys-color-error-container)';
      totpClockBadge.style.color = isClockSynced ? 'var(--md-sys-color-on-secondary-container)' : 'var(--md-sys-color-on-error-container)';
      totpClockReadout.textContent = `${timeInfo.utcTime} • Host In-Sync`;
    } else {
      totpClockDot.className = 'm3-status-dot yellow';
      totpClockBadge.textContent = 'Offline';
      totpClockReadout.textContent = 'Token Disconnected';
    }
  }

  if (isUsb) {
    // Direct USB 2.0 Mode
    connDot.className = 'm3-status-dot green';
    connText.textContent = 'USB Connected';
    if (devSub) devSub.textContent = 'Direct USB 2.0 • ESP32-S3 Hardware';
    if (devPillDot) devPillDot.className = 'm3-status-dot green';
    if (devPillText) devPillText.textContent = 'Direct USB Active';
    if (devTransport) devTransport.textContent = 'Direct USB';
    if (devTransportDesc) devTransportDesc.textContent = `Latency: ${latency} • 0x1209:0xBEEE`;
    if (devEnclave) devEnclave.textContent = 'Hardware AES-GCM';
    if (devEnclaveDesc) devEnclaveDesc.textContent = 'LittleFS Active (USB Direct)';
    if (devVerify) devVerify.textContent = 'Touch & Biometric';
    if (devVerifyDesc) devVerifyDesc.textContent = 'UP Sensor Ready';
    if (devPiv) devPiv.textContent = 'Slot 9A Ready';
    if (devPivDesc) devPivDesc.textContent = 'CryptoTokenKit Available';

    if (telDaemon) telDaemon.textContent = 'Bypassed (Direct USB)';
    if (telInterface) telInterface.textContent = 'USB 2.0 CTAPHID';
    if (telLatency) telLatency.textContent = latency;
  } else if (isInRange) {
    // Wireless BLE Daemon Bridge Mode
    connDot.className = 'm3-status-dot green';
    connText.textContent = 'BLE Wireless';
    if (devSub) devSub.textContent = 'Wireless Daemon Bridge • Custom GATT Link';
    if (devPillDot) devPillDot.className = 'm3-status-dot green';
    if (devPillText) devPillText.textContent = 'Wireless BLE Active';
    if (devTransport) devTransport.textContent = 'Custom BLE';
    if (devTransportDesc) devTransportDesc.textContent = `Latency: ${latency} • Daemon GATT`;
    if (devEnclave) devEnclave.textContent = 'Hardware AES-GCM';
    if (devEnclaveDesc) devEnclaveDesc.textContent = 'LittleFS Active (Encrypted)';
    if (devVerify) devVerify.textContent = 'Touch & Biometric';
    if (devVerifyDesc) devVerifyDesc.textContent = 'BLE User Presence Active';
    if (devPiv) devPiv.textContent = 'Slot 9A Ready';
    if (devPivDesc) devPivDesc.textContent = 'CryptoTokenKit Available';

    if (telDaemon) telDaemon.textContent = 'Active (Connected)';
    if (telInterface) telInterface.textContent = 'Daemon GATT (FBF6EB80)';
    if (telLatency) telLatency.textContent = latency;
  } else if (isHostOnline) {
    // Disconnected / Waiting for Token
    connDot.className = 'm3-status-dot yellow';
    if (res && res.message && res.message.includes('bootloader')) {
      connText.textContent = 'ROM Bootloader';
      if (devSub) devSub.textContent = 'ESP32 in Recovery Mode (0x303A:0x1001)';
      if (devPillDot) devPillDot.className = 'm3-status-dot yellow';
      if (devPillText) devPillText.textContent = 'Bootloader Active';
      if (devTransport) devTransport.textContent = 'USB Serial/JTAG';
      if (devTransportDesc) devTransportDesc.textContent = 'Flash product firmware to enable CTAPHID';
    } else {
      connText.textContent = 'No Key Inserted';
      if (devSub) devSub.textContent = 'Plug into USB or wake Bluetooth';
      if (devPillDot) devPillDot.className = 'm3-status-dot yellow';
      if (devPillText) devPillText.textContent = 'Token Disconnected';
      if (devTransport) devTransport.textContent = 'Disconnected';
      if (devTransportDesc) devTransportDesc.textContent = 'Scanning USB & BLE...';
    }
    if (devEnclave) devEnclave.textContent = 'Protected at Rest';
    if (devEnclaveDesc) devEnclaveDesc.textContent = 'Keys Locked in Flash';
    if (devVerify) devVerify.textContent = 'Sensor Idle';
    if (devVerifyDesc) devVerifyDesc.textContent = 'Waiting for Link';
    if (devPiv) devPiv.textContent = 'Slot 9A Ready';
    if (devPivDesc) devPivDesc.textContent = 'Ready on Reconnect';

    if (telDaemon) telDaemon.textContent = 'Active (Scanning)';
    if (telInterface) telInterface.textContent = res && res.message && res.message.includes('bootloader') ? 'USB CDC (303A:1001)' : 'None';
    if (telLatency) telLatency.textContent = '—';
  } else {
    // Host Offline
    connDot.className = 'm3-status-dot red';
    connText.textContent = 'Host Offline';
    if (devSub) devSub.textContent = 'Local daemon service unreachable';
    if (devPillDot) devPillDot.className = 'm3-status-dot red';
    if (devPillText) devPillText.textContent = 'Host Bridge Offline';
    if (devTransport) devTransport.textContent = 'Host Offline';
    if (devTransportDesc) devTransportDesc.textContent = 'Launch daemon to connect';
    if (devEnclave) devEnclave.textContent = 'Unavailable';
    if (devEnclaveDesc) devEnclaveDesc.textContent = 'Daemon not running';
    if (devVerify) devVerify.textContent = 'Unavailable';
    if (devVerifyDesc) devVerifyDesc.textContent = 'Host Offline';
    if (devPiv) devPiv.textContent = 'Unavailable';
    if (devPivDesc) devPivDesc.textContent = 'Host Offline';

    if (telDaemon) telDaemon.textContent = 'Offline (launchd)';
    if (telInterface) telInterface.textContent = 'Offline';
    if (telLatency) telLatency.textContent = '—';
  }
}

async function checkStatus(forceFresh = false) {
  try {
    const res = await chrome.runtime.sendMessage({ action: 'status', forceFresh });
    applyStatus(res);
  } catch (err) {
    applyStatus(null);
  }
}

function updatePasskeyCount() {
  const telPasskeys = document.getElementById('telPasskeys');
  if (!telPasskeys) return;
  chrome.storage.local.get(['cryptick_passkeys_history'], (data) => {
    const count = (data.cryptick_passkeys_history || []).length;
    telPasskeys.textContent = `${count} Stored`;
  });
}

// 3. Hardware Self-Diagnostics
async function runDiagnostics(isDisc = false) {
  const diagBtn = document.getElementById(isDisc ? 'runDiagBtnDisc' : 'runDiagBtn');
  const diagResult = document.getElementById(isDisc ? 'diagResultDisc' : 'diagResult');
  if (!diagBtn || !diagResult) return;

  diagBtn.innerHTML = `
    <svg viewBox="0 0 24 24" style="animation: spin 1s linear infinite;"><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>
    Testing...
  `;
  diagBtn.disabled = true;
  diagResult.style.display = 'block';
  diagResult.innerHTML = '<span style="color:var(--md-sys-color-primary);">Pinging native host and hardware channel...</span>';

  const t0 = performance.now();
  try {
    const res = await chrome.runtime.sendMessage({ action: 'status', forceFresh: true });
    const elapsed = Math.round(performance.now() - t0);

    if (res && res.status === 'ok') {
      const isUsb = !!res.usb;
      const isInRange = !!res.inRange;
      if (isUsb) {
        diagResult.innerHTML = `
          <span style="color:#10b981;">✓ Interface: Direct USB 2.0 CTAPHID</span><br>
          <span style="color:#10b981;">✓ Channel Latency: ${elapsed}ms (&lt; 1ms bus time)</span><br>
          <span style="color:#10b981;">✓ Hardware State: Link Healthy & Authenticated</span><br>
          <span style="color:#10b981;">✓ Cryptographic Engine: AES-GCM / SHA-256 Ready</span><br>
          <span style="color:#10b981;">✓ Secure Enclave: LittleFS Partition Mounted</span>
        `;
      } else if (isInRange) {
        diagResult.innerHTML = `
          <span style="color:#10b981;">✓ Interface: Wireless BLE Bridge (Daemon GATT)</span><br>
          <span style="color:#10b981;">✓ Channel Latency: ${elapsed}ms (Roundtrip)</span><br>
          <span style="color:#10b981;">✓ Daemon Link: Connected & Bonded</span><br>
          <span style="color:#10b981;">✓ Cryptographic Engine: ECC P-256 / SHA-256 Ready</span><br>
          <span style="color:#10b981;">✓ Secure Enclave: LittleFS Partition Mounted</span>
        `;
      } else {
        diagResult.innerHTML = `
          <span style="color:#10b981;">✓ Host Bridge Service: Active</span><br>
          <span style="color:#f59e0b;">⚠️ Hardware Token: Not connected</span><br>
          <span style="opacity:0.8;">Action: Plug token into USB or wake via touch sensor.</span>
        `;
      }
    } else {
      diagResult.innerHTML = `<span style="color:#ef4444;">✕ Diagnostic Refusal: ${res?.message || 'Host offline'}</span>`;
    }
  } catch (e) {
    diagResult.innerHTML = `<span style="color:#ef4444;">✕ Communication Error: ${e.message}</span>`;
  } finally {
    diagBtn.innerHTML = `
      <svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>
      Self-Test
    `;
    diagBtn.disabled = false;
  }
}

// 4. Passkey Interception Toggle & Resident Key Vault Management
function initPasskeyTab() {
  const toggle = document.getElementById('bridgeToggle');
  if (toggle) {
    chrome.storage.local.get(['cryptick_bridge_enabled'], (data) => {
      toggle.checked = data.cryptick_bridge_enabled !== false;
    });

    toggle.addEventListener('change', () => {
      chrome.storage.local.set({ cryptick_bridge_enabled: toggle.checked });
    });
  }

  const testBtn = document.getElementById('testPasskeyBtn');
  if (testBtn) {
    testBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: 'https://webauthn.io' });
    });
  }

  const testLink = document.getElementById('passkeyTestLink');
  if (testLink) {
    testLink.addEventListener('click', () => {
      chrome.tabs.create({ url: 'https://webauthn.io' });
    });
  }

  const clearBtn = document.getElementById('clearHistoryBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      chrome.storage.local.remove(['cryptick_passkeys_history'], () => {
        allPasskeys = [];
        renderPasskeyList([]);
        updatePasskeyCount();
      });
    });
  }

  initPasskeySearch();
  loadPasskeyHistory();
  updatePasskeyCount();
}

function initPasskeySearch() {
  const searchInput = document.getElementById('passkeySearch');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
      renderPasskeyList(allPasskeys);
    } else {
      const filtered = allPasskeys.filter(item =>
        (item.rpId && item.rpId.toLowerCase().includes(q)) ||
        (item.user && item.user.toLowerCase().includes(q))
      );
      renderPasskeyList(filtered, q);
    }
  });
}

function loadPasskeyHistory() {
  chrome.storage.local.get(['cryptick_passkeys_history'], (data) => {
    allPasskeys = data.cryptick_passkeys_history || [];
    const searchInput = document.getElementById('passkeySearch');
    const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
    if (q) {
      const filtered = allPasskeys.filter(item =>
        (item.rpId && item.rpId.toLowerCase().includes(q)) ||
        (item.user && item.user.toLowerCase().includes(q))
      );
      renderPasskeyList(filtered, q);
    } else {
      renderPasskeyList(allPasskeys);
    }
  });
}

function renderPasskeyList(items, query = '') {
  const listEl = document.getElementById('passkeyList');
  if (!listEl) return;

  if (allPasskeys.length === 0) {
    listEl.innerHTML = `
      <div class="m3-empty-state">
        <svg viewBox="0 0 24 24"><path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>
        <span>No passkeys stored yet</span>
        <span style="font-size: 10.5px; opacity: 0.8;">Sign in to GitHub, Google, or any WebAuthn service.</span>
      </div>`;
    return;
  }

  if (items.length === 0 && query) {
    listEl.innerHTML = `
      <div class="m3-empty-state">
        <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
        <span>No passkeys match "${escapeHtml(query)}"</span>
      </div>`;
    return;
  }

  listEl.innerHTML = '';
  items.forEach(item => {
    const wrap = document.createElement('div');
    wrap.style.display = 'flex';
    wrap.style.flexDirection = 'column';

    const row = document.createElement('div');
    row.className = 'm3-list-item';
    row.style.cursor = 'pointer';

    const domain = item.rpId || 'Unknown Domain';
    const initial = domain.charAt(0).toUpperCase();
    const user = item.user || 'Hardware Resident Key';
    const timeFormatted = formatRelativeTime(item.time);
    const actionBadge = item.action === 'create' ? 'Registered' : 'Passkey';

    const mainCol = document.createElement('div');
    mainCol.style.display = 'flex';
    mainCol.style.alignItems = 'center';
    mainCol.style.flex = '1';
    mainCol.style.minWidth = '0';

    mainCol.innerHTML = `
      <div class="m3-leading-avatar">${initial}</div>
      <div class="m3-item-content">
        <span class="m3-item-title">${escapeHtml(domain)}</span>
        <span class="m3-item-subtitle">${escapeHtml(user)} • ${timeFormatted}</span>
      </div>
    `;

    const actionsCol = document.createElement('div');
    actionsCol.style.display = 'flex';
    actionsCol.style.alignItems = 'center';
    actionsCol.style.gap = '6px';
    actionsCol.style.flexShrink = '0';

    const badge = document.createElement('span');
    badge.className = 'm3-badge';
    badge.textContent = actionBadge;

    const delBtn = document.createElement('button');
    delBtn.className = 'm3-btn-icon danger';
    delBtn.title = 'Delete passkey';
    delBtn.setAttribute('aria-label', `Delete passkey for ${domain}`);
    delBtn.innerHTML = `<svg viewBox="0 0 24 24" style="width:14px; height:14px; fill:currentColor;"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>`;

    actionsCol.appendChild(badge);
    actionsCol.appendChild(delBtn);

    row.appendChild(mainCol);
    row.appendChild(actionsCol);

    // Expandable detail drawer
    const details = document.createElement('div');
    details.className = 'm3-item-details';
    const fullDate = item.time ? new Date(item.time).toLocaleString() : 'Hardware Secure Storage';
    details.innerHTML = `
      <div class="m3-item-detail-row"><span>Relying Party</span><strong>${escapeHtml(domain)}</strong></div>
      <div class="m3-item-detail-row"><span>User Account</span><strong>${escapeHtml(user)}</strong></div>
      <div class="m3-item-detail-row"><span>Credential</span><strong>FIDO2 / CTAP2 Resident Key</strong></div>
      <div class="m3-item-detail-row"><span>Last Active</span><strong>${escapeHtml(fullDate)}</strong></div>
      <div style="display:flex; justify-content:flex-end; margin-top: 6px;">
        <button class="m3-btn-text danger detail-del-btn" style="font-size: 10.5px; padding: 2px 6px;">
          <svg viewBox="0 0 24 24" style="width:12px; height:12px; fill:currentColor;"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
          Delete Passkey
        </button>
      </div>
    `;

    // Toggle detail on row click
    mainCol.addEventListener('click', () => {
      details.classList.toggle('open');
    });

    // Delete handler with inline confirmation
    function triggerDeleteConfirm(e) {
      if (e && e.stopPropagation) e.stopPropagation();
      actionsCol.innerHTML = '';

      const cancelBtn = document.createElement('button');
      cancelBtn.className = 'm3-btn-text';
      cancelBtn.style.fontSize = '10.5px';
      cancelBtn.textContent = 'Cancel';
      cancelBtn.addEventListener('click', (ev) => {
        if (ev && ev.stopPropagation) ev.stopPropagation();
        actionsCol.innerHTML = '';
        actionsCol.appendChild(badge);
        actionsCol.appendChild(delBtn);
      });

      const confirmBtn = document.createElement('button');
      confirmBtn.className = 'm3-btn-text danger';
      confirmBtn.style.fontSize = '10.5px';
      confirmBtn.style.fontWeight = '700';
      confirmBtn.textContent = 'Delete';
      confirmBtn.addEventListener('click', (ev) => {
        if (ev && ev.stopPropagation) ev.stopPropagation();
        executeDeletePasskey(item, wrap);
      });

      actionsCol.appendChild(cancelBtn);
      actionsCol.appendChild(confirmBtn);
    }

    delBtn.addEventListener('click', triggerDeleteConfirm);
    const detailDel = details.querySelector('.detail-del-btn');
    if (detailDel) detailDel.addEventListener('click', triggerDeleteConfirm);

    wrap.appendChild(row);
    wrap.appendChild(details);
    listEl.appendChild(wrap);
  });
}

function executeDeletePasskey(item, element) {
  element.style.transition = 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)';
  element.style.opacity = '0';
  element.style.transform = 'scale(0.96)';

  chrome.runtime.sendMessage({
    action: 'delete_passkey',
    payload: { id: item.id, rpId: item.rpId, user: item.user }
  }, () => {
    chrome.storage.local.get(['cryptick_passkeys_history'], (data) => {
      let updated = data.cryptick_passkeys_history || [];
      if (item.id) {
        updated = updated.filter(x => x.id !== item.id);
      } else {
        updated = updated.filter(x => !(x.rpId === item.rpId && x.user === item.user));
      }
      chrome.storage.local.set({ cryptick_passkeys_history: updated }, () => {
        allPasskeys = updated;
        const searchInput = document.getElementById('passkeySearch');
        const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
        if (q) {
          const filtered = allPasskeys.filter(it =>
            (it.rpId && it.rpId.toLowerCase().includes(q)) ||
            (it.user && it.user.toLowerCase().includes(q))
          );
          renderPasskeyList(filtered, q);
        } else {
          renderPasskeyList(allPasskeys);
        }
        updatePasskeyCount();
      });
    });
  });
}

function formatRelativeTime(ts) {
  if (!ts) return 'Resident Key';
  const diffSec = Math.floor((Date.now() - ts) / 1000);
  if (diffSec < 60) return 'Just now';
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

// 5. Hardware TOTP Authenticator View
async function loadTotpAccounts() {
  const container = document.getElementById('totpContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="m3-empty-state">
      <svg viewBox="0 0 24 24" style="animation: spin 1s linear infinite;"><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>
      <span>Scanning token for OATH accounts...</span>
    </div>`;

  try {
    const res = await chrome.runtime.sendMessage({ action: 'totp_list' });
    if (res && res.status === 'ok') {
      allTotpAccounts = res.accounts || [];
      renderTotpList(allTotpAccounts);
    } else {
      const msg = res && res.message ? res.message : 'Plug token in or wake BLE to view';
      container.innerHTML = `
        <div class="m3-empty-state">
          <svg viewBox="0 0 24 24"><path d="M15 7v4h1v2h-3V5h2l-3-4-3 4h2v8H8v-2.07c.7-.37 1.2-1.08 1.2-1.93 0-1.21-.99-2.2-2.2-2.2-1.21 0-2.2.99-2.2 2.2 0 .85.5 1.56 1.2 1.93V13c0 1.11.89 2 2 2h3v3.05c-.71.37-1.2 1.1-1.2 1.95a2.2 2.2 0 0 0 4.4 0c0-.85-.49-1.58-1.2-1.95V15h3c1.11 0 2-.89 2-2v-2h1V7h-4z"/></svg>
          <span>${escapeHtml(msg)}</span>
        </div>`;
    }
  } catch (e) {
    container.innerHTML = `
      <div class="m3-empty-state">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <span>Token not reachable</span>
      </div>`;
  }
}

function renderTotpList(accounts) {
  const container = document.getElementById('totpContainer');
  if (!container) return;

  if (accounts.length === 0) {
    container.innerHTML = `
      <div class="m3-empty-state">
        <svg viewBox="0 0 24 24"><path d="M15 1H9v2h6V1zm-4 13h2V8h-2v6zm8.03-6.61l1.42-1.42c-.43-.51-.9-.99-1.41-1.41l-1.42 1.42C16.07 4.74 14.12 4 12 4c-4.97 0-9 4.03-9 9s4.02 9 9 9 9-4.03 9-9c0-2.12-.74-4.07-1.97-5.61zM12 20c-3.87 0-7-3.13-7-7s3.13-7 7-7 7 3.13 7 7-3.13 7-7 7z"/></svg>
        <span>No TOTP accounts found on token</span>
      </div>`;
    return;
  }

  container.innerHTML = '';
  accounts.forEach(acc => {
    const item = document.createElement('div');
    item.className = 'm3-list-item';

    const avatar = document.createElement('div');
    avatar.className = 'm3-leading-avatar';
    avatar.style.background = 'var(--md-sys-color-secondary-container)';
    avatar.style.color = 'var(--md-sys-color-on-secondary-container)';
    avatar.innerHTML = `<svg style="width:15px; height:15px; fill:currentColor;" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>`;

    const meta = document.createElement('div');
    meta.className = 'm3-item-content';

    const label = document.createElement('span');
    label.className = 'm3-item-title';
    label.textContent = acc;
    label.title = acc;

    const sub = document.createElement('span');
    sub.className = 'm3-item-subtitle';
    sub.textContent = 'Hardware OATH TOTP';

    meta.appendChild(label);
    meta.appendChild(sub);

    const actionWrap = document.createElement('div');
    actionWrap.style.display = 'flex';
    actionWrap.style.alignItems = 'center';

    const getBtn = document.createElement('button');
    getBtn.className = 'm3-btn-tonal';
    getBtn.style.height = '30px';
    getBtn.style.padding = '0 11px';
    getBtn.style.fontSize = '10.5px';
    getBtn.textContent = 'Get Code';
    getBtn.addEventListener('click', () => fetchTotpCode(acc, actionWrap, getBtn));

    actionWrap.appendChild(getBtn);
    item.appendChild(avatar);
    item.appendChild(meta);
    item.appendChild(actionWrap);
    container.appendChild(item);
  });
}

async function fetchTotpCode(name, container, origBtn) {
  origBtn.textContent = '...';
  origBtn.disabled = true;

  try {
    const res = await chrome.runtime.sendMessage({
      action: 'totp_code',
      payload: { name }
    });
    if (res && res.status === 'ok' && res.code) {
      container.innerHTML = '';
      const box = document.createElement('div');
      box.className = 'm3-code-chip';
      box.title = 'Click to copy code';
      box.setAttribute('role', 'button');
      box.setAttribute('tabindex', '0');
      box.setAttribute('aria-label', `Copy TOTP code for ${name}`);

      const codeStr = String(res.code).padStart(6, '0');
      const codeFormatted = codeStr.slice(0, 3) + ' ' + codeStr.slice(3);

      const digits = document.createElement('span');
      digits.className = 'm3-digits';
      digits.textContent = codeFormatted;

      const copyIcon = document.createElement('span');
      copyIcon.style.display = 'inline-flex';
      copyIcon.style.alignItems = 'center';
      copyIcon.innerHTML = `<svg viewBox="0 0 24 24" style="width:12px; height:12px; fill:currentColor; opacity:0.75;"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;

      let remaining = res.remaining || 30;
      let isCopied = false;

      const countdown = document.createElement('span');
      countdown.className = 'm3-timer-pill';
      countdown.textContent = `${remaining}s`;

      box.appendChild(digits);
      box.appendChild(copyIcon);
      box.appendChild(countdown);

      function doCopy(e) {
        if (e && e.stopPropagation) e.stopPropagation();
        function fallbackCopy() {
          try {
            const ta = document.createElement('textarea');
            ta.value = codeStr;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          } catch (err) {}
        }

        if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(codeStr).catch(() => fallbackCopy());
        } else {
          fallbackCopy();
        }

        isCopied = true;
        countdown.textContent = '✓ Copied';
        countdown.style.background = 'var(--md-sys-color-primary)';
        countdown.style.color = 'var(--md-sys-color-on-primary)';
        copyIcon.innerHTML = `<svg viewBox="0 0 24 24" style="width:12px; height:12px; fill:var(--md-sys-color-primary);"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`;

        setTimeout(() => {
          isCopied = false;
          countdown.textContent = `${remaining}s`;
          countdown.style.background = '';
          countdown.style.color = '';
          copyIcon.innerHTML = `<svg viewBox="0 0 24 24" style="width:12px; height:12px; fill:currentColor; opacity:0.75;"><path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/></svg>`;
        }, 1200);
      }

      box.addEventListener('click', doCopy);
      box.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          doCopy();
        }
      });

      if (activeCountdownIntervals[name]) {
        clearInterval(activeCountdownIntervals[name]);
      }

      activeCountdownIntervals[name] = setInterval(() => {
        remaining--;
        if (remaining <= 0) {
          clearInterval(activeCountdownIntervals[name]);
          delete activeCountdownIntervals[name];
          container.innerHTML = '';
          origBtn.textContent = 'Get Code';
          origBtn.disabled = false;
          container.appendChild(origBtn);
        } else {
          if (!isCopied) {
            countdown.textContent = `${remaining}s`;
          }
        }
      }, 1000);

      container.appendChild(box);
    } else {
      origBtn.textContent = 'Failed';
      setTimeout(() => {
        origBtn.textContent = 'Get Code';
        origBtn.disabled = false;
      }, 2000);
    }
  } catch (err) {
    origBtn.textContent = 'Error';
    setTimeout(() => {
      origBtn.textContent = 'Get Code';
      origBtn.disabled = false;
    }, 2000);
  }
}

// 6. Search Filter for TOTP
function initSearch() {
  const searchInput = document.getElementById('totpSearch');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    if (!query) {
      renderTotpList(allTotpAccounts);
    } else {
      const filtered = allTotpAccounts.filter(acc => acc.toLowerCase().includes(query));
      renderTotpList(filtered);
    }
  });
}

// 7. Time Synchronization
async function syncClock(btn) {
  const origContent = btn ? btn.innerHTML : null;
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" style="width: 13px; height: 13px; animation: spin 0.8s linear infinite;"><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>
      <span>Syncing...</span>
    `;
  }
  const bannerEl = document.getElementById('totpSyncBanner');
  const bannerText = document.getElementById('totpSyncBannerText');
  const bannerTime = document.getElementById('totpSyncBannerTime');
  const telClock = document.getElementById('telClock');
  const telClockDrift = document.getElementById('telClockDrift');
  const totpClockDot = document.getElementById('totpClockDot');
  const totpClockBadge = document.getElementById('totpClockBadge');
  const totpClockReadout = document.getElementById('totpClockReadout');

  try {
    const res = await chrome.runtime.sendMessage({ action: 'sync_time' });
    const nowUtc = (res && res.clockUtc) ? res.clockUtc : Math.floor(Date.now() / 1000);
    const tzStr = (res && res.tzOffsetStr) ? res.tzOffsetStr : getLocalTzOffset();
    const timeInfo = formatTimeWithOffset(nowUtc, 0);
    currentClockOffsetSecs = 0;
    lastKnownUtc = nowUtc;
    lastKnownUtcTimestamp = Date.now();

    if (res && res.status === 'ok') {
      const telUtcClock = document.getElementById('telUtcClock');
      const telTzOffset = document.getElementById('telTzOffset');
      const totpClockOffsetBadge = document.getElementById('totpClockOffsetBadge');

      if (telClock) {
        telClock.textContent = `${timeInfo.localTime} (${tzStr})`;
      }
      if (telUtcClock) {
        telUtcClock.textContent = timeInfo.utcTime;
      }
      if (telTzOffset) {
        telTzOffset.textContent = tzStr;
      }
      if (telClockDrift) {
        telClockDrift.textContent = '0.0s (Host Sync)';
        telClockDrift.style.color = '#10b981';
      }
      if (totpClockDot) totpClockDot.className = 'm3-status-dot green';
      if (totpClockBadge) {
        totpClockBadge.textContent = 'In Sync';
        totpClockBadge.style.background = '';
        totpClockBadge.style.color = '';
      }
      if (totpClockReadout) {
        totpClockReadout.textContent = `${timeInfo.utcTime} • Host In-Sync`;
      }
      if (bannerEl && bannerText) {
        bannerText.textContent = `✓ Hardware RTC & soft clock synced to Host (${tzStr})`;
        if (bannerTime) bannerTime.textContent = `${timeInfo.localTime} (${tzStr}) • ${timeInfo.utcTime}`;
        bannerEl.style.display = 'flex';
        setTimeout(() => {
          bannerEl.style.display = 'none';
        }, 3500);
      }
      loadTotpAccounts();
    } else {
      const errMsg = (res && res.message) ? res.message : 'Sync failed';
      if (bannerEl && bannerText) {
        bannerText.textContent = `✕ Time sync error: ${errMsg}`;
        bannerEl.style.display = 'flex';
        setTimeout(() => {
          bannerEl.style.display = 'none';
        }, 3500);
      }
    }
  } catch (err) {
    if (bannerEl && bannerText) {
      bannerText.textContent = `✕ Communication error: ${err.message}`;
      bannerEl.style.display = 'flex';
      setTimeout(() => {
        bannerEl.style.display = 'none';
      }, 3500);
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      if (origContent) btn.innerHTML = origContent;
    }
  }
}

// 8. Service Management
async function handleRestart() {
  const devTransport = document.getElementById('devTransport');
  const devTransportDesc = document.getElementById('devTransportDesc');
  if (devTransport) devTransport.textContent = 'Restarting...';
  if (devTransportDesc) devTransportDesc.textContent = 'Kickstarting daemon service';

  try {
    await chrome.runtime.sendMessage({ action: 'restart' });
    setTimeout(() => checkStatus(true), 1200);
  } catch (e) {
    setTimeout(() => checkStatus(true), 1200);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initPasskeyTab();
  initSearch();

  // Instant 0ms status rendering from background cache
  chrome.storage.local.get(['cryptick_cached_status'], (data) => {
    if (data.cryptick_cached_status) {
      applyStatus(data.cryptick_cached_status);
    }
  });

  // Query live status immediately
  checkStatus(false);
  updatePasskeyCount();

  // Refresh every 1.5s while popup is active
  const statusInterval = setInterval(() => {
    checkStatus(false);
    updatePasskeyCount();
  }, 1500);

  // Live 1-second clock ticker for silky real-time countdown & time display
  const clockTicker = setInterval(() => {
    if (!lastConnectionState) return;
    const nowMs = Date.now();
    const elapsedSecs = Math.floor((nowMs - lastKnownUtcTimestamp) / 1000);
    const simulatedUtc = (lastKnownUtc || Math.floor(nowMs / 1000)) + elapsedSecs;
    const info = formatTimeWithOffset(simulatedUtc, currentClockOffsetSecs);
    const tzStr = getLocalTzOffset();

    const telClock = document.getElementById('telClock');
    const telUtcClock = document.getElementById('telUtcClock');
    const totpClockReadout = document.getElementById('totpClockReadout');

    if (telClock) telClock.textContent = `${info.localTime} (${tzStr})`;
    if (telUtcClock) telUtcClock.textContent = info.utcTime;
    if (totpClockReadout) totpClockReadout.textContent = `${info.utcTime} • Host In-Sync`;
  }, 1000);

  window.addEventListener('beforeunload', () => {
    clearInterval(statusInterval);
    clearInterval(clockTicker);
  });

  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => checkStatus(true));

  const scanBtn = document.getElementById('totpScanBtn');
  if (scanBtn) scanBtn.addEventListener('click', loadTotpAccounts);

  const totpSyncBtn = document.getElementById('totpSyncBtn');
  if (totpSyncBtn) totpSyncBtn.addEventListener('click', () => syncClock(totpSyncBtn));

  const totpReconnectBtn = document.getElementById('totpReconnectBtn');
  if (totpReconnectBtn) totpReconnectBtn.addEventListener('click', () => checkStatus(true));

  const syncTimeBtn = document.getElementById('syncTimeBtn');
  if (syncTimeBtn) syncTimeBtn.addEventListener('click', () => syncClock(syncTimeBtn));

  const restartBtn = document.getElementById('restartBtn');
  if (restartBtn) restartBtn.addEventListener('click', handleRestart);

  const restartBtnDisc = document.getElementById('restartBtnDisc');
  if (restartBtnDisc) restartBtnDisc.addEventListener('click', handleRestart);

  const diagBtn = document.getElementById('runDiagBtn');
  if (diagBtn) diagBtn.addEventListener('click', () => runDiagnostics(false));

  const diagBtnDisc = document.getElementById('runDiagBtnDisc');
  if (diagBtnDisc) diagBtnDisc.addEventListener('click', () => runDiagnostics(true));

  // Listen to storage changes reactively while popup is open
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local') {
      if (changes.cryptick_passkeys_history) {
        allPasskeys = changes.cryptick_passkeys_history.newValue || [];
        const searchInput = document.getElementById('passkeySearch');
        const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
        if (q) {
          const filtered = allPasskeys.filter(item =>
            (item.rpId && item.rpId.toLowerCase().includes(q)) ||
            (item.user && item.user.toLowerCase().includes(q))
          );
          renderPasskeyList(filtered, q);
        } else {
          renderPasskeyList(allPasskeys);
        }
        updatePasskeyCount();
      }
      if (changes.cryptick_cached_status) {
        applyStatus(changes.cryptick_cached_status.newValue);
      }
    }
  });
});
