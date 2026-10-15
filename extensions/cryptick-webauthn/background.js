// Cryptick Token - Background Service Worker
const HOST_NAME = 'com.cryptick.webauthn';

let cachedStatus = null;
let lastStatusFetchTime = 0;
let isFetchingStatus = false;
let wasPreviouslyConnected = false;

function sendNativeMessage(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(HOST_NAME, msg, (response) => {
      if (chrome.runtime.lastError) {
        return reject(new Error(chrome.runtime.lastError.message));
      }
      resolve(response);
    });
  });
}

async function getLiveStatus(forceFresh = false) {
  const now = Date.now();
  // Return cached state instantly if fresh (< 300ms) and not forced
  if (!forceFresh && cachedStatus && (now - lastStatusFetchTime < 300)) {
    return cachedStatus;
  }
  if (isFetchingStatus && cachedStatus && !forceFresh) {
    return cachedStatus;
  }

  isFetchingStatus = true;
  try {
    const res = await sendNativeMessage({ action: 'status' });
    if (res && res.status === 'ok') {
      cachedStatus = res;
    } else {
      cachedStatus = res || { status: 'error', message: 'No response from host' };
    }
    lastStatusFetchTime = Date.now();

    const isConnected = !!(cachedStatus && (cachedStatus.usb || cachedStatus.inRange));
    if (isConnected && !wasPreviouslyConnected) {
      // Auto-sync hardware RTC to host UTC upon token insertion or reconnection
      sendNativeMessage({ action: 'sync_time' }).catch(() => {});
    }
    wasPreviouslyConnected = isConnected;

    chrome.storage.local.set({ cryptick_cached_status: cachedStatus });
    return cachedStatus;
  } catch (err) {
    cachedStatus = {
      status: 'error',
      message: err.message || 'Host offline',
      usb: false,
      inRange: false,
      daemonRunning: false,
      transport: 'offline'
    };
    wasPreviouslyConnected = false;
    lastStatusFetchTime = Date.now();
    chrome.storage.local.set({ cryptick_cached_status: cachedStatus });
    return cachedStatus;
  } finally {
    isFetchingStatus = false;
  }
}

// Initial warm-up query on service worker start
getLiveStatus(true);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const { action, payload } = request;

  if (action === 'status') {
    getLiveStatus(request.forceFresh || false)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ status: 'error', message: err.message }));
    return true; // Keep channel open
  }

  if (action === 'delete_passkey') {
    const credId = payload?.id;
    const rpId = payload?.rpId;
    const user = payload?.user;
    chrome.storage.local.get(['cryptick_passkeys_history'], (data) => {
      const list = data.cryptick_passkeys_history || [];
      const updated = list.filter(item => {
        if (credId && item.id) return item.id !== credId;
        if (rpId && user) return !(item.rpId === rpId && item.user === user);
        if (rpId) return item.rpId !== rpId;
        return true;
      });
      chrome.storage.local.set({ cryptick_passkeys_history: updated }, () => {
        sendResponse({ status: 'ok', remaining: updated.length });
      });
    });
    return true;
  }

  let nativeMsg = null;
  if (action === 'ping' || action === 'restart' || action === 'totp_list' || action === 'sync_time' || action === 'totp_sync_time') {
    nativeMsg = { action };
  } else if (action === 'create' || action === 'get' || action === 'totp_code') {
    nativeMsg = { action, ...payload };
  } else {
    sendResponse({ status: 'error', message: 'Unknown action' });
    return false;
  }

  sendNativeMessage(nativeMsg)
    .then((result) => {
      if (result && result.status === 'ok' && (action === 'create' || action === 'get')) {
        const rpId = payload?.rpId || payload?.rp?.id || 'WebAuthn Relying Party';
        const user = payload?.user?.name || payload?.user?.displayName || null;
        chrome.storage.local.get(['cryptick_passkeys_history'], (data) => {
          const list = data.cryptick_passkeys_history || [];
          const entry = {
            id: 'cred_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
            rpId,
            user,
            action,
            time: Date.now()
          };
          const updated = [entry, ...list.filter(item => !(item.rpId === rpId && item.user === user))].slice(0, 50);
          chrome.storage.local.set({ cryptick_passkeys_history: updated });
        });
      }
      if (action === 'restart') {
        setTimeout(() => getLiveStatus(true), 1200);
      }
      sendResponse(result);
    })
    .catch((err) => sendResponse({ status: 'error', message: err.message }));

  return true; // Keep message channel open for async response
});
