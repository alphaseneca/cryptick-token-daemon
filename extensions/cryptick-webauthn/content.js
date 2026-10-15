// Cryptick WebAuthn Content Script (ISOLATED World)
// Relays messages between page execution context (MAIN World) and background service worker
(function() {
  function syncState() {
    chrome.storage.local.get(['cryptick_bridge_enabled'], (data) => {
      const enabled = data.cryptick_bridge_enabled !== false;
      window.postMessage({
        source: 'cryptick-content-status',
        enabled
      }, '*');
    });
  }

  // Initial sync
  syncState();

  // Watch for toggle switches in the popup without requiring page reload
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local' && changes.cryptick_bridge_enabled) {
      window.postMessage({
        source: 'cryptick-content-status',
        enabled: changes.cryptick_bridge_enabled.newValue !== false
      }, '*');
    }
  });

  window.addEventListener('message', async (event) => {
    if (event.source !== window || !event.data || event.data.source !== 'cryptick-page') {
      return;
    }

    const { requestId, action, payload } = event.data;

    // Check if user disabled hardware bridging in the popup
    if (action === 'create' || action === 'get') {
      const isEnabled = await new Promise((resolve) => {
        chrome.storage.local.get(['cryptick_bridge_enabled'], (data) => {
          resolve(data.cryptick_bridge_enabled !== false);
        });
      });

      if (!isEnabled) {
        window.postMessage({
          source: 'cryptick-content',
          requestId,
          result: { status: 'disabled', message: 'Cryptick passkey bridge is toggled off' }
        }, '*');
        return;
      }
    }

    try {
      const response = await chrome.runtime.sendMessage({
        action,
        payload
      });

      window.postMessage({
        source: 'cryptick-content',
        requestId,
        result: response
      }, '*');
    } catch (err) {
      window.postMessage({
        source: 'cryptick-content',
        requestId,
        error: err.message || 'Cryptick bridge communication error'
      }, '*');
    }
  });
})();
