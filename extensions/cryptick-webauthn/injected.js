(function() {
  if (window.__cryptick_webauthn_injected) return;
  window.__cryptick_webauthn_injected = true;

  if (window === window.top) {
    console.log('[Cryptick Token] Wireless passkey bridge active on', window.location.hostname);
  }

  const originalCreate = navigator.credentials.create.bind(navigator.credentials);
  const originalGet = navigator.credentials.get.bind(navigator.credentials);

  const originalIsUVPAA = (typeof PublicKeyCredential !== 'undefined' && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable)
    ? PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable.bind(PublicKeyCredential)
    : async () => false;

  // Enable platform authenticator checks for all passkey-ready websites
  if (typeof PublicKeyCredential !== 'undefined') {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async function() {
      if (!isBridgeEnabled) {
        return originalIsUVPAA();
      }
      return true;
    };
  }

  function bufferToBase64Url(buffer) {
    if (!buffer) return '';
    let bytes;
    if (buffer instanceof Uint8Array) {
      bytes = buffer;
    } else if (ArrayBuffer.isView(buffer)) {
      bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } else if (buffer instanceof ArrayBuffer) {
      bytes = new Uint8Array(buffer);
    } else if (typeof buffer === 'string') {
      return buffer.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } else {
      return '';
    }
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  function base64UrlToBuffer(base64url) {
    if (!base64url) return new ArrayBuffer(0);
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function utf8ToBase64Url(str) {
    const encoder = new TextEncoder();
    return bufferToBase64Url(encoder.encode(str));
  }

  // Auto-theme floating prompt (matches system light/dark mode)
  let activeCancelHandler = null;
  let isBridgeEnabled = true;

  // Listen for dynamic status updates from extension
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.source !== 'cryptick-content-status') return;
    if (typeof event.data.enabled === 'boolean') {
      isBridgeEnabled = event.data.enabled;
    }
  });

  function showPrompt(text, isError = false) {
    const isDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

    let el = document.getElementById('cryptick-prompt-overlay');
    if (!el) {
      el = document.createElement('div');
      el.id = 'cryptick-prompt-overlay';
      el.style.position = 'fixed';
      el.style.bottom = '24px';
      el.style.right = '24px';
      el.style.zIndex = '2147483647';
      el.style.padding = '14px 18px';
      el.style.borderRadius = '12px';
      el.style.fontFamily = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
      el.style.fontSize = '13px';
      el.style.minWidth = '280px';
      el.style.maxWidth = '360px';
      el.style.transition = 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)';
      document.body.appendChild(el);
    }

    const bg = isDark ? 'rgba(15, 23, 42, 0.96)' : 'rgba(255, 255, 255, 0.98)';
    const textMain = isDark ? '#f8fafc' : '#0f172a';
    const textSub = isDark ? '#cbd5e1' : '#475569';
    const borderAccent = isError 
      ? (isDark ? 'rgba(244, 63, 94, 0.5)' : 'rgba(244, 63, 94, 0.4)')
      : (isDark ? 'rgba(6, 182, 212, 0.3)' : 'rgba(2, 132, 199, 0.25)');
    const shadow = isDark
      ? '0 20px 40px -10px rgba(0, 0, 0, 0.7), 0 0 0 1px ' + borderAccent
      : '0 16px 36px -8px rgba(0, 0, 0, 0.12), 0 0 0 1px ' + borderAccent;

    el.style.display = 'block';
    el.style.opacity = '1';
    el.style.backgroundColor = bg;
    el.style.backdropFilter = 'blur(16px)';
    el.style.webkitBackdropFilter = 'blur(16px)';
    el.style.color = textMain;
    el.style.boxShadow = shadow;

    const dotColor = isError ? '#f43f5e' : (isDark ? '#06b6d4' : '#0284c7');
    const badgeBg = isError 
      ? 'rgba(244,63,94,0.1)' 
      : (isDark ? 'rgba(6,182,212,0.15)' : 'rgba(2,132,199,0.1)');
    const badgeText = isError ? '#f43f5e' : (isDark ? '#06b6d4' : '#0284c7');
    const statusText = isError ? 'Error' : 'Passkey';

    el.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <div style="width: 8px; height: 8px; border-radius: 50%; background: ${dotColor}; box-shadow: 0 0 6px ${dotColor};"></div>
          <span style="font-weight: 700; font-size: 12px; color: ${textMain}; letter-spacing: -0.1px;">Cryptick Token</span>
          <span style="font-size: 10px; color: ${badgeText}; background: ${badgeBg}; padding: 1.5px 7px; border-radius: 9999px; font-weight: 600;">${statusText}</span>
        </div>
        <button id="cryptick-btn-close" title="Dismiss to native WebAuthn" style="background: none; border: none; color: ${isDark ? '#94a3b8' : '#64748b'}; font-size: 14px; cursor: pointer; padding: 2px 6px; border-radius: 4px; line-height: 1; transition: all 0.15s ease;">✕</button>
      </div>
      <div style="color: ${textSub}; font-size: 12px; line-height: 1.4; margin-bottom: ${isError ? '0' : '10px'};">${text}</div>
      ${!isError ? `
        <div style="display: flex; justify-content: flex-end; align-items: center;">
          <button id="cryptick-btn-fallback" style="background: ${isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.05)'}; border: 1px solid ${isDark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.1)'}; color: ${textMain}; font-family: inherit; font-size: 11px; font-weight: 500; border-radius: 9999px; padding: 4px 10px; cursor: pointer; transition: all 0.15s ease;">
            Use System Passkey
          </button>
        </div>
      ` : ''}
    `;

    const closeBtn = document.getElementById('cryptick-btn-close');
    if (closeBtn) {
      closeBtn.onclick = (e) => {
        e.stopPropagation();
        if (activeCancelHandler) activeCancelHandler('User canceled passkey verification');
      };
    }
    const fallbackBtn = document.getElementById('cryptick-btn-fallback');
    if (fallbackBtn) {
      fallbackBtn.onclick = (e) => {
        e.stopPropagation();
        if (activeCancelHandler) activeCancelHandler('User chose system passkey fallback');
      };
    }
    return el;
  }

  function hidePrompt(delay = 1000) {
    const el = document.getElementById('cryptick-prompt-overlay');
    if (!el) return;
    setTimeout(() => {
      el.style.opacity = '0';
      setTimeout(() => {
        el.style.display = 'none';
      }, 200);
    }, delay);
  }

  let requestCounter = 0;
  function callCryptick(action, payload) {
    return new Promise((resolve, reject) => {
      const requestId = 'cryptick_' + Date.now() + '_' + (++requestCounter);
      
      activeCancelHandler = (reason) => {
        cleanup();
        hidePrompt(0);
        reject(new DOMException(reason || 'User canceled', 'NotAllowedError'));
      };

      showPrompt('Touch your Cryptick Token to verify...', false);

      const timer = setTimeout(() => {
        cleanup();
        showPrompt('Timed out waiting for token touch', true);
        hidePrompt(1500);
        reject(new DOMException('Cryptick Token request timed out', 'TimeoutError'));
      }, payload.timeout || 60000);

      function cleanup() {
        clearTimeout(timer);
        activeCancelHandler = null;
        window.removeEventListener('message', handleResponse);
      }

      function handleResponse(event) {
        if (event.source !== window || !event.data || event.data.source !== 'cryptick-content') {
          return;
        }
        if (event.data.requestId !== requestId) {
          return;
        }

        cleanup();

        if (event.data.result?.status === 'disabled') {
          hidePrompt(0);
          reject(new Error('Passkey bridge disabled by user'));
          return;
        }

        if (event.data.error || event.data.result?.status === 'error') {
          const rawErr = event.data.error || event.data.result?.message || 'Transaction failed';
          const isDisconnected = rawErr.includes('NotConnected') ||
                                 rawErr.includes('offline') ||
                                 rawErr.includes('Host offline') ||
                                 rawErr.includes('No response') ||
                                 rawErr.includes('not connected');

          if (isDisconnected) {
            // Token is disconnected or host offline: immediately hide prompt so native WebAuthn fallback dialog is unobstructed
            hidePrompt(0);
            console.log('[Cryptick Token] Hardware token disconnected. Falling back seamlessly to native WebAuthn...');
            reject(new DOMException('Hardware token disconnected', 'NotAllowedError'));
            return;
          }

          let displayMsg = rawErr;
          if (rawErr.includes('0x2e') || rawErr.includes('NoCredentials')) {
            displayMsg = 'No matching passkey found on this token';
          } else if (rawErr.includes('Timed out') || rawErr.includes('Timeout')) {
            displayMsg = 'Touch timed out';
          }
          showPrompt(displayMsg, true);
          hidePrompt(1500);
          reject(new DOMException(rawErr, 'NotAllowedError'));
        } else {
          showPrompt('Verified! Signing in...');
          hidePrompt(600);
          resolve(event.data.result);
        }
      }

      window.addEventListener('message', handleResponse);
      window.postMessage({
        source: 'cryptick-page',
        requestId,
        action,
        payload
      }, '*');
    });
  }

  // Override navigator.credentials.create
  navigator.credentials.create = async function(options) {
    if (!isBridgeEnabled || !options || !options.publicKey) {
      return originalCreate(options);
    }

    console.log('[Cryptick Token] Intercepted navigator.credentials.create:', options.publicKey);

    try {
      const pk = options.publicKey;
      const challengeB64 = bufferToBase64Url(pk.challenge);

      // Build clientDataJSON
      const clientDataObj = {
        type: 'webauthn.create',
        challenge: challengeB64,
        origin: window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = JSON.stringify(clientDataObj);
      const clientDataJSON_b64 = utf8ToBase64Url(clientDataJSON);

      const userIdB64 = bufferToBase64Url(pk.user.id);
      const pubKeyCredParams = (pk.pubKeyCredParams || []).map(p => p.alg);

      const reqPayload = {
        rp: {
          id: pk.rp.id || window.location.hostname,
          name: pk.rp.name || pk.rp.id || window.location.hostname
        },
        user: {
          id: userIdB64,
          name: pk.user.name || '',
          displayName: pk.user.displayName || pk.user.name || ''
        },
        clientDataJSON: clientDataJSON_b64,
        pubKeyCredParams: pubKeyCredParams,
        residentKey: pk.authenticatorSelection?.residentKey === 'required',
        userVerification: pk.authenticatorSelection?.userVerification === 'required',
        timeout: pk.timeout || 60000
      };

      const result = await callCryptick('create', reqPayload);
      if (!result || result.status !== 'ok') {
        throw new Error(result?.message || 'Cryptick Token creation failed');
      }

      const rawIdBuffer = base64UrlToBuffer(result.rawId);
      const attestationBuffer = base64UrlToBuffer(result.response.attestationObject);
      const clientDataBuffer = base64UrlToBuffer(result.response.clientDataJSON);
      const authDataBuffer = base64UrlToBuffer(result.response.authenticatorData || '');

      const respObj = {
        clientDataJSON: clientDataBuffer,
        attestationObject: attestationBuffer,
        getTransports: () => ['usb', 'ble', 'hybrid', 'internal'],
        getAuthenticatorData: () => authDataBuffer,
        getPublicKey: () => {
          // Extract COSE public key bytes from authData (attestedCredentialData)
          if (authDataBuffer.byteLength > 55) {
            const view = new DataView(authDataBuffer);
            const credIdLen = view.getUint16(53);
            if (authDataBuffer.byteLength > 55 + credIdLen) {
              return authDataBuffer.slice(55 + credIdLen);
            }
          }
          return null;
        },
        getPublicKeyAlgorithm: () => -7
      };
      if (typeof AuthenticatorAttestationResponse !== 'undefined') {
        Object.setPrototypeOf(respObj, AuthenticatorAttestationResponse.prototype);
      }

      const cred = {
        id: result.id,
        rawId: rawIdBuffer,
        type: 'public-key',
        authenticatorAttachment: pk.authenticatorSelection?.authenticatorAttachment || 'cross-platform',
        response: respObj,
        getClientExtensionResults: () => ({ credProps: { rk: true } })
      };
      if (typeof PublicKeyCredential !== 'undefined') {
        Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
      }

      cred.toJSON = () => ({
        id: result.id,
        rawId: result.rawId,
        type: 'public-key',
        authenticatorAttachment: pk.authenticatorSelection?.authenticatorAttachment || 'cross-platform',
        response: {
          clientDataJSON: result.response.clientDataJSON,
          attestationObject: result.response.attestationObject,
          authenticatorData: result.response.authenticatorData,
          transports: ['usb', 'ble', 'hybrid', 'internal'],
          publicKeyAlgorithm: -7
        },
        clientExtensionResults: { credProps: { rk: true } }
      });

      console.log('[Cryptick Token] MakeCredential successful! Returning credential:', cred);
      return cred;
    } catch (err) {
      const errMsg = err?.message || String(err);
      console.warn('[Cryptick Token] Passkey create fallback to native WebAuthn:', errMsg);
      return originalCreate(options);
    }
  };

  // Override navigator.credentials.get
  navigator.credentials.get = async function(options) {
    if (!isBridgeEnabled || !options || !options.publicKey || options.mediation === 'conditional') {
      return originalGet(options);
    }

    console.log('[Cryptick Token] Intercepted navigator.credentials.get:', options.publicKey);

    try {
      const pk = options.publicKey;
      const challengeB64 = bufferToBase64Url(pk.challenge);

      // Build clientDataJSON
      const clientDataObj = {
        type: 'webauthn.get',
        challenge: challengeB64,
        origin: window.location.origin,
        crossOrigin: false
      };
      const clientDataJSON = JSON.stringify(clientDataObj);
      const clientDataJSON_b64 = utf8ToBase64Url(clientDataJSON);

      const allowCredentials = (pk.allowCredentials || []).map(c => bufferToBase64Url(c.id));

      const reqPayload = {
        rpId: pk.rpId || window.location.hostname,
        clientDataJSON: clientDataJSON_b64,
        allowCredentials: allowCredentials,
        userVerification: pk.userVerification === 'required',
        timeout: pk.timeout || 60000
      };

      const result = await callCryptick('get', reqPayload);
      if (!result || result.status !== 'ok') {
        throw new Error(result?.message || 'Cryptick Token assertion failed');
      }

      const rawIdBuffer = base64UrlToBuffer(result.rawId);
      const clientDataBuffer = base64UrlToBuffer(result.response.clientDataJSON);
      const authDataBuffer = base64UrlToBuffer(result.response.authenticatorData);
      const signatureBuffer = base64UrlToBuffer(result.response.signature);
      const userHandleBuffer = result.response.userHandle ? base64UrlToBuffer(result.response.userHandle) : null;

      const respObj = {
        clientDataJSON: clientDataBuffer,
        authenticatorData: authDataBuffer,
        signature: signatureBuffer,
        userHandle: userHandleBuffer
      };
      if (typeof AuthenticatorAssertionResponse !== 'undefined') {
        Object.setPrototypeOf(respObj, AuthenticatorAssertionResponse.prototype);
      }

      const cred = {
        id: result.id,
        rawId: rawIdBuffer,
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        response: respObj,
        getClientExtensionResults: () => ({})
      };
      if (typeof PublicKeyCredential !== 'undefined') {
        Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
      }

      cred.toJSON = () => ({
        id: result.id,
        rawId: result.rawId,
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        response: {
          clientDataJSON: result.response.clientDataJSON,
          authenticatorData: result.response.authenticatorData,
          signature: result.response.signature,
          userHandle: result.response.userHandle || null
        },
        clientExtensionResults: {}
      });

      console.log('[Cryptick Token] GetAssertion successful! Returning assertion:', cred);
      return cred;
    } catch (err) {
      const errMsg = err?.message || String(err);
      console.warn('[Cryptick Token] Passkey get fallback to native WebAuthn:', errMsg);
      return originalGet(options);
    }
  };
})();
