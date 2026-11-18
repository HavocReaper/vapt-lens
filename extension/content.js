/**
 * VAPT Lens — content script (classic script, isolated world).
 *
 * Purpose: observe the DOM structurally at the user's request and show a small
 * floating orb. It never reads field values, cookies, tokens, or keystrokes,
 * and never modifies page behaviour.
 */
(function () {
  'use strict';

  const api = globalThis.browser || globalThis.chrome;
  if (!api?.runtime) return;

  const HOST_ID = 'vapt-lens-orb-host';

  const MESSAGE_NAMES = [
    'SCAN_PAGE', 'SCAN_RESULT', 'GET_STATE', 'STATE_RESULT', 'STATE_UPDATED',
    'IMPORT_BURP', 'BURP_IMPORTED', 'ANALYZE', 'OPEN_PANEL',
    'GET_CONFIG', 'CONFIG_RESULT', 'SET_AI', 'SET_AUTHORIZED',
    'REQUEST_OBSERVATION', 'OBSERVATION',
  ];

  const FALLBACK_MESSAGES = {
    SCAN_PAGE: 'SCAN_PAGE',
    SCAN_RESULT: 'SCAN_RESULT',
    GET_STATE: 'GET_STATE',
    STATE_RESULT: 'STATE_RESULT',
    STATE_UPDATED: 'STATE_UPDATED',
    IMPORT_BURP: 'IMPORT_BURP',
    BURP_IMPORTED: 'BURP_IMPORTED',
    ANALYZE: 'ANALYZE',
    OPEN_PANEL: 'OPEN_PANEL',
    GET_CONFIG: 'GET_CONFIG',
    CONFIG_RESULT: 'CONFIG_RESULT',
    SET_AI: 'SET_AI',
    SET_AUTHORIZED: 'SET_AUTHORIZED',
    REQUEST_OBSERVATION: 'REQUEST_OBSERVATION',
    OBSERVATION: 'OBSERVATION',
  };

  let MSG = { ...FALLBACK_MESSAGES };
  let observePage = null;
  let sendHelper = null;
  let toastTimer = null;

  function resolveMessages(mod) {
    const NS = mod || {};
    const containers = [
      NS,
      NS.default,
      NS.MSG,
      NS.MESSAGES,
      NS.MESSAGE_TYPES,
      NS.TYPES,
      NS.default?.MSG,
      NS.default?.MESSAGES,
      NS.default?.MESSAGE_TYPES,
    ];

    for (const c of containers) {
      if (!c || typeof c !== 'object') continue;
      for (const name of MESSAGE_NAMES) {
        const value = c[name];
        if (typeof value === 'string' && value.length) MSG[name] = value;
      }
    }
    for (const c of containers) {
      if (!c || typeof c !== 'object') continue;
      for (const name of ['sendToBackground', 'sendMessage', 'send', 'sendMsg', 'runtimeSend']) {
        if (typeof c[name] === 'function') {
          sendHelper = c[name];
          break;
        }
      }
      if (sendHelper) break;
    }
  }

  function normalizeReply(reply) {
    if (reply && typeof reply === 'object') return reply;
    if (reply === undefined) return { ok: true };
    return { ok: true, value: reply };
  }

  function runtimeSend(message) {
    if (globalThis.browser?.runtime?.sendMessage) {
      try {
        return Promise.resolve(globalThis.browser.runtime.sendMessage(message))
          .then(normalizeReply)
          .catch((err) => ({ ok: false, error: err?.message || String(err) }));
      } catch (err) {
        return Promise.resolve({ ok: false, error: err?.message || String(err) });
      }
    }
    if (api.runtime?.sendMessage) {
      return new Promise((resolve) => {
        try {
          api.runtime.sendMessage(message, (reply) => {
            const lastError = api.runtime?.lastError;
            if (lastError) resolve({ ok: false, error: lastError.message });
            else resolve(normalizeReply(reply));
          });
        } catch (err) {
          resolve({ ok: false, error: err?.message || String(err) });
        }
      });
    }
    return Promise.resolve({ ok: false, error: 'Runtime messaging unavailable.' });
  }

  function send(type, payload = {}) {
    const message = { type, ...payload };
    if (sendHelper) {
      try {
        const out = sendHelper.length >= 2 ? sendHelper(type, payload) : sendHelper(message);
        return Promise.resolve(out)
          .then(normalizeReply)
          .catch((err) => ({ ok: false, error: err?.message || String(err) }));
      } catch (err) {
        // Fall through to the local wrapper.
      }
    }
    return runtimeSend(message);
  }

  async function initModules() {
    try {
      const scanner = await import(api.runtime.getURL('src/core/scanner.js'));
      observePage = scanner?.observePage || scanner?.default?.observePage || null;
    } catch {
      observePage = null;
    }
    try {
      const msgs = await import(api.runtime.getURL('src/core/messages.js'));
      resolveMessages(msgs);
    } catch {
      // Keep the canonical fallback constants.
    }
  }

  /** Structural, value-free observation. Never include query values. */
  async function capture() {
    const safeUrl = `${location.origin}${location.pathname}`;
    if (observePage) {
      try {
        const result = await observePage({
          href: location.href,
          title: document.title,
          doc: document,
          cookies: [],
          headers: [],
        });
        if (result) return result.observation || result;
      } catch {
        // Fall back to a minimal observation below.
      }
    }
    return {
      capturedAt: new Date().toISOString(),
      url: safeUrl,
      origin: location.origin,
      host: location.hostname,
      path: location.pathname,
      title: document.title || '',
      queryParams: [],
      technologies: [],
      headers: [],
      cookies: [],
      forms: [],
      links: [],
      scripts: [],
      endpoints: [],
      domSinks: [],
      signals: {},
      counts: { forms: 0, inputs: 0, links: 0, scripts: 0, endpoints: 0 },
    };
  }

  function showToast(text) {
    // The shadow root is closed to the page; we kept our own reference.
    const shadow = document.getElementById(HOST_ID)?.__vlShadow;
    const toast = shadow?.querySelector?.('.vl-toast');
    if (!toast) return;
    toast.textContent = text || '';
    toast.classList.toggle('vl-show', !!text);
    clearTimeout(toastTimer);
    if (text) {
      toastTimer = setTimeout(() => {
        toast.textContent = '';
        toast.classList.remove('vl-show');
      }, 3600);
    }
  }

  async function onOrbClick() {
    showToast('Opening VAPT Lens…');
    send(MSG.OPEN_PANEL);
    try {
      showToast('Scanning structure (read-only)…');
      const observation = await capture();
      const reply = await send(MSG.SCAN_PAGE, { observation });
      if (reply && reply.ok === false && reply.error) showToast(reply.error);
      else showToast('Guidance ready in VAPT Lens.');
    } catch {
      showToast('Scan failed — open VAPT Lens for details.');
    }
  }

  function buildOrb() {
    if (document.getElementById(HOST_ID)) return;

    const host = document.createElement('div');
    host.id = HOST_ID;
    (document.documentElement || document.body).appendChild(host);

    let shadow;
    try {
      shadow = host.attachShadow({ mode: 'closed' });
    } catch {
      return;
    }
    // Keep an internal reference: closed mode hides it from the page.
    host.__vlShadow = shadow;

    // Critical layout styles first, so the orb is never unpositioned while
    // content.css is loading.
    const critical = document.createElement('style');
    critical.textContent = [
      ':host{position:fixed;right:18px;bottom:18px;z-index:2147483647;pointer-events:none}',
      '.vl-orb{pointer-events:auto}',
    ].join('');
    shadow.appendChild(critical);

    try {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = api.runtime.getURL('content.css');
      shadow.appendChild(link);
    } catch {
      // Inline minimal styling below still keeps the orb usable.
      const fallback = document.createElement('style');
      fallback.textContent = [
        '.vl-orb{width:44px;height:44px;border-radius:50%;border:1px solid #7cc4ff;',
        'background:#0b1220;color:#e8f1ff;display:grid;place-items:center;cursor:pointer}',
        '.vl-orb svg{width:23px;height:23px}',
        '.vl-orb-tip{display:none}',
        '.vl-toast{position:absolute;right:56px;bottom:4px;background:#0b1220;color:#e8f1ff;',
        'padding:8px;border-radius:8px;font:12px system-ui;opacity:0;pointer-events:none}',
        '.vl-toast.vl-show{opacity:1}',
      ].join('');
      shadow.appendChild(fallback);
    }

    const button = document.createElement('button');
    button.className = 'vl-orb';
    button.type = 'button';
    button.title = 'VAPT Lens — guided testing only';
    button.setAttribute('aria-label', 'VAPT Lens — guided testing only');
    button.innerHTML = [
      '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">',
      '<circle cx="10.2" cy="10.2" r="8" stroke="#b18cff" stroke-opacity="0.75" stroke-width="1.1" stroke-dasharray="6 4" transform="rotate(-30 10.2 10.2)"/>',
      '<circle cx="10.2" cy="10.2" r="6.2" fill="rgba(124,196,255,0.14)" stroke="currentColor" stroke-width="1.7"/>',
      '<path d="M10.2 6.5v1.8M10.2 12.1v1.8M6.5 10.2h1.8M12.1 10.2h1.8" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>',
      '<circle cx="10.2" cy="10.2" r="1.5" fill="#67e8f9"/>',
      '<path d="m14.8 14.8 5 5" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
      '<path d="m15.9 15.9 3.2 3.2" stroke="#a78bfa" stroke-width="0.9" stroke-linecap="round"/>',
      '</svg>',
      '<span class="vl-orb-tip">VAPT Lens — guided testing only</span>',
    ].join('');
    button.addEventListener('click', onOrbClick);

    const toast = document.createElement('div');
    toast.className = 'vl-toast';
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');

    shadow.appendChild(button);
    shadow.appendChild(toast);
  }

  api.runtime.onMessage?.addListener((message, sender, sendResponse) => {
    const type = message?.type;
    if (type === 'PING') {
      sendResponse({ ok: true });
      return true;
    }
    if (type === MSG.REQUEST_OBSERVATION) {
      capture()
        .then((observation) => sendResponse({ ok: true, observation }))
        .catch(() => sendResponse({ ok: false }));
      return true;
    }
    // STATE_UPDATED and all other types are handled by the panel/background.
    return false;
  });

  // Inject immediately; module imports finish in the background.
  if (document.documentElement || document.body) buildOrb();
  initModules();
})();
