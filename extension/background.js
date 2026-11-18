/**
 * VAPT Lens — background (MV3 service worker / event page).
 *
 * Owns per-tab state, talks only to the local bridge, and never stores or logs
 * secret-looking values. Guidance only — this file never sends attack traffic.
 */
import * as MSG_MOD from './src/core/messages.js';

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

const BRIDGE = 'http://127.0.0.1:8787';

const TIMEOUTS = Object.freeze({
  health: 5000,
  config: 5000,
  analyze: 100000, // AI analysis may take up to ~90s on the bridge
  import: 20000,
  traffic: 10000,
  crawl: 120000, // bounded GET-only crawl lives on the bridge
  stream: 2000, // passive traffic POST must never block page requests
});

// SPEC.md § PageObservation — header allowlist.
const ALLOWED_HEADERS = new Set([
  'content-type',
  'x-frame-options',
  'content-security-policy',
  'strict-transport-security',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'server',
  'x-powered-by',
  'cache-control',
]);

const SENSITIVE_VALUE = /token|key|secret|auth|session|bearer/i;

const MESSAGE_NAMES = [
  'SCAN_PAGE', 'SCAN_RESULT', 'GET_STATE', 'STATE_RESULT', 'STATE_UPDATED',
  'IMPORT_BURP', 'BURP_IMPORTED', 'ANALYZE', 'OPEN_PANEL',
  'GET_CONFIG', 'CONFIG_RESULT', 'SET_AI', 'SET_AUTHORIZED',
  'REQUEST_OBSERVATION', 'OBSERVATION',
  // v2 — resolved defensively while messages.js is being extended.
  'CRAWL_SITE', 'CRAWL_RESULT', 'GET_TRAFFIC', 'TRAFFIC_RESULT',
];

// Canonical fallback strings. Every extension file uses the same list, so the
// wire protocol stays consistent even if messages.js is still being authored.
const FALLBACK_MESSAGES = Object.freeze({
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
  CRAWL_SITE: 'CRAWL_SITE',
  CRAWL_RESULT: 'CRAWL_RESULT',
  GET_TRAFFIC: 'GET_TRAFFIC',
  TRAFFIC_RESULT: 'TRAFFIC_RESULT',
});

/* ------------------------------------------------------------------ *
 * messages.js interoperability (constants + optional helper)
 * ------------------------------------------------------------------ */

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

  const MSG = { ...FALLBACK_MESSAGES };
  for (const c of containers) {
    if (!c || typeof c !== 'object') continue;
    for (const name of MESSAGE_NAMES) {
      const value = c[name];
      if (typeof value === 'string' && value.length) MSG[name] = value;
    }
  }

  let sendHelper = null;
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

  return { MSG, sendHelper };
}

const { MSG, sendHelper } = resolveMessages(MSG_MOD);

const api = globalThis.chrome || globalThis.browser;

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
  if (api?.runtime?.sendMessage) {
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

/* ------------------------------------------------------------------ *
 * Local bridge client — offline errors are explicit and human-readable
 * ------------------------------------------------------------------ */

async function request(path, { method = 'GET', body, timeout = 8000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(`${BRIDGE}${path}`, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      cache: 'no-store',
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      throw new Error('Bridge returned a non-JSON response.');
    }
    if (!response.ok) {
      throw new Error(json?.error || json?.message || `Bridge HTTP ${response.status}.`);
    }
    return json;
  } catch (err) {
    if (err?.name === 'AbortError') throw new Error('Bridge timed out. Please try again.');
    if (err instanceof TypeError) {
      throw new Error('Bridge offline — start the local bridge with `npm run bridge`. Raw page observations remain available.');
    }
    throw new Error(err?.message || 'Bridge request failed.');
  } finally {
    clearTimeout(timer);
  }
}

const apiGet = (path, options = {}) => request(path, { ...options, method: 'GET' });
const apiPost = (path, body, options = {}) => request(path, { ...options, method: 'POST', body });

/* ------------------------------------------------------------------ *
 * Redaction helpers — names and flags only, never values
 * ------------------------------------------------------------------ */

function redactValue(value) {
  const text = String(value ?? '');
  if (SENSITIVE_VALUE.test(text)) return '[REDACTED]';
  return text.slice(0, 300);
}

function sanitizeHeaders(headers) {
  if (!Array.isArray(headers)) return [];
  const out = [];
  for (const h of headers) {
    const name = String(h?.name || '').toLowerCase();
    if (!name || !ALLOWED_HEADERS.has(name)) continue;
    out.push({ name, value: redactValue(h.value) });
  }
  return out;
}

function sanitizeCookies(cookies) {
  if (!Array.isArray(cookies)) return [];
  return cookies
    .filter((c) => c && c.name)
    .map((c) => ({
      name: String(c.name).slice(0, 200),
      httpOnly: !!c.httpOnly,
      secure: !!c.secure,
      sameSite: c.sameSite || 'unspecified',
      valueLength: Number.isFinite(c.valueLength) ? c.valueLength : 0,
    }));
}

// Defence in depth: strip query strings and fragments from any URL-shaped
// field, so a token in a query value can never be persisted. Parameter *names*
// live in the dedicated queryParams[] array and remain untouched.
function scrubUrl(value) {
  if (typeof value !== 'string' || !value) return value;
  try {
    const parsed = new URL(value, BRIDGE);
    parsed.search = '';
    parsed.hash = '';
    return /^[a-z][a-z0-9+.-]*:/i.test(value) ? parsed.toString() : parsed.pathname;
  } catch {
    return value.split('#')[0].split('?')[0];
  }
}

function scrubObservation(observation) {
  if (!observation || typeof observation !== 'object') return observation;
  const out = { ...observation };
  out.url = scrubUrl(out.url);
  if (Array.isArray(out.forms)) out.forms = out.forms.map((f) => ({ ...f, action: scrubUrl(f.action) }));
  if (Array.isArray(out.links)) out.links = out.links.map((l) => ({ ...l, href: scrubUrl(l.href) }));
  if (Array.isArray(out.endpoints)) out.endpoints = out.endpoints.map((e) => ({ ...e, url: scrubUrl(e.url) }));
  if (Array.isArray(out.scripts)) out.scripts = out.scripts.map((s) => ({ ...s, src: scrubUrl(s.src) }));
  return out;
}

/* ------------------------------------------------------------------ *
 * Per-tab state
 * ------------------------------------------------------------------ */

const state = new Map();   // tabId -> { observation, analysis, crawl, traffic, lastError, authorized }
const headerCache = new Map(); // tabId -> allowlisted response headers
// AI is on by default (SPEC2 §4). The bridge config is authoritative once loaded;
// we never force it off locally.
let config = { aiEnabled: true, model: null, bridgeOnline: false, error: null };

function getTabState(tabId) {
  if (!state.has(tabId)) {
    state.set(tabId, {
      observation: null,
      analysis: null,
      crawl: null,
      traffic: [],
      lastError: null,
      authorized: false,
    });
  }
  return state.get(tabId);
}

function publicState(tabState) {
  return {
    observation: tabState.observation || null,
    analysis: tabState.analysis || null,
    crawl: tabState.crawl || null,
    traffic: Array.isArray(tabState.traffic) ? tabState.traffic : [],
    lastError: tabState.lastError || null,
    authorized: !!tabState.authorized,
  };
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname || '';
  } catch {
    return '';
  }
}

async function getTab(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  try {
    if (globalThis.browser?.tabs?.get) return await globalThis.browser.tabs.get(tabId);
    if (api?.tabs?.get) {
      return await new Promise((resolve) => {
        try {
          api.tabs.get(tabId, (tab) => resolve(api.runtime?.lastError ? null : tab || null));
        } catch {
          resolve(null);
        }
      });
    }
  } catch {
    // Tab may have been closed between the message and this lookup.
  }
  return null;
}

async function queryActiveTab() {
  try {
    if (globalThis.browser?.tabs?.query) {
      const tabs = await globalThis.browser.tabs.query({ active: true, currentWindow: true });
      return tabs?.[0] || null;
    }
    if (api?.tabs?.query) {
      return await new Promise((resolve) => {
        try {
          api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            resolve(api.runtime?.lastError ? null : tabs?.[0] || null);
          });
        } catch {
          resolve(null);
        }
      });
    }
  } catch {
    // Fall through to null.
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * Messaging to/from content scripts and the panel
 * ------------------------------------------------------------------ */

function tabsSend(tabId, message, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);

    try {
      if (globalThis.browser?.tabs?.sendMessage) {
        globalThis.browser.tabs.sendMessage(tabId, message)
          .then((value) => { clearTimeout(timer); finish(value ?? null); })
          .catch(() => { clearTimeout(timer); finish(null); });
      } else if (api?.tabs?.sendMessage) {
        api.tabs.sendMessage(tabId, message, (reply) => {
          clearTimeout(timer);
          if (api.runtime?.lastError) finish(null);
          else finish(reply ?? null);
        });
      } else {
        clearTimeout(timer);
        finish(null);
      }
    } catch {
      clearTimeout(timer);
      finish(null);
    }
  });
}

function broadcast(type, payload = {}) {
  const message = { type, ...payload };
  try {
    if (globalThis.browser?.runtime?.sendMessage) {
      Promise.resolve(globalThis.browser.runtime.sendMessage(message)).catch(() => {});
    } else if (api?.runtime?.sendMessage) {
      api.runtime.sendMessage(message, () => { void api.runtime?.lastError; });
    }
  } catch {
    // No listeners (e.g. panel closed) — harmless.
  }
}

async function requestObservation(tabId) {
  const reply = await tabsSend(tabId, { type: MSG.REQUEST_OBSERVATION });
  if (!reply || reply.ok === false) return null;
  return reply.observation || null;
}

/* ------------------------------------------------------------------ *
 * Header capture (main documents only, allowlisted + redacted)
 * ------------------------------------------------------------------ */

if (api?.webRequest?.onHeadersReceived) {
  try {
    api.webRequest.onHeadersReceived.addListener(
      (details) => {
        if (details.type !== 'main_frame') return;
        const tabId = details.tabId;
        if (!Number.isInteger(tabId) || tabId < 0) return;
        headerCache.set(tabId, sanitizeHeaders(details.responseHeaders || []));
      },
      { urls: ['<all_urls>'], types: ['main_frame'] },
      ['responseHeaders'],
    );
  } catch {
    // If webRequest is restricted for a host, scanning still works without headers.
  }
}

/* ------------------------------------------------------------------ *
 * Passive traffic observation (metadata only, never values)
 * ------------------------------------------------------------------ *
 * onBeforeRequest records only URL structure and parameter NAMES. onCompleted
 * enriches the item with status/content type/length, then fire-and-forgets it
 * to the local bridge. Nothing here awaits a response, so page loads never
 * block, and no request/response body values are retained.
 */

const MAX_PASSIVE_PER_TAB_PER_MINUTE = 40;
const PASSIVE_WINDOW_MS = 60_000;
const passiveBudget = new Map(); // tabId -> { start, count }
const passivePending = new Map(); // requestId -> minimal BurpItem skeleton

function canCapturePassive(tabId) {
  const now = Date.now();
  let bucket = passiveBudget.get(tabId);
  if (!bucket || now - bucket.start >= PASSIVE_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    passiveBudget.set(tabId, bucket);
  }
  if (bucket.count >= MAX_PASSIVE_PER_TAB_PER_MINUTE) return false;
  bucket.count += 1;
  return true;
}

/** URL without query values; parameter names are returned separately. */
function passiveUrlParts(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const queryParams = Array.from(new Set(Array.from(parsed.searchParams.keys())))
      .map((name) => String(name).slice(0, 200));
    parsed.search = '';
    parsed.hash = '';
    return { url: parsed.href, host: parsed.hostname, path: parsed.pathname, queryParams };
  } catch {
    return { url: '', host: '', path: '', queryParams: [] };
  }
}

/** Only formData KEYS are read. Raw bodies are intentionally ignored. */
function passiveBodyParamNames(requestBody) {
  const formData = requestBody?.formData;
  if (!formData || typeof formData !== 'object') return [];
  return Object.keys(formData).map((name) => String(name).slice(0, 200));
}

/** Fire-and-forget POST — short timeout, no retries, no stored values. */
function streamTrafficItem(item) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUTS.stream);
  try {
    fetch(`${BRIDGE}/api/burp/stream`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(item),
      signal: controller.signal,
      cache: 'no-store',
    }).catch(() => {}).finally(() => clearTimeout(timer));
  } catch {
    clearTimeout(timer);
  }
}

function finalizePassive(requestId, details = {}) {
  const pending = passivePending.get(requestId);
  if (!pending) return;
  passivePending.delete(requestId);

  const responseHeaders = Array.isArray(details.responseHeaders) ? details.responseHeaders : [];
  let contentType = '';
  let length = 0;
  for (const header of responseHeaders) {
    const name = String(header?.name || '').toLowerCase();
    if (name === 'content-type' && !contentType) contentType = String(header?.value || '').slice(0, 120);
    if (name === 'content-length' && !length) length = Number(header?.value) || 0;
  }

  streamTrafficItem({
    method: pending.method || 'GET',
    url: pending.url,
    host: pending.host,
    path: pending.path,
    queryParams: pending.queryParams,
    bodyParams: pending.bodyParams,
    headers: [], // names only if needed — passive capture stores no header values
    status: Number.isFinite(details.statusCode) ? details.statusCode : null,
    contentType,
    length,
    source: 'browser-passive',
  });
}

if (api?.webRequest?.onBeforeRequest && api?.webRequest?.onCompleted) {
  try {
    api.webRequest.onBeforeRequest.addListener(
      (details) => {
        const tabId = details.tabId;
        if (!Number.isInteger(tabId) || tabId < 0) return;
        const raw = String(details.url || '');
        if (!/^https?:\/\//i.test(raw) || raw.startsWith(BRIDGE)) return;
        if (!canCapturePassive(tabId)) return;

        const parts = passiveUrlParts(raw);
        if (!parts.host) return;
        // Keep the pending map bounded in case a tab never completes a request.
        if (passivePending.size > 1000) passivePending.clear();
        passivePending.set(details.requestId, {
          method: String(details.method || 'GET').toUpperCase(),
          ...parts,
          bodyParams: passiveBodyParamNames(details.requestBody),
        });
      },
      { urls: ['<all_urls>'], types: ['main_frame', 'xmlhttprequest', 'sub_frame'] },
      ['requestBody'],
    );

    api.webRequest.onCompleted.addListener(
      (details) => finalizePassive(details.requestId, details),
      { urls: ['<all_urls>'], types: ['main_frame', 'xmlhttprequest', 'sub_frame'] },
    );

    api.webRequest.onErrorOccurred?.addListener?.(
      (details) => finalizePassive(details.requestId, { statusCode: 0 }),
      { urls: ['<all_urls>'], types: ['main_frame', 'xmlhttprequest', 'sub_frame'] },
    );
  } catch {
    // Passive observation is best-effort; scanning and notes still work without it.
  }
}

api?.tabs?.onRemoved?.addListener((tabId) => {
  state.delete(tabId);
  headerCache.delete(tabId);
  passiveBudget.delete(tabId);
});

api?.tabs?.onUpdated?.addListener((tabId, changeInfo) => {
  // A new navigation invalidates any previously captured document headers.
  if (changeInfo.status === 'loading' && changeInfo.url) headerCache.delete(tabId);
});

async function safeCookies(tab) {
  if (!tab?.url || !api?.cookies?.getAll) return [];
  try {
    const cookies = await api.cookies.getAll({ url: tab.url });
    return sanitizeCookies(cookies.map((c) => ({
      name: c.name,
      httpOnly: c.httpOnly,
      secure: c.secure,
      sameSite: c.sameSite,
      valueLength: typeof c.value === 'string' ? c.value.length : 0,
    })));
  } catch {
    return [];
  }
}

/* ------------------------------------------------------------------ *
 * Bridge-backed operations
 * ------------------------------------------------------------------ */

async function refreshConfig() {
  try {
    const cfg = await apiGet('/api/config', { timeout: TIMEOUTS.config });
    config = {
      // AI is on by default; only an explicit bridge boolean can turn it off.
      aiEnabled: typeof cfg?.aiEnabled === 'boolean' ? cfg.aiEnabled : true,
      model: cfg?.model || null,
      bridgeOnline: true,
      error: null,
    };
  } catch (err) {
    config = { aiEnabled: false, model: null, bridgeOnline: false, error: err.message };
  }
  return config;
}

async function runAnalysis(tabId, tabState, options = {}) {
  const observation = tabState.observation;
  if (!observation) {
    tabState.lastError = 'No page observation yet. Click Scan page first.';
    return { ok: false, error: tabState.lastError, state: publicState(tabState) };
  }

  const ai = typeof options.ai === 'boolean'
    ? options.ai
    : (typeof options.aiEnabled === 'boolean' ? options.aiEnabled : !!config.aiEnabled);

  try {
    const result = await apiPost('/api/analyze', {
      observation,
      traffic: Array.isArray(tabState.traffic) ? tabState.traffic : [],
      options: { ai, maxCards: 12, authorized: !!tabState.authorized },
    }, { timeout: TIMEOUTS.analyze });

    tabState.analysis = result;
    tabState.lastError = null;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: true, analysis: result, state: publicState(tabState) };
  } catch (err) {
    tabState.lastError = err.message;
    broadcast(MSG.STATE_UPDATED, { tabId });
    // Keep any previous analysis; the panel can still show the raw observation.
    return { ok: false, error: err.message, state: publicState(tabState) };
  }
}

async function handleScan(message, sender) {
  const tabId = message.tabId ?? sender?.tab?.id;
  if (!Number.isInteger(tabId) || tabId < 0) {
    return { ok: false, error: 'No active tab is available for scanning.' };
  }

  const tabState = getTabState(tabId);
  if (typeof message.authorized === 'boolean') tabState.authorized = message.authorized;

  let observation = message.observation || null;
  if (!observation) observation = await requestObservation(tabId);
  // The content script may be missing if the page was open before the
  // extension was installed/reloaded. Inject it once, then retry.
  if (!observation) {
    await ensureContent(tabId);
    observation = await requestObservation(tabId);
  }

  if (!observation || typeof observation !== 'object') {
    tabState.lastError = 'Could not read the page. Open a normal http/https page (not chrome:// or a new tab), wait for it to load, then scan again.';
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: false, error: tabState.lastError, state: publicState(tabState) };
  }

  // Background fills in headers (from webRequest) and cookie flags (from the
  // cookies API). Values are already redacted / stripped before this point.
  const safe = scrubObservation(observation);
  safe.headers = Array.isArray(safe.headers) && safe.headers.length
    ? sanitizeHeaders(safe.headers)
    : (headerCache.get(tabId) || []);
  if (!Array.isArray(safe.cookies) || safe.cookies.length === 0) {
    safe.cookies = await safeCookies(await getTab(tabId));
  } else {
    safe.cookies = sanitizeCookies(safe.cookies);
  }

  tabState.observation = safe;
  tabState.lastError = null;
  broadcast(MSG.STATE_UPDATED, { tabId });

  const outcome = await runAnalysis(tabId, tabState, { ai: message.ai });
  return {
    ok: outcome.ok,
    error: outcome.error || tabState.lastError || null,
    analysis: tabState.analysis,
    state: publicState(tabState),
  };
}

async function handleImport(message, sender) {
  const tabId = message.tabId ?? sender?.tab?.id;
  const tabState = getTabState(tabId ?? -1);
  const host = message.host
    || hostFromUrl(tabState.observation?.url)
    || hostFromUrl((await getTab(tabId))?.url);

  if (!host) {
    const error = 'No target host is known yet. Scan the page first, then import traffic.';
    tabState.lastError = error;
    return { ok: false, error, state: publicState(tabState) };
  }

  try {
    const result = await apiPost('/api/burp/import', {
      host,
      source: message.source || 'panel-paste',
      raw: String(message.raw || ''),
    }, { timeout: TIMEOUTS.import });

    let items = [];
    try {
      const traffic = await apiGet(`/api/burp/traffic?host=${encodeURIComponent(host)}`, {
        timeout: TIMEOUTS.traffic,
      });
      if (Array.isArray(traffic?.items)) items = traffic.items;
    } catch {
      if (Array.isArray(result?.items)) items = result.items;
    }

    tabState.traffic = items;
    tabState.lastError = null;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return {
      ok: true,
      count: Number.isFinite(result?.count) ? result.count : items.length,
      state: publicState(tabState),
    };
  } catch (err) {
    tabState.lastError = err.message;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: false, error: err.message, state: publicState(tabState) };
  }
}

async function handleBurpImported(message, sender) {
  const tabId = message.tabId ?? sender?.tab?.id;
  const tabState = getTabState(tabId ?? -1);
  const host = message.host || hostFromUrl(tabState.observation?.url);
  if (!host) return { ok: false, error: 'Unknown host for imported traffic.' };
  try {
    const traffic = await apiGet(`/api/burp/traffic?host=${encodeURIComponent(host)}`, {
      timeout: TIMEOUTS.traffic,
    });
    tabState.traffic = Array.isArray(traffic?.items) ? traffic.items : [];
    tabState.lastError = null;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: true, state: publicState(tabState) };
  } catch (err) {
    tabState.lastError = err.message;
    return { ok: false, error: err.message, state: publicState(tabState) };
  }
}

function clampInt(value, fallback, min, max) {
  const num = Number(value);
  return Number.isFinite(num) ? Math.min(max, Math.max(min, Math.round(num))) : fallback;
}

/** Bounded, GET-only, same-origin crawl is performed by the local bridge. */
async function handleCrawl(message, sender) {
  const tabId = message.tabId ?? sender?.tab?.id ?? -1;
  const tabState = getTabState(tabId);
  const tab = await getTab(tabId);
  const url = String(message.url || tabState.observation?.url || tab?.url || '').split('#')[0];

  if (!/^https?:\/\//i.test(url)) {
    const error = 'No http(s) target URL is available. Open the site in a tab, then try again.';
    tabState.lastError = error;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: false, error, crawl: tabState.crawl, state: publicState(tabState) };
  }

  try {
    const result = await apiPost('/api/crawl', {
      url,
      maxPages: clampInt(message.maxPages, 12, 1, 50),
      maxDepth: clampInt(message.maxDepth, 2, 0, 5),
    }, { timeout: TIMEOUTS.crawl });

    tabState.crawl = result || null;
    tabState.lastError = null;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: true, crawl: tabState.crawl, state: publicState(tabState) };
  } catch (err) {
    tabState.lastError = err.message;
    broadcast(MSG.STATE_UPDATED, { tabId });
    return { ok: false, error: err.message, crawl: tabState.crawl, state: publicState(tabState) };
  }
}

/** Refresh passive + imported browser traffic for the current target host. */
async function handleTraffic(message, sender) {
  const tabId = message.tabId ?? sender?.tab?.id ?? -1;
  const tabState = getTabState(tabId);
  const host = String(
    message.host || hostFromUrl(tabState.observation?.url) || hostFromUrl((await getTab(tabId))?.url) || '',
  );

  if (!host) {
    return { ok: false, error: 'No target host is known yet. Scan the page first.', items: [], state: publicState(tabState) };
  }

  try {
    const traffic = await apiGet(`/api/burp/traffic?host=${encodeURIComponent(host)}`, {
      timeout: TIMEOUTS.traffic,
    });
    const items = Array.isArray(traffic?.items) ? traffic.items : [];
    tabState.traffic = items;
    tabState.lastError = null;
    return { ok: true, items, state: publicState(tabState) };
  } catch (err) {
    tabState.lastError = err.message;
    return {
      ok: false,
      error: err.message,
      items: Array.isArray(tabState.traffic) ? tabState.traffic : [],
      state: publicState(tabState),
    };
  }
}

async function handleAnalyze(message, sender) {
  const tabId = message.tabId ?? sender?.tab?.id;
  const tabState = getTabState(tabId ?? -1);
  if (typeof message.authorized === 'boolean') tabState.authorized = message.authorized;
  return runAnalysis(tabId, tabState, { ai: message.ai, aiEnabled: message.aiEnabled });
}

function panelUrl(tabId) {
  const base = api?.runtime?.getURL ? api.runtime.getURL('panel.html') : 'panel.html';
  return Number.isInteger(tabId) && tabId >= 0 ? `${base}?tabId=${tabId}` : base;
}

/**
 * Open the guidance UI. Chrome side panel is preferred; Firefox uses its
 * sidebar. If either API is unavailable or rejects (for example, because a
 * user gesture was lost on the message round-trip), fall back to opening the
 * same panel in a regular tab so clicking always produces something visible.
 */
async function openPanel(sender, options = {}) {
  let tabId = options.tabId ?? sender?.tab?.id;
  let windowId = options.windowId ?? sender?.tab?.windowId;
  if (!Number.isInteger(tabId)) {
    const active = await queryActiveTab();
    tabId = active?.id;
    windowId = windowId ?? active?.windowId;
  }
  const primaryError = [];

  if (globalThis.chrome?.sidePanel?.open) {
    try {
      const target = Number.isInteger(tabId) ? { tabId } : { windowId };
      await globalThis.chrome.sidePanel.open(target);
      return { ok: true, mode: 'sidepanel' };
    } catch (err) {
      primaryError.push(err?.message || String(err));
    }
  }
  if (globalThis.browser?.sidebarAction?.open || api?.sidebarAction?.open) {
    try {
      const open = globalThis.browser?.sidebarAction?.open || api.sidebarAction.open;
      await open();
      return { ok: true, mode: 'sidebar' };
    } catch (err) {
      primaryError.push(err?.message || String(err));
    }
  }

  try {
    const created = await api?.tabs?.create?.({ url: panelUrl(tabId), active: true });
    return { ok: true, mode: 'tab', tabId: created?.id ?? tabId };
  } catch (err) {
    return {
      ok: false,
      error: err?.message || primaryError[0] || 'Unable to open the VAPT Lens panel.',
    };
  }
}

async function ensureContent(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0 || !api?.scripting?.executeScript) return;
  const ping = await tabsSend(tabId, { type: 'PING' }, 800);
  if (ping) return;
  try {
    await api.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
  } catch {
    // activeTab may not be granted (e.g. restricted page) — content_scripts still cover normal pages.
  }
}

/* ------------------------------------------------------------------ *
 * Message router
 * ------------------------------------------------------------------ */

api?.runtime?.onMessage?.addListener((message, sender, sendResponse) => {
  const type = message?.type;
  let work = null;

  switch (type) {
    case MSG.SCAN_PAGE:
      work = handleScan(message, sender);
      break;
    case MSG.GET_STATE: {
      const tabId = message.tabId ?? sender?.tab?.id ?? -1;
      const tabState = getTabState(tabId);
      work = Promise.resolve({
        ok: true,
        state: publicState(tabState),
        config: { ...config },
      });
      break;
    }
    case MSG.IMPORT_BURP:
      work = handleImport(message, sender);
      break;
    case MSG.BURP_IMPORTED:
      work = handleBurpImported(message, sender);
      break;
    case MSG.CRAWL_SITE:
      work = handleCrawl(message, sender);
      break;
    case MSG.GET_TRAFFIC:
      work = handleTraffic(message, sender);
      break;
    case MSG.ANALYZE:
      work = handleAnalyze(message, sender);
      break;
    case MSG.GET_CONFIG:
      work = refreshConfig().then((cfg) => ({ ok: cfg.bridgeOnline, config: cfg, error: cfg.error }));
      break;
    case MSG.SET_AI:
      work = (async () => {
        try {
          const cfg = await apiPost('/api/config', { aiEnabled: !!message.aiEnabled }, {
            timeout: TIMEOUTS.config,
          });
          config.aiEnabled = !!cfg?.aiEnabled;
          config.bridgeOnline = true;
          config.error = null;
          return { ok: true, config: { ...config } };
        } catch (err) {
          config.bridgeOnline = false;
          config.error = err.message;
          return { ok: false, error: err.message, config: { ...config } };
        }
      })();
      break;
    case MSG.SET_AUTHORIZED: {
      const tabId = message.tabId ?? sender?.tab?.id ?? -1;
      getTabState(tabId).authorized = !!message.authorized;
      work = Promise.resolve({ ok: true, state: publicState(getTabState(tabId)) });
      break;
    }
    case MSG.OPEN_PANEL:
      work = openPanel(sender, { tabId: message.tabId, windowId: message.windowId });
      break;
    default:
      // Includes REQUEST_OBSERVATION (handled by content.js) and PING.
      return false;
  }

  Promise.resolve(work)
    .then((reply) => sendResponse(reply))
    .catch((err) => sendResponse({ ok: false, error: err?.message || 'Unexpected background error.' }));
  return true; // asynchronous response
});

/* ------------------------------------------------------------------ *
 * Startup / toolbar behaviour
 * ------------------------------------------------------------------ */

try {
  const result = globalThis.chrome?.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true });
  if (result && typeof result.catch === 'function') result.catch(() => {});
} catch {
  // Older Chrome versions simply won't auto-open the side panel.
}

api?.action?.onClicked?.addListener(async (tab) => {
  await ensureContent(tab?.id);
  await openPanel({ tab });
});

refreshConfig();
