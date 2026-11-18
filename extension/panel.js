/**
 * VAPT Lens — panel UI logic (ES module).
 * Talks only to the local bridge via background. Never issues attack traffic.
 */
import * as MSG_MOD from './src/core/messages.js';

const MESSAGE_NAMES = [
  'SCAN_PAGE', 'SCAN_RESULT', 'GET_STATE', 'STATE_RESULT', 'STATE_UPDATED',
  'IMPORT_BURP', 'BURP_IMPORTED', 'ANALYZE', 'OPEN_PANEL',
  'GET_CONFIG', 'CONFIG_RESULT', 'SET_AI', 'SET_AUTHORIZED',
  'REQUEST_OBSERVATION', 'OBSERVATION',
  // v2 — resolved defensively while messages.js is being extended.
  'CRAWL_SITE', 'CRAWL_RESULT', 'GET_TRAFFIC', 'TRAFFIC_RESULT',
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
  CRAWL_SITE: 'CRAWL_SITE',
  CRAWL_RESULT: 'CRAWL_RESULT',
  GET_TRAFFIC: 'GET_TRAFFIC',
  TRAFFIC_RESULT: 'TRAFFIC_RESULT',
};

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

const ui = {
  tabId: null,
  host: '—',
  targetUrl: '',
  state: null,
  // AI is on by default (SPEC2 §4); the bridge config may refine it.
  config: { aiEnabled: true, model: null, bridgeOnline: false, error: null },
  authorized: false,
  category: '',
  owasp: '',
  search: '',
  trafficLive: null,
  trafficTimer: null,
  notesTimer: null,
  siteScan: null,
  siteScanTimer: null,
};

/* ------------------------------------------------------------------ *
 * Small utilities
 * ------------------------------------------------------------------ */

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

/** Direct read-only call to the local bridge (CORS allows extension origins). */
async function bridgeFetch(path, body) {
  const res = await fetch(`http://127.0.0.1:8787${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok || data?.ok === false) throw new Error(data?.error || `Bridge returned ${res.status}`);
  return data;
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
const escAttr = esc;

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
      // Fall through.
    }
  }
  return runtimeSend(message);
}

function queryActiveTab() {
  if (globalThis.browser?.tabs?.query) return globalThis.browser.tabs.query({ active: true, currentWindow: true }).then((t) => t?.[0] || null).catch(() => null);
  if (api?.tabs?.query) {
    return new Promise((resolve) => {
      try {
        api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          resolve(api.runtime?.lastError ? null : tabs?.[0] || null);
        });
      } catch {
        resolve(null);
      }
    });
  }
  return Promise.resolve(null);
}

function getTabById(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return Promise.resolve(null);
  if (globalThis.browser?.tabs?.get) return globalThis.browser.tabs.get(tabId).catch(() => null);
  if (api?.tabs?.get) {
    return new Promise((resolve) => {
      try {
        api.tabs.get(tabId, (tab) => resolve(api.runtime?.lastError ? null : tab || null));
      } catch {
        resolve(null);
      }
    });
  }
  return Promise.resolve(null);
}

function queryTabs(query) {
  if (globalThis.browser?.tabs?.query) {
    return globalThis.browser.tabs.query(query).catch(() => []);
  }
  if (api?.tabs?.query) {
    return new Promise((resolve) => {
      try {
        api.tabs.query(query, (tabs) => resolve(api.runtime?.lastError ? [] : tabs || []));
      } catch {
        resolve([]);
      }
    });
  }
  return Promise.resolve([]);
}

function isWebTab(tab) {
  return !!tab && Number.isInteger(tab.id) && tab.id >= 0 && /^https?:\/\//i.test(tab.url || '');
}

/** Find the real page this panel should scan, even when opened as a tab. */
async function findTargetTab() {
  const params = new URLSearchParams(location.search);
  const requested = Number(params.get('tabId'));
  if (Number.isInteger(requested) && requested >= 0) {
    const explicit = await getTabById(requested);
    if (isWebTab(explicit)) return explicit;
  }
  const active = await queryTabs({ active: true, currentWindow: true });
  const activeWeb = active.find(isWebTab);
  if (activeWeb) return activeWeb;
  const all = await queryTabs({});
  return all.filter(isWebTab).sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0))[0] || null;
}

/** Ask the content script in a specific tab for a value-free observation. */
function tabsSend(tabId, message, timeoutMs = 5000) {
  if (!Number.isInteger(tabId) || tabId < 0) return Promise.resolve(null);
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => { if (!done) { done = true; clearTimeout(timer); resolve(value ?? null); } };
    const timer = setTimeout(() => finish(null), timeoutMs);
    try {
      if (globalThis.browser?.tabs?.sendMessage) {
        globalThis.browser.tabs.sendMessage(tabId, message)
          .then((value) => finish(value))
          .catch(() => finish(null));
      } else if (api?.tabs?.sendMessage) {
        api.tabs.sendMessage(tabId, message, (reply) => {
          if (api.runtime?.lastError) finish(null);
          else finish(reply);
        });
      } else {
        finish(null);
      }
    } catch {
      finish(null);
    }
  });
}

function storageGet(key) {
  if (globalThis.browser?.storage?.local?.get) {
    return globalThis.browser.storage.local.get(key)
      .then((obj) => obj?.[key] ?? '')
      .catch(() => '');
  }
  if (api?.storage?.local?.get) {
    return new Promise((resolve) => {
      try {
        api.storage.local.get(key, (obj) => resolve(api.runtime?.lastError ? '' : obj?.[key] ?? ''));
      } catch {
        resolve('');
      }
    });
  }
  return Promise.resolve('');
}

function storageSet(key, value) {
  if (globalThis.browser?.storage?.local?.set) {
    return globalThis.browser.storage.local.set({ [key]: value }).catch(() => {});
  }
  if (api?.storage?.local?.set) {
    return new Promise((resolve) => {
      try {
        api.storage.local.set({ [key]: value }, () => { void api.runtime?.lastError; resolve(); });
      } catch {
        resolve();
      }
    });
  }
  return Promise.resolve();
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname || '';
  } catch {
    return '';
  }
}

function notesKey() {
  return `vapt-lens:notes:${ui.host || 'unknown'}`;
}

function empty(title, message) {
  return `<div class="vl-empty"><strong>${esc(title)}</strong>${esc(message)}</div>`;
}

function chips(items, fallback = 'None observed') {
  if (!Array.isArray(items) || !items.length) return `<span class="vl-subtle">${esc(fallback)}</span>`;
  return `<div class="chips">${items.map((item) => `<span class="chip">${esc(item)}</span>`).join('')}</div>`;
}

/** Display URL without query values — names are shown in dedicated columns. */
function displayUrl(value) {
  try {
    const parsed = new URL(value);
    parsed.search = '';
    parsed.hash = '';
    return parsed.href;
  } catch {
    return String(value || '').split('?')[0].split('#')[0];
  }
}

/** OWASP categories from the analysis summary, with card-level fallback. */
function owaspCategories() {
  const summary = ui.state?.analysis?.summary?.owasp;
  const out = [];
  const seen = new Set();
  for (const entry of (Array.isArray(summary) ? summary : [])) {
    const id = String(entry?.id || '');
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name: String(entry?.name || ''), cardCount: Number(entry?.cardCount) || 0 });
  }
  for (const card of (Array.isArray(ui.state?.analysis?.cards) ? ui.state.analysis.cards : [])) {
    const id = String(card?.owasp?.id || '');
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name: String(card?.owasp?.name || ''), cardCount: 1 });
  }
  return out.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
}

/** Scrollable, table-like layout. Cells are pre-escaped HTML strings. */
function locTable(headers, rows, emptyTitle, emptyMessage) {
  if (!rows.length) return empty(emptyTitle, emptyMessage);
  return `
    <div class="vl-scroll">
      <table class="vl-loc-table">
        <thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead>
        <tbody>${rows.map((cells) => `<tr>${cells.map((cell) => `<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody>
      </table>
    </div>
  `;
}

/* ------------------------------------------------------------------ *
 * Rendering — Overview
 * ------------------------------------------------------------------ */

function renderOverview() {
  const root = $('#overviewContent');
  const analysis = ui.state?.analysis;
  const observation = ui.state?.observation;

  if (!observation && !analysis) {
    root.innerHTML = empty(
      'No scan yet',
      'Click “Scan page” to observe the current page. VAPT Lens only reads structure — it never changes the page or sends attacks.',
    );
    return;
  }

  const summary = analysis?.summary || {};
  const tech = Array.isArray(summary.tech) ? summary.tech : [];
  const risks = Array.isArray(summary.riskHints) ? summary.riskHints : [];
  const signals = observation?.signals || {};
  const activeSignals = Object.keys(signals).filter((key) => signals[key] === true).slice(0, 8);
  const cards = Array.isArray(analysis?.cards) ? analysis.cards : [];

  const parts = [];

  parts.push(`
    <div class="vl-card">
      <h2>Scan summary</h2>
      <div class="vl-grid vl-grid-3">
        <div class="vl-stat"><div class="vl-num">${cards.length}</div><div class="vl-label">Guided tests</div></div>
        <div class="vl-stat"><div class="vl-num">${Number(observation?.counts?.forms || 0)}</div><div class="vl-label">Forms</div></div>
        <div class="vl-stat"><div class="vl-num">${Number(observation?.counts?.endpoints || 0)}</div><div class="vl-label">Endpoints</div></div>
      </div>
      <p class="vl-subtle" style="margin:9px 0 0">Captured ${esc(observation?.capturedAt ? new Date(observation.capturedAt).toLocaleString() : 'just now')} · ${esc(observation?.host || ui.host)}</p>
    </div>
  `);

  parts.push(`
    <div class="vl-card">
      <h2>Technologies</h2>
      ${chips(tech, 'No technologies detected')}
    </div>
  `);

  parts.push(`
    <div class="vl-card">
      <h2>Risk hints</h2>
      ${risks.length
        ? `<ul class="vl-list">${risks.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>`
        : '<p class="vl-subtle">No rule-based hints for this page.</p>'}
    </div>
  `);

  if (activeSignals.length) {
    parts.push(`
      <div class="vl-card">
        <h2>Observed signals</h2>
        ${chips(activeSignals, 'None')}
        <p class="vl-subtle" style="margin:8px 0 0">Signals are structural booleans only — no input values were read.</p>
      </div>
    `);
  }

  if (analysis?.aiUsed) {
    parts.push('<p class="vl-subtle">Optional AI hints were used for this analysis. Always verify suggestions manually.</p>');
  }
  if (Array.isArray(analysis?.warnings) && analysis.warnings.length) {
    parts.push(`
      <div class="vl-card">
        <h2>Analysis warnings</h2>
        <ul class="vl-list">${analysis.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>
      </div>
    `);
  }

  root.innerHTML = parts.join('');
}

/* ------------------------------------------------------------------ *
 * Rendering — Attack surface (names only)
 * ------------------------------------------------------------------ */

function renderSurface() {
  const root = $('#surfaceContent');
  const observation = ui.state?.observation;
  if (!observation) {
    root.innerHTML = empty('No observation yet', 'Scan the page to see its observable attack surface and element locations.');
    return;
  }

  const counts = observation.counts || {};
  const statList = [
    ['Forms', counts.forms], ['Inputs', counts.inputs], ['Links', counts.links],
    ['Scripts', counts.scripts], ['Endpoints', counts.endpoints],
  ];
  const parts = [`
    <div class="vl-grid vl-grid-3">
      ${statList.map(([label, value]) => `<div class="vl-stat"><div class="vl-num">${Number(value || 0)}</div><div class="vl-label">${esc(label)}</div></div>`).join('')}
    </div>
  `];

  // Form locations + the field names inside each form.
  const formRows = (Array.isArray(observation.forms) ? observation.forms : []).map((form, index) => {
    const names = (Array.isArray(form?.fields) ? form.fields : [])
      .map((field) => field?.name).filter(Boolean).join(', ') || '—';
    return [
      `<span class="vl-mono">${esc(form?.selector || `form[${index}]`)}</span>`,
      esc(form?.method || 'GET'),
      `<span class="vl-mono">${esc(form?.xpath || '—')}</span>`,
      `<span class="vl-mono">${esc(names)}</span>`,
      `<span class="vl-subtle">${esc(displayUrl(form?.action || observation.url))}</span>`,
    ];
  });
  parts.push('<div class="vl-section-title">Form locations &amp; fields</div>');
  parts.push(locTable(
    ['Selector', 'Method', 'XPath', 'Field names', 'Action / page'],
    formRows,
    'No forms observed',
    'This page exposed no forms during the scan.',
  ));

  // Flattened inputs, each with the selector/XPath that locates it.
  const inputRows = (Array.isArray(observation.inputs) ? observation.inputs : []).map((input) => [
    `<span class="vl-mono">${esc(input?.name || '—')}</span>`,
    esc(input?.type || '—'),
    `<span class="vl-mono">${esc(input?.id || '—')}</span>`,
    `<span class="vl-mono">${esc(input?.selector || '—')}</span>`,
    `<span class="vl-mono">${esc(input?.xpath || '—')}</span>`,
    `<span class="vl-subtle">${esc(displayUrl(input?.page || observation.url))}</span>`,
  ]);
  parts.push('<div class="vl-section-title">Input locations</div>');
  parts.push(locTable(
    ['Name', 'Type', 'Id', 'Selector', 'XPath', 'Page / form'],
    inputRows,
    'No inputs observed',
    'This page exposed no inputs during the scan.',
  ));

  // URL parameter origins — names and pages only, never values.
  const paramRows = (Array.isArray(observation.queryParams) ? observation.queryParams : []).map((param) => {
    const item = typeof param === 'string' ? { name: param } : (param || {});
    return [
      `<span class="vl-mono">${esc(item.name || '—')}</span>`,
      esc(item.location || 'query'),
      `<span class="vl-subtle">${esc(displayUrl(item.page || observation.url))}</span>`,
      esc(Number.isFinite(item.valueLength) ? item.valueLength : '—'),
    ];
  });
  parts.push('<div class="vl-section-title">URL parameter origins</div>');
  parts.push(locTable(
    ['Name', 'Location', 'Page', 'Value length'],
    paramRows,
    'No URL parameters observed',
    'No query parameter names were seen on this page.',
  ));

  const endpointNames = (Array.isArray(observation.endpoints) ? observation.endpoints : [])
    .map((e) => displayUrl(e?.url || e?.path || '')).filter(Boolean);
  const cookieNames = (Array.isArray(observation.cookies) ? observation.cookies : []).map((c) => c?.name).filter(Boolean);
  const headerNames = (Array.isArray(observation.headers) ? observation.headers : []).map((h) => h?.name).filter(Boolean);
  const sections = [
    ['Endpoints', endpointNames],
    ['Cookies (flags only)', cookieNames],
    ['Response headers (allowlisted)', headerNames],
  ];

  root.innerHTML = parts.join('') + sections.map(([title, values]) => `
    <div class="vl-section-title">${esc(title)}</div>
    <div class="vl-card">${chips(values, `No ${title.toLowerCase()} observed`)}</div>
  `).join('') + '<p class="vl-subtle">Only names, types, lengths, flags, and element locations are shown. Values, tokens, and credentials are never captured or displayed.</p>';
}

/* ------------------------------------------------------------------ *
 * Rendering — Site map (bounded crawl inventory)
 * ------------------------------------------------------------------ */

function renderSitemap() {
  const root = $('#sitemapContent');
  const crawl = ui.state?.crawl;
  if (!crawl) {
    root.innerHTML = empty(
      'No site map yet',
      'Click “Crawl site” to build a bounded, same-origin, GET-only map of the current site. Forms are never submitted.',
    );
    return;
  }

  const stats = crawl.stats || {};
  const pages = Array.isArray(crawl.pages) ? crawl.pages : [];
  const inventory = crawl.inventory || {};
  const warnings = Array.isArray(crawl.warnings) ? crawl.warnings : [];
  const parts = [`
    <div class="vl-card">
      <h2>${esc(crawl.host || 'Site map')}</h2>
      <div class="vl-grid vl-grid-3">
        <div class="vl-stat"><div class="vl-num">${Number(stats.pagesCrawled || 0)}</div><div class="vl-label">Pages crawled</div></div>
        <div class="vl-stat"><div class="vl-num">${Number(stats.skipped || 0)}</div><div class="vl-label">Skipped links</div></div>
        <div class="vl-stat"><div class="vl-num">${stats.maxPagesReached ? 'yes' : 'no'}</div><div class="vl-label">Page limit reached</div></div>
      </div>
      <p class="vl-subtle" style="margin:9px 0 0">Start: ${esc(displayUrl(crawl.startUrl || ''))}</p>
    </div>
  `];

  if (warnings.length) {
    parts.push('<div class="vl-section-title">Crawl warnings</div>');
    parts.push(warnings.map((warning) => `<div class="vl-warn">${esc(warning)}</div>`).join(''));
  }

  parts.push('<div class="vl-section-title">Pages</div>');
  parts.push(pages.length
    ? `<div class="vl-scroll">${pages.map((page) => `
        <div class="vl-page">
          <div class="vl-page-head">
            <span class="vl-status${page.error || (page.status && Number(page.status) >= 400) ? ' status-error' : ''}">${esc(page.error ? 'error' : (page.status || '—'))}</span>
            <span class="vl-page-title">${esc(page.title || '(untitled)')}</span>
          </div>
          <div class="vl-mono" style="margin-top:4px;word-break:break-all">${esc(displayUrl(page.url || ''))}</div>
          ${page.error ? `<div class="vl-warn" style="margin:6px 0 0">${esc(page.error)}</div>` : ''}
        </div>
      `).join('')}</div>`
    : empty('No pages crawled', 'The bridge did not return any pages for this target.'));

  const formRows = (Array.isArray(inventory.forms) ? inventory.forms : []).map((form) => [
    `<span class="vl-mono">${esc(form?.selector || '—')}</span>`,
    esc(form?.method || 'GET'),
    `<span class="vl-mono">${esc(form?.xpath || '—')}</span>`,
    `<span class="vl-mono">${esc((Array.isArray(form?.fields) ? form.fields : []).map((f) => f?.name).filter(Boolean).join(', ') || '—')}</span>`,
    `<span class="vl-subtle">${esc(displayUrl(form?.page || form?.action || ''))}</span>`,
  ]);
  parts.push('<div class="vl-section-title">Forms</div>');
  parts.push(locTable(['Selector', 'Method', 'XPath', 'Field names', 'Page'], formRows, 'No forms found', 'The crawl found no forms on the visited pages.'));

  const inputRows = (Array.isArray(inventory.inputs) ? inventory.inputs : []).map((input) => [
    `<span class="vl-mono">${esc(input?.name || '—')}</span>`,
    esc(input?.type || '—'),
    `<span class="vl-mono">${esc(input?.selector || '—')}</span>`,
    `<span class="vl-mono">${esc(input?.xpath || '—')}</span>`,
    `<span class="vl-mono">${esc(input?.formSelector || '—')}</span>`,
    `<span class="vl-subtle">${esc(displayUrl(input?.page || ''))}</span>`,
  ]);
  parts.push('<div class="vl-section-title">Inputs</div>');
  parts.push(locTable(['Name', 'Type', 'Selector', 'XPath', 'Form selector', 'Page'], inputRows, 'No inputs found', 'The crawl found no inputs on the visited pages.'));

  // Group URL parameter names by the page they originated from.
  const paramsByPage = new Map();
  for (const param of (Array.isArray(inventory.urlParams) ? inventory.urlParams : [])) {
    const page = displayUrl(param?.page || '');
    const name = String(param?.name || '');
    if (!name) continue;
    if (!paramsByPage.has(page)) paramsByPage.set(page, []);
    paramsByPage.get(page).push(name);
  }
  const paramRows = Array.from(paramsByPage, ([page, names]) => [
    `<span class="vl-subtle">${esc(page)}</span>`,
    `<span class="vl-mono">${esc(Array.from(new Set(names)).join(', '))}</span>`,
  ]);
  parts.push('<div class="vl-section-title">URL parameters by page</div>');
  parts.push(locTable(['Page', 'Parameter names'], paramRows, 'No URL parameters found', 'No query parameter names were seen in the crawl.'));

  const endpointRows = (Array.isArray(inventory.endpoints) ? inventory.endpoints : []).map((endpoint) => [
    `<span class="vl-mono">${esc(displayUrl(endpoint?.url || ''))}</span>`,
    esc(endpoint?.source || '—'),
    `<span class="vl-subtle">${esc(displayUrl(endpoint?.page || ''))}</span>`,
  ]);
  parts.push('<div class="vl-section-title">Endpoints</div>');
  parts.push(locTable(['Endpoint', 'Source', 'Page'], endpointRows, 'No endpoints found', 'The crawl found no linked endpoints.'));

  root.innerHTML = parts.join('');
}

/* ------------------------------------------------------------------ *
 * Rendering — Security checks (passive header review + manual guidance)
 * ------------------------------------------------------------------ */

function checkStatus(status) {
  const label = status === 'ok' ? 'OK' : status === 'weak' ? 'WEAK' : 'MISSING';
  return `<span class="vl-check-status is-${esc(status)}">${label}</span>`;
}

function renderChecks() {
  const root = $('#checksContent');
  const checks = ui.state?.analysis?.checks;
  if (!checks) {
    root.innerHTML = empty(
      'No checks yet',
      'Click "Scan page" first. Security headers are read from the captured response; port and TLS steps are manual commands you run yourself.',
    );
    return;
  }

  const headers = checks.headers || {};
  const summary = headers.summary || {};
  const headerRows = (headers.results || []).map((h) => [
    `${checkStatus(h.status)} <strong>${esc(h.name)}</strong><br><span class="vl-subtle">${esc(h.note || '')}</span>`,
    h.observed
      ? `<code>${esc(h.observed)}</code><br><span class="vl-subtle">${esc(h.manualCheck || '')}</span>`
      : `<span class="vl-subtle">Not present in captured headers. ${esc(h.manualCheck || '')}</span>`,
    `<span class="vl-subtle">${esc(h.fix || '')}</span>`,
  ]);

  const guidance = Array.isArray(checks.guidance) ? checks.guidance : [];
  const guidanceHTML = guidance.map((item, index) => `
    <div class="vl-card vl-check-card">
      <h2>${esc(item.title)} <span class="vl-subtle">· ${esc(item.tool)} · ${esc(item.owasp?.id || '')}</span></h2>
      <p class="vl-check-why">${esc(item.why || '')}</p>
      <div class="vl-cmd-row">
        <code class="vl-cmd">${esc(item.command || '')}</code>
        <button type="button" class="vl-copy" data-check-copy="${index}">Copy</button>
      </div>
      <p class="vl-check-why"><strong>Interpret:</strong> ${esc(item.interpret || '')}</p>
    </div>
  `).join('');

  root.innerHTML = `
    <div class="vl-section-title">Security headers
      <span class="vl-subtle">${Number(summary.ok || 0)} OK · ${Number(summary.weak || 0)} weak · ${Number(summary.missing || 0)} missing</span>
    </div>
    ${headers.available
      ? locTable(['Header', 'Observed / check', 'Recommendation'], headerRows)
      : empty('No response headers captured', 'The browser did not expose response headers for this page. Header results are unavailable; the manual commands below still apply.')}
    <p class="vl-subtle">${esc(headers.source || 'Headers come from the current page response only.')}</p>

    <div class="vl-section-title">Open ports &amp; TLS (manual checks)</div>
    <p class="vl-subtle">${esc(checks.scope || '')}</p>
    ${guidanceHTML || empty('No guidance available', 'Run a scan to generate target-specific commands.')}
  `;
}

/* ------------------------------------------------------------------ *
 * Rendering — OWASP Top 10
 * ------------------------------------------------------------------ */

function renderOwasp() {
  const root = $('#owaspContent');
  const categories = owaspCategories();
  if (!categories.length) {
    root.innerHTML = empty(
      'No OWASP data yet',
      'Scan the page first. The ten OWASP Top 10 categories and their related test counts will appear here.',
    );
    return;
  }

  root.innerHTML = `
    <p class="vl-hint">Click a category to open Guided tests filtered to that OWASP id. Counts reflect the cards from the latest scan.</p>
    <div class="owasp-grid">
      ${categories.map((category) => {
        const count = Number(category.cardCount) || 0;
        return `
          <button type="button" class="owasp-card" data-owasp="${escAttr(category.id)}" title="Show ${escAttr(category.id)} guided tests">
            <span class="owasp-id">${esc(category.id)}</span>
            <span class="owasp-name">${esc(category.name || 'Category')}</span>
            <span class="owasp-count">${count} related test${count === 1 ? '' : 's'}</span>
          </button>
        `;
      }).join('')}
    </div>
    <div id="siteFindings"></div>
  `;
  renderSiteFindings();
}

function renderSiteFindings() {
  const root = $('#siteFindings');
  if (!root) return;
  const data = ui.siteScan?.result?.findings;
  if (!data) {
    root.innerHTML = `
      <div class="vl-section-title">Possible vulnerabilities across the site</div>
      ${empty(
        'No whole-site findings yet',
        'Click “Scan whole site” above. Findings are passive inferences from crawled pages, with the exact URL and location for manual verification.',
      )}
    `;
    return;
  }

  const findings = Array.isArray(data.findings) ? data.findings : [];
  const rows = findings.map((f) => [
    `<span class="vl-owasp">${esc(f?.owasp?.id || '')} · ${esc(f?.owasp?.name || '')}</span>`,
    `<strong>${esc(f.title || '')}</strong><br><span class="vl-subtle">${esc(f.possibleVulnerability || '')}</span>`,
    `<span class="vl-sev sev-${esc(String(f.severity || 'low').toLowerCase())}">${esc(f.severity || 'low')}</span>`,
    `<code>${esc(f.url || '')}</code>`,
    `<code>${esc(f.point || '')}</code><br><span class="vl-subtle">${esc(f.evidence || '')}</span>`,
    `<span class="vl-subtle">${esc(f.manualCheck || '')}</span>`,
  ]);

  const spaRoutes = Number(ui.siteScan?.result?.stats?.jsRoutesDiscovered || 0);
  const spaNote = spaRoutes
    ? `<p class="vl-hint">SPA detected: ${spaRoutes} routes were recovered from same-host JavaScript bundles. Forms and inputs created by JavaScript are not visible to this passive crawler — use “Scan page” on that rendered page or Burp traffic for those checks.</p>`
    : '';

  root.innerHTML = `
    <div class="vl-section-title">Possible vulnerabilities across the site
      <span class="vl-subtle">${Number(data.summary?.total || findings.length)} possible · ${Number(data.summary?.pagesCovered || 0)} pages</span>
    </div>
    <p class="vl-subtle">${esc(data.scope || 'Passive inference only — verify manually. No payloads are sent by this tool.')}</p>
    ${spaNote}
    ${locTable(['OWASP', 'Possible vulnerability', 'Severity', 'Exact URL', 'Exact point / evidence', 'Manual check'], rows,
      'No likely issues found', 'The crawled pages produced no passive OWASP findings. Guided tests below still apply.')}
  `;
}

/* ------------------------------------------------------------------ *
 * Rendering — Guided tests
 * ------------------------------------------------------------------ */

function severityClass(severity) {
  return `sev-${String(severity || 'info').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
}

function cardHTML(card) {
  const steps = (Array.isArray(card.steps) ? card.steps : [])
    .map((step) => `<li>${esc(step)}</li>`).join('');
  const payloads = (Array.isArray(card.payloads) ? card.payloads : [])
    .map((p) => `<button type="button" class="vl-copy" data-payload="${escAttr(p?.value ?? '')}" title="Copy safe test string">${esc(p?.label || 'Copy')}</button>`)
    .join('');

  return `
    <article class="vl-card test-card" data-category="${escAttr(card.category || '')}">
      <div class="vl-card-head">
        <h3>${esc(card.title || 'Untitled test')}</h3>
        <div class="chips">
          ${card?.owasp?.id ? `<span class="vl-owasp">${esc(card.owasp.id)} · ${esc(card.owasp.name || '')}</span>` : ''}
          <span class="vl-sev ${severityClass(card.severityHint)}">${esc(card.severityHint || 'info')}</span>
        </div>
      </div>
      <p class="vl-why">${esc(card.whyHere || '')}</p>
      <ol class="vl-steps">${steps}</ol>
      ${payloads ? `
        <div class="vl-payloads">
          <span class="vl-subtle">Copyable test strings (guidance only)</span>
          ${payloads}
        </div>
      ` : ''}
      <div class="vl-verify"><strong>Verify:</strong> ${esc(card.verify || 'Review the response manually.')}</div>
      <div class="vl-defense"><strong>Defense:</strong> ${esc(card.defense || 'Apply the relevant secure coding control.')}</div>
      <div class="vl-source">Category: ${esc(card.category || 'general')}${card?.owasp?.id ? ` · OWASP: ${esc(card.owasp.id)} ${esc(card.owasp.name || '')}` : ''} · Source: ${esc(card.skillId || card.source || 'local rules')} · No attacks are sent by this tool.</div>
    </article>
  `;
}

function renderTests() {
  const cardsRoot = $('#cards');
  const gate = $('#authGate');
  const count = $('#cardCount');
  const allCards = Array.isArray(ui.state?.analysis?.cards) ? ui.state.analysis.cards : [];

  // OWASP + category filter options.
  const owaspSelect = $('#owaspFilter');
  const owaspOptions = owaspCategories();
  const currentOwasp = owaspSelect.value || ui.owasp;
  owaspSelect.innerHTML = `<option value="">All OWASP categories</option>${owaspOptions.map((o) => `<option value="${escAttr(o.id)}">${esc(o.id)} · ${esc(o.name || 'Category')}</option>`).join('')}`;
  if (owaspOptions.some((o) => o.id === currentOwasp)) {
    ui.owasp = currentOwasp;
    owaspSelect.value = currentOwasp;
  } else {
    ui.owasp = '';
    owaspSelect.value = '';
  }

  const categories = Array.from(new Set(allCards.map((c) => c.category || 'general'))).sort();
  const select = $('#categoryFilter');
  const current = select.value;
  select.innerHTML = `<option value="">All categories</option>${categories.map((c) => `<option value="${escAttr(c)}">${esc(c)}</option>`).join('')}`;
  if (categories.includes(current)) select.value = current;
  else select.value = '';

  if (!ui.authorized) {
    gate.classList.remove('vl-hidden');
    gate.innerHTML = '<strong>Guided tests are hidden.</strong><br>Check “I’m authorized to test this target” above to reveal them.';
    cardsRoot.innerHTML = '';
    count.textContent = `${allCards.length} available once authorized`;
    return;
  }

  gate.classList.add('vl-hidden');
  if (!allCards.length) {
    cardsRoot.innerHTML = empty(
      ui.state?.observation ? 'No guided tests yet' : 'Scan first',
      ui.state?.observation
        ? 'This page produced no rule-based cards. Adjust filters or try again after importing traffic.'
        : 'Click “Scan page” to generate guidance for the current target.',
    );
    count.textContent = '';
    return;
  }

  const needle = ui.search.trim().toLowerCase();
  const filtered = allCards.filter((card) => {
    if (ui.category && (card.category || 'general') !== ui.category) return false;
    if (ui.owasp && String(card?.owasp?.id || '') !== ui.owasp) return false;
    if (!needle) return true;
    const haystack = [
      card.title, card.category, card.whyHere, card.verify, card.defense, card.skillId,
      card?.owasp?.id, card?.owasp?.name,
      ...(Array.isArray(card.steps) ? card.steps : []),
    ].join(' ').toLowerCase();
    return haystack.includes(needle);
  });

  count.textContent = `${filtered.length} of ${allCards.length} tests`;
  cardsRoot.innerHTML = filtered.length
    ? filtered.map(cardHTML).join('')
    : empty('No matching tests', 'Try a different category or search term.');
}

/* ------------------------------------------------------------------ *
 * Rendering — Burp traffic
 * ------------------------------------------------------------------ */

function renderTraffic() {
  const root = $('#trafficContent');
  const items = Array.isArray(ui.state?.traffic) ? ui.state.traffic : [];
  if (!items.length) {
    root.innerHTML = empty(
      'No traffic yet',
      'Requests passively observed in this browser — or traffic you import above — will appear here. Only paths and parameter names are kept; this list refreshes every 5 seconds.',
    );
    return;
  }

  root.innerHTML = `
    <div class="vl-section-title">Observed &amp; imported items (${items.length})</div>
    ${items.map((item) => {
      const query = (Array.isArray(item.queryParams) ? item.queryParams : []).map((p) => (typeof p === 'string' ? p : p?.name)).filter(Boolean);
      const body = (Array.isArray(item.bodyParams) ? item.bodyParams : []).map((p) => (typeof p === 'string' ? p : p?.name)).filter(Boolean);
      return `
        <div class="traffic-item">
          <span class="vl-method">${esc(item.method || '—')}</span>
          <div class="traffic-body">
            <div class="traffic-path">${esc(item.path || item.url || '—')}</div>
            <div class="traffic-meta">Query: ${esc(query.join(', ') || 'none')} · Body: ${esc(body.join(', ') || 'none')}${item.status ? ` · Status: ${esc(item.status)}` : ''} · Source: ${esc(item.source || 'import')}</div>
          </div>
        </div>
      `;
    }).join('')}
    <p class="vl-subtle">Parameter names only — values are not displayed.</p>
  `;
}

/* ------------------------------------------------------------------ *
 * Rendering — global state
 * ------------------------------------------------------------------ */

function renderBridgeStatus() {
  const banner = $('#bridgeBanner');
  const footer = $('#bridgeState');
  const lastError = ui.state?.lastError || '';
  const bridgeError = /bridge|offline|timed out/i.test(lastError) ? lastError : '';
  const offline = !ui.config.bridgeOnline || !!bridgeError;
  const message = ui.config.error || bridgeError || 'Start the local bridge with `npm run bridge`.';

  if (offline) {
    banner.classList.remove('vl-hidden');
    banner.textContent = '';
    const lead = document.createElement('strong');
    lead.textContent = 'Bridge unavailable. ';
    banner.appendChild(lead);
    banner.appendChild(document.createTextNode(`${message} Raw observations and local notes still work.`));
  } else {
    banner.classList.add('vl-hidden');
    banner.textContent = '';
  }

  footer.textContent = ui.config.bridgeOnline
    ? `bridge online${ui.config.model ? ` · ${ui.config.model}` : ''}`
    : 'bridge offline';
  renderBadges();
}

function renderBadges() {
  const ai = $('#aiBadge');
  const traffic = $('#trafficBadge');
  const aiOn = !!ui.config.aiEnabled;
  if (ai) {
    ai.textContent = `AI: ${aiOn ? 'on' : 'off'}`;
    ai.classList.toggle('is-on', aiOn);
    ai.classList.toggle('is-off', !aiOn);
  }
  // "Live" means the bridge is reachable and the last traffic poll succeeded.
  const live = !!ui.config.bridgeOnline && ui.trafficLive !== false;
  if (traffic) {
    traffic.textContent = `Traffic: ${live ? 'live' : 'offline'}`;
    traffic.classList.toggle('is-on', live);
    traffic.classList.toggle('is-off', !live);
  }
}

function renderAll() {
  renderBridgeStatus();
  renderBadges();
  renderOverview();
  renderSurface();
  renderSitemap();
  renderChecks();
  renderOwasp();
  renderTests();
  renderTraffic();
}

async function refreshState() {
  const reply = await send(MSG.GET_STATE, { tabId: ui.tabId });
  if (reply?.ok && reply.state) ui.state = reply.state;
  else if (reply?.error) ui.state = { lastError: reply.error };
  renderAll();
}

async function refreshConfig() {
  const reply = await send(MSG.GET_CONFIG);
  if (reply?.config) {
    ui.config = {
      ...ui.config,
      ...reply.config,
      aiEnabled: typeof reply.config.aiEnabled === 'boolean' ? reply.config.aiEnabled : ui.config.aiEnabled,
    };
  }
  $('#aiToggle').checked = !!ui.config.aiEnabled;
  renderBadges();
}

/** Poll passive/imported traffic for the current host while the panel is open. */
async function pollTraffic() {
  const host = ui.host && ui.host !== '—' ? ui.host : '';
  const reply = await send(MSG.GET_TRAFFIC, { tabId: ui.tabId, host });
  if (reply?.ok) {
    ui.trafficLive = true;
    if (reply.state) ui.state = { ...(ui.state || {}), ...reply.state };
    if (Array.isArray(reply.items)) ui.state = { ...(ui.state || {}), traffic: reply.items };
    renderTraffic();
  } else {
    ui.trafficLive = false;
  }
  renderBadges();
}

/* ------------------------------------------------------------------ *
 * Interaction
 * ------------------------------------------------------------------ */

async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fall back below.
  }
  try {
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  } catch {
    return false;
  }
}

function switchTab(name) {
  $$('.vl-tab').forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle('is-active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  $$('.vl-panel').forEach((panel) => {
    const active = panel.dataset.panel === name;
    panel.classList.toggle('is-active', active);
    panel.hidden = !active;
  });
}

function exportMarkdown() {
  const observation = ui.state?.observation;
  const analysis = ui.state?.analysis;
  const lines = [
    `# VAPT Lens report — ${ui.host}`,
    '',
    'Guidance only — no attacks were performed by VAPT Lens. Test only systems you own or are explicitly authorized to test.',
    '',
    `Generated: ${new Date().toISOString()}`,
    '',
  ];

  if (observation) {
    lines.push('## Observed surface', '');
    lines.push(`- URL: ${observation.url || 'unknown'}`);
    lines.push(`- Title: ${observation.title || 'n/a'}`);
    lines.push(`- Forms: ${observation.counts?.forms || 0}, endpoints: ${observation.counts?.endpoints || 0}`);
    lines.push('');
  }

  if (analysis?.summary) {
    lines.push('## Summary', '');
    lines.push(`- Technologies: ${(analysis.summary.tech || []).join(', ') || 'none detected'}`);
    for (const hint of analysis.summary.riskHints || []) lines.push(`- Risk hint: ${hint}`);
    lines.push('');
  }

  if (ui.authorized && Array.isArray(analysis?.cards)) {
    lines.push('## Guided tests', '');
    for (const card of analysis.cards) {
      lines.push(`### ${card.title || 'Untitled test'} (${card.severityHint || 'info'})`, '');
      if (card.whyHere) lines.push(card.whyHere, '');
      for (const step of card.steps || []) lines.push(`1. ${step}`);
      lines.push('');
      if (card.verify) lines.push(`**Verify:** ${card.verify}`, '');
      if (card.defense) lines.push(`**Defense:** ${card.defense}`, '');
      lines.push(`Source: ${card.skillId || card.source || 'local rules'}`, '');
    }
  }

  const notes = $('#notes').value.trim();
  if (notes) lines.push('## Notes', '', notes, '');

  const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `vapt-lens-${(ui.host || 'target').replace(/[^a-z0-9.-]+/gi, '_')}.md`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  $('#notesStatus').textContent = 'Markdown exported.';
}

/** Kick off a bounded whole-site crawl and poll its progress bar. */
async function startWholeSiteScan() {
  const button = $('#siteScanBtn');
  const bar = $('#siteScanBar');
  const label = $('#siteScanLabel');
  const percent = $('#siteScanPercent');
  const fill = $('#siteScanFill');
  const detail = $('#siteScanDetail');
  const status = $('#crawlStatus');

  const url = ui.state?.observation?.url || ui.targetUrl || (await findTargetTab())?.url || '';
  if (!/^https?:\/\//i.test(url)) {
    status.textContent = 'Open a web page first.';
    status.classList.add('vl-error');
    return;
  }

  if (ui.siteScanTimer) clearInterval(ui.siteScanTimer);
  ui.siteScan = null;
  button.disabled = true;
  button.textContent = 'Scanning…';
  bar.classList.remove('vl-hidden');
  status.textContent = '';
  status.classList.remove('vl-error');

  const show = (phase, done, max, current) => {
    const pct = phase === 'done' ? 100 : phase === 'analyzing' ? 98
      : Math.min(95, Math.round((Number(done || 0) / Math.max(1, Number(max || 1))) * 100));
    const names = {
      start: 'Starting', queued: 'Queued', crawling: 'Crawling pages',
      discovering: 'Discovering app routes', analyzing: 'Analyzing OWASP findings',
      done: 'Complete', error: 'Failed',
    };
    label.textContent = `Whole-site scan · ${names[phase] || phase}`;
    percent.textContent = `${pct}%`;
    fill.style.width = `${pct}%`;
    detail.textContent = current ? `${done || 0}/${max || '?'} pages · ${current}` : `${done || 0}/${max || '?'} pages`;
  };
  show('queued', 0, 100, url);

  try {
    const job = await bridgeFetch('/api/site/scan', {
      url,
      maxPages: 100,
      maxDepth: 8,
      delayMs: 80,
    });
    if (!job?.id) throw new Error('Bridge did not return a scan id.');

    ui.siteScanTimer = setInterval(async () => {
      try {
        const view = await bridgeFetch(`/api/site/scan/status?id=${encodeURIComponent(job.id)}`);
        ui.siteScan = view;
        const p = view.progress || {};
        show(view.phase, p.pagesDone, p.maxPages, p.currentUrl);
        if (view.status === 'done' || view.status === 'error') {
          clearInterval(ui.siteScanTimer);
          ui.siteScanTimer = null;
          button.disabled = false;
          button.textContent = 'Scan whole site';
          if (view.status === 'error') {
            status.textContent = view.error || 'Scan failed';
            status.classList.add('vl-error');
          } else {
            const summary = view.result?.findings?.summary || {};
            const routes = Number(view.stats?.jsRoutesDiscovered || 0);
            status.textContent = `Scanned ${view.stats?.pagesCrawled || 0} pages${routes ? ` · ${routes} SPA routes` : ''} · ${summary.total || 0} possible findings`;
            renderOwasp();
            switchTab('owasp');
          }
        }
      } catch (err) {
        clearInterval(ui.siteScanTimer);
        ui.siteScanTimer = null;
        button.disabled = false;
        button.textContent = 'Scan whole site';
        status.textContent = err?.message || 'Progress check failed';
        status.classList.add('vl-error');
      }
    }, 700);
  } catch (err) {
    button.disabled = false;
    button.textContent = 'Scan whole site';
    status.textContent = err?.message || 'Could not start scan';
    status.classList.add('vl-error');
    show('error', 0, 100, '');
  }
}

function wireEvents() {
  $$('.vl-tab').forEach((tab) => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

  $('#scanBtn').addEventListener('click', async () => {
    const button = $('#scanBtn');
    const status = $('#scanStatus');
    button.disabled = true;
    button.textContent = 'Scanning…';
    status.textContent = 'Reading page structure…';
    status.classList.remove('vl-error');
    try {
      // Prefer reading the observation directly from the target tab. The
      // background still retries/injects if this content script isn't ready.
      const obsReply = await tabsSend(ui.tabId, { type: MSG.REQUEST_OBSERVATION });
      const observation = obsReply?.ok ? obsReply.observation : null;

      const reply = await send(MSG.SCAN_PAGE, {
        tabId: ui.tabId,
        observation,
        authorized: ui.authorized,
        ai: !!ui.config.aiEnabled,
      });
      if (reply?.state) ui.state = reply.state;
      status.textContent = reply?.ok
        ? `Scanned ${ui.host || 'page'}`
        : (reply?.error || 'Scan failed');
      if (!reply?.ok) status.classList.add('vl-error');
      await refreshState();
    } catch (err) {
      status.textContent = err?.message || 'Scan failed';
      status.classList.add('vl-error');
    } finally {
      button.disabled = false;
      button.textContent = 'Scan page';
    }
  });

  $('#crawlBtn').addEventListener('click', async () => {
    const button = $('#crawlBtn');
    const status = $('#crawlStatus');
    const url = ui.state?.observation?.url || ui.targetUrl || (await findTargetTab())?.url || '';
    if (!/^https?:\/\//i.test(url)) {
      status.textContent = 'Open a web page first.';
      status.classList.add('vl-error');
      return;
    }
    button.disabled = true;
    button.textContent = 'Crawling…';
    status.textContent = 'Mapping same-origin pages…';
    status.classList.remove('vl-error');
    try {
      const reply = await send(MSG.CRAWL_SITE, { tabId: ui.tabId, url, maxPages: 60, maxDepth: 6 });
      if (reply?.state) ui.state = reply.state;
      else if (reply?.crawl) ui.state = { ...(ui.state || {}), crawl: reply.crawl };
      const pages = Array.isArray(reply?.crawl?.pages) ? reply.crawl.pages.length : 0;
      status.textContent = reply?.ok
        ? `Mapped ${pages} page${pages === 1 ? '' : 's'}`
        : (reply?.error || 'Crawl failed');
      if (!reply?.ok) status.classList.add('vl-error');
      await refreshState();
      if (reply?.ok && reply.crawl) switchTab('sitemap');
    } catch (err) {
      status.textContent = err?.message || 'Crawl failed';
      status.classList.add('vl-error');
    } finally {
      button.disabled = false;
      button.textContent = 'Crawl site';
    }
  });

  $('#siteScanBtn').addEventListener('click', startWholeSiteScan);

  $('#owaspFilter').addEventListener('change', (event) => {
    ui.owasp = event.target.value || '';
    renderTests();
  });

  $('#checksContent').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-check-copy]');
    if (!button) return;
    const item = ui.state?.analysis?.checks?.guidance?.[Number(button.dataset.checkCopy)];
    if (!item?.command) return;
    const copied = await copyText(item.command);
    button.textContent = copied ? 'Copied' : 'Select manually';
    setTimeout(() => { button.textContent = 'Copy'; }, 1200);
  });

  $('#owaspContent').addEventListener('click', (event) => {
    const card = event.target.closest('.owasp-card[data-owasp]');
    if (!card) return;
    ui.owasp = card.dataset.owasp || '';
    ui.category = '';
    const categorySelect = $('#categoryFilter');
    if (categorySelect) categorySelect.value = '';
    renderTests();
    switchTab('tests');
  });

  $('#authorized').addEventListener('change', (event) => {
    ui.authorized = !!event.target.checked;
    send(MSG.SET_AUTHORIZED, { tabId: ui.tabId, authorized: ui.authorized });
    renderTests();
  });

  $('#aiToggle').addEventListener('change', async (event) => {
    const desired = !!event.target.checked;
    const reply = await send(MSG.SET_AI, { aiEnabled: desired });
    if (reply?.config) ui.config = reply.config;
    if (reply?.ok === false) event.target.checked = !!ui.config.aiEnabled;
    renderBridgeStatus();
  });

  $('#categoryFilter').addEventListener('change', (event) => {
    ui.category = event.target.value;
    renderTests();
  });

  $('#searchTests').addEventListener('input', (event) => {
    ui.search = event.target.value || '';
    renderTests();
  });

  $('#cards').addEventListener('click', async (event) => {
    const button = event.target.closest('.vl-copy');
    if (!button) return;
    const ok = await copyText(button.dataset.payload || '');
    const original = button.textContent;
    button.textContent = ok ? 'Copied' : 'Copy failed';
    setTimeout(() => { button.textContent = original; }, 1200);
  });

  $('#importBtn').addEventListener('click', async () => {
    const raw = $('#burpRaw').value;
    const status = $('#importStatus');
    if (!raw.trim()) {
      status.textContent = 'Paste traffic first.';
      return;
    }
    const button = $('#importBtn');
    button.disabled = true;
    status.textContent = 'Importing…';
    try {
      const reply = await send(MSG.IMPORT_BURP, {
        tabId: ui.tabId,
        host: ui.host === '—' ? '' : ui.host,
        source: 'panel-paste',
        raw,
      });
      if (reply?.state) ui.state = reply.state;
      status.textContent = reply?.ok
        ? `Imported ${reply.count ?? 0} items.`
        : (reply?.error || 'Import failed.');
      renderAll();
    } finally {
      button.disabled = false;
    }
  });

  $('#notes').addEventListener('input', (event) => {
    clearTimeout(ui.notesTimer);
    const value = event.target.value;
    ui.notesTimer = setTimeout(async () => {
      await storageSet(notesKey(), value);
      $('#notesStatus').textContent = 'Saved locally.';
    }, 250);
  });

  $('#exportBtn').addEventListener('click', exportMarkdown);

  api?.runtime?.onMessage?.addListener((message) => {
    if (message?.type === MSG.STATE_UPDATED) refreshState();
    return false;
  });
}

async function init() {
  wireEvents();
  const tab = await findTargetTab();
  ui.tabId = tab?.id ?? null;
  ui.host = hostFromUrl(tab?.url) || '—';
  ui.targetUrl = tab?.url || '';
  $('#targetHost').textContent = ui.host;
  $('#targetHost').title = tab?.url ? `${tab.title || ''} — ${tab.url}` : 'No web tab detected';

  $('#notes').value = await storageGet(notesKey());

  await refreshConfig();
  await refreshState();
  await pollTraffic();
  ui.trafficTimer = setInterval(pollTraffic, 5000);
  window.addEventListener('unload', () => {
    if (ui.trafficTimer) clearInterval(ui.trafficTimer);
    ui.trafficTimer = null;
  });
}

init();
