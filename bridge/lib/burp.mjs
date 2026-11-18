import { truncate } from './util.mjs';

const MAX_ITEMS = 2000;

// Only these header names are ever retained. Values are always discarded.
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

/* ------------------------------------------------------------------ helpers */

export function normalizeHost(input = '') {
  let s = String(input ?? '').trim();
  if (!s) return 'default';
  if (s.includes('://')) {
    try {
      s = new URL(s).host;
    } catch {
      s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    }
  } else {
    s = s.replace(/^\/\//, '');
  }
  s = s.split('/')[0].replace(/[?#].*$/, '');
  return s.toLowerCase() || 'default';
}

function decodeEntities(value = '') {
  return String(value ?? '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;|&#39;/gi, "'")
    .replace(/&amp;/g, '&')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16) || 0))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10) || 0));
}

function stripTags(value = '') {
  return decodeEntities(String(value ?? '').replace(/<[^>]*>/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
}

function parseAttrs(fragment = '') {
  const out = {};
  const re = /([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(fragment))) {
    out[m[1]] = m[3] !== undefined ? m[3] : m[4];
  }
  return out;
}

function toNum(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number.parseInt(String(value).replace(/,/g, ''), 10);
  return Number.isFinite(n) ? n : null;
}

function uniq(values) {
  const out = [];
  for (const v of values) {
    if (v === null || v === undefined) continue;
    const s = String(v).trim();
    if (s && !out.includes(s)) out.push(s);
  }
  return out;
}

function namesFrom(value, key = 'name') {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => {
      if (typeof v === 'string') return v;
      if (v && typeof v === 'object') return v[key] ?? v.name ?? '';
      return '';
    })
    .filter(Boolean);
}

function parseUrlInfo(url = '', fallbackHost = '') {
  let host = fallbackHost || '';
  let path = '';
  let qNames = [];
  try {
    const u = new URL(url);
    host = host || u.host;
    path = u.pathname || '/';
    qNames = [...u.searchParams.keys()];
  } catch {
    const m = String(url || '').match(/^(?:https?:\/\/[^/?#]+)?([^?#]*)(?:\?([^#]*))?/);
    if (m) {
      path = m[1] || '';
      if (m[2]) {
        qNames = m[2]
          .split('&')
          .map((part) => {
            try {
              return decodeURIComponent(part.split('=')[0] || '');
            } catch {
              return part.split('=')[0] || '';
            }
          })
          .filter(Boolean);
      }
    }
  }
  return { host, path, qNames };
}

/** Drop query values and fragments; keep only scheme, host and path. */
function sanitizeUrl(rawUrl, path) {
  if (!rawUrl) return path || '';
  try {
    const u = new URL(rawUrl);
    return `${u.protocol}//${u.host}${u.pathname || '/'}`;
  } catch {
    const m = String(rawUrl).match(/^(https?:\/\/[^/?#]+)(\/[^?#]*)?/i);
    if (m) return `${m[1]}${m[2] || '/'}`;
    return path || truncate(rawUrl, 512);
  }
}

/**
 * Build a safe BurpItem. Only names, flags and structural metadata survive.
 */
function makeItem(partial = {}, source = 'unknown') {
  const rawUrl = String(partial.url || '').trim();
  const info = parseUrlInfo(rawUrl, partial.host || '');
  const host = normalizeHost(info.host || partial.host || '');
  const path = String(partial.path || info.path || '').slice(0, 512);
  const url = sanitizeUrl(rawUrl, path);

  const queryParams = uniq(
    [...namesFrom(partial.queryParams), ...info.qNames].map((n) => truncate(n, 128)),
  );
  const bodyParams = uniq(namesFrom(partial.bodyParams).map((n) => truncate(n, 128)));

  const headers = [];
  for (const h of partial.headers || []) {
    const name = String((h && (h.name ?? h)) || '')
      .trim()
      .toLowerCase();
    if (!name || !ALLOWED_HEADERS.has(name) || headers.some((x) => x.name === name)) continue;
    headers.push({ name, value: '' });
  }

  return {
    method: String(partial.method || 'GET').toUpperCase().slice(0, 16),
    url,
    host,
    path,
    queryParams,
    bodyParams,
    headers,
    status: toNum(partial.status),
    contentType: truncate(partial.contentType || '', 128),
    length: toNum(partial.length),
    source,
  };
}

/* ------------------------------------------------------------------ parsers */

function parseXml(raw, host) {
  const items = [];
  const itemRe = /<(?:[\w.-]+:)?item\b([^>]*)>([\s\S]*?)<\/(?:[\w.-]+:)?item\s*>/gi;
  let m;
  while ((m = itemRe.exec(raw))) {
    const attrs = parseAttrs(m[1]);
    const body = m[2];

    const child = (name) => {
      const re = new RegExp(
        `<(?:[\\w.-]+:)?${name}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${name}\\s*>`,
        'i',
      );
      const found = body.match(re);
      return found ? stripTags(found[1]) : '';
    };

    const url = decodeEntities(attrs.url || child('url') || '');
    if (!url) continue;

    const queryParams = [];
    const bodyParams = [];
    const paramRe = /<(?:[\w.-]+:)?parameter\b([^>]*?)\/?>/gi;
    let pm;
    while ((pm = paramRe.exec(body))) {
      const pa = parseAttrs(pm[1]);
      const name = decodeEntities(pa.name || '');
      if (!name) continue;
      const type = String(pa.type || pa.parameterType || '').toLowerCase();
      if (type.includes('body') || type.includes('post') || type.includes('form')) {
        bodyParams.push(name);
      } else {
        queryParams.push(name);
      }
    }

    items.push(
      makeItem(
        {
          url,
          host: decodeEntities(attrs.host || child('host') || '') || host || '',
          method: decodeEntities(attrs.method || child('method') || '') || 'GET',
          status: attrs.status || child('status'),
          contentType: decodeEntities(attrs.mimeType || attrs.mime || child('mimeType') || child('mime') || ''),
          length: attrs.length || child('length'),
          queryParams,
          bodyParams,
        },
        'burp-xml',
      ),
    );
  }
  return items;
}

function safeParseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseHar(obj, host) {
  const entries = obj?.log?.entries;
  if (!Array.isArray(entries)) return [];
  const items = [];

  for (const entry of entries) {
    const req = entry?.request || {};
    const res = entry?.response || {};
    const url = String(req.url || '');
    if (!url) continue;

    let contentType = '';
    for (const h of res.headers || []) {
      if (String(h?.name || '').toLowerCase() === 'content-type') {
        contentType = String(h?.value || '');
        break;
      }
    }
    if (!contentType) contentType = String(res.content?.mimeType || '');

    const bodyParams = namesFrom(req.postData?.params);
    const postText = req.postData?.text;
    if (typeof postText === 'string' && !bodyParams.length && /[=&]/.test(postText)) {
      for (const part of postText.split('&')) {
        const name = part.split('=')[0];
        if (!name) continue;
        try {
          bodyParams.push(decodeURIComponent(name));
        } catch {
          bodyParams.push(name);
        }
      }
    }

    items.push(
      makeItem(
        {
          url,
          host: host || '',
          method: req.method || 'GET',
          headers: namesFrom(req.headers).map((name) => ({ name })),
          queryParams: namesFrom(req.queryString),
          bodyParams,
          status: res.status,
          contentType,
          length: res.content?.size ?? res.bodySize,
        },
        'har',
      ),
    );
  }
  return items;
}

function parseJsonArray(arr, host) {
  if (!Array.isArray(arr)) return [];
  const items = [];
  for (const o of arr) {
    if (!o || typeof o !== 'object') continue;
    const url = String(o.url || o.request?.url || '');
    if (!url) continue;
    items.push(
      makeItem(
        {
          url,
          host: o.host || host || '',
          method: o.method || o.request?.method || 'GET',
          headers: namesFrom(o.headers).map((name) => ({ name })),
          queryParams: namesFrom(o.queryParams),
          bodyParams: namesFrom(o.bodyParams || o.postData?.params),
          status: o.status ?? o.response?.status,
          contentType: o.contentType || o.response?.content?.mimeType || '',
          length: o.length ?? o.response?.content?.size,
        },
        'json',
      ),
    );
  }
  return items;
}

function tokenizeShell(input = '') {
  const re = /"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|(\S+)/g;
  const tokens = [];
  let m;
  while ((m = re.exec(input))) {
    if (m[1] !== undefined) tokens.push(m[1].replace(/\\(.)/g, '$1'));
    else if (m[2] !== undefined) tokens.push(m[2]);
    else tokens.push(m[3]);
  }
  return tokens;
}

function parseCurl(raw, host) {
  const normalized = String(raw || '').replace(/\\\r?\n/g, ' ');
  const lines = normalized.split(/\r?\n/);
  const commands = [];
  let current = '';

  for (const line of lines) {
    if (/^\s*curl\b/i.test(line)) {
      if (current) commands.push(current);
      current = line;
    } else if (current) {
      current += ` ${line}`;
    }
  }
  if (current) commands.push(current);

  const items = [];
  for (const cmd of commands) {
    const tokens = tokenizeShell(cmd);
    if (!tokens.length || !/^curl$/i.test(tokens[0])) continue;

    let url = '';
    let method = '';
    const dataTokens = [];
    const headerTokens = [];

    for (let i = 1; i < tokens.length; i += 1) {
      const t = tokens[i];

      if (t === '-X' || t === '--request') {
        method = tokens[(i += 1)] || method;
      } else if (/^-X/.test(t) && t.length > 2) {
        method = t.slice(2);
      } else if (t.startsWith('--request=')) {
        method = t.slice(10);
      } else if (t === '-H' || t === '--header') {
        headerTokens.push(tokens[(i += 1)] || '');
      } else if (/^-H/.test(t) && t.length > 2) {
        headerTokens.push(t.slice(2));
      } else if (t.startsWith('--header=')) {
        headerTokens.push(t.slice(9));
      } else if (['-d', '--data', '--data-raw', '--data-ascii', '--data-binary', '--data-urlencoded'].includes(t)) {
        dataTokens.push(tokens[(i += 1)] || '');
      } else if (!t.startsWith('--') && t.startsWith('-d') && t.length > 2) {
        dataTokens.push(t.slice(2));
      } else if (t.startsWith('--data')) {
        const eq = t.indexOf('=');
        if (eq > -1) dataTokens.push(t.slice(eq + 1));
      } else if (t === '--url') {
        url = tokens[(i += 1)] || url;
      } else if (t.startsWith('--url=')) {
        url = t.slice(6);
      } else if (/^https?:\/\//i.test(t)) {
        if (!url) url = t;
      } else if (['-b', '--cookie', '--cookie-jar', '-c'].includes(t)) {
        i += 1; // never keep cookie values
      } else if (t.startsWith('--cookie=')) {
        // ignored
      }
    }

    if (!url) continue;

    const headers = headerTokens.map((h) => {
      const idx = h.indexOf(':');
      return { name: idx > -1 ? h.slice(0, idx).trim() : h.trim() };
    });

    const bodyParams = [];
    for (const data of dataTokens) {
      if (!data || data.startsWith('@')) continue;
      if (data.trim().startsWith('{')) {
        try {
          const parsed = JSON.parse(data);
          for (const key of Object.keys(parsed)) bodyParams.push(key);
        } catch {
          // ignore unparseable data blobs rather than storing raw values
        }
        continue;
      }
      for (const part of data.split('&')) {
        const name = part.split('=')[0];
        if (!name) continue;
        try {
          bodyParams.push(decodeURIComponent(name));
        } catch {
          bodyParams.push(name);
        }
      }
    }

    items.push(
      makeItem(
        {
          url,
          host: host || '',
          method: method || (dataTokens.length ? 'POST' : 'GET'),
          headers,
          bodyParams,
        },
        'curl',
      ),
    );
  }
  return items;
}

function parseUrlList(raw, host) {
  const lines = String(raw || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  const items = [];
  for (let line of lines) {
    if (line.startsWith('//')) line = `https:${line}`;
    else if (line.startsWith('/') && host) line = `https://${normalizeHost(host)}${line}`;
    if (!/^https?:\/\//i.test(line)) continue;
    items.push(makeItem({ url: line, host: host || '' }, 'url-list'));
  }
  return items;
}

/* ------------------------------------------------------------------- public */

/**
 * Parse pasted Burp XML, HAR, JSON, curl commands or a newline URL list.
 * Always returns at most MAX_ITEMS safe items.
 */
export function parseBurpRaw({ source = '', raw = '', host = '' } = {}) {
  let items = [];
  try {
    const text = String(raw ?? '').trim();
    if (!text) return { items: [] };

    const src = String(source || '').toLowerCase();
    if (src.includes('xml')) {
      items = parseXml(text, host);
    } else if (src.includes('har')) {
      const parsed = safeParseJson(text);
      items = parsed ? parseHar(parsed, host) : [];
    } else if (src.includes('curl')) {
      items = parseCurl(text, host);
    } else if (src.includes('url')) {
      items = parseUrlList(text, host);
    } else if (src.includes('json')) {
      const parsed = safeParseJson(text);
      items = Array.isArray(parsed) ? parseJsonArray(parsed, host) : parsed ? parseJsonArray([parsed], host) : [];
    } else if (text.startsWith('<')) {
      items = parseXml(text, host);
    } else if (/^\s*curl\b/im.test(text)) {
      items = parseCurl(text, host);
    } else {
      const parsed = safeParseJson(text);
      if (Array.isArray(parsed)) items = parseJsonArray(parsed, host);
      else if (parsed?.log?.entries) items = parseHar(parsed, host);
      else if (parsed && typeof parsed === 'object') items = parseJsonArray([parsed], host);
      else items = parseUrlList(text, host);
    }
  } catch {
    items = [];
  }
  return { items: items.slice(0, MAX_ITEMS) };
}

/* -------------------------------------------------------------- in-memory store */

const trafficStore = new Map();

export function addTraffic(host, items = []) {
  const key = normalizeHost(host);
  const list = [...(trafficStore.get(key) || []), ...(Array.isArray(items) ? items : [])]
    .slice(0, MAX_ITEMS)
    .map((item) => makeItem(item, item?.source || 'traffic'));
  trafficStore.set(key, list);
  return list;
}

export function getTraffic(host) {
  return [...(trafficStore.get(normalizeHost(host)) || [])];
}

export function appendLive(host, item) {
  const key = normalizeHost(host || item?.host || item?.url || '');
  // Keep the caller's label: 'browser-passive' (webRequest) and 'live' (Burp feeder).
  const safe = makeItem(item || {}, item?.source || 'live');
  const list = trafficStore.get(key) || [];
  list.push(safe);
  if (list.length > MAX_ITEMS) list.splice(0, list.length - MAX_ITEMS);
  trafficStore.set(key, list);
  return safe;
}

/** Count stored traffic items by source. Never returns item values. */
export function getTrafficSummary(host) {
  const items = getTraffic(host);
  const bySource = {};
  for (const item of items) {
    const key = String(item?.source || 'unknown');
    bySource[key] = (bySource[key] || 0) + 1;
  }
  return { total: items.length, bySource };
}

export function clearTraffic(host) {
  trafficStore.delete(normalizeHost(host));
  return true;
}

export const store = { addTraffic, getTraffic, appendLive, clearTraffic, getTrafficSummary };
