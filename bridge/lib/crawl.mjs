import { truncate } from './util.mjs';

const DEFAULT_MAX_PAGES = 40;
const DEFAULT_MAX_DEPTH = 4;
const HARD_MAX_PAGES = 150;
const HARD_MAX_DEPTH = 10;
const DEFAULT_DELAY_MS = 120;
const TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_LINKS = 400;
const MAX_ENDPOINTS = 250;
const MAX_INPUTS = 400;

// SPA support: same-host JavaScript bundles can contain route strings even
// when the served HTML is an empty app shell. Bundles are fetched with GET
// only, never executed, and only path-like literals are retained.
const MAX_JS_BYTES = 8 * 1024 * 1024;
const MAX_JS_TOTAL_BYTES = 24 * 1024 * 1024;
const MAX_JS_BUNDLES = 4;
const MAX_JS_ROUTES = 120;
const STATIC_PATH_RE =
  /\.(?:js|mjs|cjs|css|map|json|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|mp4|webm|pdf|txt|xml)$/i;
const NON_PAGE_PATH_RE = /^\/(?:api|graphql|assets|static|node_modules|dist|build)(?:\/|$)/i;

// Metadata-only response headers kept from each page (names + redacted values).
const HEADER_ALLOWLIST = new Set([
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'server',
  'x-powered-by',
  'cache-control',
  'content-type',
]);

const DOM_SINK_PATTERNS = [
  ['innerHTML', /\binnerHTML\b/i],
  ['outerHTML', /\bouterHTML\b/i],
  ['document.write', /\bdocument\s*\.\s*write\b/i],
  ['eval', /\beval\s*\(/i],
  ['location.href', /\blocation\s*\.\s*href\s*=/i],
  ['Function()', /\bnew\s+Function\s*\(/i],
];

// GET-only, same-host crawling: never follow links that look like an action.
const RISKY_HREF =
  /logout|signout|sign-out|delete|remove|destroy|reset|submit|pay|checkout|unsubscribe|\/api\/(?:delete|update|post)/i;

/* ------------------------------------------------------------------ helpers */

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clampInt(value, fallback, min, max) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function escapeRe(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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

function attr(fragment = '', name = '') {
  const re = new RegExp(
    `\\b${escapeRe(name)}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`,
    'i',
  );
  const m = String(fragment).match(re);
  if (!m) return '';
  return decodeEntities(m[1] ?? m[2] ?? m[3] ?? '');
}

function cssEscape(value = '') {
  return String(value).replace(/([^\w-])/g, '\\$1');
}

function xpathEscape(value = '') {
  return String(value).replace(/'/g, "\\'");
}

/** Drop query values and fragments; keep scheme, host, path and param NAMES. */
function safeUrl(raw) {
  const value = String(raw ?? '').trim();
  try {
    const u = new URL(value);
    const names = [...u.searchParams.keys()];
    const base = `${u.protocol}//${u.host}${u.pathname || '/'}`;
    return names.length ? `${base}?${names.join('&')}` : base;
  } catch {
    return truncate(value.split('#')[0], 512);
  }
}

function resolveUrl(raw, base) {
  try {
    return new URL(String(raw ?? '').trim(), base);
  } catch {
    return null;
  }
}

/** Dedupe by pathname + query param names (values and fragments never matter). */
function dedupeKey(u) {
  const names = [...u.searchParams.keys()]
    .map((n) => n.toLowerCase())
    .sort()
    .join(',');
  return `${u.hostname.toLowerCase()}|${u.pathname || '/'}|${names}`;
}

function uniq(values) {
  return [...new Set(values.filter((v) => v !== null && v !== undefined && v !== '').map(String))];
}

/** Keep only allowlisted response header names, with short redacted values. */
function safeHeaders(headers) {
  const out = [];
  if (!headers || typeof headers.forEach !== 'function') return out;
  headers.forEach((value, rawName) => {
    const name = String(rawName || '').trim().toLowerCase();
    if (!HEADER_ALLOWLIST.has(name)) return;
    out.push({ name, value: truncate(String(value ?? '').replace(/[\r\n]+/g, ' ').trim(), 200) });
  });
  return out;
}

/** Record which DOM sink names appear in inline script — never the code itself. */
function domSinksFrom(inline = '') {
  return DOM_SINK_PATTERNS.filter(([, re]) => re.test(String(inline || ''))).map(([name]) => name);
}

/* -------------------------------------------------------------- HTML parsing */

function parseInputs(html = '', formSelector = '') {
  const out = [];
  const seen = new Set();
  const patterns = [
    { re: /<input\b([^>]*?)\/?>/gi, type: 'input' },
    { re: /<textarea\b([^>]*)>([\s\S]*?)<\/textarea\s*>/gi, type: 'textarea' },
    { re: /<select\b([^>]*)>([\s\S]*?)<\/select\s*>/gi, type: 'select' },
  ];

  for (const { re, type } of patterns) {
    let m;
    let index = 0;
    while ((m = re.exec(html))) {
      const a = m[1] || '';
      const name = truncate(attr(a, 'name'), 128);
      const id = truncate(attr(a, 'id'), 128);
      const inputType = type === 'input' ? truncate(attr(a, 'type') || 'text', 32) : type;
      const key = `${type}|${name}|${id}|${inputType}`;
      if (seen.has(key) || out.length >= MAX_INPUTS) continue;
      seen.add(key);

      const selector = id
        ? `#${cssEscape(id)}`
        : name
          ? `${type}[name="${cssEscape(name)}"]`
          : `${type}:nth-of-type(${index + 1})`;
      const xpath = name
        ? `//${type}[@name='${xpathEscape(name)}']`
        : `//${type}[${index + 1}]`;

      out.push({
        name,
        type: inputType,
        id,
        placeholder: truncate(attr(a, 'placeholder'), 160),
        required: /\brequired\b/i.test(a),
        maxLength: Number.parseInt(attr(a, 'maxlength'), 10) || null,
        selector,
        xpath,
        formSelector: formSelector || null,
      });
      index += 1;
    }
  }
  return out;
}

function parseForms(html = '') {
  const forms = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
  let m;
  let index = 0;

  while ((m = re.exec(html))) {
    const a = m[1] || '';
    const id = truncate(attr(a, 'id'), 128);
    const name = truncate(attr(a, 'name'), 128);
    const selector = id
      ? `#${cssEscape(id)}`
      : name
        ? `form[name="${cssEscape(name)}"]`
        : `form:nth-of-type(${index + 1})`;
    const xpath = id ? `//form[@id='${xpathEscape(id)}']` : `//form[${index + 1}]`;
    const fields = parseInputs(m[2] || '', selector);

    forms.push({
      action: truncate(attr(a, 'action'), 512),
      method: (attr(a, 'method') || 'get').toUpperCase().slice(0, 10),
      enctype: truncate(attr(a, 'enctype'), 80),
      selector,
      xpath,
      index,
      fields,
      hasFileInput: fields.some((f) => f.type === 'file'),
    });
    index += 1;
  }
  return forms;
}

function parseLinks(html = '', base = '') {
  const links = [];
  const re = /<a\b([^>]*)>/gi;
  let m;
  while ((m = re.exec(html)) && links.length < MAX_LINKS) {
    const raw = attr(m[1], 'href');
    if (!raw) continue;
    const absolute = resolveUrl(raw, base);
    if (!absolute) continue;
    const protocol = absolute.protocol.toLowerCase();
    let kind;
    if (RISKY_HREF.test(raw) || (protocol !== 'http:' && protocol !== 'https:')) {
      kind = 'suspicious';
    } else if (absolute.hostname.toLowerCase() === new URL(base).hostname.toLowerCase()) {
      kind = 'internal';
    } else {
      kind = 'external';
    }
    links.push({ href: safeUrl(absolute.href), kind, _raw: absolute.href });
  }
  return links;
}

function parseScripts(html = '', base = '') {
  const scripts = [];
  const scriptUrls = [];
  const inline = [];
  const seen = new Set();
  const add = (raw, inlineLength) => {
    const absolute = raw ? resolveUrl(raw, base) : null;
    if (!absolute) return;
    const src = safeUrl(absolute.href);
    const key = `${src}|${inlineLength > 0}`;
    if (seen.has(key)) return;
    seen.add(key);
    scripts.push({ src, inlineLength });
    if (/\.m?js(?:$|\?)/i.test(absolute.pathname)) scriptUrls.push(absolute.href);
  };

  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let m;
  while ((m = re.exec(html))) {
    const body = m[2] || '';
    add(attr(m[1] || '', 'src'), body.trim().length);
    if (body.trim()) inline.push(body);
  }

  // Bundlers emit modulepreload hints for chunks that are loaded as scripts.
  const preloadRe = /<link\b([^>]*)>/gi;
  while ((m = preloadRe.exec(html))) {
    if (!/modulepreload/i.test(attr(m[1], 'rel'))) continue;
    add(attr(m[1], 'href'), 0);
  }

  return { scripts, scriptUrls, inline: inline.join('\n') };
}

function parseEndpoints(html = '', base = '', forms = [], links = [], scripts = [], inline = '') {
  const found = [];
  const add = (raw, source) => {
    if (!raw) return;
    const absolute = resolveUrl(String(raw).replace(/[`'"]+$/, ''), base);
    if (!absolute) return;
    if (!/^https?:$/i.test(absolute.protocol)) return;
    found.push({ url: safeUrl(absolute.href), source });
  };

  for (const form of forms) add(form.action, 'form');
  for (const script of scripts) if (script.src) add(script.src, 'script');
  for (const link of links) {
    if (/\/(?:api|graphql)\b/i.test(link._raw || '')) add(link._raw, 'link');
  }

  const callRe = /\b(fetch|axios(?:\.\w+)?)\s*\(\s*(?:new\s+URL\(\s*)?["'`]([^"'`]+)["'`]/gi;
  let m;
  while ((m = callRe.exec(inline))) add(m[2], /axios/i.test(m[1]) ? 'axios' : 'fetch');

  const literalRe = /["'`](\/(?:api|graphql)[^"'`\s]*)/gi;
  while ((m = literalRe.exec(html))) add(m[1], 'inline');

  const seen = new Set();
  return found
    .filter((e) => {
      const key = `${e.url}|${e.source}`;
      if (!e.url || seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, MAX_ENDPOINTS);
}

function queryParamsFrom(u, pageUrl) {
  const out = [];
  const seen = new Set();
  for (const [name, value] of u.searchParams.entries()) {
    const safeName = truncate(name, 128);
    if (!safeName || seen.has(safeName)) continue;
    seen.add(safeName);
    out.push({
      name: safeName,
      valueLength: value.length,
      location: 'query',
      page: pageUrl,
    });
  }
  return out;
}

function signalsFor({ forms, inputs, queryParams, endpoints, scripts }) {
  const inputNames = inputs.map((i) => String(i.name || '').toLowerCase());
  const inputTypes = inputs.map((i) => String(i.type || '').toLowerCase());
  const queryNames = queryParams.map((q) => String(q.name || '').toLowerCase());
  const endpointText = endpoints.map((e) => e.url).join(' ').toLowerCase();

  return {
    hasForm: forms.length > 0,
    hasTextInput: inputTypes.some((t) => ['text', 'search', 'email', 'password', 'tel', 'url', 'number'].includes(t)),
    hasFileInput: inputTypes.includes('file'),
    hasLogin:
      inputNames.some((n) => /user|email|login|username/.test(n)) &&
      inputNames.some((n) => /pass|pwd|password/.test(n)),
    hasSearch: inputNames.some((n) => /search|query|^q$/.test(n)),
    hasUpload: inputTypes.includes('file'),
    hasGraphql: /graphql/i.test(endpointText),
    hasApiBase: /\/api\//i.test(endpointText),
    hasRedirectParam: queryNames.some((n) => /redirect|return|next|dest/.test(n)),
    hasDebugParam: queryNames.some((n) => /debug|test|dev/.test(n)),
    hasIdParam: queryNames.some((n) => /(^id$)|(?:^|_)id$|uuid|guid/.test(n)),
    hasUrlParam: queryNames.some((n) => /url|uri|href|target|src/.test(n)),
    hasJsonBodyHint: /json/i.test(endpointText),
    hasInlineScript: scripts.some((s) => s.inlineLength > 0),
    hasCsrfTokenField: inputNames.some((n) => /csrf|xsrf|token/.test(n)),
  };
}

/** Read at most `maxBytes` of a response body; never keep more than that. */
async function readBodyWithCap(response, maxBytes = MAX_BODY_BYTES) {
  const reader = response?.body?.getReader?.();
  if (!reader) {
    const text = await response.text();
    return { text: text.slice(0, maxBytes), truncated: text.length > maxBytes };
  }

  const decoder = new TextDecoder();
  let text = '';
  let bytes = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value?.byteLength || 0;
      if (bytes > maxBytes) {
        truncated = true;
        const allowed = Math.max(0, maxBytes - (bytes - (value?.byteLength || 0)));
        text += decoder.decode(value?.subarray(0, allowed), { stream: true });
        await reader.cancel().catch(() => {});
        break;
      }
      text += decoder.decode(value, { stream: true });
    }
    if (!truncated) text += decoder.decode();
  } catch {
    // Keep whatever was read before the stream failed.
  }
  return { text, truncated };
}

async function fetchPage(rawUrl, expectedHost) {
  const response = await fetch(rawUrl, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5' },
  });

  const finalUrl = response.url || rawUrl;
  let final;
  try {
    final = new URL(finalUrl);
  } catch {
    final = null;
  }
  if (!final || final.hostname.toLowerCase() !== expectedHost.toLowerCase()) {
    throw new Error('Redirect left the start host; page skipped');
  }

  const { text, truncated } = await readBodyWithCap(response);
  return {
    status: response.status,
    finalUrl,
    contentType: String(response.headers.get('content-type') || '').slice(0, 128),
    headers: safeHeaders(response.headers),
    domSinks: domSinksFrom(text),
    html: text,
    truncated,
  };
}

/**
 * Extract same-origin, static-looking page routes from JavaScript source.
 * Only path literals are kept — no code, values, secrets or dynamic segments.
 */
export function routesFromJs(source = '') {
  const routes = new Set();
  const re = /["'`](\/[A-Za-z0-9_./-]{2,120})["'`]/g;
  let m;
  while ((m = re.exec(String(source || '')))) {
    const route = m[1];
    if (!route.startsWith('/') || route.startsWith('//')) continue;
    if (/[?#:*${}\\]/.test(route) || STATIC_PATH_RE.test(route) || NON_PAGE_PATH_RE.test(route)) continue;
    if (RISKY_HREF.test(route)) continue;
    const segments = route.split('/').filter(Boolean);
    if (!segments.length || segments.length > 8) continue;
    if (!segments.every((segment) => /^[A-Za-z0-9_-]+$/.test(segment))) continue;
    routes.add(route);
    if (routes.size >= MAX_JS_ROUTES) break;
  }
  return [...routes];
}

/** GET a same-host JS bundle and return the route literals found in it. */
async function fetchJsRoutes(rawUrl, expectedHost, budget) {
  let url;
  try {
    url = new URL(String(rawUrl));
  } catch {
    return [];
  }
  if (url.hostname.toLowerCase() !== expectedHost.toLowerCase()) return [];
  if (!/\.m?js(?:$|\?)/i.test(url.pathname)) return [];

  const response = await fetch(url.href, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: 'application/javascript,text/javascript,*/*;q=0.5' },
  });
  const final = new URL(response.url || url.href);
  if (final.hostname.toLowerCase() !== expectedHost.toLowerCase()) return [];

  const contentType = String(response.headers.get('content-type') || '');
  if (!/javascript|ecmascript/i.test(contentType) && !/\.m?js$/i.test(final.pathname)) return [];

  const remaining = Math.min(MAX_JS_BYTES, budget.remaining);
  if (remaining <= 0) return [];
  const { text } = await readBodyWithCap(response, remaining);
  budget.remaining -= text.length;
  return routesFromJs(text);
}

function addInventory(bucket, seen, key, item) {
  if (seen.has(key)) return;
  seen.add(key);
  bucket.push(item);
}

/* --------------------------------------------------------------------- main */

/**
 * Bounded, read-only, GET-only crawl of a single host. Never throws; all
 * problems are returned as page errors or warnings. No response bodies,
 * header values or parameter values are retained.
 */
export async function crawlSite(options = {}) {
  const input = options && typeof options === 'object' ? options : {};
  const limitPages = clampInt(input.maxPages, DEFAULT_MAX_PAGES, 1, HARD_MAX_PAGES);
  const limitDepth = clampInt(input.maxDepth, DEFAULT_MAX_DEPTH, 0, HARD_MAX_DEPTH);
  const delayMs = clampInt(input.delayMs, DEFAULT_DELAY_MS, 0, 5000);
  const onProgress = typeof input.onProgress === 'function' ? input.onProgress : null;
  const progress = (phase, extra = {}) => {
    if (!onProgress) return;
    try {
      onProgress({
        phase,
        pagesDone: result.pages.length,
        queued: 0,
        maxPages: limitPages,
        currentUrl: '',
        ...extra,
      });
    } catch {
      // Progress reporting must never break the crawl.
    }
  };

  const result = {
    startUrl: '',
    host: '',
    pages: [],
    inventory: { forms: [], inputs: [], urlParams: [], endpoints: [] },
    stats: {
      pagesCrawled: 0,
      skipped: 0,
      maxPagesReached: false,
      jsBundlesFetched: 0,
      jsRoutesDiscovered: 0,
    },
    warnings: [],
  };

  const jsBudget = { remaining: MAX_JS_TOTAL_BYTES };

  const rawStart = String(input.url ?? '').trim();
  if (!rawStart) {
    result.warnings.push('No URL supplied. Provide an http/https URL to crawl.');
    return result;
  }

  let start;
  try {
    start = new URL(rawStart);
  } catch {
    result.startUrl = truncate(rawStart, 512);
    result.warnings.push('Invalid URL supplied. Provide a fully qualified http/https URL.');
    return result;
  }
  if (!/^https?:$/i.test(start.protocol)) {
    result.startUrl = truncate(rawStart, 512);
    result.warnings.push('Only http and https URLs can be crawled.');
    return result;
  }

  start.hash = '';
  result.startUrl = safeUrl(start.href);
  result.host = start.hostname.toLowerCase();
  progress('start', { currentUrl: result.startUrl });

  const visited = new Set();
  const queue = [{ url: start.href, depth: 0 }];
  visited.add(dedupeKey(start));
  const seenInventory = { forms: new Set(), inputs: new Set(), urlParams: new Set(), endpoints: new Set() };
  let requestCount = 0;
  let skipped = 0;

  while (queue.length && result.pages.length < limitPages) {
    const { url: current, depth } = queue.shift();
    if (delayMs > 0 && requestCount > 0) await sleep(delayMs);
    requestCount += 1;

    let parsed;
    try {
      parsed = new URL(current);
    } catch {
      continue;
    }
    const pageUrl = safeUrl(current);
    let page;

    try {
      const fetched = await fetchPage(current, result.host);
      const html = fetched.html || '';
      const finalUrl = safeUrl(fetched.finalUrl);
      const title = truncate(stripTags((html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i) || [])[1] || ''), 200);
      const forms = parseForms(html);
      const allInputs = parseInputs(html);
      // Flattened inputs need to remember which form they belong to.
      for (const input of allInputs) {
        const owner = forms.find((f) =>
          f.fields.some(
            (field) => field.name === input.name && field.type === input.type && field.id === input.id,
          ),
        );
        if (owner) input.formSelector = owner.selector;
      }
      const links = parseLinks(html, fetched.finalUrl);
      const { scripts, scriptUrls, inline } = parseScripts(html, fetched.finalUrl);
      const endpoints = parseEndpoints(html, fetched.finalUrl, forms, links, scripts, inline);
      const queryParams = queryParamsFrom(parsed, finalUrl);
      const signals = signalsFor({ forms, inputs: allInputs, queryParams, endpoints, scripts });
      const publicLinks = links.map(({ href, kind }) => ({ href, kind }));
      const observation = {
        url: finalUrl,
        title,
        forms,
        inputs: allInputs,
        queryParams,
        links: publicLinks,
        scripts,
        endpoints,
        signals,
        headers: fetched.headers,
        domSinks: fetched.domSinks,
        counts: {
          forms: forms.length,
          inputs: allInputs.length,
          links: publicLinks.length,
          scripts: scripts.length,
          endpoints: endpoints.length,
        },
      };

      page = {
        url: finalUrl,
        status: fetched.status,
        title,
        forms,
        inputs: allInputs,
        queryParams,
        links: publicLinks,
        scripts,
        endpoints,
        signals,
        headers: fetched.headers,
        domSinks: fetched.domSinks,
        counts: observation.counts,
        observation,
      };
      if (fetched.truncated) {
        page.warning = `Response body exceeded ${MAX_BODY_BYTES} bytes and was truncated.`;
      }

      if (depth < limitDepth) {
        for (const link of links) {
          const raw = link._raw || '';
          let target;
          try {
            target = new URL(raw);
          } catch {
            continue;
          }
          const protocol = target.protocol.toLowerCase();
          if (RISKY_HREF.test(raw) || (protocol !== 'http:' && protocol !== 'https:')) {
            skipped += 1;
            continue;
          }
          if (target.hostname.toLowerCase() !== result.host) {
            skipped += 1;
            continue;
          }
          target.hash = '';
          const key = dedupeKey(target);
          if (visited.has(key)) continue;
          visited.add(key);
          queue.push({ url: target.href, depth: depth + 1 });
        }

        // SPA fallback: same-host JS bundles often carry the real route table
        // while the HTML shell contains no links at all.
        if (scriptUrls.length && jsBudget.remaining > 0 && result.stats.jsBundlesFetched < MAX_JS_BUNDLES) {
          progress('discovering', { queued: queue.length, currentUrl: page.url });
          for (const scriptUrl of scriptUrls.slice(0, MAX_JS_BUNDLES)) {
            if (result.stats.jsBundlesFetched >= MAX_JS_BUNDLES || jsBudget.remaining <= 0) break;
            try {
              const routes = await fetchJsRoutes(scriptUrl, result.host, jsBudget);
              result.stats.jsBundlesFetched += 1;
              result.stats.jsRoutesDiscovered += routes.length;
              for (const route of routes) {
                const target = resolveUrl(route, fetched.finalUrl);
                if (!target) continue;
                target.hash = '';
                const key = dedupeKey(target);
                if (visited.has(key)) continue;
                visited.add(key);
                queue.push({ url: target.href, depth: depth + 1 });
              }
            } catch {
              // A failed bundle fetch must not break the crawl.
            }
          }
        }
      }
    } catch (e) {
      page = {
        url: pageUrl,
        status: null,
        title: '',
        forms: [],
        inputs: [],
        queryParams: [],
        links: [],
        scripts: [],
        endpoints: [],
        signals: {},
        headers: [],
        domSinks: [],
        observation: null,
        error: truncate(e?.message || String(e), 240),
      };
    }

    result.pages.push(page);
    progress('crawling', { queued: queue.length, currentUrl: page.url });

    for (const form of page.forms || []) {
      addInventory(
        result.inventory.forms,
        seenInventory.forms,
        `${page.url}|${form.selector}|${form.action}`,
        {
          page: page.url,
          action: form.action,
          method: form.method,
          selector: form.selector,
          xpath: form.xpath,
          fields: form.fields,
        },
      );
    }
    for (const input of page.inputs || []) {
      addInventory(
        result.inventory.inputs,
        seenInventory.inputs,
        `${page.url}|${input.selector}|${input.name}`,
        {
          page: page.url,
          name: input.name,
          type: input.type,
          id: input.id,
          selector: input.selector,
          xpath: input.xpath,
          formSelector: input.formSelector,
        },
      );
    }
    for (const qp of page.queryParams || []) {
      addInventory(result.inventory.urlParams, seenInventory.urlParams, `${page.url}|${qp.name}`, {
        page: page.url,
        name: qp.name,
      });
    }
    for (const endpoint of page.endpoints || []) {
      addInventory(
        result.inventory.endpoints,
        seenInventory.endpoints,
        `${page.url}|${endpoint.url}|${endpoint.source}`,
        { page: page.url, url: endpoint.url, source: endpoint.source },
      );
    }
  }

  result.stats.pagesCrawled = result.pages.length;
  result.stats.skipped = skipped;
  result.stats.maxPagesReached = result.pages.length >= limitPages && queue.length > 0;
  progress('done', { queued: queue.length, currentUrl: result.startUrl });

  if (!result.pages.length) {
    result.warnings.push(
      'No pages were crawled. Check that the URL is reachable over http/https and that the host accepts local requests.',
    );
  }
  return result;
}

export default crawlSite;
