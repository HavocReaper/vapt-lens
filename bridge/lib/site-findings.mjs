import { truncate } from './util.mjs';

const MAX_FINDINGS = 80;
const URL_LIMIT = 512;

/** OWASP Top 10 (2021) categories, in the same order as analyze.mjs. */
export const OWASP_SCAN_CATEGORIES = [
  { id: 'A01', name: 'Broken Access Control' },
  { id: 'A02', name: 'Cryptographic Failures' },
  { id: 'A03', name: 'Injection' },
  { id: 'A04', name: 'Insecure Design' },
  { id: 'A05', name: 'Security Misconfiguration' },
  { id: 'A06', name: 'Vulnerable Components' },
  { id: 'A07', name: 'Auth Failures' },
  { id: 'A08', name: 'Software/Data Integrity' },
  { id: 'A09', name: 'Logging & Monitoring Failures' },
  { id: 'A10', name: 'SSRF' },
];

const OWASP_BY_ID = new Map(OWASP_SCAN_CATEGORIES.map(({ id, name }) => [id, name]));
const OWASP_KIND = {
  A01: 'access-control',
  A02: 'crypto',
  A03: 'injection',
  A04: 'design',
  A05: 'misconfig',
  A06: 'components',
  A07: 'auth',
  A08: 'integrity',
  A09: 'logging',
  A10: 'ssrf',
};

const SCOPE_TEXT =
  'Passive inference only from existing crawl metadata; no active testing performed, manual verification required.';

const TRAFFIC_SCOPE_TEXT =
  'Passive inference only from captured Burp traffic metadata; no active testing performed, manual verification required.';

const ID_PARAM_NAMES = new Set(['id', 'userid', 'account', 'uuid', 'guid', 'orderid']);
const SEARCH_PARAM_NAMES = new Set(['q', 'search', 'query', 'keyword', 'term']);
const ORDER_PARAM_NAMES = new Set(['sort', 'order', 'filter', 'column']);
const DEBUG_PARAM_NAMES = new Set(['debug', 'test', 'dev']);
const SSRF_PARAM_NAMES = new Set(['url', 'uri', 'href', 'target', 'src', 'callback', 'webhook']);
const DOM_SINK_NAMES = new Set(['innerhtml', 'eval', 'document.write']);
const TEXT_INPUT_TYPES = new Set(['text', 'search', 'email', 'url', 'tel', 'number', 'textarea']);

const LIBRARY_PATTERNS = [
  ['jquery', /jquery[/@._-]?v?\d+/i],
  ['bootstrap', /bootstrap[/@._-]?v?\d+/i],
  ['angular', /angular(?:js)?[/@._-]?v?\d+/i],
  ['vue', /vue[/@._-]?v?\d+/i],
  ['moment', /moment[/@._-]?v?\d+/i],
];

/** Fresh, zeroed counts for every OWASP category (A01..A10). */
export function EMPTY_OWASP_COUNTS() {
  return Object.fromEntries(OWASP_SCAN_CATEGORIES.map(({ id }) => [id, 0]));
}

/* ------------------------------------------------------------------ helpers */

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function clean(value, max = 512) {
  return truncate(
    String(value ?? '')
      .replace(/[\r\n\t]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim(),
    max,
  );
}

/** Keep scheme/host/path and query NAMES; drop all values and fragments. */
function safeUrl(raw) {
  const value = String(raw ?? '').trim();
  if (!value) return '';
  try {
    const u = new URL(value);
    const names = [...u.searchParams.keys()].map((n) => clean(n, 128)).filter(Boolean);
    const base = `${u.protocol}//${u.host}${u.pathname || '/'}`;
    return clean(names.length ? `${base}?${names.join('&')}` : base, URL_LIMIT);
  } catch {
    const withoutHash = value.split('#')[0];
    const q = withoutHash.indexOf('?');
    if (q === -1) return clean(withoutHash, URL_LIMIT);
    const base = withoutHash.slice(0, q);
    const names = withoutHash
      .slice(q + 1)
      .split('&')
      .map((pair) => pair.split('=')[0])
      .filter(Boolean)
      .map((name) => clean(name, 128));
    return clean(names.length ? `${base}?${names.join('&')}` : base, URL_LIMIT);
  }
}

/** Query parameter names from a URL, never its values. */
function queryNames(raw) {
  const value = String(raw ?? '');
  try {
    return [...new URL(value).searchParams.keys()].map((n) => clean(n, 128)).filter(Boolean);
  } catch {
    const q = value.indexOf('?');
    if (q === -1) return [];
    return value
      .slice(q + 1)
      .split('&')
      .map((pair) => pair.split('=')[0])
      .filter(Boolean)
      .map((name) => clean(name, 128));
  }
}

/** Pathname only, used for route-pattern checks. */
function pathOf(raw) {
  const safe = safeUrl(raw);
  try {
    return new URL(safe).pathname;
  } catch {
    return safe.split('?')[0];
  }
}

/** Prefer the page copy, then the mirrored observation copy. */
function pick(page, key) {
  const direct = page?.[key];
  if (direct !== undefined) return direct;
  return page?.observation?.[key];
}

/** Lowercase header name -> raw value; values stay internal and are never emitted. */
function headerMap(headers) {
  const map = new Map();
  for (const header of asArray(headers)) {
    if (!header || typeof header !== 'object') continue;
    const name = clean(header.name, 128).toLowerCase();
    if (!name || map.has(name)) continue;
    map.set(name, String(header.value ?? ''));
  }
  return map;
}

function endpointsForPage(crawl, page, pageUrl) {
  const out = [];
  const seen = new Set();
  const add = (endpoint) => {
    if (!endpoint || typeof endpoint !== 'object') return;
    const url = clean(endpoint.url, URL_LIMIT);
    const source = clean(endpoint.source || 'unknown', 64);
    if (!url || seen.has(`${url}|${source}`)) return;
    seen.add(`${url}|${source}`);
    out.push({ url, source });
  };
  for (const endpoint of asArray(pick(page, 'endpoints'))) add(endpoint);
  for (const endpoint of asArray(crawl?.inventory?.endpoints)) {
    if (clean(endpoint?.page, URL_LIMIT) === pageUrl) add(endpoint);
  }
  return out;
}

function fieldsForForm(page, form) {
  const direct = asArray(form?.fields);
  if (direct.length) return direct;
  const selector = clean(form?.selector, 128);
  return asArray(pick(page, 'inputs')).filter((input) => clean(input?.formSelector, 128) === selector);
}

function inputPoint(page, input) {
  const name = clean(input?.name, 128);
  const formSelector = clean(input?.formSelector, 128);
  const label = name
    ? `input[name="${name}"]`
    : `input[type="${clean(input?.type || 'text', 32)}"]`;
  return formSelector ? `form ${formSelector} -> ${label}` : label;
}

function isLoginForm(signals, fields) {
  const names = fields.map((field) => clean(field?.name, 128).toLowerCase());
  const hasPassword =
    fields.some((field) => clean(field?.type, 32).toLowerCase() === 'password') ||
    names.some((name) => /pass|pwd|password/.test(name));
  if (!hasPassword) return false;
  const hasUser = names.some((name) => /user|email|login|username/.test(name));
  return hasUser || signals?.hasLogin === true;
}

function isSamePageAction(action, pageUrl) {
  const raw = String(action ?? '').trim();
  if (!raw || raw.startsWith('#')) return true;
  try {
    const base = new URL(safeUrl(pageUrl));
    const target = new URL(raw, base);
    const key = (u) => `${u.protocol}//${u.host}${u.pathname || '/'}`;
    return key(target) === key(base);
  } catch {
    return false;
  }
}

function domSinkNames(value) {
  return asArray(value)
    .map((sink) => (typeof sink === 'string' ? sink : clean(sink?.name ?? sink?.type, 64)))
    .map((sink) => clean(sink, 64))
    .filter(Boolean);
}

function libraryHit(src) {
  const value = String(src ?? '');
  for (const [name, pattern] of LIBRARY_PATTERNS) {
    if (pattern.test(value)) return name;
  }
  return '';
}

function isExternalScript(src, host, pageUrl) {
  if (!host) return false;
  try {
    const base = safeUrl(pageUrl);
    const target = base ? new URL(String(src), base) : new URL(String(src));
    return target.hostname.toLowerCase() !== host.toLowerCase();
  } catch {
    return false;
  }
}

/** Append a deduped finding and assign a stable, per-page ordinal id. */
function addFinding(ctx, spec) {
  const { pageIndex, owaspId, kind, severity, title, possibleVulnerability, url, point, evidence, manualCheck, source } = spec;
  const safePoint = clean(point, URL_LIMIT);
  const safePageUrl = safeUrl(url);
  if (!safePageUrl || !safePoint) return;
  const dedupeKey = `${safePageUrl}\u0000${safePoint}\u0000${owaspId}`;
  if (ctx.seen.has(dedupeKey)) return;
  ctx.seen.add(dedupeKey);

  const key = `${owaspId}-${kind}-${pageIndex}`;
  const ordinal = (ctx.counters.get(key) || 0) + 1;
  ctx.counters.set(key, ordinal);

  ctx.findings.push({
    id: `${owaspId}-${kind}-${pageIndex}-${ordinal}`,
    owasp: { id: owaspId, name: OWASP_BY_ID.get(owaspId) || '' },
    severity,
    title: clean(title, 160),
    possibleVulnerability: clean(possibleVulnerability, 400),
    url: safePageUrl,
    point: safePoint,
    evidence: clean(evidence, 400),
    manualCheck: clean(manualCheck, 400),
    source,
  });
}

/* ------------------------------------------------------------------ finalize */

/** Sort high-severity findings first, dedupe already done by addFinding, cap output. */
function finalizeFindings(ctx, scope) {
  const severityRank = { high: 0, medium: 1, low: 2 };
  const findings = ctx.findings
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) =>
      (severityRank[a.finding.severity] ?? 3) - (severityRank[b.finding.severity] ?? 3) || a.index - b.index,
    )
    .map(({ finding }) => finding)
    .slice(0, MAX_FINDINGS);
  const byOwasp = EMPTY_OWASP_COUNTS();
  const summary = { total: 0, high: 0, medium: 0, low: 0, pagesCovered: 0 };
  const covered = new Set();

  for (const finding of findings) {
    if (byOwasp[finding.owasp.id] !== undefined) byOwasp[finding.owasp.id] += 1;
    if (summary[finding.severity] !== undefined) summary[finding.severity] += 1;
    covered.add(finding.url);
  }
  summary.total = findings.length;
  summary.pagesCovered = covered.size;

  return { findings, byOwasp, summary, scope };
}

/* --------------------------------------------------------------------- main */

/**
 * Turn an existing crawl result into passive, metadata-only "possible
 * vulnerability" findings. Pure and synchronous: no network, no payloads, no
 * active testing and no parameter values in the output.
 *
 * `summary.pagesCovered` counts distinct page URLs that produced a finding.
 */
export function buildSiteFindings(crawl = {}) {
  const input = crawl && typeof crawl === 'object' ? crawl : {};
  const pages = asArray(input.pages);
  const host = clean(input.host, 256).toLowerCase();
  const ctx = { findings: [], seen: new Set(), counters: new Map() };

  for (let pageIndex = 0; pageIndex < pages.length; pageIndex += 1) {
    const page = pages[pageIndex];
    if (!page || typeof page !== 'object') continue;

    const pageUrl = safeUrl(pick(page, 'url'));
    if (!pageUrl) continue;

    const signals = pick(page, 'signals') && typeof pick(page, 'signals') === 'object'
      ? pick(page, 'signals')
      : {};
    const forms = asArray(pick(page, 'forms'));
    const inputs = asArray(pick(page, 'inputs'));
    const queryParams = asArray(pick(page, 'queryParams'));
    const scripts = asArray(pick(page, 'scripts'));
    const endpoints = endpointsForPage(input, page, pageUrl);
    const headers = headerMap(pick(page, 'headers'));
    const status = Number(pick(page, 'status'));
    const pageIndexForId = pageIndex;

    /** Shorthand that fixes the page url and index for every rule below. */
    const add = (spec) => {
      const { owasp, ...rest } = spec;
      return addFinding(ctx, {
        ...rest,
        owaspId: owasp,
        pageIndex: pageIndexForId,
        url: pageUrl,
        kind: OWASP_KIND[owasp] || 'check',
      });
    };

    /* ------------------------------------------------ A01 Broken Access Control */
    for (const qp of queryParams) {
      const name = clean(qp?.name, 128);
      if (!ID_PARAM_NAMES.has(name.toLowerCase())) continue;
      add({
        owasp: 'A01',
        severity: 'high',
        title: 'Object identifier in URL',
        possibleVulnerability: 'The identifier may be enumerable and could expose another users data (possible IDOR).',
        point: `query parameter "${name}" in URL`,
        evidence: 'query parameter name matches an object-identifier pattern; values not retained',
        manualCheck: 'In Burp Repeater, keep the session constant and change only the identifier; confirm whether a different object is returned.',
        source: 'query',
      });
    }

    for (const form of forms) {
      const selector = clean(form?.selector, 128) || 'form';
      for (const field of fieldsForForm(page, form)) {
        const name = clean(field?.name, 128);
        if (!/^(user|role|id)$/i.test(name)) continue;
        if (clean(field?.type, 32).toLowerCase() !== 'hidden') continue;
        add({
          owasp: 'A01',
          severity: 'medium',
          title: 'Hidden authorization field',
          possibleVulnerability: 'A hidden user/role/id field may be trusted by the server and could be tampered with (possible parameter tampering).',
          point: `form ${selector} -> input[name="${name}"]`,
          evidence: 'hidden field name present in form; value not retained',
          manualCheck: 'In Burp Repeater, compare the request with and without this hidden field and check whether the server enforces authorization independently.',
          source: 'form',
        });
      }
    }

    if (signals?.hasCsrfTokenField === false) {
      for (const form of forms) {
        const method = clean(form?.method, 16).toUpperCase() || 'GET';
        if (method !== 'POST') continue;
        const selector = clean(form?.selector, 128) || 'form';
        add({
          owasp: 'A01',
          severity: 'medium',
          title: 'POST form without CSRF field',
          possibleVulnerability: 'This POST form has no csrf/xsrf/token field, so state changes may be forgeable (possible CSRF).',
          point: `form ${selector} (method POST)`,
          evidence: 'method POST and signals.hasCsrfTokenField is false',
          manualCheck: 'In a browser session, confirm whether the server validates a per-session token for this form; inspect the request in Burp Proxy.',
          source: 'form',
        });
      }
    }

    for (const endpoint of endpoints) {
      if (!/\/admin\/|\/api\/user\//i.test(pathOf(endpoint.url))) continue;
      add({
        owasp: 'A01',
        severity: 'high',
        title: 'Administrative or user endpoint',
        possibleVulnerability: 'An administrative or user endpoint may be reachable without authorization (possible missing access control).',
        point: `endpoint ${safeUrl(endpoint.url)} (source: ${endpoint.source})`,
        evidence: 'endpoint path matches an admin or user route pattern',
        manualCheck: 'In Burp Repeater, repeat this request with a low-privilege session and confirm that the server denies access.',
        source: 'endpoint',
      });
    }

    /* --------------------------------------- A02 Cryptographic Failures */
    if (/^http:\/\//i.test(pageUrl) && signals?.hasLogin === true) {
      add({
        owasp: 'A02',
        severity: 'high',
        title: 'Login form served over HTTP',
        possibleVulnerability: 'Credentials from a login form on an http:// page may be transmitted in cleartext.',
        point: 'page URL (http:// login form)',
        evidence: 'page URL scheme is http and signals.hasLogin is true',
        manualCheck: 'In a browser, inspect the login request in Burp Proxy and confirm whether credentials traverse an unencrypted channel.',
        source: 'signal',
      });
    }

    {
      const present = (name) => headers.has(name);
      const display = {
        'content-security-policy': 'Content-Security-Policy',
        'strict-transport-security': 'Strict-Transport-Security',
        'referrer-policy': 'Referrer-Policy',
      };
      const hasHeaders = Array.isArray(pick(page, 'headers'));

      if (hasHeaders && !present('content-security-policy')) {
        add({
          owasp: 'A02',
          severity: 'medium',
          title: 'Content-Security-Policy not observed',
          possibleVulnerability: 'No Content-Security-Policy was captured, which may leave the page exposed to content injection.',
          point: 'response header Content-Security-Policy',
          evidence: 'header absent from captured response headers',
          manualCheck: 'In Burp Repeater, inspect the response headers and confirm whether a policy is applied consistently.',
          source: 'header',
        });
      }
      if (hasHeaders && !present('strict-transport-security')) {
        add({
          owasp: 'A02',
          severity: 'medium',
          title: 'HSTS not observed',
          possibleVulnerability: 'No Strict-Transport-Security header was captured, so HTTPS enforcement may be incomplete.',
          point: 'response header Strict-Transport-Security',
          evidence: 'header absent from captured response headers',
          manualCheck: 'In a browser, revisit the page over http:// and confirm whether the server upgrades to HTTPS.',
          source: 'header',
        });
      }
      if (hasHeaders && !present('referrer-policy')) {
        add({
          owasp: 'A02',
          severity: 'low',
          title: 'Referrer-Policy not observed',
          possibleVulnerability: 'No Referrer-Policy header was captured, which may allow unnecessary referrer disclosure.',
          point: 'response header Referrer-Policy',
          evidence: 'header absent from captured response headers',
          manualCheck: 'In Burp Repeater, inspect the response headers and confirm the referrer behaviour on navigation.',
          source: 'header',
        });
      }
      if (present('strict-transport-security')) {
        const match = String(headers.get('strict-transport-security') || '').match(/max-age\s*=\s*(\d+)/i);
        const age = match ? Number.parseInt(match[1], 10) : NaN;
        if (Number.isFinite(age) && (age === 0 || age < 31536000)) {
          add({
            owasp: 'A02',
            severity: 'medium',
            title: 'Weak HSTS lifetime',
            possibleVulnerability: 'The captured HSTS max-age is below the recommended minimum, so protection may lapse.',
            point: `response header ${display['strict-transport-security']}`,
            evidence: 'max-age parsed below the recommended minimum; value not reproduced',
            manualCheck: 'In Burp Repeater, inspect the HSTS header and confirm the effective max-age across the whole host.',
            source: 'header',
          });
        }
      }
      if (present('referrer-policy') && /unsafe-url/i.test(String(headers.get('referrer-policy') || ''))) {
        add({
          owasp: 'A02',
          severity: 'low',
          title: 'Unsafe referrer policy',
          possibleVulnerability: 'A referrer policy containing unsafe-url may leak full URLs to third parties.',
          point: `response header ${display['referrer-policy']}`,
          evidence: 'referrer policy contains the unsafe-url token',
          manualCheck: 'In a browser, navigate to a third-party destination and inspect the Referer header in Burp Proxy.',
          source: 'header',
        });
      }
    }

    /* ------------------------------------------------------ A03 Injection */
    for (const input of inputs) {
      const name = clean(input?.name, 128);
      if (!SEARCH_PARAM_NAMES.has(name.toLowerCase())) continue;
      if (!TEXT_INPUT_TYPES.has(clean(input?.type, 32).toLowerCase())) continue;
      add({
        owasp: 'A03',
        severity: 'medium',
        title: 'Search-like input field',
        possibleVulnerability: 'A search-like input may be reflected or used in a query (possible SQLi/XSS reflection).',
        point: inputPoint(page, input),
        evidence: 'input name matches a search-term pattern; type metadata only',
        manualCheck: 'In Burp Repeater, vary this input with a benign marker and look for reflection or data-dependent responses.',
        source: 'form',
      });
    }

    for (const qp of queryParams) {
      const name = clean(qp?.name, 128);
      const lower = name.toLowerCase();
      if (SEARCH_PARAM_NAMES.has(lower)) {
        add({
          owasp: 'A03',
          severity: 'medium',
          title: 'Search-like URL parameter',
          possibleVulnerability: 'A search-like URL parameter may be reflected or used in a query (possible SQLi/XSS reflection).',
          point: `query parameter "${name}" in URL`,
          evidence: 'query parameter name matches a search-term pattern',
          manualCheck: 'In Burp Repeater, vary this parameter with a benign marker and compare the response with the baseline.',
          source: 'query',
        });
      }
      if (ORDER_PARAM_NAMES.has(lower)) {
        add({
          owasp: 'A03',
          severity: 'high',
          title: 'Sort/order URL parameter',
          possibleVulnerability: 'A sort/order parameter may be concatenated into a query (possible SQLi via ordering).',
          point: `query parameter "${name}" in URL`,
          evidence: 'query parameter name suggests ordering or filtering',
          manualCheck: 'In Burp Repeater, vary only this parameter and observe error text or changed row ordering.',
          source: 'query',
        });
      }
    }

    for (const endpoint of endpoints) {
      const safeEndpoint = safeUrl(endpoint.url);
      if (!/\/api\//i.test(pathOf(safeEndpoint))) continue;
      if (!queryNames(safeEndpoint).length) continue;
      add({
        owasp: 'A03',
        severity: 'medium',
        title: 'API endpoint with query parameters',
        possibleVulnerability: 'An API endpoint accepting query parameters may be an injection surface.',
        point: `endpoint ${safeEndpoint} (source: ${endpoint.source})`,
        evidence: 'API path with query parameter names present',
        manualCheck: 'In Burp Repeater, vary one query parameter at a time and compare the response with the baseline.',
        source: 'endpoint',
      });
    }

    /* -------------------------------------------------- A04 Insecure Design */
    if (signals?.hasUpload === true) {
      const fileInputs = inputs.filter((input) => clean(input?.type, 32).toLowerCase() === 'file');
      if (fileInputs.length) {
        for (const input of fileInputs) {
          add({
            owasp: 'A04',
            severity: 'high',
            title: 'File upload input',
            possibleVulnerability: 'A file upload input may accept unrestricted file types (possible unrestricted upload).',
            point: inputPoint(page, input),
            evidence: 'file input present and signals.hasUpload is true',
            manualCheck: 'In a browser, inspect the upload request in Burp Proxy and confirm server-side type and size checks.',
            source: 'form',
          });
        }
      } else {
        add({
          owasp: 'A04',
          severity: 'high',
          title: 'Upload capability signalled',
          possibleVulnerability: 'Upload capability was observed, so file type restrictions may be missing.',
          point: 'page URL (upload signal)',
          evidence: 'signals.hasUpload is true',
          manualCheck: 'In a browser, locate the upload control and confirm server-side validation in Burp Proxy.',
          source: 'signal',
        });
      }
    }

    for (const qp of queryParams) {
      const name = clean(qp?.name, 128);
      if (!DEBUG_PARAM_NAMES.has(name.toLowerCase())) continue;
      add({
        owasp: 'A04',
        severity: 'low',
        title: 'Debug-like URL parameter',
        possibleVulnerability: 'A debug/test/dev parameter may expose development behaviour in production.',
        point: `query parameter "${name}" in URL`,
        evidence: 'query parameter name matches a debug/test pattern',
        manualCheck: 'In Burp Repeater, compare the response with and without this parameter using benign values only.',
        source: 'query',
      });
    }

    /* -------------------------------------- A05 Security Misconfiguration */
    for (const name of ['server', 'x-powered-by']) {
      if (!headers.has(name)) continue;
      if (!/\d+\.\d+/.test(String(headers.get(name) || ''))) continue;
      const display = name === 'server' ? 'Server' : 'X-Powered-By';
      add({
        owasp: 'A05',
        severity: 'low',
        title: 'Version-bearing response header',
        possibleVulnerability: 'A version-bearing Server/X-Powered-By header may disclose component versions.',
        point: `response header ${display}`,
        evidence: 'header value contains a version-like token; value not reproduced',
        manualCheck: 'In Burp Repeater, inspect the header and confirm whether the disclosed version is still supported.',
        source: 'header',
      });
    }

    const hasInline = signals?.hasInlineScript === true || scripts.some((s) => Number(s?.inlineLength) > 0);
    if (hasInline && !headers.has('content-security-policy')) {
      add({
        owasp: 'A05',
        severity: 'medium',
        title: 'Inline script without observed CSP',
        possibleVulnerability: 'An inline script was observed with no Content-Security-Policy header, which may permit unsafe execution.',
        point: 'inline script on page',
        evidence: 'inline script metadata present and no Content-Security-Policy observed',
        manualCheck: 'In a browser, inspect the inline script and confirm whether a restrictive CSP is enforced.',
        source: 'signal',
      });
    }

    if ((status === 404 || status === 500) && hasInline) {
      add({
        owasp: 'A05',
        severity: 'low',
        title: 'Error page with inline content',
        possibleVulnerability: 'An error page with inline content may reveal verbose implementation details.',
        point: `page URL (status ${status})`,
        evidence: `status ${status} with inline script content`,
        manualCheck: 'In Burp Repeater, request the same path and confirm whether the error response is generic.',
        source: 'signal',
      });
    }

    /* ------------------------------------------- A06 Vulnerable Components */
    for (const script of scripts) {
      const src = clean(script?.src, URL_LIMIT);
      if (!src) continue;
      const library = libraryHit(src);
      if (!library) continue;
      add({
        owasp: 'A06',
        severity: 'medium',
        title: 'Versioned JavaScript library',
        possibleVulnerability: 'A script src contains a version-like token for a common library and may be outdated.',
        point: `script src ${safeUrl(src)}`,
        evidence: `script src contains a ${library} version-like token`,
        manualCheck: 'In a browser, confirm the loaded library version and compare it with the current supported release.',
        source: 'script',
      });
    }

    /* --------------------------------- A07 Identification and Auth Failures */
    for (const form of forms) {
      const fields = fieldsForForm(page, form);
      const selector = clean(form?.selector, 128) || 'form';
      const method = clean(form?.method, 16).toUpperCase() || 'GET';
      const action = clean(form?.action, URL_LIMIT);

      if (isLoginForm(signals, fields) && isSamePageAction(action, pageUrl)) {
        add({
          owasp: 'A07',
          severity: 'medium',
          title: 'Self-submitting login form',
          possibleVulnerability: 'A login form with an empty or same-page action may indicate a weak login flow.',
          point: `form ${selector} (login flow)`,
          evidence: 'login form action is empty or resolves to the current page',
          manualCheck: 'In a browser, inspect the login request in Burp Proxy and confirm where credentials are actually submitted.',
          source: 'form',
        });
      }

      if (method === 'GET' && fields.some((field) => clean(field?.type, 32).toLowerCase() === 'password')) {
        add({
          owasp: 'A07',
          severity: 'high',
          title: 'Password submitted with GET',
          possibleVulnerability: 'A form with a password input and method GET may place credentials in the URL.',
          point: `form ${selector}`,
          evidence: 'password input present and method GET',
          manualCheck: 'In Burp Proxy, confirm that credentials are not present in the request URL or browser history.',
          source: 'form',
        });
      }
    }

    /* -------------------------------- A08 Software and Data Integrity Failures */
    for (const sink of new Set(domSinkNames(pick(page, 'domSinks')))) {
      if (!DOM_SINK_NAMES.has(sink.toLowerCase())) continue;
      add({
        owasp: 'A08',
        severity: 'high',
        title: 'DOM write sink',
        possibleVulnerability: 'A DOM write sink was observed and may be reachable with untrusted data (possible DOM XSS).',
        point: `DOM sink: ${sink}`,
        evidence: 'DOM sink type observed in page metadata',
        manualCheck: 'In browser DevTools, trace data reaching this sink and confirm whether it is sanitized.',
        source: 'dom',
      });
    }

    for (const script of scripts) {
      const src = clean(script?.src, URL_LIMIT);
      if (!src || !isExternalScript(src, host, pageUrl)) continue;
      add({
        owasp: 'A08',
        severity: 'medium',
        title: 'Third-party script',
        possibleVulnerability: 'A script is loaded from a different hostname, so its integrity may not be assured.',
        point: `script src ${safeUrl(src)}`,
        evidence: 'script hostname differs from the crawl host',
        manualCheck: 'In Burp Repeater, inspect the script response and confirm whether integrity checks are used.',
        source: 'script',
      });
    }

    /* ----------------------------------------------------------- A09 (none) */
    // No passive evidence is available from crawl metadata for logging failures.

    /* --------------------------------------------------------------- A10 SSRF */
    for (const qp of queryParams) {
      const name = clean(qp?.name, 128);
      if (!SSRF_PARAM_NAMES.has(name.toLowerCase())) continue;
      add({
        owasp: 'A10',
        severity: 'high',
        title: 'URL-like URL parameter',
        possibleVulnerability: 'A URL-like parameter may be fetched server-side (possible SSRF).',
        point: `query parameter "${name}" in URL`,
        evidence: 'query parameter name suggests a URL destination',
        manualCheck: 'In Burp Repeater, confirm whether the server fetches the destination and restrict it to an allowlist.',
        source: 'query',
      });
    }

    for (const endpoint of endpoints) {
      const safeEndpoint = safeUrl(endpoint.url);
      if (!queryNames(safeEndpoint).some((name) => SSRF_PARAM_NAMES.has(name.toLowerCase()))) continue;
      add({
        owasp: 'A10',
        severity: 'high',
        title: 'URL-like endpoint parameter',
        possibleVulnerability: 'An endpoint accepts a URL-like parameter that may be fetched server-side (possible SSRF).',
        point: `endpoint ${safeEndpoint} (source: ${endpoint.source})`,
        evidence: 'endpoint query parameter name suggests a URL destination',
        manualCheck: 'In Burp Repeater, confirm whether the server makes a request to the supplied destination.',
        source: 'endpoint',
      });
    }
  }

  return finalizeFindings(ctx, SCOPE_TEXT);
}

/* ------------------------------------------------------------ Burp traffic */

const AUTH_PATH_RE = /(?:^|\/)(?:login|signin|sign-in|auth|oauth|register|signup|forgot|reset)(?:\/|$)/i;
const ADMIN_PATH_RE = /(?:\/admin\/|\/api\/users?\/|\/users\/\d|\/administration\/)/i;
const FETCH_PATH_RE = /(?:\/fetch|\/proxy|\/download|\/webhook|\/import)(?:\/|$)/i;
const CSRF_PARAM_NAMES = new Set(['csrf', 'csrfmiddlewaretoken', 'xsrf', 'xsrf-token', 'authenticity_token', 'token']);
const PASSWORD_PARAM_NAMES = new Set(['password', 'pass', 'pwd', 'passwd']);
const STATE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function paramNames(value) {
  return asArray(value)
    .map((item) => {
      if (typeof item === 'string') return clean(item, 128);
      if (item && typeof item === 'object') return clean(item.name ?? '', 128);
      return '';
    })
    .filter(Boolean);
}

/** Exact safe request URL: path plus query parameter NAMES only. */
function trafficUrl(item) {
  const base = safeUrl(item?.url || item?.path || '');
  const names = [...new Set([...queryNames(item?.url || ''), ...paramNames(item?.queryParams)])];
  const withoutQuery = base.split('?')[0];
  return clean(names.length ? `${withoutQuery}?${names.join('&')}` : withoutQuery, URL_LIMIT);
}

function trafficStatus(item) {
  const raw = item?.status;
  if (raw === null || raw === undefined || raw === '') return null;
  const parsed = Number.parseInt(String(raw).replace(/,/g, ''), 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function requestMethod(item) {
  return clean(item?.method || 'GET', 16).toUpperCase() || 'GET';
}

function endpointPoint(item, suffix = '') {
  const method = requestMethod(item);
  const path = clean(item?.path || pathOf(item?.url || '') || '/', 512);
  return `captured ${method} ${path}${suffix ? ` -> ${suffix}` : ''} (Burp traffic)`;
}

function paramPoint(item, where, name) {
  return endpointPoint(item, `${where} parameter "${name}"`);
}

/**
 * Turn captured Burp traffic metadata into passive OWASP observations.
 *
 * Only names and structural metadata are used: no values, bodies, cookies or
 * auth headers. Both request and response proxy events may be supplied; the
 * dedupe key in addFinding collapses identical observations.
 */
export function buildTrafficFindings(items = []) {
  const list = asArray(items).filter((item) => item && typeof item === 'object');
  const ctx = { findings: [], seen: new Set(), counters: new Map() };

  for (let itemIndex = 0; itemIndex < list.length; itemIndex += 1) {
    const item = list[itemIndex];
    const url = trafficUrl(item);
    if (!url) continue;

    const method = requestMethod(item);
    const path = clean(item?.path || pathOf(item?.url || '') || '/', 512);
    const status = trafficStatus(item);
    const isResponse = status !== null;
    const queryParams = paramNames(item?.queryParams).length
      ? paramNames(item?.queryParams)
      : queryNames(item?.url || '');
    const bodyParams = paramNames(item?.bodyParams);
    const allParams = [...new Set([...queryParams, ...bodyParams])].map((name) => name.toLowerCase());
    const headers = headerMap(item?.headers);
    const hasHeaders = Array.isArray(item?.headers) && item.headers.length > 0;
    const hasCsrfParam = allParams.some((name) => CSRF_PARAM_NAMES.has(name));
    const hasCsrfHeader = headers.has('csrf-token') || headers.has('x-csrf-token') || headers.has('x-xsrf-token');

    const add = (spec) => {
      const { owasp, ...rest } = spec;
      return addFinding(ctx, {
        ...rest,
        owaspId: owasp,
        pageIndex: itemIndex,
        url,
        kind: OWASP_KIND[owasp] || 'check',
      });
    };

    /* A01 — Broken Access Control */
    for (const name of queryParams) {
      if (!ID_PARAM_NAMES.has(name.toLowerCase())) continue;
      add({
        owasp: 'A01',
        severity: 'high',
        title: 'Object identifier in captured request',
        possibleVulnerability: 'An object identifier was observed in a query parameter and may be enumerable (possible IDOR).',
        point: paramPoint(item, 'query', name),
        evidence: 'query parameter name matches an object-identifier pattern; value not retained',
        manualCheck: 'In Burp Repeater, keep the session constant and change only this identifier to confirm whether another object is returned.',
        source: 'burp-query',
      });
    }
    for (const name of bodyParams) {
      if (!ID_PARAM_NAMES.has(name.toLowerCase())) continue;
      add({
        owasp: 'A01',
        severity: 'high',
        title: 'Object identifier in captured body',
        possibleVulnerability: 'An object identifier was observed in a request body parameter and may be enumerable (possible IDOR).',
        point: paramPoint(item, 'body', name),
        evidence: 'body parameter name matches an object-identifier pattern; value not retained',
        manualCheck: 'In Burp Repeater, keep the session constant and change only this identifier to confirm whether another object is returned.',
        source: 'burp-body',
      });
    }
    if (ADMIN_PATH_RE.test(path)) {
      add({
        owasp: 'A01',
        severity: 'high',
        title: 'Administrative or user endpoint in traffic',
        possibleVulnerability: 'An administrative or user endpoint was captured and may be reachable without authorization.',
        point: endpointPoint(item),
        evidence: 'captured path matches an admin or user route pattern',
        manualCheck: 'In Burp Repeater, repeat this request with a low-privilege session and confirm that the server denies access.',
        source: 'burp-endpoint',
      });
    }

    /* A02 — Cryptographic Failures */
    if (/^http:\/\//i.test(url) && AUTH_PATH_RE.test(path)) {
      add({
        owasp: 'A02',
        severity: 'high',
        title: 'Authentication endpoint over HTTP',
        possibleVulnerability: 'An authentication-related endpoint was captured over http://, so credentials may traverse an unencrypted channel.',
        point: endpointPoint(item, 'request URL uses http://'),
        evidence: 'captured URL scheme is http and path matches an authentication endpoint',
        manualCheck: 'In Burp Proxy, confirm whether this endpoint redirects to HTTPS and never accepts credentials over HTTP.',
        source: 'burp-signal',
      });
    }
    if (isResponse && hasHeaders) {
      const missing = [
        ['content-security-policy', 'Content-Security-Policy', 'medium', 'may leave the page exposed to content injection'],
        ['strict-transport-security', 'Strict-Transport-Security', 'medium', 'so HTTPS enforcement may be incomplete'],
        ['referrer-policy', 'Referrer-Policy', 'low', 'which may allow unnecessary referrer disclosure'],
      ];
      for (const [name, display, severity, impact] of missing) {
        if (headers.has(name)) continue;
        add({
          owasp: 'A02',
          severity,
          title: `${display} not observed in traffic`,
          possibleVulnerability: `No ${display} header was captured on this response, ${impact}.`,
          point: endpointPoint(item, `response header ${display}`),
          evidence: 'header absent from captured response header names',
          manualCheck: 'In Burp Repeater, inspect the response headers and confirm whether the header is applied consistently.',
          source: 'burp-header',
        });
      }
    }

    /* A03 — Injection */
    for (const name of queryParams) {
      const lower = name.toLowerCase();
      if (SEARCH_PARAM_NAMES.has(lower)) {
        add({
          owasp: 'A03',
          severity: 'medium',
          title: 'Search-like parameter in captured query',
          possibleVulnerability: 'A search-like parameter may be reflected or used in a query (possible SQLi/XSS reflection).',
          point: paramPoint(item, 'query', name),
          evidence: 'query parameter name matches a search-term pattern; value not retained',
          manualCheck: 'In Burp Repeater, vary this parameter with a benign marker and compare the response with the baseline.',
          source: 'burp-query',
        });
      }
      if (ORDER_PARAM_NAMES.has(lower)) {
        add({
          owasp: 'A03',
          severity: 'high',
          title: 'Sort/order parameter in captured query',
          possibleVulnerability: 'A sort/order parameter may be concatenated into a query (possible SQLi via ordering).',
          point: paramPoint(item, 'query', name),
          evidence: 'query parameter name suggests ordering or filtering',
          manualCheck: 'In Burp Repeater, vary only this parameter and observe error text or changed row ordering.',
          source: 'burp-query',
        });
      }
    }
    for (const name of bodyParams) {
      const lower = name.toLowerCase();
      if (!SEARCH_PARAM_NAMES.has(lower) && !ORDER_PARAM_NAMES.has(lower)) continue;
      add({
        owasp: 'A03',
        severity: ORDER_PARAM_NAMES.has(lower) ? 'high' : 'medium',
        title: 'Filter-like parameter in captured body',
        possibleVulnerability: 'A search or ordering parameter in the request body may be used in a query (possible injection).',
        point: paramPoint(item, 'body', name),
        evidence: 'body parameter name matches a search or ordering pattern; value not retained',
        manualCheck: 'In Burp Repeater, vary one body parameter at a time and compare the response with the baseline.',
        source: 'burp-body',
      });
    }
    if (/\/api\//i.test(path) && queryParams.length) {
      add({
        owasp: 'A03',
        severity: 'medium',
        title: 'API endpoint with query parameters',
        possibleVulnerability: 'An API endpoint accepting query parameters may be an injection surface.',
        point: endpointPoint(item, `query parameters ${queryParams.map((n) => `"${n}"`).join(', ')}`),
        evidence: 'captured API path with query parameter names present',
        manualCheck: 'In Burp Repeater, vary one query parameter at a time and compare the response with the baseline.',
        source: 'burp-endpoint',
      });
    }

    /* A04 — Insecure Design */
    for (const name of allParams) {
      if (!DEBUG_PARAM_NAMES.has(name)) continue;
      add({
        owasp: 'A04',
        severity: 'low',
        title: 'Debug-like parameter in captured request',
        possibleVulnerability: 'A debug/test/dev parameter may expose development behaviour in production.',
        point: paramPoint(item, queryParams.some((q) => q.toLowerCase() === name) ? 'query' : 'body', name),
        evidence: 'parameter name matches a debug/test pattern; value not retained',
        manualCheck: 'In Burp Repeater, compare the response with and without this parameter using benign values only.',
        source: 'burp-signal',
      });
    }
    if (STATE_METHODS.has(method) && !hasCsrfParam && !hasCsrfHeader && !AUTH_PATH_RE.test(path)) {
      add({
        owasp: 'A04',
        severity: 'medium',
        title: 'State-changing request without CSRF token name',
        possibleVulnerability: 'A state-changing request was captured without an obvious CSRF token parameter or header name, so forgery may be possible.',
        point: endpointPoint(item, `method ${method}`),
        evidence: 'no csrf/xsrf/token name observed in captured parameter or header names',
        manualCheck: 'In Burp Repeater, confirm whether the server validates a per-session token for this state-changing request.',
        source: 'burp-signal',
      });
    }

    /* A05 — Security Misconfiguration */
    if (isResponse && hasHeaders) {
      for (const name of ['server', 'x-powered-by']) {
        if (!headers.has(name)) continue;
        const display = name === 'server' ? 'Server' : 'X-Powered-By';
        add({
          owasp: 'A05',
          severity: 'low',
          title: `${display} header exposed in traffic`,
          possibleVulnerability: `A ${display} header was captured, which may disclose implementation details.`,
          point: endpointPoint(item, `response header ${display}`),
          evidence: 'allowlisted header name present; value not retained',
          manualCheck: 'In Burp Repeater, inspect the header and confirm whether the disclosed component is still supported.',
          source: 'burp-header',
        });
      }
    }

    /* A06 — Vulnerable Components */
    const library = libraryHit(path);
    if (library) {
      add({
        owasp: 'A06',
        severity: 'medium',
        title: 'Versioned JavaScript library in traffic',
        possibleVulnerability: 'A captured resource path contains a version-like token for a common library and may be outdated.',
        point: endpointPoint(item, `resource path ${path}`),
        evidence: `captured path contains a ${library} version-like token`,
        manualCheck: 'In a browser, confirm the loaded library version and compare it with the current supported release.',
        source: 'burp-endpoint',
      });
    }

    /* A07 — Identification and Auth Failures */
    if (AUTH_PATH_RE.test(path)) {
      add({
        owasp: 'A07',
        severity: 'medium',
        title: 'Authentication endpoint in traffic',
        possibleVulnerability: 'An authentication-related endpoint was captured and may be subject to weak login or session controls.',
        point: endpointPoint(item, 'authentication endpoint'),
        evidence: 'captured path matches a login/auth/register/reset pattern',
        manualCheck: 'In Burp Proxy, inspect the authentication request and confirm rate limiting, MFA and session rotation.',
        source: 'burp-endpoint',
      });
      if (method === 'GET' && bodyParams.some((n) => PASSWORD_PARAM_NAMES.has(n.toLowerCase()))) {
        add({
          owasp: 'A07',
          severity: 'high',
          title: 'Password-like body parameter on GET',
          possibleVulnerability: 'A GET request contains a password-like parameter name, which may place credentials in URLs or history.',
          point: endpointPoint(item, `body parameter "${bodyParams.find((n) => PASSWORD_PARAM_NAMES.has(n.toLowerCase()))}"`),
          evidence: 'method GET with a password-like body parameter name; value not retained',
          manualCheck: 'In Burp Proxy, confirm that credentials are not present in the request URL, logs or browser history.',
          source: 'burp-body',
        });
      }
    }

    /* A08 — no passive traffic metadata rule */

    /* A09 — no passive evidence for logging failures */

    /* A10 — SSRF */
    for (const [where, params] of [['query', queryParams], ['body', bodyParams]]) {
      for (const name of params) {
        if (!SSRF_PARAM_NAMES.has(name.toLowerCase())) continue;
        add({
          owasp: 'A10',
          severity: 'high',
          title: 'URL-like parameter in captured request',
          possibleVulnerability: 'A URL-like parameter may be fetched server-side (possible SSRF).',
          point: paramPoint(item, where, name),
          evidence: `${where} parameter name suggests a URL destination; value not retained`,
          manualCheck: 'In Burp Repeater, confirm whether the server fetches the destination and restrict it to an allowlist.',
          source: where === 'query' ? 'burp-query' : 'burp-body',
        });
      }
    }
    if (FETCH_PATH_RE.test(path) && allParams.some((name) => SSRF_PARAM_NAMES.has(name))) {
      add({
        owasp: 'A10',
        severity: 'high',
        title: 'Fetch/proxy endpoint with URL-like parameter',
        possibleVulnerability: 'A fetch/proxy endpoint accepts a URL-like parameter and may perform server-side requests.',
        point: endpointPoint(item, 'fetch/proxy endpoint'),
        evidence: 'captured fetch/proxy path with URL-like parameter name',
        manualCheck: 'In Burp Repeater, confirm whether the server makes a request to the supplied destination.',
        source: 'burp-endpoint',
      });
    }
  }

  return finalizeFindings(ctx, TRAFFIC_SCOPE_TEXT);
}

export default buildSiteFindings;
