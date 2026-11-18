/**
 * scanner.js — pure, read-only DOM/page observation builder.
 *
 * Safety contract (see SPEC.md):
 *  - never read or emit form field *values*, cookie values, header values
 *    (except allowlisted + redacted ones), localStorage/sessionStorage, or
 *    token-looking strings;
 *  - only names, types, lengths, flags and short redacted evidence snippets.
 */

const MAX_EVIDENCE = 160;

/** Header names the background is allowed to capture. */
const HEADER_ALLOWLIST = new Set([
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

/** Words that make a captured value unsafe to show. */
const SENSITIVE_WORD_RE = /(token|key|secret|auth|session|bearer|password|passwd|jwt)/i;

const SUSPICIOUS_LINK_RE =
  /(\.bak|\.old|\.zip|\.tar|\.gz|\.7z|\.map|\.json|\.pdf|admin|debug|phpmyadmin|\.git|backup|config|\.env|\/api\/|graphql)/i;

const TEXT_INPUT_TYPES = new Set([
  'text', 'search', 'email', 'password', 'tel', 'url', 'number',
  'textarea', 'select', '',
]);

const SINK_PATTERNS = [
  { type: 'innerHTML', re: /\.innerHTML\s*=/gi },
  { type: 'outerHTML', re: /\.outerHTML\s*=/gi },
  { type: 'document.write', re: /document\.write\s*\(/gi },
  { type: 'eval', re: /\beval\s*\(/gi },
  { type: 'Function(', re: /\b(?:new\s+)?Function\s*\(/gi },
  { type: 'location.hash', re: /location\.hash/gi },
  { type: 'postMessage', re: /\.postMessage\s*\(/gi },
  { type: 'dangerouslySetInnerHTML', re: /dangerouslySetInnerHTML/gi },
  { type: 'v-html', re: /v-html/gi },
];

const TECH_HINTS = [
  { re: /jquery/i, name: 'jQuery' },
  { re: /react/i, name: 'React' },
  { re: /vue/i, name: 'Vue' },
  { re: /angular/i, name: 'Angular' },
  { re: /_next\//i, name: 'Next.js' },
  { re: /bootstrap/i, name: 'Bootstrap' },
  { re: /tailwind/i, name: 'Tailwind CSS' },
];

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

function truncate(text, max = MAX_EVIDENCE) {
  const value = text == null ? '' : String(text);
  return value.length > max ? `${value.slice(0, Math.max(0, max - 3))}...` : value;
}

/**
 * Redact secret-looking fragments and clamp length. Exported so other core
 * modules (and tests) can reuse the exact same behaviour.
 */
export function redactText(text) {
  let value = text == null ? '' : String(text);
  value = value.replace(/(bearer\s+)[a-z0-9._~+/=-]+/gi, '$1[REDACTED]');
  value = value.replace(
    /((?:token|secret|key|jwt|password|passwd)\s*[=:]\s*["']?)[^"'\s,;&}]+/gi,
    '$1[REDACTED]',
  );
  value = value.replace(
    /([?&](?:token|key|secret|jwt|auth)=)[^&\s#"']+/gi,
    '$1[REDACTED]',
  );
  return truncate(value);
}

/** Header values are either wholly safe or wholly redacted. */
function safeHeaderValue(value) {
  const text = value == null ? '' : String(value);
  if (SENSITIVE_WORD_RE.test(text)) return '[REDACTED]';
  return truncate(text);
}

function toArray(value) {
  if (value == null) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') return [value];
  try {
    return [...value];
  } catch {
    try {
      return Array.from(value);
    } catch {
      return [];
    }
  }
}

function attr(el, name) {
  try {
    const viaGetter = el?.getAttribute?.(name);
    if (viaGetter != null) return String(viaGetter);
  } catch {
    /* ignore */
  }
  const direct = el?.[name];
  if (typeof direct === 'boolean') return direct ? name : '';
  return direct == null ? '' : String(direct);
}

function textOf(node) {
  const text = node?.textContent ?? node?.innerText ?? node?.nodeValue ?? '';
  return text == null ? '' : String(text);
}

function tagOf(node) {
  return String(node?.tagName ?? node?.nodeName ?? '').toLowerCase();
}

function parseUrl(href) {
  try {
    return new URL(String(href || ''));
  } catch {
    return null;
  }
}

function dedupeBy(items, keyFn) {
  const seen = new Set();
  const out = [];
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* CSS / XPath location helpers                                        */
/*                                                                     */
/* These walk a real DOM when a parent chain is available and fall     */
/* back to deterministic, attribute-derived placeholders for the       */
/* lightweight fake DOM objects used in tests (and other DOM-like      */
/* inputs).  They only ever look at tags / ids / names — never values.  */
/* ------------------------------------------------------------------ */

function escapeCssId(value) {
  const id = String(value ?? '');
  if (typeof globalThis.CSS !== 'undefined' && typeof globalThis.CSS.escape === 'function') {
    return globalThis.CSS.escape(id);
  }
  return id.replace(/([^\w-])/g, '\\$1');
}

function childrenOf(node) {
  if (!node) return [];
  if (Array.isArray(node.children)) return node.children;
  if (node.childNodes != null) return toArray(node.childNodes);
  return [];
}

/** Locate an element inside a (possibly fake) document for placeholder paths. */
function locate(el, doc, tag) {
  const forms = toArray(doc?.forms ?? doc?.querySelectorAll?.('form'));
  if (tag === 'form') {
    const index = forms.indexOf(el);
    return { formIndex: 0, index: index >= 0 ? index + 1 : 1 };
  }

  for (let fi = 0; fi < forms.length; fi += 1) {
    const form = forms[fi];
    const candidates = toArray(form?.elements);
    if (typeof form?.querySelectorAll === 'function') {
      for (const extra of toArray(form.querySelectorAll('input, textarea, select'))) {
        if (!candidates.includes(extra)) candidates.push(extra);
      }
    }
    let counter = 0;
    for (const candidate of candidates) {
      if (tagOf(candidate) !== tag) continue;
      counter += 1;
      if (candidate === el) return { formIndex: fi + 1, index: counter };
    }
  }

  if (typeof doc?.querySelectorAll === 'function') {
    const index = toArray(doc.querySelectorAll(tag)).indexOf(el);
    if (index >= 0) return { formIndex: 0, index: index + 1 };
  }
  return { formIndex: 0, index: 1 };
}

/** Stable CSS selector for an element (safe on fake DOM objects). */
export function cssPath(el, doc) {
  if (!el) return '';
  const tag = tagOf(el);
  if (!tag) return '';

  const parent = el.parentElement ?? el.parentNode;
  const hasTree =
    el.nodeType === 1 && parent && typeof parent === 'object' && Boolean(tagOf(parent));

  if (hasTree) {
    const segments = [];
    let node = el;
    while (node && node.nodeType === 1 && tagOf(node)) {
      const nodeTag = tagOf(node);
      const id = attr(node, 'id');
      if (id) {
        segments.unshift(`${nodeTag}#${escapeCssId(id)}`);
      } else {
        let segment = nodeTag;
        const p = node.parentElement ?? node.parentNode;
        if (p && typeof p === 'object' && tagOf(p)) {
          const sameTag = childrenOf(p).filter((candidate) => tagOf(candidate) === nodeTag);
          if (sameTag.length > 1) {
            segment += `:nth-of-type(${sameTag.indexOf(node) + 1})`;
          }
        }
        segments.unshift(segment);
      }
      const p = node.parentElement ?? node.parentNode;
      if (!p || typeof p !== 'object' || !tagOf(p)) break;
      node = p;
    }
    return segments.join(' > ');
  }

  // Graceful placeholder for fake / method-less DOM objects.
  const id = attr(el, 'id');
  if (id) return `${tag}#${escapeCssId(id)}`;
  const name = attr(el, 'name');
  if (name) return `${tag}[name="${String(name).replace(/["\\]/g, '\\$&')}"]`;
  const { formIndex, index } = locate(el, doc, tag);
  const prefix = formIndex ? `form:nth-of-type(${formIndex}) > ` : '';
  return `${prefix}${tag}:nth-of-type(${index})`;
}

/** Absolute XPath for an element (safe on fake DOM objects). */
export function xpathFor(el, doc) {
  if (!el) return '';
  const tag = tagOf(el);
  if (!tag) return '';

  const parent = el.parentElement ?? el.parentNode;
  const hasTree =
    el.nodeType === 1 && parent && typeof parent === 'object' && Boolean(tagOf(parent));

  if (hasTree) {
    const segments = [];
    let node = el;
    while (node && node.nodeType === 1 && tagOf(node)) {
      const nodeTag = tagOf(node);
      const p = node.parentElement ?? node.parentNode;
      let index = 1;
      if (p && typeof p === 'object' && tagOf(p)) {
        const sameTag = childrenOf(p).filter((candidate) => tagOf(candidate) === nodeTag);
        index = Math.max(1, sameTag.indexOf(node) + 1);
      }
      segments.unshift(
        nodeTag === 'html' || nodeTag === 'body' ? nodeTag : `${nodeTag}[${index}]`,
      );
      if (!p || typeof p !== 'object' || !tagOf(p)) break;
      node = p;
    }
    return `/${segments.join('/')}`;
  }

  // Graceful placeholder for fake / method-less DOM objects.
  const { formIndex, index } = locate(el, doc, tag);
  const base = formIndex ? `/html/body/form[${formIndex}]` : '/html/body';
  return `${base}/${tag}[${index}]`;
}

/* ------------------------------------------------------------------ */
/* main entry                                                          */
/* ------------------------------------------------------------------ */

/**
 * Build a PageObservation from a DOM-like object.
 * @param {{href?:string,title?:string,doc?:object,cookies?:Array,headers?:Array}} input
 */
export function observePage({ href, title, doc, cookies = [], headers = [] } = {}) {
  const url = parseUrl(href ?? doc?.URL ?? doc?.location?.href);
  const origin = url?.origin ?? '';
  const rawCookies = toArray(cookies);
  const rawHeaders = toArray(headers);

  // "page" is the location with any query string / fragment removed.  It is
  // used to attribute every observed location back to a stable page.
  const page = url ? `${url.origin}${url.pathname}` : truncate(String(href ?? ''));

  /* ---------- URL + query params (names / lengths only) ---------- */
  const queryParams = [];
  if (url) {
    for (const [name, value] of url.searchParams.entries()) {
      queryParams.push({
        name: truncate(name),
        valueLength: typeof value === 'string' ? value.length : 0,
        location: 'query',
        page: truncate(page),
      });
    }
  }

  /* ---------- forms + fields (no values) ---------- */
  const formNodes = toArray(doc?.forms ?? doc?.querySelectorAll?.('form'));
  const forms = [];
  const allFields = [];
  const fieldEntries = []; // { node, formSelector } — used for the flat inputs[]

  for (let formIndex = 0; formIndex < formNodes.length; formIndex += 1) {
    const form = formNodes[formIndex];
    let fieldNodes = toArray(form?.elements);
    if (!fieldNodes.length && typeof form?.querySelectorAll === 'function') {
      fieldNodes = toArray(form.querySelectorAll('input, textarea, select'));
    }

    const formSelector = cssPath(form, doc);
    const formXpath = xpathFor(form, doc);

    const fields = fieldNodes.map((field) => {
      const tag = tagOf(field);
      let type = attr(field, 'type');
      if (tag === 'textarea') type = 'textarea';
      if (tag === 'select') type = 'select';
      if (!type) type = 'text';

      const maxLengthRaw = attr(field, 'maxLength') || attr(field, 'maxlength');
      const maxLength = Number.parseInt(maxLengthRaw, 10);

      return {
        name: truncate(attr(field, 'name')),
        type: truncate(type),
        id: truncate(attr(field, 'id')),
        placeholder: redactText(attr(field, 'placeholder')),
        required: Boolean(field?.required) || attr(field, 'required') !== '',
        maxLength: Number.isFinite(maxLength) ? maxLength : 0,
        selector: cssPath(field, doc),
        xpath: xpathFor(field, doc),
      };
    }).filter((field) => field.name || field.type || field.id);

    for (const field of fieldNodes) {
      fieldEntries.push({ node: field, formSelector });
    }
    allFields.push(...fields);

    forms.push({
      action: redactText(attr(form, 'action')),
      method: (attr(form, 'method') || 'get').toLowerCase(),
      enctype: truncate(attr(form, 'enctype')),
      hasFileInput: fields.some((f) => f.type.toLowerCase() === 'file'),
      selector: formSelector,
      xpath: formXpath,
      index: formIndex,
      fields,
    });
  }

  // Include fields that live outside of any <form> as well.
  if (typeof doc?.querySelectorAll === 'function') {
    for (const node of toArray(doc.querySelectorAll('input, textarea, select'))) {
      if (fieldEntries.some((entry) => entry.node === node)) continue;
      fieldEntries.push({ node, formSelector: '' });
    }
  }

  /* ---------- flat inputs inventory (names / types only) ---------- */
  const inputs = fieldEntries.map(({ node, formSelector }) => {
    const tag = tagOf(node);
    let type = attr(node, 'type');
    if (tag === 'textarea') type = 'textarea';
    if (tag === 'select') type = 'select';
    if (!type) type = 'text';

    return {
      page: truncate(page),
      name: truncate(attr(node, 'name')),
      type: truncate(type),
      id: truncate(attr(node, 'id')),
      selector: truncate(cssPath(node, doc), 200),
      xpath: truncate(xpathFor(node, doc), 200),
      formSelector: truncate(formSelector, 200),
    };
  });

  /* ---------- links ---------- */
  const linkNodes = toArray(doc?.links ?? doc?.querySelectorAll?.('a[href]'));
  const links = linkNodes.map((link) => {
    const hrefValue = attr(link, 'href');
    let kind = 'internal';
    if (SUSPICIOUS_LINK_RE.test(hrefValue)) {
      kind = 'suspicious';
    } else {
      const target = parseUrl(hrefValue);
      if (target?.origin && origin && target.origin !== origin) kind = 'external';
      else if (/^[a-z][a-z0-9+.-]*:/i.test(hrefValue) && !hrefValue.startsWith('/')) kind = 'external';
    }
    return { href: redactText(hrefValue), kind };
  });

  /* ---------- scripts + inline text ---------- */
  const scriptNodes = toArray(doc?.scripts ?? doc?.querySelectorAll?.('script'));
  const scripts = [];
  const inlineChunks = [];

  for (const script of scriptNodes) {
    const src = attr(script, 'src');
    const inlineText = src ? '' : textOf(script);
    if (inlineText.trim()) inlineChunks.push(inlineText);
    scripts.push({
      src: redactText(src),
      inlineLength: inlineText.length,
    });
  }
  const inlineText = inlineChunks.join('\n');
  const inlineProbe = inlineText.toLowerCase();

  /* ---------- endpoints ---------- */
  const endpointCandidates = [];
  for (const link of links) {
    endpointCandidates.push({ url: link.href, source: 'link' });
  }
  for (const script of scripts) {
    if (script.src) endpointCandidates.push({ url: script.src, source: 'script' });
  }

  const quotedRe = /['"`]([^'"`\n]{2,160})['"`]/g;
  let quotedMatch;
  while ((quotedMatch = quotedRe.exec(inlineText)) !== null) {
    const candidate = quotedMatch[1];
    if (/(\/api\/|\/graphql|^\/|^https?:\/\/|\.json)/i.test(candidate)) {
      endpointCandidates.push({ url: candidate, source: 'inline' });
    }
  }
  const pathRe = /(\/api\/[\w./-]+|\/graphql[\w./-]*)/gi;
  let pathMatch;
  while ((pathMatch = pathRe.exec(inlineText)) !== null) {
    endpointCandidates.push({ url: pathMatch[1], source: 'inline' });
  }

  const endpoints = dedupeBy(endpointCandidates, (item) => `${item.source}|${item.url}`)
    .map((item) => ({ url: redactText(item.url), source: item.source }))
    .filter((item) => item.url);

  /* ---------- meta tags (technology evidence) ---------- */
  let metaNodes = toArray(doc?.getElementsByTagName?.('meta'));
  if (!metaNodes.length && typeof doc?.querySelectorAll === 'function') {
    metaNodes = toArray(doc.querySelectorAll('meta'));
  }

  /* ---------- technologies ---------- */
  const techList = [];
  const addTech = (name, evidence) => {
    if (!name) return;
    techList.push({ name: truncate(name, 80), evidence: redactText(evidence) });
  };

  const view = doc?.defaultView ?? globalThis;
  if (view?.jQuery || view?.$) addTech('jQuery', 'window.jQuery');
  if (view?.React) addTech('React', 'window.React');
  if (view?.Vue) addTech('Vue', 'window.Vue');
  if (view?.angular || view?.ng) addTech('Angular', 'window.angular');
  if (view?.__NEXT_DATA__ || view?.next) addTech('Next.js', 'window.__NEXT_DATA__');

  for (const meta of metaNodes) {
    if (String(attr(meta, 'name')).toLowerCase() === 'generator') {
      addTech(truncate(attr(meta, 'content'), 60), 'meta generator');
    }
  }
  for (const script of scripts) {
    for (const hint of TECH_HINTS) {
      if (hint.re.test(script.src)) addTech(hint.name, `script: ${script.src}`);
    }
  }
  const technologies = dedupeBy(techList, (tech) => tech.name.toLowerCase());

  /* ---------- DOM sinks (regex only, redacted evidence) ---------- */
  const domSinkList = [];
  const sinkSeen = new Set();
  for (const { type, re } of SINK_PATTERNS) {
    re.lastIndex = 0;
    let match;
    while ((match = re.exec(inlineText)) !== null) {
      if (sinkSeen.has(type)) break;
      sinkSeen.add(type);
      const start = Math.max(0, match.index - 40);
      const snippet = inlineText.slice(start, match.index + match[0].length + 40);
      domSinkList.push({ type, evidence: redactText(snippet) });
      break;
    }
  }
  const domSinks = domSinkList;

  /* ---------- cookies + headers ---------- */
  const cookieNames = [];
  const cookiesOut = rawCookies.map((cookie) => {
    const name = truncate(cookie?.name);
    cookieNames.push(name.toLowerCase());
    const rawValue = cookie?.value;
    return {
      name,
      httpOnly: Boolean(cookie?.httpOnly),
      secure: Boolean(cookie?.secure),
      sameSite: truncate(cookie?.sameSite),
      valueLength: typeof rawValue === 'string' ? rawValue.length : 0,
    };
  });

  const headerNames = [];
  const headersOut = [];
  for (const header of rawHeaders) {
    const name = String(header?.name ?? '').toLowerCase();
    headerNames.push(name);
    if (!HEADER_ALLOWLIST.has(name)) continue;
    headersOut.push({ name, value: safeHeaderValue(header?.value) });
  }

  /* ---------- signals ---------- */
  const fieldNames = allFields.map((f) => f.name.toLowerCase());
  const fieldTypes = allFields.map((f) => f.type.toLowerCase());
  const actionText = forms.map((f) => f.action).join(' ').toLowerCase();
  const paramNames = queryParams.map((p) => p.name.toLowerCase());
  const endpointText = endpoints.map((e) => e.url).join(' ').toLowerCase();
  const techText = technologies.map((t) => t.name).join(' ').toLowerCase();
  const searchableText = `${inlineProbe} ${endpointText}`;
  const allNamesText = `${cookieNames.join(' ')} ${headerNames.join(' ')}`;

  const hasFileInput = fieldTypes.includes('file');
  const hasSessionPattern = /(session|sid|auth|jwt|token)/i;

  const signals = {
    hasForm: forms.length > 0,
    hasTextInput: allFields.some((f) => TEXT_INPUT_TYPES.has(f.type.toLowerCase())),
    hasFileInput,
    hasLogin:
      fieldTypes.includes('password') ||
      fieldNames.some((n) => /(login|signin|sign-in|logon|auth|pass|pwd|username|user|email)/.test(n)) ||
      /(login|signin|sign-in|logon)/.test(actionText),
    hasSearch:
      fieldTypes.includes('search') ||
      fieldNames.some((n) => /(search|query|keyword|^q$)/.test(n)),
    hasUpload:
      hasFileInput ||
      /upload/.test(actionText) ||
      forms.some((f) => /multipart/.test(f.enctype.toLowerCase())),
    hasGraphql: /graphql/.test(searchableText),
    hasApiBase: /\/api\/|\bapi\b/.test(searchableText),
    hasRedirectParam: paramNames.some((n) => /(redirect|return|next|dest|goto|continue)/.test(n)),
    hasDebugParam: paramNames.some((n) => /(debug|test|dev|trace|verbose|admin)/.test(n)),
    hasIdParam: paramNames.some((n) => /(^id$|(^|_)id($|_)|uid|user|file|doc|record|account|uuid|guid)/.test(n)),
    hasUrlParam: paramNames.some((n) => /(url|uri|link|href|path|target|src|redirect)/.test(n)),
    hasJsonBodyHint:
      /application\/json/.test(searchableText) ||
      headersOut.some((h) => /application\/json/.test(h.value.toLowerCase())),
    hasJwt:
      /jwt/i.test(allNamesText) ||
      /jwt|bearer\s/.test(inlineProbe),
    hasSessionCookie: hasSessionPattern.test(allNamesText),
    hasCsp: headersOut.some((h) => h.name === 'content-security-policy'),
    hasMissingSecurityHeaders: [
      'content-security-policy',
      'strict-transport-security',
      'x-frame-options',
      'x-content-type-options',
    ].some((name) => !headerNames.includes(name)),
    hasInlineScript: inlineChunks.length > 0,
    hasDomSink: domSinks.length > 0,
    hasCsrfTokenField: fieldNames.some((n) => /(csrf|_token|nonce)/.test(n)),
  };

  return {
    capturedAt: new Date().toISOString(),
    url: redactText(url?.href ?? href ?? ''),
    origin: redactText(origin),
    host: redactText(url?.host ?? ''),
    path: redactText(url?.pathname ?? ''),
    title: redactText(title ?? doc?.title ?? ''),
    queryParams,
    technologies,
    headers: headersOut,
    cookies: cookiesOut,
    forms,
    inputs,
    links,
    scripts,
    endpoints,
    domSinks,
    signals,
    counts: {
      forms: forms.length,
      inputs: inputs.length,
      links: links.length,
      scripts: scripts.length,
      endpoints: endpoints.length,
    },
  };
}

export default observePage;
