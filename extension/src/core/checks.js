/**
 * checks.js — security posture checks and manual-test guidance.
 *
 * IMPORTANT: this module is deliberately passive.
 *  - Security headers are evaluated from headers the extension already
 *    captured from the current page's main document response.
 *  - Port and TLS guidance is a set of copyable commands for the operator to
 *    run themselves, never code that performs a scan. Lens does not open
 *    sockets, probe ports or negotiate TLS here.
 *
 * All guidance is restricted to the target you are authorized to test.
 */

const OWASP = Object.freeze({
  A02: Object.freeze({ id: 'A02', name: 'Cryptographic Failures' }),
  A05: Object.freeze({ id: 'A05', name: 'Security Misconfiguration' }),
});

const HEADER_RULES = Object.freeze([
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    severity: 'high',
    owasp: OWASP.A05,
    weak: /unsafe-inline|unsafe-eval|default-src\s+\*|script-src\s+\*/i,
    good: /default-src|script-src|object-src|base-uri/i,
    note: 'A restrictive CSP reduces XSS and data-injection impact.',
    fix: 'Use a nonce/hash-based CSP with explicit default-src, script-src, object-src \'none\' and base-uri \'self\'.',
  },
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security',
    severity: 'high',
    owasp: OWASP.A02,
    weak: /max-age\s*=\s*0|max-age\s*=\s*[1-9]\d{0,6}\b/i,
    good: /max-age\s*=\s*(\d{8,})/i,
    note: 'HSTS forces HTTPS and prevents SSL-strip/downgrade on repeat visits.',
    fix: 'Set max-age=31536000; includeSubDomains; preload (only when all subdomains support HTTPS).',
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'medium',
    owasp: OWASP.A05,
    weak: /allow-from/i,
    good: /^\s*(deny|sameorigin)\s*$/i,
    note: 'Blocks framing, reducing clickjacking risk. CSP frame-ancestors is the modern replacement.',
    fix: 'Set DENY or SAMEORIGIN, and/or CSP frame-ancestors \'none\' / \'self\'.',
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: 'medium',
    owasp: OWASP.A05,
    weak: null,
    good: /^\s*nosniff\s*$/i,
    note: 'Prevents browsers from MIME-sniffing responses into executable content.',
    fix: 'Set X-Content-Type-Options: nosniff on all responses.',
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'low',
    owasp: OWASP.A02,
    weak: /unsafe-url|no-referrer-when-downgrade/i,
    good: /no-referrer|strict-origin|same-origin|origin/i,
    note: 'Controls how much URL information leaks to third parties via Referer.',
    fix: 'Use strict-origin-when-cross-origin or no-referrer.',
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    severity: 'low',
    owasp: OWASP.A05,
    weak: /\*\)\s*=|=\s*\*/i,
    good: /-=|=\s*\(\s*\)/i,
    note: 'Restricts powerful browser features (camera, geolocation, microphone, etc.).',
    fix: 'Deny unused features explicitly, e.g. camera=(), geolocation=(), microphone=().',
  },
]);

const HEADER_GUIDANCE = Object.freeze({
  'content-security-policy': 'Check whether inline scripts or wildcards are actually required; prefer nonces/hashes over unsafe-inline.',
  'strict-transport-security': 'Confirm the max-age value and whether all subdomains can be covered before adding includeSubDomains/preload.',
  'x-frame-options': 'Try framing the page in a test page you control and confirm the browser blocks it.',
  'x-content-type-options': 'Upload/serve a file with a misleading content type and confirm the browser does not execute it.',
  'referrer-policy': 'Follow a link to a third-party site you control and inspect the Referer header.',
  'permissions-policy': 'Inspect document.featurePolicy / the Permissions-Policy header for features that should be disabled.',
});

function asString(value) {
  return typeof value === 'string' ? value : value == null ? '' : String(value);
}

/** Normalise observation.headers (array of {name,value}) into a lowercase map. */
function headerMap(observation) {
  const headers = observation?.headers;
  const map = new Map();
  if (!Array.isArray(headers)) return map;
  for (const header of headers) {
    const name = asString(header?.name).trim().toLowerCase();
    if (!name) continue;
    // First occurrence is enough; redacted placeholder values are still "present".
    if (!map.has(name)) map.set(name, asString(header?.value).trim());
  }
  return map;
}

function hstsIsWeak(value) {
  const match = value.match(/max-age\s*=\s*(\d+)/i);
  if (!match) return true;
  return Number(match[1]) < 31536000;
}

/**
 * Evaluate captured security headers. No requests are made here: headers come
 * from the PageObservation produced by the extension's webRequest listener.
 */
export function evaluateSecurityHeaders(observation = {}) {
  const present = headerMap(observation);
  const results = HEADER_RULES.map((rule) => {
    const value = present.get(rule.key);
    let status = 'missing';
    if (value) {
      const weakByPattern = rule.weak ? rule.weak.test(value) : false;
      const weakByValue = rule.key === 'strict-transport-security' ? hstsIsWeak(value) : false;
      status = weakByPattern || weakByValue || (rule.good && !rule.good.test(value)) ? 'weak' : 'ok';
    }
    return {
      name: rule.name,
      key: rule.key,
      status,
      severity: rule.severity,
      owasp: { ...rule.owasp },
      observed: value ? value.slice(0, 160) : '',
      note: rule.note,
      fix: rule.fix,
      manualCheck: HEADER_GUIDANCE[rule.key] || '',
    };
  });

  const summary = { ok: 0, weak: 0, missing: 0, total: results.length };
  for (const result of results) summary[result.status] += 1;
  return {
    available: present.size > 0,
    results,
    summary,
    source: 'Captured from the current page main-document response (allowlisted headers only).',
  };
}

/** Copyable commands for the operator. These are strings, never executed. */
const GUIDANCE_ITEMS = Object.freeze([
  {
    id: 'ports-top',
    area: 'ports',
    title: 'Common open ports on the in-scope host',
    tool: 'nmap',
    command: 'nmap -sT --top-ports 20 --open -T3 <target-host>',
    why: 'Finds services exposed beyond the web app (SSH, databases, admin panels) that widen the attack surface.',
    interpret: 'Compare each open port with the approved scope and expected service list. Unneeded services should be firewalled or disabled.',
    severity: 'medium',
    owasp: OWASP.A05,
  },
  {
    id: 'ports-web',
    area: 'ports',
    title: 'Targeted web/service ports',
    tool: 'nmap',
    command: 'nmap -sT -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443 --open <target-host>',
    why: 'Checks common management and data-store ports that often sit next to a web deployment.',
    interpret: 'A reachable DB, RDP or SSH port on a public host is a finding worth reporting if it is outside the agreed scope of exposure.',
    severity: 'medium',
    owasp: OWASP.A05,
  },
  {
    id: 'tls-ciphers',
    area: 'tls',
    title: 'TLS versions and cipher suite strength',
    tool: 'testssl.sh',
    command: 'testssl.sh --fast <target-host>:443',
    why: 'Detects deprecated protocols (SSLv3, TLS 1.0/1.1) and weak ciphers (RC4, 3DES, NULL, EXPORT, MD5).',
    interpret: 'Flag any protocol below TLS 1.2 (prefer TLS 1.3), export/anonymous/NULL ciphers, and CBC suites still offered to modern clients.',
    severity: 'high',
    owasp: OWASP.A02,
  },
  {
    id: 'tls-enum',
    area: 'tls',
    title: 'Cipher enumeration with Nmap',
    tool: 'nmap',
    command: 'nmap --script ssl-enum-ciphers -p 443 <target-host>',
    why: 'A quick second opinion on negotiated protocols and cipher grades when testssl.sh is not installed.',
    interpret: 'Look for grade C or below, TLS 1.0/1.1, 3DES, RC4 and small key sizes. Confirm results against the server configuration.',
    severity: 'medium',
    owasp: OWASP.A02,
  },
  {
    id: 'tls-protocol',
    area: 'tls',
    title: 'Manual protocol handshake check',
    tool: 'openssl',
    command: 'openssl s_client -connect <target-host>:443 -tls1_2 </dev/null',
    why: 'Confirms individually whether a specific TLS version can still complete a handshake.',
    interpret: 'A successful handshake with -tls1 or -tls1_1 means an obsolete protocol is enabled. Only test hosts you are authorized to assess.',
    severity: 'low',
    owasp: OWASP.A02,
  },
]);

/**
 * Build the full passive checks payload for a PageObservation.
 * The guidance commands are intentionally inert strings for the user to copy.
 */
export function buildSecurityChecks(observation = {}) {
  let host = '';
  try {
    // hostname (not host) so TLS commands don't produce "host:8443:443".
    host = new URL(observation.url || '').hostname || '';
  } catch {
    host = asString(observation.host || '').replace(/:\d+$/, '');
  }
  const guidance = GUIDANCE_ITEMS.map((item) => ({
    ...item,
    owasp: { ...item.owasp },
    command: item.command.replace('<target-host>', host || '<target-host>'),
  }));

  return {
    headers: evaluateSecurityHeaders(observation),
    guidance,
    targetHost: host,
    scope: 'Guidance only. Lens does not run these commands, open ports or negotiate TLS. Replace <target-host> only with a host you are authorized to test.',
  };
}

export const SECURITY_HEADER_KEYS = Object.freeze(HEADER_RULES.map((rule) => rule.key));
