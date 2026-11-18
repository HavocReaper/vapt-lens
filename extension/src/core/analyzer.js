/**
 * analyzer.js — offline, data-driven mapping of a PageObservation (+ optional
 * Burp traffic metadata) into guidance-only "cards".
 *
 * Cards never send requests. They only describe manual steps, safe copyable
 * strings, how to verify, and a defence reminder.
 */

const SCOPE_REMINDER =
  'Scope reminder: guidance only, no attacks are performed — confirm you are authorized and test only systems you own.';

const BOOSTED_CATEGORIES = new Set(['api', 'xss', 'sqli', 'idor']);

const SEVERITY_BY_CATEGORY = [
  [/sqli|rce|command|deserial|auth|ssrf|upload/i, 'high'],
  [/xss|idor|graphql|api|business|csrf|redirect|authz/i, 'medium'],
  [/info|header|csp|tls|config|recon|misc|tech/i, 'low'],
];

const GENERIC_STEPS = [
  'Map the relevant request in Burp Proxy and note the parameter names only.',
  'Replay the request in Repeater with a harmless probe value.',
  'Compare the modified response with the baseline and note any reflected input, error text or behaviour change.',
];

const VERIFY_BY_CATEGORY = {
  sqli: 'Confirm by comparing error output or timing between the baseline and the modified request; note any database error text.',
  xss: 'Check whether the probe appears unescaped in the HTML source and whether the browser renders it as markup.',
  idor: 'Check whether changing the identifier returns data for a different object; compare responses without viewing another user’s private data.',
  api: 'Check whether the endpoint accepts the request without the expected authorization and note the response shape.',
  graphql: 'Check whether introspection or verbose errors are exposed and note the schema surface.',
  redirect: 'Check the final Location header and confirm whether an off-origin destination is accepted.',
};

const GENERIC_VERIFY =
  'Compare the modified response with the baseline and note any reflected input, error, or behavioural difference.';

const GENERIC_DEFENSE =
  'Validate and canonicalise input server-side, enforce least-privilege authorization on every request, and keep frameworks patched.';

/* ------------------------------------------------------------------ */
/* OWASP Top 10 (2021) mapping                                         */
/*                                                                     */
/* Keyword lists mirror SPEC2 section 3.  When a skill/category would   */
/* fit more than one category, the first matching entry wins so the     */
/* mapping stays deterministic.                                        */
/* ------------------------------------------------------------------ */

export const OWASP_CATEGORIES = Object.freeze([
  Object.freeze({ id: 'A01', name: 'Broken Access Control', keywords: ['idor', 'auth', 'business-logic', 'csrf', 'jwt', 'oauth'] }),
  Object.freeze({ id: 'A02', name: 'Cryptographic Failures', keywords: ['crypto', 'tls', 'jwt', 'session', 'headers'] }),
  Object.freeze({ id: 'A03', name: 'Injection', keywords: ['sqli', 'xss', 'ssti', 'command', 'xxe', 'deserialization'] }),
  Object.freeze({ id: 'A04', name: 'Insecure Design', keywords: ['business-logic', 'race-condition', 'workflow'] }),
  Object.freeze({ id: 'A05', name: 'Security Misconfiguration', keywords: ['headers', 'debug', 'config', 'cloud', 'container', 'default'] }),
  Object.freeze({ id: 'A06', name: 'Vulnerable Components', keywords: ['dependency', 'supply-chain', 'cve', 'c2', 'framework'] }),
  Object.freeze({ id: 'A07', name: 'Auth Failures', keywords: ['auth', 'login', 'jwt', 'oauth', 'session', 'brute'] }),
  Object.freeze({ id: 'A08', name: 'Software/Data Integrity', keywords: ['deserialization', 'supply-chain', 'ci', 'webhook', 'jwt'] }),
  Object.freeze({ id: 'A09', name: 'Logging & Monitoring Failures', keywords: ['logging', 'recon', 'exfil', 'persistence'] }),
  Object.freeze({ id: 'A10', name: 'SSRF', keywords: ['ssrf', 'url-param', 'redirect', 'fetch', 'webhook'] }),
]);

const DEFAULT_OWASP = Object.freeze({ id: 'A04', name: 'Insecure Design' });

function matchesKeyword(text, keyword) {
  const escaped = String(keyword).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/-/g, '[-_]?');
  try {
    return new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, 'i').test(text);
  } catch {
    return false;
  }
}

/** Map a card category (and optional skill id) to an OWASP 2021 category. */
export function mapOwasp(category, skillId) {
  const text = `${String(category ?? '')} ${String(skillId ?? '')}`.toLowerCase();
  if (!text.trim()) return { ...DEFAULT_OWASP };
  for (const entry of OWASP_CATEGORIES) {
    for (const keyword of entry.keywords) {
      if (matchesKeyword(text, keyword)) return { id: entry.id, name: entry.name };
    }
  }
  return { ...DEFAULT_OWASP };
}

/** Count cards per OWASP category, always returning all ten entries. */
export function owaspSummary(cards = []) {
  const counts = new Map(OWASP_CATEGORIES.map((entry) => [entry.id, 0]));
  for (const card of Array.isArray(cards) ? cards : []) {
    const id = card?.owasp?.id;
    if (counts.has(id)) counts.set(id, counts.get(id) + 1);
  }
  return OWASP_CATEGORIES.map((entry) => ({
    id: entry.id,
    name: entry.name,
    cardCount: counts.get(entry.id),
  }));
}

/* ------------------------------------------------------------------ */
/* tiny utilities                                                      */
/* ------------------------------------------------------------------ */

function slug(value) {
  return String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function cleanText(text) {
  return String(text ?? '')
    .replace(/^\s*(?:[-*+]|\d+[.)])\s*/, '')
    .replace(/```[a-z0-9]*\s*/gi, '')
    .replace(/[`*_]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Turn a knowledge-base bullet into a manual, imperative-looking step. */
function asInstruction(bullet) {
  const text = cleanText(bullet);
  if (!text) return '';
  if (/^(use|test|try|check|verify|send|observe|compare|map|note|submit|replay|inspect|record|identify|change|look)\b/i.test(text)) {
    return text;
  }
  return `Check ${text.charAt(0).toLowerCase()}${text.slice(1)}`;
}

function isDefensive(text) {
  return /(defen[cs]|mitigat|remediat|\bfix\b|prevent|protect|sanitis|sanitiz|validat|harden|secure)/i.test(
    String(text ?? ''),
  );
}

/* ------------------------------------------------------------------ */
/* condition engine                                                    */
/* ------------------------------------------------------------------ */

/** Resolve a dotted path into a flat list of values; `[]` scans arrays. */
function resolvePath(obj, expr) {
  let current = [obj];
  const segments = String(expr).split('.');

  for (const rawSegment of segments) {
    const scanArray = rawSegment.endsWith('[]');
    const key = scanArray ? rawSegment.slice(0, -2) : rawSegment;
    const next = [];

    for (const node of current) {
      if (node == null) continue;
      let value;
      if (key === '') {
        value = node;
      } else if (Array.isArray(node)) {
        value = node.map((item) => item?.[key]).filter((v) => v != null);
      } else {
        value = node[key];
      }
      if (value == null) continue;

      if (scanArray) {
        const items = Array.isArray(value) ? value : [value];
        next.push(...items);
      } else if (Array.isArray(value)) {
        next.push(...value);
      } else {
        next.push(value);
      }
    }
    current = next;
  }
  return current;
}

function parseCondition(condition) {
  const raw = String(condition ?? '').trim();
  const tilde = raw.indexOf('~');
  if (tilde >= 0) {
    return {
      expr: raw.slice(0, tilde).trim(),
      matcher: { kind: 'regex', value: raw.slice(tilde + 1) },
    };
  }
  const equals = raw.indexOf('=');
  if (equals >= 0) {
    return {
      expr: raw.slice(0, equals).trim(),
      matcher: { kind: 'equals', value: raw.slice(equals + 1) },
    };
  }
  return { expr: raw, matcher: null };
}

function normaliseExpr(observation, expr) {
  if (expr.includes('.') || expr.includes('[]')) return expr;
  const signals = observation?.signals ?? {};
  if (Object.prototype.hasOwnProperty.call(signals, expr)) return `signals.${expr}`;
  if (Object.prototype.hasOwnProperty.call(observation ?? {}, expr)) return expr;
  return expr;
}

function conditionTruthy(condition, observation) {
  const { expr, matcher } = parseCondition(condition);
  if (!expr) return false;
  const values = resolvePath(observation, normaliseExpr(observation, expr));
  if (!values.length) return false;

  if (!matcher) return values.some((value) => Boolean(value));
  if (matcher.kind === 'equals') {
    return values.some((value) => String(value) === matcher.value);
  }
  try {
    const regex = new RegExp(matcher.value, 'i');
    return values.some((value) => regex.test(String(value)));
  } catch {
    return false;
  }
}

function ruleMatches(rule, observation) {
  const any = Array.isArray(rule?.when?.any) ? rule.when.any : [];
  const all = Array.isArray(rule?.when?.all) ? rule.when.all : [];
  if (!any.length && !all.length) return false;
  if (all.length && !all.every((c) => conditionTruthy(c, observation))) return false;
  if (any.length && !any.some((c) => conditionTruthy(c, observation))) return false;
  return true;
}

function friendlyCondition(condition) {
  const { expr } = parseCondition(condition);
  const last = expr.split('.').pop().replace(/\[\]$/, '');
  const labels = {
    hasForm: 'a form is present',
    hasTextInput: 'text inputs are present',
    hasFileInput: 'a file input is present',
    hasLogin: 'a login surface is present',
    hasSearch: 'a search surface is present',
    hasUpload: 'an upload surface is present',
    hasGraphql: 'GraphQL is hinted',
    hasApiBase: 'an API base is hinted',
    hasRedirectParam: 'a redirect-style parameter is present',
    hasDebugParam: 'a debug-style parameter is present',
    hasIdParam: 'an id-style parameter is present',
    hasUrlParam: 'a URL-style parameter is present',
    hasJsonBodyHint: 'JSON request hints are present',
    hasJwt: 'JWT/bearer hints are present',
    hasSessionCookie: 'session-style cookies are present',
    hasCsp: 'a CSP is present',
    hasMissingSecurityHeaders: 'security headers appear to be missing',
    hasInlineScript: 'inline script is present',
    hasDomSink: 'DOM sinks are present',
    hasCsrfTokenField: 'a CSRF-style field is present',
    name: 'a matching name is present',
  };
  return labels[last] || String(expr).replace(/\[\]/g, '');
}

/* ------------------------------------------------------------------ */
/* card content helpers                                                */
/* ------------------------------------------------------------------ */

function severityFor(category) {
  for (const [re, severity] of SEVERITY_BY_CATEGORY) {
    if (re.test(String(category ?? ''))) return severity;
  }
  return 'medium';
}

function collectBullets(skill) {
  const bullets = [];
  for (const section of skill?.sections ?? []) {
    if (isDefensive(section?.heading)) continue;
    for (const bullet of section?.bullets ?? []) {
      const text = cleanText(bullet);
      if (!text) continue;
      bullets.push(asInstruction(text));
    }
  }
  return bullets;
}

function buildSteps(skill, category) {
  const steps = [];
  for (const bullet of collectBullets(skill)) {
    if (steps.length >= 6) break;
    if (!steps.includes(bullet)) steps.push(bullet);
  }
  if (steps.length < 3) {
    for (const step of GENERIC_STEPS) {
      if (steps.length >= 3) break;
      if (!steps.includes(step)) steps.push(step);
    }
  }
  if (!steps.length) steps.push(...GENERIC_STEPS);
  return steps.slice(0, 6);
}

function buildPayloads(skill) {
  const blocks = [];
  for (const section of skill?.sections ?? []) {
    if (isDefensive(section?.heading)) continue;
    for (const block of section?.codeBlocks ?? []) {
      const raw = String(block ?? '');
      if (!raw.trim()) continue;
      if (/mermaid|sequenceDiagram|graph\s+(TD|LR|TB)/i.test(raw)) continue;
      if (raw.length > 200) continue;
      if (/^(curl|wget|nc|ncat|bash|sh|powershell)\b/im.test(raw)) continue;
      if (/\b(fetch|axios|XMLHttpRequest|requests\.|subprocess|os\.system)\s*\(/i.test(raw)) continue;
      const firstLine = cleanText(raw.split('\n').find((line) => line.trim()) ?? '');
      if (!firstLine || firstLine.length > 160) continue;
      blocks.push(firstLine);
    }
  }
  return dedupeStrings(blocks).slice(0, 3).map((value, index) => ({
    label: `Safe test string ${index + 1}`,
    value,
  }));
}

function dedupeStrings(values) {
  return [...new Set(values)];
}

function findDefense(skill) {
  for (const section of skill?.sections ?? []) {
    if (!isDefensive(section?.heading) && !isDefensive((section?.bullets ?? []).join(' '))) continue;
    for (const bullet of section?.bullets ?? []) {
      const text = cleanText(bullet);
      if (text) return text;
    }
  }
  for (const section of skill?.sections ?? []) {
    for (const bullet of section?.bullets ?? []) {
      const text = cleanText(bullet);
      if (text && isDefensive(text)) return text;
    }
  }
  return GENERIC_DEFENSE;
}

function verifyFor(category) {
  const key = Object.keys(VERIFY_BY_CATEGORY).find((k) => new RegExp(k, 'i').test(String(category)));
  return key ? VERIFY_BY_CATEGORY[key] : GENERIC_VERIFY;
}

/* ------------------------------------------------------------------ */
/* traffic metadata (counts + names only — never raw values)          */
/* ------------------------------------------------------------------ */

function trafficSummary(traffic) {
  const items = Array.isArray(traffic) ? traffic : [];
  const methods = new Set();
  const paramNames = new Set();
  let jsonEndpoints = 0;

  for (const item of items) {
    if (item?.method) methods.add(String(item.method).toUpperCase());
    for (const name of item?.queryParams ?? []) paramNames.add(String(name));
    for (const name of item?.bodyParams ?? []) paramNames.add(String(name));
    const contentType = String(item?.contentType ?? '').toLowerCase();
    const path = String(item?.path ?? '').toLowerCase();
    if (contentType.includes('json') || path.includes('/api/') || path.endsWith('.json')) {
      jsonEndpoints += 1;
    }
  }

  const hints = [];
  if (jsonEndpoints) hints.push(`${jsonEndpoints} JSON endpoints observed in Burp traffic`);
  if (methods.size) hints.push(`Methods seen in Burp traffic: ${[...methods].sort().join(', ')}`);
  if (paramNames.size) hints.push(`${paramNames.size} distinct parameter names observed in Burp traffic`);
  if (items.length) hints.push(`${items.length} requests observed in Burp traffic`);
  return { hints, hasTraffic: items.length > 0, jsonEndpoints, methodCount: methods.size, paramCount: paramNames.size };
}

function observationHints(observation) {
  const hints = [];
  const signals = observation?.signals ?? {};
  if (signals.hasForm) hints.push('Form surface detected — enumerate parameter names only, never submit real credentials.');
  if (signals.hasJwt || signals.hasSessionCookie) hints.push('Session/JWT indicators present — do not capture or replay live tokens.');
  if (signals.hasGraphql) hints.push('GraphQL endpoint hinted — check introspection posture manually.');
  if (signals.hasMissingSecurityHeaders) hints.push('Security headers appear to be missing — confirm with live response headers.');
  const techs = (observation?.technologies ?? []).map((t) => t?.name).filter(Boolean);
  if (techs.length) hints.push(`Technologies hinted: ${dedupeStrings(techs).slice(0, 5).join(', ')}.`);
  return hints;
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * @param {{observation?:object,traffic?:Array,kb?:object,maxCards?:number}} input
 * @returns {{cards:Array,riskHints:string[]}}
 */
export function buildLocalCards({ observation = {}, traffic = [], kb = {}, maxCards = 12 } = {}) {
  const skills = Array.isArray(kb?.skills) ? kb.skills : [];
  const rules = Array.isArray(kb?.rules) ? kb.rules : [];
  const skillsById = new Map(skills.filter((s) => s?.id).map((skill) => [skill.id, skill]));

  const cards = [];
  const priorities = new Map();
  const seenIds = new Set();

  for (const rule of rules) {
    if (!ruleMatches(rule, observation)) continue;
    const category = String(rule?.category ?? 'general');
    for (const skillId of rule?.skillIds ?? []) {
      const skill = skillsById.get(skillId);
      if (!skill) continue;

      const id = `${slug(category)}--${slug(skillId)}`;
      if (seenIds.has(id)) continue;
      seenIds.add(id);

      const matchedConditions = [
        ...(rule?.when?.all ?? []),
        ...(rule?.when?.any ?? []),
      ];
      const whyHere = matchedConditions.length
        ? `Matched: ${dedupeStrings(matchedConditions.map(friendlyCondition)).join(', ')}.`
        : `Rule ${rule?.id ?? 'matched'} fired for this page.`;

      const title = cleanText(String(skill?.name ?? skillId).replace(/^SKILL:\s*/i, '')) || String(skillId);
      const card = {
        id,
        category,
        title,
        severityHint: severityFor(category),
        whyHere,
        steps: buildSteps(skill, category),
        payloads: buildPayloads(skill),
        verify: verifyFor(category),
        defense: findDefense(skill),
        owasp: mapOwasp(category, skill.id ?? skillId),
        skillId: skill.id,
        source: 'local',
      };

      let priority = Number.isFinite(rule?.priority) ? rule.priority : 0;
      if (BOOSTED_CATEGORIES.has(category.toLowerCase())) priority += 1;
      cards.push(card);
      priorities.set(id, priority);
    }
  }

  cards.sort((a, b) => {
    const delta = (priorities.get(b.id) ?? 0) - (priorities.get(a.id) ?? 0);
    if (delta !== 0) return delta;
    return a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
  });

  const summary = trafficSummary(traffic);
  if (summary.hasTraffic) {
    for (const card of cards) {
      if (BOOSTED_CATEGORIES.has(card.category.toLowerCase())) {
        priorities.set(card.id, (priorities.get(card.id) ?? 0) + 2);
      }
    }
    cards.sort((a, b) => {
      const delta = (priorities.get(b.id) ?? 0) - (priorities.get(a.id) ?? 0);
      if (delta !== 0) return delta;
      return a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
    });
  }

  const riskHints = dedupeStrings([
    SCOPE_REMINDER,
    ...observationHints(observation),
    ...summary.hints,
  ]);

  const finalCards = cards.slice(0, Math.max(0, Number(maxCards) || 0));

  return {
    cards: finalCards,
    riskHints,
    owasp: owaspSummary(finalCards),
  };
}

export default buildLocalCards;
