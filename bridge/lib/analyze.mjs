import { askOpencode } from './ai.mjs';
import { nowIso, safeId, truncate } from './util.mjs';
import { buildSecurityChecks } from '../../extension/src/core/checks.js';
import { findPlaybook, payloadsFor } from '../../extension/src/core/playbooks.js';

const DEFAULT_MAX_CARDS = 12;

/** OWASP Top 10 (2021) categories exposed by /api/owasp and summary.owasp. */
export const OWASP_CATEGORIES = [
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

const OWASP_BY_ID = new Map(OWASP_CATEGORIES.map((c) => [c.id, c]));
const DEFAULT_OWASP_ID = 'A05';

// Precise category names first, so ambiguous tokens resolve consistently.
const CATEGORY_TO_OWASP = {
  idor: 'A01',
  csrf: 'A01',
  'access-control': 'A01',
  authorization: 'A01',
  privilege: 'A01',
  api: 'A01',
  graphql: 'A01',
  crypto: 'A02',
  tls: 'A02',
  ssl: 'A02',
  encryption: 'A02',
  sqli: 'A03',
  xss: 'A03',
  ssti: 'A03',
  command: 'A03',
  rce: 'A03',
  xxe: 'A03',
  injection: 'A03',
  upload: 'A03',
  template: 'A03',
  pollution: 'A03',
  'business-logic': 'A04',
  'race-condition': 'A04',
  workflow: 'A04',
  design: 'A04',
  headers: 'A05',
  debug: 'A05',
  config: 'A05',
  cloud: 'A05',
  container: 'A05',
  default: 'A05',
  misconfig: 'A05',
  'request-smuggling': 'A05',
  waf: 'A05',
  mobile: 'A05',
  dependency: 'A06',
  'supply-chain': 'A06',
  cve: 'A06',
  c2: 'A06',
  framework: 'A06',
  component: 'A06',
  auth: 'A07',
  login: 'A07',
  jwt: 'A07',
  oauth: 'A07',
  session: 'A07',
  brute: 'A07',
  credential: 'A07',
  deserialization: 'A08',
  ci: 'A08',
  webhook: 'A08',
  integrity: 'A08',
  pipeline: 'A08',
  logging: 'A09',
  recon: 'A09',
  exfil: 'A09',
  persistence: 'A09',
  osint: 'A09',
  ssrf: 'A10',
  'url-param': 'A10',
  redirect: 'A10',
  'open-redirect': 'A10',
  fetch: 'A10',
};

// Fallback keyword lists mirror the v2 OWASP mapping table.
const OWASP_KEYWORDS = [
  ['A01', ['access control', 'idor', 'authorization', 'csrf', 'privilege', 'api', 'graphql']],
  ['A02', ['crypto', 'tls', 'ssl', 'cipher', 'encryption']],
  ['A03', ['injection', 'sqli', 'xss', 'ssti', 'command', 'xxe', 'upload', 'template', 'rce', 'pollution']],
  ['A04', ['business logic', 'race condition', 'workflow', 'design']],
  ['A05', ['header', 'debug', 'config', 'cloud', 'container', 'default', 'misconfig', 'smuggling', 'waf', 'mobile']],
  ['A06', ['dependency', 'supply chain', 'cve', 'framework', 'component', 'outdated']],
  ['A07', ['auth', 'login', 'jwt', 'oauth', 'session', 'brute', 'credential', 'password']],
  ['A08', ['deserialization', 'supply chain', 'integrity', 'webhook', 'pipeline', 'ci']],
  ['A09', ['logging', 'recon', 'exfil', 'persistence', 'monitoring', 'osint']],
  ['A10', ['ssrf', 'url param', 'redirect', 'fetch', 'webhook', 'open redirect']],
];

const OWASP_SIGNALS = [
  ['A10', ['hasUrlParam', 'hasRedirectParam']],
  ['A03', ['hasDomSink', 'hasJsonBodyHint', 'hasIdParam']],
  ['A07', ['hasJwt', 'hasSessionCookie', 'hasLogin']],
  ['A05', ['hasDebugParam', 'hasMissingSecurityHeaders', 'hasApiBase']],
  ['A01', ['hasForm', 'hasCsrfTokenField']],
];

const SEVERITY_BY_CATEGORY = [
  ['sqli', 'high'],
  ['injection', 'high'],
  ['rce', 'high'],
  ['deserial', 'high'],
  ['ssrf', 'high'],
  ['idor', 'high'],
  ['auth', 'high'],
  ['jwt', 'high'],
  ['upload', 'high'],
  ['xss', 'medium'],
  ['csrf', 'medium'],
  ['graphql', 'medium'],
  ['api', 'medium'],
  ['redirect', 'low'],
  ['clickjack', 'low'],
  ['info', 'low'],
];

const GENERIC_STEPS = [
  'Open the relevant request in Burp Proxy/Repeater and capture a clean baseline response.',
  'Change only one input at a time (parameter, header or path) and compare status, length and headers.',
  'Note any error text or behaviour change that reveals how the input is handled.',
  'Repeat with a second benign value to confirm the behaviour is consistent.',
  'Record observations locally; do not automate or send bulk requests.',
];

const SAFE_EXAMPLES = {
  injection: ['test-value', '"<>probe', "test' OR 1=1--"],
  upload: ['benign.txt', 'test-image.png'],
  redirect: ['https://example.invalid/', '/relative-path'],
  xss: ['"<b>test</b>"', 'test-<svg>'],
  default: ['test-value', '"<>probe'],
};

const GENERIC_DEFENSE =
  'Validate and canonicalise all input server-side, use strict allowlists and parameterised queries, enforce authorisation on every object reference, and apply context-aware output encoding.';

const DEFENSE_BY_CATEGORY = {
  injection: 'Use parameterised queries/prepared statements and strict input validation; never concatenate untrusted data into queries.',
  upload: 'Verify content type and extension server-side, store uploads outside the web root, and re-encode or scan files before use.',
  xss: 'Apply context-aware output encoding, use a restrictive Content-Security-Policy and avoid inserting untrusted data into sinks.',
  redirect: 'Allowlist redirect destinations and never accept arbitrary URLs from request parameters.',
  auth: 'Enforce server-side authorisation on every request, rotate session identifiers after privilege changes and use secure cookie flags.',
  csrf: 'Require unpredictable per-session tokens for state-changing requests and set SameSite cookies.',
  info: 'Remove debug endpoints and verbose errors from production, and return only generic error messages.',
};

function uniq(values) {
  return [...new Set(values.filter((v) => v !== null && v !== undefined && v !== '').map((v) => String(v)))];
}

function humanize(value = '') {
  return String(value)
    .replace(/[-_]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase()) || 'Manual checks';
}

function normalizeOwaspToken(value = '') {
  return String(value ?? '').toLowerCase().replace(/_/g, '-').trim();
}

function owaspWords(value = '') {
  return normalizeOwaspToken(value).replace(/-/g, ' ').replace(/\s+/g, ' ').trim();
}

function keywordHit(text, keyword) {
  const k = owaspWords(keyword);
  if (!k) return false;
  if (k.includes(' ')) return text.includes(k);
  return text.split(' ').includes(k);
}

function findOwaspByKeywords(value = '') {
  const text = owaspWords(value);
  if (!text) return null;
  for (const [id, keywords] of OWASP_KEYWORDS) {
    if (keywords.some((keyword) => keywordHit(text, keyword))) return id;
  }
  return null;
}

function findOwaspBySignals(signals = {}) {
  if (!signals || typeof signals !== 'object') return null;
  for (const [id, keys] of OWASP_SIGNALS) {
    if (keys.some((key) => signals[key] === true)) return id;
  }
  return null;
}

/**
 * Map a card's category / skill id / observation signals to an OWASP Top 10
 * entry. Always returns a fresh { id, name } object.
 */
export function mapOwasp(category = '', skillId = '', signals = {}) {
  const cat = normalizeOwaspToken(category);
  const skill = normalizeOwaspToken(skillId).replace(/^offensive-/, '');
  const id =
    CATEGORY_TO_OWASP[cat] ||
    findOwaspByKeywords(cat) ||
    findOwaspByKeywords(skill) ||
    findOwaspBySignals(signals) ||
    DEFAULT_OWASP_ID;
  const chosen = OWASP_BY_ID.get(id) || OWASP_BY_ID.get(DEFAULT_OWASP_ID);
  return { id: chosen.id, name: chosen.name };
}

function owaspSummary(cards = []) {
  const counts = new Map(OWASP_CATEGORIES.map((c) => [c.id, 0]));
  for (const card of Array.isArray(cards) ? cards : []) {
    const id = card?.owasp?.id;
    if (counts.has(id)) counts.set(id, counts.get(id) + 1);
  }
  return OWASP_CATEGORIES.map((c) => ({ id: c.id, name: c.name, cardCount: counts.get(c.id) }));
}

/** Resolve a dotted path such as `queryParams[].name` into a flat value list. */
export function resolvePath(obj, path = '') {
  const parts = String(path || '').split('.').filter(Boolean);
  return walk(obj, parts);
}

function walk(obj, parts) {
  if (!parts.length) return [obj];
  const raw = parts[0];
  const isArray = raw.endsWith('[]');
  const key = isArray ? raw.slice(0, -2) : raw;
  const next = obj === null || obj === undefined ? undefined : obj[key];
  if (isArray) {
    if (!Array.isArray(next)) return [];
    return next.flatMap((item) => walk(item, parts.slice(1)));
  }
  return walk(next, parts.slice(1));
}

function splitExpression(expression = '') {
  const s = String(expression).trim();
  const idx = s.indexOf('=');
  if (idx === -1) return { path: s, expected: null };
  return {
    path: s.slice(0, idx).trim(),
    expected: s.slice(idx + 1).trim().replace(/^["']|["']$/g, ''),
  };
}

/** Evaluate a KB rule `when` object against a PageObservation. */
export function matchesWhen(when = {}, observation = {}) {
  const checks = [];
  if (Array.isArray(when?.any)) checks.push(...when.any.map((p) => ({ expression: p, mode: 'any' })));
  if (Array.isArray(when?.all)) checks.push(...when.all.map((p) => ({ expression: p, mode: 'all' })));
  if (!checks.length) return { matched: false, evidence: [] };

  const evidence = [];
  const anyResults = [];
  const allResults = [];

  for (const { expression, mode } of checks) {
    const { path, expected } = splitExpression(expression);
    const values = resolvePath(observation, path).filter(
      (v) => v !== null && v !== undefined && v !== '' && v !== false,
    );
    const hit = expected === null
      ? values.length > 0
      : values.some((v) => String(v).toLowerCase() === expected.toLowerCase());
    if (hit) evidence.push(expected === null ? path : `${path}=${expected}`);
    (mode === 'all' ? allResults : anyResults).push(hit);
  }

  const anyOk = anyResults.length ? anyResults.some(Boolean) : true;
  const allOk = allResults.length ? allResults.every(Boolean) : true;
  return { matched: anyOk && allOk, evidence };
}

function categoryKey(category = '') {
  const c = String(category).toLowerCase();
  for (const [key] of SEVERITY_BY_CATEGORY) if (c.includes(key)) return key;
  return 'default';
}

function severityFor(category = '', skill = {}) {
  const key = categoryKey(category);
  const found = SEVERITY_BY_CATEGORY.find(([k]) => k === key);
  if (found) return found[1];
  const text = `${skill.name || ''} ${skill.description || ''}`.toLowerCase();
  for (const [k, v] of SEVERITY_BY_CATEGORY) if (text.includes(k)) return v;
  return 'medium';
}

function titleFor(rule, skills) {
  const category = humanize(rule.category || skills[0]?.categories?.[0] || 'checks');
  const name = String(skills[0]?.name || '').trim();
  if (name && !name.toLowerCase().includes(category.toLowerCase())) {
    return `${name} - ${category}`;
  }
  return category;
}

function evidenceDetails(evidence, observation) {
  return evidence.slice(0, 6).map((item) => {
    const path = item.split('=')[0];
    const values = resolvePath(observation, path).filter(Boolean);
    const shown = uniq(values).slice(0, 4);
    return shown.length ? `${item} (${shown.join(', ')})` : item;
  });
}

/** Detect shell/tool commands that must never become steps or payloads. */
function looksLikeCommand(value = '') {
  return /(\.exe\b|\.ps1\b|\.py\b|\b(?:curl|wget|nxc|netexec|hashcat|certipy|responder|mimikatz|rubeus|bloodhound|certutil|powershell|pwsh|python3?|ssh|nc|socat)\b|[|;$`]|\s--?[a-zA-Z]\b|(?:Invoke|Get|New|Set|Add|Remove)-[A-Z])/.test(
    String(value),
  );
}

/** Only short, single-line literal strings are safe to show as copyable probes. */
function isSafeCopyableString(value) {
  const s = String(value || '').trim();
  if (!s || s.length > 160 || /[\r\n]/.test(s)) return false;
  return !looksLikeCommand(s);
}

function stepsFromSkill(skill, category) {
  const bullets = [];
  for (const section of skill?.sections || []) {
    for (const bullet of section?.bullets || []) {
      const s = String(bullet).trim();
      if (s.length > 4 && !looksLikeCommand(s)) bullets.push(truncate(s, 280));
    }
  }
  const steps = bullets.slice(0, 6);
  while (steps.length < 3) steps.push(GENERIC_STEPS[steps.length % GENERIC_STEPS.length]);
  return steps.slice(0, 6);
}

function payloadsFromSkill(skill, category, skillId = '') {
  const out = [];
  for (const block of skill?.codeBlocks || []) {
    if (out.length >= 3) break;
    const raw = String(block || '').trim();
    if (!isSafeCopyableString(raw)) continue;
    out.push({ label: `KB example ${out.length + 1}`, value: truncate(raw, 200) });
  }
  if (out.length < 3) {
    for (const item of payloadsFor(category, skillId || skill?.id || '', 3)) {
      if (out.length >= 3) break;
      if (out.some((p) => p.value === item.value)) continue;
      out.push({ label: `Playbook · ${item.label}`, value: item.value });
    }
  }
  if (!out.length) {
    const seeds = SAFE_EXAMPLES[categoryKey(category)] || SAFE_EXAMPLES.default;
    out.push({ label: 'Benign probe', value: seeds[0] });
  }
  return out.slice(0, 3);
}

function verifyText(category) {
  return `In Burp Repeater, compare the modified response with the baseline: look for a changed status code, response length, headers, or distinct error text that confirms how ${category || 'the input'} is processed.`;
}

function defenseText(category) {
  const key = categoryKey(category);
  return DEFENSE_BY_CATEGORY[key] || GENERIC_DEFENSE;
}

/** Build cards from KB rules using the dotted-path matcher. */
export function localCards(observation = {}, kb = {}, maxCards = DEFAULT_MAX_CARDS) {
  const skillsById = new Map((Array.isArray(kb?.skills) ? kb.skills : []).map((s) => [s?.id, s]));
  const rules = [...(Array.isArray(kb?.rules) ? kb.rules : [])].sort(
    (a, b) => (Number(b?.priority) || 0) - (Number(a?.priority) || 0),
  );

  const cards = [];
  const seen = new Set();

  for (const rule of rules) {
    const { matched, evidence } = matchesWhen(rule?.when || {}, observation);
    if (!matched) continue;

    const skillIds = (rule?.skillIds || []).filter((id) => skillsById.has(id));
    const skills = skillIds.map((id) => skillsById.get(id));
    const category = rule?.category || skills[0]?.categories?.[0] || 'general';
    const dedupeKey = `${category}::${skillIds[0] || ''}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    cards.push({
      id: safeId('local-'),
      category,
      title: titleFor(rule || {}, skills),
      severityHint: severityFor(category, skills[0]),
      whyHere: `Matched ${evidenceDetails(evidence, observation).join('; ') || 'KB rule'}.`,
      steps: stepsFromSkill(skills[0], category),
      payloads: payloadsFromSkill(skills[0], category, skillIds[0] || ''),
      playbookId: findPlaybook(category, skillIds[0] || '')?.id || '',
      verify: verifyText(category),
      defense: defenseText(category),
      skillId: skillIds[0] || '',
      source: 'local',
      owasp: mapOwasp(category, skillIds[0], observation?.signals),
    });

    if (cards.length >= maxCards) break;
  }
  return cards;
}

function buildSummary(observation = {}, cards = []) {
  const tech = uniq(namesFrom(observation.technologies, 'name'));
  const queryNames = uniq(namesFrom(observation.queryParams, 'name'));
  const cookieNames = uniq(namesFrom(observation.cookies, 'name'));
  const domSinks = uniq(namesFrom(observation.domSinks, 'type'));
  const headerNames = uniq(namesFrom(observation.headers, 'name'));
  const signals = Object.entries(observation.signals || {})
    .filter(([, v]) => v === true)
    .map(([k]) => k);
  const counts = observation.counts || {};

  const surface = {
    forms: counts.forms ?? (Array.isArray(observation.forms) ? observation.forms.length : 0),
    inputs: counts.inputs ?? 0,
    links: counts.links ?? (Array.isArray(observation.links) ? observation.links.length : 0),
    scripts: counts.scripts ?? (Array.isArray(observation.scripts) ? observation.scripts.length : 0),
    endpoints: counts.endpoints ?? (Array.isArray(observation.endpoints) ? observation.endpoints.length : 0),
    hasForm: Boolean(observation.signals?.hasForm),
    hasUpload: Boolean(observation.signals?.hasUpload),
    hasGraphql: Boolean(observation.signals?.hasGraphql),
    hasApiBase: Boolean(observation.signals?.hasApiBase),
    hasLogin: Boolean(observation.signals?.hasLogin),
    queryParamNames: queryNames,
    cookieNames,
    headerNames,
    domSinkTypes: domSinks,
  };

  const riskHints = [...signals.map((s) => `signal: ${s}`), ...tech.map((t) => `tech: ${t}`)].slice(0, 20);
  return { tech, surface, riskHints, owasp: owaspSummary(cards) };
}

function namesFrom(value, key = 'name') {
  if (!Array.isArray(value)) return [];
  return value.map((v) => (typeof v === 'string' ? v : v?.[key] || '')).filter(Boolean);
}

/**
 * Always-available local analysis with optional, non-blocking AI enrichment.
 */
export async function analyze({ observation = {}, traffic = [], options = {}, kb = {} } = {}) {
  const warnings = [];
  const requestedMax = Number(options?.maxCards);
  const maxCards = Number.isFinite(requestedMax) && requestedMax > 0
    ? Math.min(requestedMax, 50)
    : DEFAULT_MAX_CARDS;

  let local = [];
  try {
    local = localCards(observation, kb, maxCards);
    if (!(Array.isArray(kb?.rules) ? kb.rules : []).length) {
      warnings.push('Knowledge base contains no rules; showing generic guidance only.');
    }
  } catch (e) {
    warnings.push(`Local analysis failed: ${e?.message || String(e)}`);
  }

  let cards = [...local];
  let aiUsed = false;

  if (options?.ai === true) {
    try {
      const result = await askOpencode({ observation, traffic, cards: local });
      if (result?.ok === true && Array.isArray(result.cards)) {
        // Reserve room for AI cards so hybrid mode actually mixes both sources.
        const localQuota = Math.floor(maxCards / 2);
        const aiQuota = maxCards - localQuota;
        cards = [...local.slice(0, localQuota), ...result.cards.slice(0, aiQuota)];
        aiUsed = true;
      } else {
        warnings.push(`AI analysis unavailable: ${result?.error || 'unknown error'}`);
      }
    } catch (e) {
      warnings.push(`AI analysis failed: ${e?.message || String(e)}`);
    }
  }

  const seen = new Set();
  cards = cards.filter((card) => {
    const id = card?.id || '';
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  cards = cards.slice(0, maxCards);

  // AI cards (and any card from a custom KB) must carry an OWASP mapping too.
  const signals = observation?.signals && typeof observation.signals === 'object' ? observation.signals : {};
  for (const card of cards) {
    const current = card?.owasp;
    if (current && OWASP_BY_ID.has(current.id)) {
      const chosen = OWASP_BY_ID.get(current.id);
      card.owasp = { id: chosen.id, name: chosen.name };
    } else {
      card.owasp = mapOwasp(card?.category, card?.skillId, signals);
    }
  }

  return {
    summary: buildSummary(observation, cards),
    cards,
    // Passive: header evaluation from captured metadata + copy-only commands.
    checks: buildSecurityChecks(observation),
    aiUsed,
    generatedAt: nowIso(),
    warnings,
  };
}
