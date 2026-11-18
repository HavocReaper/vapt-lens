#!/usr/bin/env node
/**
 * build-kb.mjs — compile every offensive-* SKILL.md under
 * ~/.config/opencode/skills into bridge/data/knowledge-base.json
 * (contract: SPEC.md -> "KnowledgeBase").
 *
 * No external dependencies. Deterministic: arrays are sorted or emitted in
 * stable document order, so reruns differ only in `generatedAt`.
 *
 * Signal syntax used by `rules.when` (dotted paths from SPEC.md), matching
 * bridge/lib/analyze.mjs -> matchesWhen():
 *   signals.hasForm                  boolean field on observation.signals
 *   queryParams[].name               every item's `name` in that array
 *   queryParams[].name=redirect      "=" suffix = case-insensitive exact match
 *   technologies[].name=React        (same convention for cookies/headers)
 * `any` is OR, `all` is AND; an empty `all` is always true. The scanner's
 * substring-derived booleans (hasUrlParam, hasRedirectParam, hasIdParam,
 * hasJwt, hasSessionCookie, hasGraphql, ...) carry the "name contains"
 * semantics; the `=` entries add exact-name coverage for common cases.
 */

import { existsSync, readdirSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';

const HOME = homedir();
const SKILLS_DIR = process.env.VAPT_LENS_SKILLS_DIR
  ? resolve(process.env.VAPT_LENS_SKILLS_DIR)
  : join(HOME, '.config', 'opencode', 'skills');
const PROJECT_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const OUT_PATH = join(PROJECT_ROOT, 'bridge', 'data', 'knowledge-base.json');

const MAX_BULLET = 240;
const MAX_CODE = 1200;
const cmp = (a, b) => String(a).localeCompare(String(b), 'en');

// ---------------------------------------------------------------------------
// Frontmatter (tiny hand-rolled YAML: scalars + folded/literal blocks only)
// ---------------------------------------------------------------------------
function parseFrontmatter(raw) {
  const lines = raw.split(/\r?\n/);
  if (lines[0]?.trim() !== '---') {
    return { ok: false, error: 'missing opening ---' };
  }
  const end = lines.findIndex((line, i) => i > 0 && line.trim() === '---');
  if (end === -1) {
    return { ok: false, error: 'missing closing ---' };
  }

  const meta = {};
  const block = lines.slice(1, end);
  for (let i = 0; i < block.length; i++) {
    const m = block[i].match(/^([A-Za-z][\w-]*):\s*(.*)$/);
    if (!m) continue;
    const [, key, rawValue] = m;
    let value = rawValue.trim();

    // Folded (>) / literal (|) block scalars, optionally with +/- chomping.
    const blockMatch = value.match(/^([>|][+-]?)$/);
    if (blockMatch) {
      const folded = blockMatch[1].startsWith('>');
      const parts = [];
      i++;
      while (i < block.length && /^\s+/.test(block[i])) {
        parts.push(block[i].trim());
        i++;
      }
      i--;
      value = parts.join(folded ? ' ' : '\n');
    } else if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1).replace(/\\(["'\\])/g, '$1');
    }
    meta[key] = value;
  }

  return { ok: true, meta, body: lines.slice(end + 1).join('\n') };
}

// ---------------------------------------------------------------------------
// Markdown helpers
// ---------------------------------------------------------------------------
function stripMarkdown(value) {
  return String(value)
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1') // images -> alt text
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1') // links -> label
    .replace(/`{1,3}([^`]+)`{1,3}/g, '$1') // inline code
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/~~([^~]+)~~/g, '$1')
    .replace(/\*([^*\n]+)\*/g, '$1')
    .replace(/\b_([^_\n]+)_\b/g, '$1')
    .replace(/<[^>]+>/g, '') // stray HTML tags
    .replace(/\s+/g, ' ')
    .trim();
}

function cap(value, limit) {
  return value.length <= limit ? value : `${value.slice(0, limit - 1)}…`;
}

function headingIndex(body, heading) {
  return body.split(/\r?\n/).findIndex((line) => line.trim() === heading);
}

/** Trigger phrases: backticked, comma-separated list in `## Trigger Phrases`. */
function extractTriggers(body, description, id) {
  const found = new Set();
  const add = (raw) => {
    const clean = stripMarkdown(raw).replace(/[.,;]+$/, '');
    if (clean.length > 1) found.add(clean);
  };

  const start = headingIndex(body, '## Trigger Phrases');
  if (start !== -1) {
    const lines = body.split(/\r?\n/).slice(start + 1);
    const section = [];
    for (const line of lines) {
      if (/^##\s+/.test(line)) break;
      section.push(line);
    }
    for (const m of section.join('\n').matchAll(/`([^`]+)`/g)) {
      for (const phrase of m[1].split(',')) add(phrase);
    }
  }

  // Fallback for skills without a Trigger Phrases section: prefer short phrases
  // from the description, and always include id-derived phrases as a baseline.
  const hint = description.match(/(?:Trigger on|Triggers include)\s*:\s*([^\n]+)/i);
  if (hint) {
    for (const phrase of hint[1].split(/[,;]/)) {
      const cleaned = stripMarkdown(phrase).replace(/[.,;]+$/, '');
      if (cleaned.length > 1 && cleaned.length <= 60 && !/^(and|or|any mention of)\b/i.test(cleaned)) {
        found.add(cleaned);
      }
    }
  }
  if (found.size === 0) {
    add(id);
    const human = id.replace(/^offensive-/, '').replace(/-/g, ' ');
    add(human);
    for (const word of human.split(' ')) if (word.length > 2) add(word);
  }

  return [...found].sort(cmp);
}

/**
 * Split a methodology into sections on `##` / `###` headings.
 * `####`+ headings stay inside the current section (their bullets are kept).
 * Checkbox and plain dashes become bullets; fenced code is captured verbatim,
 * mermaid diagrams are skipped.
 */
function parseSections(body) {
  const fullIdx = headingIndex(body, '## Full Methodology');
  // 28 skills have an explicit "Full Methodology"; the rest keep their whole
  // body as the methodology (they use "## Quick Workflow" etc. instead).
  const text = fullIdx === -1
    ? body
    : body.split(/\r?\n/).slice(fullIdx + 1).join('\n');

  const sections = [];
  let current = null;
  let inFence = false;
  let fenceLang = '';
  let code = [];

  const flushCode = () => {
    if (current && code.length) {
      const block = cap(code.join('\n').trim(), MAX_CODE);
      if (block && !current.codeBlocks.includes(block)) current.codeBlocks.push(block);
    }
    code = [];
  };

  for (const line of text.split(/\r?\n/)) {
    const fence = line.match(/^\s*(`{3,}|~{3,})\s*([\w+-]*)/);
    if (fence) {
      if (!inFence) {
        flushCode();
        inFence = true;
        fenceLang = (fence[2] || '').toLowerCase();
      } else {
        flushCode();
        inFence = false;
        fenceLang = '';
      }
      continue;
    }
    if (inFence) {
      if (fenceLang !== 'mermaid') code.push(line);
      continue;
    }

    const heading = line.match(/^(#{2,3})\s+(.+)$/);
    if (heading) {
      flushCode();
      const name = stripMarkdown(heading[2]);
      current = { heading: name, bullets: [], codeBlocks: [] };
      sections.push(current);
      continue;
    }
    if (/^#{1}\s+/.test(line) || /^#{4,}\s+/.test(line)) continue; // titles / deep subsections

    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet && current) {
      const text = cap(stripMarkdown(bullet[1].replace(/^\[[ xX]\]\s+/, '')), MAX_BULLET);
      if (text && !current.bullets.includes(text)) current.bullets.push(text);
    }
  }
  flushCode();

  return sections.filter((section) => section.bullets.length || section.codeBlocks.length);
}

// ---------------------------------------------------------------------------
// Categories: ordered, specific-first keyword map over id + name + description
// ---------------------------------------------------------------------------
const CATEGORY_KEYWORDS = [
  ['xss', [/\bxss\b/i, /cross[- ]site scripting/i, /html injection/i]],
  ['sqli', [/\bsql\b/i, /sql injection/i, /\bnosql\b/i]],
  ['ssrf', [/\bssrf\b/i, /server[- ]side request forgery/i]],
  ['idor', [/\bidor\b/i, /insecure direct object/i, /broken access control/i]],
  ['graphql', [/\bgraphql\b/i, /introspection/i, /__schema/i]],
  ['jwt', [/\bjwt\b/i, /json web token/i, /alg:none/i]],
  ['oauth', [/\boauth\b/i, /openid/i, /\bpkce\b/i]],
  ['csrf', [/\bcsrf\b/i, /cross[- ]site request forgery/i]],
  ['upload', [/file upload/i, /\bupload\b/i, /multipart/i]],
  ['xxe', [/\bxxe\b/i, /xml external entity/i]],
  ['ssti', [/\bssti\b/i, /server[- ]side template/i, /template injection/i]],
  ['deserialization', [/deserializ/i, /gadget chain/i, /pickle/i]],
  ['request-smuggling', [/request smuggling/i, /desync/i, /cl\.te/i, /te\.cl/i]],
  ['business-logic', [/business logic/i, /workflow bypass/i, /price manipulation/i, /coupon/i]],
  ['api', [/\bapi\b/i, /\brest\b/i, /web service/i, /endpoint/i]],
  ['auth', [/\bauth(?:entication|orization)?\b/i, /login/i, /credential/i, /session/i, /password spray/i]],
  ['headers', [/http header/i, /content-security-policy/i, /\bcsp\b/i, /security header/i]],
  ['cloud', [/\baws\b/i, /\bazure\b/i, /\bgcp\b/i, /cloud metadata/i, /\bimds\b/i, /\bk8s\b/i, /kubernetes/i, /container/i, /\biam\b/i]],
  ['recon', [/recon(?:naissance|ing)?\b/i, /osint/i, /enumeration/i, /fingerprint/i, /information gathering/i, /attack surface/i]],
  ['mobile', [/mobile/i, /android/i, /\bios\b/i, /react native/i]],
  ['wireless', [/wi-?fi/i, /802\.11/i, /bluetooth/i, /\bble\b/i, /zigbee/i, /z-wave/i, /lora/i, /sub-ghz/i, /\bwpa/i, /\bwps\b/i]],
  ['rce', [/remote code execution/i, /\brce\b/i, /command injection/i, /code execution/i]],
  ['crypto', [/cryptograph/i, /\brsa\b/i, /padding oracle/i, /hash length extension/i]],
  ['redirect', [/open redirect/i, /redirect/i]],
  ['supply-chain', [/supply chain/i, /dependency confusion/i, /typosquat/i, /package/i]],
  ['waf', [/\bwaf\b/i, /web application firewall/i]],
  ['privesc', [/privilege escalation/i, /\bprivesc\b/i, /\bsystem\b/i]],
];

function deriveCategories(id, name, description) {
  const haystack = `${id} ${name} ${description}`;
  const matches = [];
  for (const [category, patterns] of CATEGORY_KEYWORDS) {
    if (patterns.some((re) => re.test(haystack))) matches.push(category);
  }
  const chosen = matches.slice(0, 5); // keep the most specific categories
  return (chosen.length ? chosen : ['misc']).sort(cmp);
}

// ---------------------------------------------------------------------------
// Core rules. Every skillIds entry is validated against the skill directory
// before write, so a typo can never emit an invented id.
// ---------------------------------------------------------------------------
function rule(id, category, priority, any, all, skillIds) {
  return {
    id,
    when: { any: [...new Set(any)].sort(cmp), all: [...new Set(all)].sort(cmp) },
    skillIds: [...new Set(skillIds)].sort(cmp),
    category,
    priority,
  };
}

function buildRules() {
  return [
    rule('xss-form-textinput', 'xss', 92, ['signals.hasForm', 'signals.hasTextInput'], [], ['offensive-xss', 'offensive-ssti']),
    rule('xss-search-param', 'xss', 78, ['signals.hasSearch', 'queryParams[].name=q', 'queryParams[].name=search', 'queryParams[].name=query', 'queryParams[].name=term'], [], ['offensive-xss', 'offensive-sqli']),
    rule('xss-dom-sink', 'xss', 96, ['signals.hasDomSink', 'signals.hasInlineScript'], [], ['offensive-xss']),
    rule('xss-spa-framework', 'xss', 74, ['technologies[].name=react', 'technologies[].name=vue', 'technologies[].name=angular', 'technologies[].name=svelte'], [], ['offensive-xss', 'offensive-oauth']),
    rule('xss-jquery', 'xss', 72, ['technologies[].name=jquery'], [], ['offensive-xss']),
    rule('headers-csp-present', 'headers', 55, ['signals.hasCsp', 'headers[].name=content-security-policy'], [], ['offensive-xss', 'offensive-tls-attacks']),
    rule('headers-missing', 'headers', 86, ['signals.hasMissingSecurityHeaders'], [], ['offensive-xss', 'offensive-tls-attacks']),
    rule('headers-transport-security', 'headers', 54, ['headers[].name=strict-transport-security', 'headers[].name=x-frame-options'], [], ['offensive-tls-attacks']),
    rule('sqli-id-param', 'sqli', 88, ['signals.hasIdParam', 'queryParams[].name=id', 'queryParams[].name=uid', 'queryParams[].name=pid', 'queryParams[].name=user'], [], ['offensive-sqli']),
    rule('sqli-api-json', 'sqli', 80, ['signals.hasApiBase', 'signals.hasJsonBodyHint'], [], ['offensive-sqli', 'offensive-api-security']),
    rule('sqli-filter-param', 'sqli', 70, ['queryParams[].name=search', 'queryParams[].name=filter', 'queryParams[].name=sort', 'queryParams[].name=order'], [], ['offensive-sqli']),
    rule('ssrf-url-param', 'ssrf', 94, ['signals.hasUrlParam', 'queryParams[].name=url', 'queryParams[].name=uri', 'queryParams[].name=target', 'queryParams[].name=dest', 'queryParams[].name=feed', 'queryParams[].name=image', 'queryParams[].name=src'], [], ['offensive-ssrf']),
    rule('ssrf-callback-param', 'ssrf', 82, ['queryParams[].name=callback', 'queryParams[].name=webhook', 'queryParams[].name=endpoint'], [], ['offensive-ssrf', 'offensive-oauth']),
    rule('cloud-metadata-url', 'cloud', 84, ['signals.hasUrlParam', 'queryParams[].name=url', 'queryParams[].name=host'], [], ['offensive-cloud', 'offensive-ssrf']),
    rule('idor-id-param', 'idor', 90, ['signals.hasIdParam', 'queryParams[].name=id', 'queryParams[].name=uid', 'queryParams[].name=account', 'queryParams[].name=order', 'queryParams[].name=doc'], [], ['offensive-idor', 'offensive-api-security']),
    rule('idor-api-base', 'idor', 76, ['signals.hasApiBase'], [], ['offensive-idor', 'offensive-api-security']),
    rule('auth-login-form', 'auth', 91, ['signals.hasLogin'], [], ['offensive-initial-access', 'offensive-api-security']),
    rule('auth-session-cookie', 'auth', 87, ['signals.hasSessionCookie', 'cookies[].name=session', 'cookies[].name=auth'], [], ['offensive-api-security', 'offensive-jwt']),
    rule('auth-credential-param', 'auth', 70, ['queryParams[].name=password', 'queryParams[].name=email', 'queryParams[].name=username', 'queryParams[].name=user'], [], ['offensive-initial-access', 'offensive-api-security']),
    rule('jwt-token-presence', 'jwt', 95, ['signals.hasJwt', 'cookies[].name=jwt', 'cookies[].name=token', 'headers[].name=authorization'], [], ['offensive-jwt']),
    rule('jwt-auth-cookie', 'jwt', 89, ['cookies[].name=auth', 'cookies[].name=token', 'cookies[].name=jwt'], [], ['offensive-jwt']),
    rule('oauth-code-state', 'oauth', 93, ['queryParams[].name=code', 'queryParams[].name=state', 'queryParams[].name=redirect_uri'], [], ['offensive-oauth']),
    rule('oauth-csrf-login', 'csrf', 80, ['signals.hasLogin', 'signals.hasRedirectParam'], [], ['offensive-oauth', 'offensive-api-security']),
    rule('csrf-token-field', 'csrf', 66, ['signals.hasCsrfTokenField'], [], ['offensive-oauth', 'offensive-api-security']),
    rule('redirect-open', 'redirect', 92, ['signals.hasRedirectParam', 'queryParams[].name=redirect', 'queryParams[].name=next', 'queryParams[].name=return', 'queryParams[].name=continue', 'queryParams[].name=goto'], [], ['offensive-open-redirect', 'offensive-oauth']),
    rule('redirect-url-param', 'redirect', 84, ['queryParams[].name=url', 'queryParams[].name=target', 'queryParams[].name=dest'], [], ['offensive-open-redirect']),
    rule('api-base', 'api', 82, ['signals.hasApiBase', 'signals.hasJsonBodyHint'], [], ['offensive-api-security', 'offensive-api-abuse']),
    rule('api-rest-tech', 'api', 60, ['technologies[].name=rest', 'technologies[].name=express', 'technologies[].name=django'], [], ['offensive-api-abuse', 'offensive-api-security']),
    rule('param-pollution', 'api', 61, ['queryParams[].name=id', 'queryParams[].name=filter', 'queryParams[].name=type'], [], ['offensive-parameter-pollution']),
    rule('graphql-signal', 'graphql', 98, ['signals.hasGraphql', 'technologies[].name=graphql', 'technologies[].name=apollo'], [], ['offensive-graphql']),
    rule('graphql-api-combo', 'graphql', 96, ['signals.hasGraphql'], ['signals.hasApiBase'], ['offensive-graphql']),
    rule('graphql-query-param', 'graphql', 94, ['queryParams[].name=query', 'queryParams[].name=operation', 'queryParams[].name=variables'], [], ['offensive-graphql', 'offensive-sqli']),
    rule('upload-file-input', 'upload', 96, ['signals.hasFileInput', 'signals.hasUpload'], [], ['offensive-file-upload']),
    rule('upload-form-enctype', 'upload', 90, ['signals.hasForm'], ['signals.hasFileInput'], ['offensive-file-upload']),
    rule('upload-params', 'upload', 70, ['queryParams[].name=file', 'queryParams[].name=filename', 'queryParams[].name=upload', 'queryParams[].name=path'], [], ['offensive-file-upload', 'offensive-xxe']),
    rule('business-logic-form', 'business-logic', 62, ['signals.hasForm'], [], ['offensive-business-logic', 'offensive-race-condition']),
    rule('business-logic-price', 'business-logic', 89, ['queryParams[].name=price', 'queryParams[].name=qty', 'queryParams[].name=quantity', 'queryParams[].name=discount', 'queryParams[].name=coupon', 'queryParams[].name=amount'], [], ['offensive-business-logic']),
    rule('business-logic-role', 'business-logic', 72, ['signals.hasIdParam', 'queryParams[].name=role', 'queryParams[].name=tenant', 'queryParams[].name=status'], [], ['offensive-business-logic', 'offensive-idor']),
    rule('race-condition-form-api', 'business-logic', 68, ['signals.hasForm'], ['signals.hasApiBase'], ['offensive-race-condition']),
    rule('file-read-param', 'ssrf', 80, ['queryParams[].name=file', 'queryParams[].name=path', 'queryParams[].name=doc', 'queryParams[].name=template', 'queryParams[].name=include'], [], ['offensive-xxe', 'offensive-ssrf']),
    rule('xxe-upload', 'xxe', 78, ['signals.hasFileInput', 'queryParams[].name=xml'], [], ['offensive-xxe']),
    rule('ssti-template-param', 'ssti', 76, ['queryParams[].name=template', 'queryParams[].name=tpl', 'queryParams[].name=view', 'queryParams[].name=page'], [], ['offensive-ssti']),
    rule('deserialization-cookie', 'deserialization', 74, ['cookies[].name=session', 'cookies[].name=data', 'queryParams[].name=data'], [], ['offensive-deserialization']),
    rule('smuggling-headers', 'request-smuggling', 70, ['headers[].name=transfer-encoding', 'headers[].name=content-length'], [], ['offensive-request-smuggling']),
    rule('supply-chain-inline-script', 'supply-chain', 58, ['signals.hasInlineScript'], [], ['offensive-supply-chain']),
    rule('recon-debug-param', 'recon', 79, ['signals.hasDebugParam', 'queryParams[].name=debug', 'queryParams[].name=test', 'queryParams[].name=admin', 'queryParams[].name=source'], [], ['offensive-fast-checking', 'offensive-bug-identification']),
    rule('recon-surface', 'recon', 52, ['signals.hasApiBase', 'signals.hasInlineScript'], [], ['offensive-fast-checking', 'offensive-osint']),
    rule('waf-evasion', 'waf', 50, ['signals.hasMissingSecurityHeaders'], [], ['offensive-waf-bypass']),
    rule('crypto-token', 'crypto', 76, ['signals.hasJwt', 'cookies[].name=token'], [], ['offensive-crypto-attacks', 'offensive-jwt']),
    rule('rce-command-param', 'rce', 82, ['queryParams[].name=cmd', 'queryParams[].name=exec', 'queryParams[].name=command', 'queryParams[].name=host', 'queryParams[].name=ip'], [], ['offensive-rce']),
    rule('mobile-tech', 'mobile', 56, ['technologies[].name=react native', 'technologies[].name=cordova', 'technologies[].name=ionic'], [], ['offensive-mobile']),
  ]
    .sort((a, b) => b.priority - a.priority || cmp(a.id, b.id)); // stable, deterministic
}

function validateRules(rules, knownIds) {
  const seen = new Set();
  const validSignals = /^(?:signals\.[\w]+|(?:queryParams|cookies|headers|technologies|links|scripts|endpoints)\[\]\.[\w]+)(?:=.+)?$/;
  for (const r of rules) {
    if (seen.has(r.id)) throw new Error(`duplicate rule id: ${r.id}`);
    seen.add(r.id);
    if (!r.category || !Number.isInteger(r.priority)) throw new Error(`bad rule metadata: ${r.id}`);
    for (const id of r.skillIds) {
      if (!knownIds.has(id)) throw new Error(`rule ${r.id} references unknown skill id: ${id}`);
    }
    for (const signal of [...r.when.any, ...r.when.all]) {
      if (!validSignals.test(signal)) throw new Error(`rule ${r.id} has malformed signal: ${signal}`);
    }
    if (r.when.any.length === 0 && r.when.all.length === 0) {
      throw new Error(`rule ${r.id} has no signals`);
    }
  }
}

// ---------------------------------------------------------------------------
// Display names
// ---------------------------------------------------------------------------
/** Prefer the skill's own "# SKILL: ..." heading over an ID-like frontmatter name. */
function deriveDisplayName(id, name, body) {
  const heading = body.match(/^#\s+SKILL:\s*(.+)$/im);
  if (heading) {
    const clean = stripMarkdown(heading[1]).trim();
    if (clean && clean.length <= 90) return clean;
  }
  if (name === id || /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(name)) {
    return id
      .replace(/^offensive-/, '')
      .replace(/-/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }
  return name;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  // A fresh clone may not have the skills installed yet. Build an empty KB instead
  // of failing so `npm run build` and `npm test` always work out of the box.
  if (!existsSync(SKILLS_DIR)) {
    const empty = { generatedAt: new Date().toISOString(), skills: [], rules: [] };
    mkdirSync(dirname(OUT_PATH), { recursive: true });
    writeFileSync(OUT_PATH, `${JSON.stringify(empty, null, 2)}\n`, 'utf8');
    console.warn('Knowledge base built with no skills');
    console.warn(`  skills directory not found: ${SKILLS_DIR}`);
    console.warn('  The extension and bridge still run, but guided cards need skills.');
    console.warn('  Install the offensive-* skills, or point VAPT_LENS_SKILLS_DIR at them,');
    console.warn(`  then rerun "npm run kb". Output: ${OUT_PATH}`);
    return;
  }

  const dirs = readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^offensive-/.test(entry.name))
    .map((entry) => entry.name)
    .sort(cmp);

  const skills = [];
  const failures = [];
  const knownIds = new Set(dirs);

  for (const id of dirs) {
    const file = join(SKILLS_DIR, id, 'SKILL.md');
    let raw;
    try {
      raw = readFileSync(file, 'utf8');
    } catch (error) {
      failures.push(`${id}: cannot read SKILL.md (${error.code || error.message})`);
      continue;
    }

    const parsed = parseFrontmatter(raw);
    if (!parsed.ok || !parsed.meta.name || !parsed.meta.description) {
      failures.push(`${id}: frontmatter (${parsed.error || 'missing name or description'})`);
      continue;
    }

    const { name, description } = parsed.meta;
    const displayName = deriveDisplayName(id, name, parsed.body);
    skills.push({
      id,
      name: displayName,
      description,
      triggers: extractTriggers(parsed.body, description, id),
      categories: deriveCategories(id, displayName, description),
      sections: parseSections(parsed.body),
      sourcePath: `~/${relative(HOME, file).split(sep).join('/')}`,
    });
  }

  const rules = buildRules();
  validateRules(rules, knownIds);

  const kb = {
    generatedAt: new Date().toISOString(),
    skills,
    rules,
  };

  mkdirSync(dirname(OUT_PATH), { recursive: true });
  writeFileSync(OUT_PATH, `${JSON.stringify(kb, null, 2)}\n`, 'utf8');

  const totals = new Map();
  for (const skill of skills) {
    for (const category of skill.categories) totals.set(category, (totals.get(category) || 0) + 1);
  }
  const top = [...totals.entries()]
    .sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]))
    .slice(0, 6)
    .map(([category, count]) => `${category}(${count})`)
    .join(', ');

  console.log('Knowledge base built');
  console.log(`  skills: ${skills.length}`);
  console.log(`  rules: ${rules.length}`);
  console.log(`  top categories: ${top}`);
  console.log(`  output: ${OUT_PATH}`);
  console.log(`  frontmatter failures: ${failures.length}${failures.length ? `\n    - ${failures.join('\n    - ')}` : ''}`);
}

main();
