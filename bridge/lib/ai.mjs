import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeId, truncate } from './util.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..'); // project root
const TIMEOUT_MS = 90_000;
const MAX_PROMPT_CHARS = 12_000;

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

function uniq(values) {
  return [...new Set(values.filter(Boolean).map((v) => String(v)))];
}

function safePath(url) {
  try {
    return new URL(url).pathname || '/';
  } catch {
    return String(url || '').split(/[?#]/)[0] || '(unknown)';
  }
}

function buildPrompt({ observation = {}, traffic = [], cards = [] } = {}) {
  const localCards = Array.isArray(cards) ? cards : [];
  const trafficItems = Array.isArray(traffic) ? traffic : [];
  const lines = [];

  // Page: host and path only, never full URLs with query values.
  let hostPath = '';
  try {
    const u = new URL(observation.url || '');
    hostPath = `${u.host}${u.pathname || '/'}`;
  } catch {
    hostPath = `${observation.host || ''}${observation.path || ''}`.trim();
  }
  lines.push(`Page: ${hostPath || '(unknown)'}`);

  const signals = Object.entries(observation.signals || {})
    .filter(([, v]) => v === true)
    .map(([k]) => k);
  if (signals.length) lines.push(`Signals: ${signals.join(', ')}`);

  const params = uniq(namesFrom(observation.queryParams)).slice(0, 40);
  if (params.length) lines.push(`Query param names: ${params.join(', ')}`);

  const tech = uniq(namesFrom(observation.technologies)).slice(0, 20);
  if (tech.length) lines.push(`Technologies: ${tech.join(', ')}`);

  const headers = uniq(namesFrom(observation.headers)).slice(0, 20);
  if (headers.length) lines.push(`Header names: ${headers.join(', ')}`);

  const cookies = (Array.isArray(observation.cookies) ? observation.cookies : [])
    .slice(0, 20)
    .map((c) => {
      const flags = [
        c?.httpOnly && 'HttpOnly',
        c?.secure && 'Secure',
        c?.sameSite && `SameSite=${c.sameSite}`,
      ]
        .filter(Boolean)
        .join('; ');
      return c?.name ? `${c.name}${flags ? ` (${flags})` : ''}` : '';
    })
    .filter(Boolean);
  if (cookies.length) lines.push(`Cookie names/flags: ${cookies.join(', ')}`);

  const sinks = uniq(namesFrom(observation.domSinks, 'type')).slice(0, 20);
  if (sinks.length) lines.push(`DOM sink types: ${sinks.join(', ')}`);

  const trafficLines = trafficItems.slice(0, 40).map((t) => {
    const names = uniq([...(t?.queryParams || []), ...(t?.bodyParams || [])]).slice(0, 10);
    return `${t?.method || 'GET'} ${t?.path || safePath(t?.url)}${names.length ? ` [${names.join(', ')}]` : ''}`;
  });
  if (trafficLines.length) lines.push(`Traffic (${trafficLines.length}):\n${trafficLines.join('\n')}`);

  const titles = localCards.map((c) => c?.title).filter(Boolean).slice(0, 20);
  if (titles.length) lines.push(`Local guidance already present: ${titles.join(' | ')}`);

  const skillIds = uniq(localCards.map((c) => c?.skillId)).slice(0, 40);
  lines.push(
    `Available skillIds (cite only these): ${skillIds.length ? skillIds.join(', ') : '(none available; set skillId to "")'}`,
  );

  const instructions = [
    'Return ONLY a single JSON object. No prose. No markdown fences.',
    'Shape: {"cards":[{"id":"...","category":"...","title":"...","severityHint":"low|medium|high",',
    '"whyHere":"...","steps":["..."],"payloads":[{"label":"...","value":"..."}],',
    '"verify":"...","defense":"...","skillId":"...","source":"ai"}]}',
    'Rules:',
    '- Maximum 8 cards.',
    '- Guidance ONLY: manual steps to try in Burp/browser. Never include code that sends requests.',
    '- Never exploit, never send payloads automatically, never include credentials, cookies, tokens or real values.',
    '- payloads are short copyable safe test strings, at most 3 per card.',
    '- Cite a real skillId from the available skillIds list only; use "" when the list is empty.',
    '- Focus on the observed signals, param names, technologies, header names, cookie flags, traffic and DOM sinks above.',
    '- Do not repeat local guidance titles unless adding a genuinely new angle.',
  ].join('\n');

  let prompt = `${lines.join('\n')}\n\n${instructions}`;
  if (prompt.length > MAX_PROMPT_CHARS) {
    prompt = `${prompt.slice(0, MAX_PROMPT_CHARS)}\n[truncated]`;
  }
  return { prompt, skillIds };
}

function runProcess(args, cwd, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn('opencode', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      resolve({ error: `Failed to spawn opencode: ${e.message}` });
      return;
    }

    let stdout = '';
    let stderr = '';
    let settled = false;
    let timer;
    let killer;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(killer);
      resolve(result);
    };

    timer = setTimeout(() => {
      try {
        child.kill('SIGTERM');
      } catch {
        /* already gone */
      }
      killer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          /* already gone */
        }
      }, 2000);
      killer.unref?.();
      finish({ stdout, stderr, error: `opencode timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    child.stdout.on('data', (d) => {
      stdout += d.toString();
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    child.on('error', (e) => finish({ error: `opencode error: ${e.message}` }));
    child.on('close', (code) => {
      finish({
        stdout,
        stderr,
        code,
        error: code === 0 ? null : `opencode exited with code ${code}${stderr ? `: ${truncate(stderr, 200)}` : ''}`,
      });
    });
  });
}

function extractText(stdout = '') {
  let text = '';
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let event;
    try {
      event = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!event || typeof event !== 'object') continue;

    if (event.type === 'text' && typeof event.text === 'string') text += event.text;
    const candidates = [];
    if (event.part && typeof event.part === 'object') candidates.push(event.part);
    if (Array.isArray(event.parts)) candidates.push(...event.parts);
    if (Array.isArray(event.content?.parts)) candidates.push(...event.content.parts);
    for (const part of candidates) {
      if (part?.type === 'text' && typeof part.text === 'string') text += part.text;
    }
  }
  if (!text && /^\s*[\[{]/.test(stdout)) text = stdout;
  return text;
}

function stripFences(text = '') {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const source = fenced ? fenced[1] : text;
  return source.replace(/^\s*```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
}

function extractFirstJsonObject(text = '') {
  const start = text.indexOf('{');
  if (start === -1) return null;
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        try {
          return JSON.parse(text.slice(start, i + 1));
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

function sanitizeCard(card, validSkillIds) {
  if (!card || typeof card !== 'object') return null;
  const str = (value, max = 400) => truncate(value, max);

  let skillId = str(card.skillId, 120);
  if (validSkillIds.length && !validSkillIds.includes(skillId)) skillId = '';

  const steps = Array.isArray(card.steps)
    ? card.steps.slice(0, 6).map((s) => str(s, 400)).filter(Boolean)
    : [];
  const payloads = Array.isArray(card.payloads)
    ? card.payloads
        .slice(0, 3)
        .map((p) => ({
          label: str(p?.label || 'Test string', 80),
          value: str(p?.value, 200),
        }))
        .filter((p) => p.value)
    : [];

  return {
    id: str(card.id, 120) || safeId('ai-'),
    category: str(card.category, 80) || 'guidance',
    title: str(card.title, 160) || 'Manual check',
    severityHint: ['low', 'medium', 'high'].includes(String(card.severityHint || '').toLowerCase())
      ? String(card.severityHint).toLowerCase()
      : 'medium',
    whyHere: str(card.whyHere, 500),
    steps: steps.length ? steps : [
      'Review the observation and identify the relevant input.',
      'Test manually in Burp Repeater, changing one value at a time.',
      'Compare the baseline and modified responses and record differences.',
    ],
    payloads,
    verify: str(card.verify, 400),
    defense: str(card.defense, 400),
    skillId,
    source: 'ai',
  };
}

/**
 * Ask the local opencode CLI for guidance-only cards.
 * This function never throws; all failures become { ok:false, error }.
 */
export async function askOpencode({ observation, traffic, cards } = {}) {
  try {
    const { prompt, skillIds } = buildPrompt({ observation, traffic, cards });
    const args = ['run', '--format', 'json', '--title', 'VAPT Lens analysis', prompt];
    const result = await runProcess(args, ROOT, TIMEOUT_MS);
    if (result.error) return { ok: false, error: result.error };

    const text = extractText(result.stdout);
    const parsed = extractFirstJsonObject(stripFences(text));
    if (!parsed || !Array.isArray(parsed.cards)) {
      return { ok: false, error: 'No valid cards array in opencode output' };
    }

    const cleaned = parsed.cards
      .slice(0, 8)
      .map((card) => sanitizeCard(card, skillIds))
      .filter(Boolean);
    if (!cleaned.length) return { ok: false, error: 'No usable cards returned by opencode' };

    return { ok: true, cards: cleaned };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}
