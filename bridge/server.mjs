import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { json, readBody, nowIso } from './lib/util.mjs';
import {
  parseBurpRaw,
  addTraffic,
  getTraffic,
  appendLive,
  clearTraffic,
  normalizeHost,
  getTrafficSummary,
} from './lib/burp.mjs';
import { analyze, OWASP_CATEGORIES } from './lib/analyze.mjs';
import { crawlSite } from './lib/crawl.mjs';
import { buildSiteFindings, buildTrafficFindings } from './lib/site-findings.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const CONFIG_PATH = path.join(HERE, 'config.json');
const KB_PATH = path.join(HERE, 'data', 'knowledge-base.json');
const VERSION = '0.1.0';
const DEFAULT_CONFIG = { aiEnabled: true, model: null, port: 8787, burpLive: true };

// Bounded in-memory site-scan jobs so the panel can show live progress.
const siteScans = new Map();
let scanSequence = 0;

function siteScanView(job) {
  if (!job) return null;
  return {
    ok: true,
    id: job.id,
    status: job.status,
    phase: job.phase,
    progress: { ...job.progress },
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    error: job.error || '',
    warnings: job.warnings || [],
    stats: job.stats || null,
    result: job.status === 'done' ? job.result : null,
  };
}

function startSiteScan(body) {
  const id = `scan-${Date.now()}-${++scanSequence}`;
  const job = {
    id,
    status: 'running',
    phase: 'queued',
    startedAt: nowIso(),
    finishedAt: null,
    error: '',
    warnings: [],
    stats: null,
    result: null,
    progress: {
      phase: 'queued',
      pagesDone: 0,
      queued: 0,
      maxPages: Number(body.maxPages) || 40,
      currentUrl: String(body.url || ''),
    },
  };
  siteScans.set(id, job);
  if (siteScans.size > 20) siteScans.delete(siteScans.keys().next().value);

  setImmediate(async () => {
    try {
      const crawl = await crawlSite({
        url: body.url,
        maxPages: body.maxPages,
        maxDepth: body.maxDepth,
        delayMs: body.delayMs,
        onProgress: (p) => {
          job.phase = p.phase === 'done' ? 'analyzing' : p.phase;
          job.progress = {
            phase: job.phase,
            pagesDone: p.pagesDone || 0,
            queued: p.queued || 0,
            maxPages: p.maxPages || job.progress.maxPages,
            currentUrl: String(p.currentUrl || '').slice(0, 512),
          };
        },
      });

      const findings = buildSiteFindings(crawl);
      job.stats = crawl.stats;
      job.warnings = crawl.warnings || [];
      job.result = {
        startUrl: crawl.startUrl,
        host: crawl.host,
        stats: crawl.stats,
        warnings: crawl.warnings || [],
        pages: (crawl.pages || []).map((p) => ({
          url: p.url,
          status: p.status,
          title: p.title,
          error: p.error || '',
          warning: p.warning || '',
        })),
        inventory: crawl.inventory,
        findings,
      };
      job.phase = 'done';
      job.status = 'done';
    } catch (e) {
      job.status = 'error';
      job.phase = 'error';
      job.error = String(e?.message || e).slice(0, 300);
    } finally {
      job.finishedAt = nowIso();
    }
  });

  return job;
}

async function loadConfig() {
  try {
    const parsed = JSON.parse(await fs.readFile(CONFIG_PATH, 'utf8'));
    return {
      aiEnabled: typeof parsed?.aiEnabled === 'boolean' ? parsed.aiEnabled : DEFAULT_CONFIG.aiEnabled,
      model: parsed?.model ?? null,
      port: Number(parsed?.port) || DEFAULT_CONFIG.port,
      burpLive: typeof parsed?.burpLive === 'boolean' ? parsed.burpLive : DEFAULT_CONFIG.burpLive,
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

async function saveConfig(config) {
  const out = {
    aiEnabled: Boolean(config.aiEnabled),
    model: config.model ?? null,
    port: Number(config.port) || DEFAULT_CONFIG.port,
    burpLive: Boolean(config.burpLive),
  };
  await fs.writeFile(CONFIG_PATH, `${JSON.stringify(out, null, 2)}\n`, 'utf8');
  return out;
}

async function loadKb() {
  try {
    const kb = JSON.parse(await fs.readFile(KB_PATH, 'utf8'));
    return {
      kb: {
        generatedAt: kb?.generatedAt ?? null,
        skills: Array.isArray(kb?.skills) ? kb.skills : [],
        rules: Array.isArray(kb?.rules) ? kb.rules : [],
      },
      warning: null,
    };
  } catch {
    return {
      kb: { generatedAt: null, skills: [], rules: [] },
      warning: 'Knowledge base file missing or invalid; using an empty KB.',
    };
  }
}

function applyCors(req, res) {
  const origin = String(req.headers.origin || '');
  const allowed =
    /^(chrome-extension:\/\/|moz-extension:\/\/|http:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?$)/i.test(origin);
  res.setHeader('Access-Control-Allow-Origin', allowed ? origin : 'null');
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

const server = http.createServer(async (req, res) => {
  applyCors(req, res);
  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  try {
    const u = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    const route = `${u.pathname}`.replace(/\/+$/, '') || '/';
    const method = req.method || 'GET';

    if (method === 'GET' && route === '/api/health') {
      const { kb } = await loadKb();
      json(res, 200, { ok: true, kbSkills: kb.skills.length, version: VERSION });
      return;
    }

    if (method === 'GET' && route === '/api/kb') {
      const { kb, warning } = await loadKb();
      if (u.searchParams.get('summary') === '1') {
        json(res, 200, {
          generatedAt: kb.generatedAt || nowIso(),
          skillCount: kb.skills.length,
          ruleCount: kb.rules.length,
          skills: kb.skills.map((s) => ({
            id: s.id,
            name: s.name,
            categories: Array.isArray(s.categories) ? s.categories : [],
          })),
          ...(warning ? { warning } : {}),
        });
      } else {
        json(res, 200, { ...kb, ...(warning ? { warning } : {}) });
      }
      return;
    }

    const skillMatch = route.match(/^\/api\/kb\/skills\/([^/]+)$/);
    if (method === 'GET' && skillMatch) {
      const { kb } = await loadKb();
      const id = decodeURIComponent(skillMatch[1]);
      const skill = kb.skills.find((s) => s.id === id);
      if (!skill) {
        json(res, 404, { ok: false, error: 'Skill not found' });
        return;
      }
      json(res, 200, skill);
      return;
    }

    if (method === 'GET' && route === '/api/owasp') {
      json(res, 200, OWASP_CATEGORIES);
      return;
    }

    if (method === 'POST' && route === '/api/crawl') {
      const body = await readBody(req);
      if (typeof body?.url !== 'string' || !body.url.trim()) {
        json(res, 400, { ok: false, error: 'A url string is required' });
        return;
      }
      const result = await crawlSite({
        url: body.url,
        maxPages: body.maxPages,
        maxDepth: body.maxDepth,
      });
      json(res, 200, result);
      return;
    }

    // Async whole-site scan with pollable progress and passive OWASP findings.
    if (method === 'POST' && route === '/api/site/scan') {
      const body = await readBody(req);
      let parsed;
      try {
        parsed = new URL(String(body?.url || '').trim());
      } catch {
        parsed = null;
      }
      if (!parsed || !/^https?:$/i.test(parsed.protocol)) {
        json(res, 400, { ok: false, error: 'A fully qualified http/https url is required' });
        return;
      }
      const job = startSiteScan({
        url: parsed.href,
        maxPages: body.maxPages,
        maxDepth: body.maxDepth,
        delayMs: body.delayMs,
      });
      json(res, 202, siteScanView(job));
      return;
    }

    if (method === 'GET' && route === '/api/site/scan/status') {
      const job = siteScans.get(String(u.searchParams.get('id') || ''));
      if (!job) {
        json(res, 404, { ok: false, error: 'Scan not found' });
        return;
      }
      json(res, 200, siteScanView(job));
      return;
    }

    if (method === 'POST' && route === '/api/analyze') {
      const body = await readBody(req);
      const { kb } = await loadKb();
      const incoming = body?.options && typeof body.options === 'object' ? body.options : {};
      const options = {
        ...incoming,
        ai: Boolean(incoming.ai) && config.aiEnabled === true,
      };
      const result = await analyze({
        observation: body?.observation && typeof body.observation === 'object' ? body.observation : {},
        traffic: Array.isArray(body?.traffic) ? body.traffic : [],
        options,
        kb,
      });
      json(res, 200, result);
      return;
    }

    if (method === 'POST' && route === '/api/burp/import') {
      const body = await readBody(req);
      const { items } = parseBurpRaw({
        source: String(body?.source || ''),
        raw: String(body?.raw ?? ''),
        host: String(body?.host || ''),
      });
      addTraffic(String(body?.host || ''), items);
      json(res, 200, { ok: true, count: items.length, items });
      return;
    }

    if (method === 'GET' && route === '/api/burp/traffic') {
      json(res, 200, { items: getTraffic(u.searchParams.get('host') || '') });
      return;
    }

    if (method === 'GET' && route === '/api/burp/summary') {
      json(res, 200, getTrafficSummary(u.searchParams.get('host') || ''));
      return;
    }

    if (method === 'GET' && route === '/api/burp/findings') {
      const host = u.searchParams.get('host') || '';
      const items = getTraffic(host);
      json(res, 200, {
        ok: true,
        host: items[0]?.host || normalizeHost(host),
        trafficCount: items.length,
        ...buildTrafficFindings(items),
      });
      return;
    }

    if (method === 'POST' && route === '/api/burp/stream') {
      const item = await readBody(req);
      const host = item?.host || normalizeHost(item?.url || '');
      appendLive(host, item);
      json(res, 200, { ok: true });
      return;
    }

    if (method === 'DELETE' && route === '/api/burp/traffic') {
      clearTraffic(u.searchParams.get('host') || '');
      json(res, 200, { ok: true });
      return;
    }

    if (method === 'GET' && route === '/api/config') {
      json(res, 200, config);
      return;
    }

    if (method === 'POST' && route === '/api/config') {
      const body = await readBody(req);
      if (typeof body?.aiEnabled === 'boolean') config.aiEnabled = body.aiEnabled;
      if (typeof body?.model === 'string' || body?.model === null) config.model = body.model;
      if (typeof body?.burpLive === 'boolean') config.burpLive = body.burpLive;
      config = await saveConfig(config);
      json(res, 200, config);
      return;
    }

    json(res, 404, { ok: false, error: 'Not found' });
  } catch (e) {
    const status = Number(e?.status) || 500;
    json(res, status, { ok: false, error: e?.message || 'Internal server error' });
  }
});

let config = await loadConfig();
try {
  await fs.access(CONFIG_PATH);
} catch {
  try {
    await saveConfig(config);
  } catch {
    // best-effort; the service still runs with in-memory defaults
  }
}

const PORT = Number(process.env.PORT) || Number(config.port) || DEFAULT_CONFIG.port;
server.listen(PORT, '127.0.0.1', () => {
  console.log(`VAPT Lens bridge listening at http://127.0.0.1:${PORT}`);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

export { server, ROOT };
