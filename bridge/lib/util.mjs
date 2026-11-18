import crypto from 'node:crypto';

const SENSITIVE_KEY = /token|secret|password|authorization|cookie|set-cookie|bearer/i;
const TRUNCATE_LEN = 200;
const BODY_LIMIT = 5 * 1024 * 1024;

/** Current time in ISO-8601 form. */
export function nowIso() {
  return new Date().toISOString();
}

/** Safe string truncation (never throws on non-strings). */
export function truncate(value, max = TRUNCATE_LEN) {
  if (value === null || value === undefined) return '';
  const s = String(value);
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max))}...`;
}

/** Random, URL-safe identifier with an optional prefix. */
export function safeId(prefix = '') {
  return `${prefix}${crypto.randomBytes(8).toString('hex')}`;
}

/** Slugify a string; falls back to a random id when nothing usable is given. */
export function slug(value) {
  if (typeof value !== 'string' || !value.trim()) return safeId();
  const s = value
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
  return s || safeId();
}

/**
 * Recursively drop sensitive keys and truncate every string.
 * Used as a last line of defence before anything leaves the process.
 */
export function redactObject(value, max = TRUNCATE_LEN) {
  if (Array.isArray(value)) return value.map((v) => redactObject(v, max));
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key)) continue;
      out[key] = redactObject(val, max);
    }
    return out;
  }
  if (typeof value === 'string') return truncate(value, max);
  return value;
}

/** Write a JSON HTTP response with sensible defaults. */
export function json(res, code = 200, data = {}) {
  const payload = JSON.stringify(data === undefined ? {} : data);
  if (!res.headersSent) {
    res.statusCode = code;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', Buffer.byteLength(payload));
  }
  res.end(payload);
}

/**
 * Read a request body, enforce a size limit and parse JSON.
 * Errors carry a `status` so the server can return a friendly JSON error.
 */
export function readBody(req, limit = BODY_LIMIT) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > limit) {
        const err = new Error(`Request body too large (limit ${limit} bytes)`);
        err.status = 413;
        fail(err);
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (settled) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        settled = true;
        return resolve({});
      }
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        const err = new Error(`Invalid JSON body: ${e.message}`);
        err.status = 400;
        return fail(err);
      }
      settled = true;
      resolve(parsed);
    });

    req.on('error', (e) => fail(e));
  });
}
