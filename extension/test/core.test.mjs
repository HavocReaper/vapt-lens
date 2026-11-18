import test from 'node:test';
import assert from 'node:assert/strict';

import { observePage, redactText, cssPath, xpathFor } from '../src/core/scanner.js';
import { buildLocalCards, mapOwasp, owaspSummary } from '../src/core/analyzer.js';
import {
  SCAN_PAGE, SCAN_RESULT, GET_STATE, STATE, OPEN_PANEL,
  ANALYZE, ANALYSIS_RESULT, IMPORT_BURP, BURP_IMPORTED,
  CRAWL_SITE, CRAWL_RESULT, GET_TRAFFIC, TRAFFIC_RESULT, MESSAGE_TYPES,
  br, sendToBackground,
} from '../src/core/messages.js';

/* ------------------------------------------------------------------ */
/* fixtures                                                            */
/* ------------------------------------------------------------------ */

function node(tag, props = {}) {
  const { attributes = {}, textContent = '', ...rest } = props;
  return {
    nodeType: 1,
    tagName: String(tag).toUpperCase(),
    nodeName: String(tag).toUpperCase(),
    attributes,
    textContent,
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name)
        ? this.attributes[name]
        : null;
    },
    ...rest,
  };
}

/** Give fake nodes a minimal parent/child tree so path helpers can walk it. */
function link(parent, ...children) {
  parent.children = [...(parent.children ?? []), ...children];
  for (const child of children) {
    child.parentElement = parent;
    child.parentNode = parent;
  }
  return parent;
}

const HREF = 'https://app.example.com/dashboard?redirect=/admin&id=42&debug=1&url=https://evil.test&q=';

const fields = [
  node('input', {
    attributes: { type: 'text', name: 'username', id: 'user', placeholder: 'Enter user', maxlength: '50' },
    required: true,
    value: 'alice',
  }),
  node('input', {
    attributes: { type: 'password', name: 'password', id: 'pass' },
    value: 'hunter2',
  }),
  node('input', {
    attributes: { type: 'hidden', name: 'csrf_token' },
    value: 'CSRFSECRETVALUE',
  }),
];

const fileField = node('input', {
  attributes: { type: 'file', name: 'avatar' },
  value: 'C:\\fakepath\\avatar.png',
});

const loginForm = node('form', {
  attributes: { action: '/login', method: 'post', enctype: 'application/x-www-form-urlencoded' },
  elements: fields,
});

const uploadForm = node('form', {
  attributes: { action: '/api/upload', method: 'post', enctype: 'multipart/form-data' },
  elements: [fileField],
});

// Minimal DOM tree: html > body > (loginForm, uploadForm) > fields.
const htmlNode = node('html');
const bodyNode = node('body');
link(htmlNode, bodyNode);
link(bodyNode, loginForm, uploadForm);
link(loginForm, ...fields);
link(uploadForm, fileField);

const links = [
  node('a', { attributes: { href: '/dashboard' } }),
  node('a', { attributes: { href: 'https://external.example.com/x' } }),
  node('a', { attributes: { href: '/admin/debug' } }),
  node('a', { attributes: { href: '/api/graphql' } }),
  node('a', { attributes: { href: 'backup.zip' } }),
  node('a', { attributes: { href: '/report.json' } }),
];

const inlineScript =
  "const q = location.hash; el.innerHTML = q; " +
  "fetch('/api/v1/users?id=' + q, {headers:{'Content-Type':'application/json'}}); " +
  "// jwt bearer abc.def.ghi token=SECRET123";

const scripts = [
  node('script', { attributes: { src: 'https://cdn.example.com/jquery.min.js' } }),
  node('script', { attributes: { src: '/_next/static/chunk.js' } }),
  node('script', { textContent: inlineScript }),
];

const metas = [node('meta', { attributes: { name: 'generator', content: 'WordPress 6.4' } })];

const doc = {
  title: 'Dashboard',
  URL: HREF,
  documentElement: htmlNode,
  body: bodyNode,
  forms: [loginForm, uploadForm],
  links,
  scripts,
  getElementsByTagName(name) {
    return name === 'meta' ? metas : [];
  },
  defaultView: { jQuery: () => {} },
};

const cookies = [
  { name: 'sessionid', value: 'super-secret-value', httpOnly: true, secure: true, sameSite: 'Lax' },
  { name: 'jwt_token', value: 'aaa.bbb.ccc', httpOnly: false, secure: true, sameSite: 'Strict' },
];

const headers = [
  { name: 'content-type', value: 'text/html; charset=utf-8' },
  { name: 'content-security-policy', value: "default-src 'self'" },
  { name: 'x-frame-options', value: 'SAMEORIGIN' },
  { name: 'server', value: 'AuthServer/1.0' },
  { name: 'authorization', value: 'Bearer abc.def.ghi' },
  { name: 'x-secret-key', value: 'supersecret' },
];

const kb = {
  generatedAt: '2026-01-01T00:00:00.000Z',
  skills: [
    {
      id: 'offensive-idor',
      name: 'SKILL: IDOR Testing',
      description: 'Test insecure direct object references.',
      triggers: ['id parameter'],
      categories: ['idor'],
      sections: [
        {
          heading: 'Enumeration',
          bullets: ['Map every endpoint that accepts an object identifier.', 'Note which identifiers are numeric or sequential.'],
          codeBlocks: ['/api/users/123'],
        },
        {
          heading: 'Testing',
          bullets: ['Change the id to another value and compare responses.'],
          codeBlocks: [],
        },
        {
          heading: 'Defense',
          bullets: ['Enforce object-level authorization on every request.'],
          codeBlocks: [],
        },
      ],
      sourcePath: 'skills/offensive-idor/SKILL.md',
    },
    {
      id: 'offensive-xss',
      name: 'SKILL: XSS Testing',
      description: 'Test reflected and stored script injection.',
      triggers: ['reflected input'],
      categories: ['xss'],
      sections: [
        {
          heading: 'Discovery',
          bullets: ['Identify reflected parameters in responses.', 'Submit a harmless marker string.'],
          codeBlocks: [
            '<b>vapt-lens</b>',
            '```mermaid\ngraph TD\nA-->B\n```',
            'fetch("/api/x")',
          ],
        },
        {
          heading: 'Mitigation',
          bullets: ['Contextually encode output.'],
          codeBlocks: [],
        },
      ],
      sourcePath: 'skills/offensive-xss/SKILL.md',
    },
  ],
  rules: [
    { id: 'r1', when: { any: ['signals.hasForm', 'signals.hasIdParam'] }, skillIds: ['offensive-idor'], category: 'idor', priority: 5 },
    { id: 'r2', when: { all: ['signals.hasInlineScript', 'signals.hasDomSink'] }, skillIds: ['offensive-xss'], category: 'xss', priority: 4 },
    { id: 'r3', when: { any: ['queryParams[].name~debug', 'technologies[].name~jquery'] }, skillIds: ['offensive-idor', 'offensive-xss'], category: 'api', priority: 1 },
  ],
};

const observation = observePage({ href: HREF, title: 'Dashboard', doc, cookies, headers });

/* ------------------------------------------------------------------ */
/* scanner                                                             */
/* ------------------------------------------------------------------ */

test('observePage: shape, counts and metadata', () => {
  assert.equal(observation.url, HREF);
  assert.equal(observation.origin, 'https://app.example.com');
  assert.equal(observation.host, 'app.example.com');
  assert.equal(observation.path, '/dashboard');
  assert.equal(observation.title, 'Dashboard');
  assert.match(observation.capturedAt, /^\d{4}-\d{2}-\d{2}T/);

  assert.deepEqual(observation.counts, {
    forms: 2, inputs: 4, links: 6, scripts: 3,
    endpoints: observation.endpoints.length,
  });
  assert.ok(observation.endpoints.length > 0);
});

test('observePage: query params capture names, lengths, location and page only', () => {
  assert.deepEqual(observation.queryParams.map((p) => p.name), ['redirect', 'id', 'debug', 'url', 'q']);
  assert.deepEqual(observation.queryParams.map((p) => p.valueLength), [6, 2, 1, 17, 0]);
  for (const param of observation.queryParams) {
    assert.deepEqual(Object.keys(param).sort(), ['location', 'name', 'page', 'valueLength']);
    assert.equal(param.location, 'query');
    assert.equal(param.page, 'https://app.example.com/dashboard');
    assert.ok(!JSON.stringify(param).includes('evil.test'));
  }
});

test('observePage: cookies expose flags but never values', () => {
  assert.deepEqual(observation.cookies.map((c) => c.name), ['sessionid', 'jwt_token']);
  assert.equal(observation.cookies[0].httpOnly, true);
  assert.equal(observation.cookies[0].secure, true);
  assert.equal(observation.cookies[0].sameSite, 'Lax');
  assert.deepEqual(Object.keys(observation.cookies[0]).sort(), [
    'httpOnly', 'name', 'sameSite', 'secure', 'valueLength',
  ]);
});

test('observePage: only allowlisted headers are kept and sensitive values redacted', () => {
  const names = observation.headers.map((h) => h.name);
  assert.deepEqual(names, ['content-type', 'content-security-policy', 'x-frame-options', 'server']);
  assert.ok(!names.includes('authorization'));
  assert.ok(!names.includes('x-secret-key'));
  assert.equal(observation.headers.find((h) => h.name === 'server').value, '[REDACTED]');
});

test('observePage: forms and fields have metadata but no values', () => {
  assert.equal(observation.forms.length, 2);
  assert.equal(observation.forms[0].action, '/login');
  assert.equal(observation.forms[0].method, 'post');
  assert.equal(observation.forms[0].hasFileInput, false);
  assert.equal(observation.forms[1].hasFileInput, true);
  assert.equal(observation.forms[1].enctype, 'multipart/form-data');

  const names = observation.forms[0].fields.map((f) => f.name);
  assert.deepEqual(names, ['username', 'password', 'csrf_token']);
  assert.equal(observation.forms[0].fields[0].required, true);
  assert.equal(observation.forms[0].fields[1].required, false);
  assert.equal(observation.forms[0].fields[0].maxLength, 50);
  for (const field of observation.forms.flatMap((f) => f.fields)) {
    assert.ok(!Object.keys(field).includes('value'));
  }
});

test('observePage: forms and fields carry stable selector + xpath locations', () => {
  assert.deepEqual(observation.forms.map((f) => f.index), [0, 1]);
  for (const form of observation.forms) {
    assert.equal(typeof form.selector, 'string');
    assert.ok(form.selector.length > 0);
    assert.match(form.xpath, /^\/html\/body\/form\[\d+\]$/);
    for (const field of form.fields) {
      assert.equal(typeof field.selector, 'string');
      assert.ok(field.selector.length > 0);
      assert.match(field.xpath, /^\/html\/body\/form\[\d+\]\/(input|textarea|select)\[\d+\]$/);
    }
  }
  assert.match(observation.forms[0].selector, /^html > body > form:nth-of-type\(1\)$/);
  assert.equal(observation.forms[0].xpath, '/html/body/form[1]');
  assert.equal(observation.forms[1].xpath, '/html/body/form[2]');
});

test('observePage: inputs[] flattens every field with a location and no values', () => {
  assert.ok(Array.isArray(observation.inputs));
  assert.deepEqual(observation.inputs.map((i) => i.name), [
    'username', 'password', 'csrf_token', 'avatar',
  ]);
  for (const input of observation.inputs) {
    assert.deepEqual(Object.keys(input).sort(), [
      'formSelector', 'id', 'name', 'page', 'selector', 'type', 'xpath',
    ]);
    assert.equal(input.page, 'https://app.example.com/dashboard');
    assert.ok(input.selector.length > 0);
    assert.ok(input.xpath.length > 0);
    assert.equal(typeof input.formSelector, 'string');
    assert.ok(!Object.keys(input).includes('value'));
    assert.ok(!JSON.stringify(input).includes('alice'));
    assert.ok(!JSON.stringify(input).includes('hunter2'));
  }
  const avatar = observation.inputs.find((i) => i.name === 'avatar');
  assert.equal(avatar.type, 'file');
  assert.match(avatar.formSelector, /^html > body > form:nth-of-type\(2\)$/);
  assert.equal(observation.counts.inputs, observation.inputs.length);
});

test('path helpers degrade gracefully on method-less fake DOM objects', () => {
  const bare = {
    tagName: 'INPUT',
    attributes: { name: 'username' },
    getAttribute(name) {
      return this.attributes[name] ?? null;
    },
  };
  const fakeDoc = { forms: [] };
  const css1 = cssPath(bare, fakeDoc);
  const xpath1 = xpathFor(bare, fakeDoc);
  assert.equal(cssPath(bare, fakeDoc), css1);
  assert.equal(xpathFor(bare, fakeDoc), xpath1);
  assert.match(css1, /^input\[name="username"\]$/);
  assert.equal(xpath1, '/html/body/input[1]');

  const bareForm = { tagName: 'FORM', attributes: {} };
  assert.equal(cssPath(bareForm, { forms: [bareForm] }), 'form:nth-of-type(1)');
  assert.equal(xpathFor(bareForm, { forms: [bareForm] }), '/html/body/form[1]');
  assert.equal(cssPath(null, {}), '');
  assert.equal(xpathFor(undefined, {}), '');
});

test('observePage: link classification and technology hints', () => {
  const kinds = Object.fromEntries(observation.links.map((l) => [l.href, l.kind]));
  assert.equal(kinds['/dashboard'], 'internal');
  assert.equal(kinds['https://external.example.com/x'], 'external');
  assert.equal(kinds['/admin/debug'], 'suspicious');
  assert.equal(kinds['/api/graphql'], 'suspicious');
  assert.equal(kinds['backup.zip'], 'suspicious');
  assert.equal(kinds['/report.json'], 'suspicious');

  const techs = observation.technologies.map((t) => t.name);
  assert.ok(techs.includes('jQuery'));
  assert.ok(techs.includes('Next.js'));
  assert.ok(techs.some((name) => /WordPress/.test(name)));
});

test('observePage: DOM sinks and inline evidence are redacted/truncated', () => {
  const sinkTypes = observation.domSinks.map((s) => s.type);
  assert.ok(sinkTypes.includes('innerHTML'));
  assert.ok(sinkTypes.includes('location.hash'));
  for (const sink of observation.domSinks) {
    assert.ok(sink.evidence.length <= 160);
  }
  for (const item of [...observation.endpoints, ...observation.technologies]) {
    assert.ok(String(item.url ?? item.evidence).length <= 160);
  }
});

test('observePage: all expected signals are computed', () => {
  assert.deepEqual(observation.signals, {
    hasForm: true,
    hasTextInput: true,
    hasFileInput: true,
    hasLogin: true,
    hasSearch: false,
    hasUpload: true,
    hasGraphql: true,
    hasApiBase: true,
    hasRedirectParam: true,
    hasDebugParam: true,
    hasIdParam: true,
    hasUrlParam: true,
    hasJsonBodyHint: true,
    hasJwt: true,
    hasSessionCookie: true,
    hasCsp: true,
    hasMissingSecurityHeaders: true,
    hasInlineScript: true,
    hasDomSink: true,
    hasCsrfTokenField: true,
  });
});

test('observePage: never leaks values or secrets into the observation', () => {
  const serialised = JSON.stringify(observation);
  for (const secret of [
    'alice', 'hunter2', 'CSRFSECRETVALUE', 'avatar.png',
    'super-secret-value', 'aaa.bbb.ccc', 'abc.def.ghi', 'supersecret', 'SECRET123',
  ]) {
    assert.ok(!serialised.includes(secret), `leaked: ${secret}`);
  }
});

test('redactText: redacts secret-looking fragments and truncates to 160', () => {
  const redacted = redactText('Authorization: Bearer abc.def.ghi');
  assert.ok(!redacted.includes('abc.def.ghi'));
  assert.ok(redacted.includes('[REDACTED]'));
  assert.equal(redactText('x'.repeat(300)).length, 160);
  assert.equal(redactText(null), '');
});

/* ------------------------------------------------------------------ */
/* analyzer                                                            */
/* ------------------------------------------------------------------ */

test('buildLocalCards: produces one card per (category, skillId) pair', () => {
  const { cards, riskHints } = buildLocalCards({ observation, kb });
  assert.equal(cards.length, 4);
  assert.deepEqual(cards.map((c) => c.id).sort(), [
    'api--offensive-idor',
    'api--offensive-xss',
    'idor--offensive-idor',
    'xss--offensive-xss',
  ]);

  const idor = cards.find((c) => c.id === 'idor--offensive-idor');
  assert.equal(idor.title, 'IDOR Testing');
  assert.equal(idor.category, 'idor');
  assert.equal(idor.skillId, 'offensive-idor');
  assert.equal(idor.source, 'local');
  assert.ok(idor.whyHere.length > 0);
  assert.ok(idor.steps.length >= 3 && idor.steps.length <= 6);
  assert.ok(idor.payloads.length <= 3);
  assert.ok(idor.defense.length > 0);
  assert.ok(idor.verify.length > 0);
  assert.ok(['low', 'medium', 'high'].includes(idor.severityHint));

  const xss = cards.find((c) => c.id === 'xss--offensive-xss');
  assert.equal(xss.title, 'XSS Testing');
  for (const payload of xss.payloads) {
    assert.ok(!payload.value.includes('mermaid'));
    assert.ok(!payload.value.includes('fetch('));
    assert.ok(payload.label.length > 0);
  }
  assert.ok(riskHints.some((h) => /authorized/i.test(h)));
  assert.ok(riskHints.some((h) => /session\/jwt/i.test(h)));
});

test('analyzer: every local card carries an OWASP mapping', () => {
  const result = buildLocalCards({ observation, kb });
  assert.ok(result.cards.length > 0);
  for (const card of result.cards) {
    assert.deepEqual(Object.keys(card.owasp).sort(), ['id', 'name']);
    assert.match(card.owasp.id, /^A\d{2}$/);
    assert.equal(typeof card.owasp.name, 'string');
    assert.ok(card.owasp.name.length > 0);
  }
  assert.equal(result.cards.find((c) => c.category === 'idor').owasp.id, 'A01');
  assert.equal(result.cards.find((c) => c.category === 'xss').owasp.id, 'A03');

  assert.ok(Array.isArray(result.owasp));
  assert.equal(result.owasp.length, 10);
  assert.deepEqual(result.owasp[0], { id: 'A01', name: 'Broken Access Control', cardCount: 2 });
  assert.equal(result.owasp.reduce((sum, entry) => sum + entry.cardCount, 0), result.cards.length);
});

test('analyzer: mapOwasp and owaspSummary', () => {
  assert.deepEqual(mapOwasp('idor'), { id: 'A01', name: 'Broken Access Control' });
  assert.deepEqual(mapOwasp('xss', 'offensive-xss'), { id: 'A03', name: 'Injection' });
  assert.deepEqual(mapOwasp('ssrf'), { id: 'A10', name: 'SSRF' });
  assert.deepEqual(mapOwasp('tls'), { id: 'A02', name: 'Cryptographic Failures' });
  assert.deepEqual(mapOwasp('login'), { id: 'A07', name: 'Auth Failures' });
  assert.deepEqual(mapOwasp('supply-chain'), { id: 'A06', name: 'Vulnerable Components' });
  assert.deepEqual(mapOwasp('unknown-thing'), { id: 'A04', name: 'Insecure Design' });

  const summary = owaspSummary([
    { owasp: { id: 'A03', name: 'Injection' } },
    { owasp: { id: 'A03', name: 'Injection' } },
    { owasp: { id: 'A10', name: 'SSRF' } },
  ]);
  assert.equal(summary.length, 10);
  assert.equal(summary.find((e) => e.id === 'A03').cardCount, 2);
  assert.equal(summary.find((e) => e.id === 'A10').cardCount, 1);
  assert.equal(summary.find((e) => e.id === 'A01').cardCount, 0);
});

test('buildLocalCards: card ids are unique and deterministic', () => {
  const first = buildLocalCards({ observation, kb }).cards;
  const second = buildLocalCards({ observation, kb }).cards;
  assert.deepEqual(first, second);
  const ids = first.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('buildLocalCards: respects maxCards', () => {
  const capped = buildLocalCards({ observation, kb, maxCards: 2 });
  assert.equal(capped.cards.length, 2);
  assert.equal(new Set(capped.cards.map((c) => c.id)).size, 2);
  assert.equal(buildLocalCards({ observation, kb, maxCards: 0 }).cards.length, 0);
});

test('buildLocalCards: merges only traffic metadata, never raw values', () => {
  const traffic = [
    { method: 'GET', path: '/api/users', queryParams: ['id'], bodyParams: [], contentType: 'application/json', source: 'burp' },
    { method: 'POST', path: '/login', queryParams: [], bodyParams: ['username', 'password'], contentType: 'application/x-www-form-urlencoded', source: 'burp' },
  ];
  const result = buildLocalCards({ observation, traffic, kb });
  assert.ok(result.riskHints.includes('1 JSON endpoints observed in Burp traffic'));
  assert.ok(result.riskHints.some((h) => /Methods seen in Burp traffic: GET, POST/.test(h)));
  assert.ok(result.riskHints.some((h) => /3 distinct parameter names/.test(h)));
  assert.equal(result.cards.length, 4);
  const serialised = JSON.stringify(result);
  assert.ok(!serialised.includes('hunter2'));
  assert.ok(!serialised.includes('super-secret-value'));
});

test('buildLocalCards: no rules matched yields only scope guidance', () => {
  const result = buildLocalCards({
    observation: { signals: {} },
    kb: { skills: [], rules: [] },
  });
  assert.deepEqual(result.cards, []);
  assert.equal(result.riskHints.length, 1);
  assert.ok(/authorized/i.test(result.riskHints[0]));
});

/* ------------------------------------------------------------------ */
/* messages                                                            */
/* ------------------------------------------------------------------ */

test('messages: constants are stable', () => {
  assert.equal(SCAN_PAGE, 'SCAN_PAGE');
  assert.equal(SCAN_RESULT, 'SCAN_RESULT');
  assert.equal(GET_STATE, 'GET_STATE');
  assert.equal(STATE, 'STATE');
  assert.equal(OPEN_PANEL, 'OPEN_PANEL');
  assert.equal(ANALYZE, 'ANALYZE');
  assert.equal(ANALYSIS_RESULT, 'ANALYSIS_RESULT');
  assert.equal(IMPORT_BURP, 'IMPORT_BURP');
  assert.equal(BURP_IMPORTED, 'BURP_IMPORTED');
  assert.equal(CRAWL_SITE, 'CRAWL_SITE');
  assert.equal(CRAWL_RESULT, 'CRAWL_RESULT');
  assert.equal(GET_TRAFFIC, 'GET_TRAFFIC');
  assert.equal(TRAFFIC_RESULT, 'TRAFFIC_RESULT');
});

test('messages: MESSAGE_TYPES exposes crawl + traffic types', () => {
  for (const type of [CRAWL_SITE, CRAWL_RESULT, GET_TRAFFIC, TRAFFIC_RESULT]) {
    assert.equal(MESSAGE_TYPES[type], type);
  }
  assert.equal(Object.keys(MESSAGE_TYPES).length, 13);
});

test('messages: br() and callback-style sendToBackground (Chrome)', async () => {
  const savedBrowser = globalThis.browser;
  const savedChrome = globalThis.chrome;
  delete globalThis.browser;
  globalThis.chrome = {
    runtime: {
      lastError: null,
      sendMessage(msg, cb) {
        cb({ ok: true, echoed: msg.type });
      },
    },
  };
  try {
    assert.equal(br(), globalThis.chrome);
    const response = await sendToBackground({ type: SCAN_PAGE });
    assert.deepEqual(response, { ok: true, echoed: SCAN_PAGE });
  } finally {
    globalThis.chrome = savedChrome;
    if (savedBrowser === undefined) delete globalThis.browser;
    else globalThis.browser = savedBrowser;
  }
});

test('messages: promise-style sendToBackground (Firefox)', async () => {
  const savedBrowser = globalThis.browser;
  const savedChrome = globalThis.chrome;
  globalThis.browser = {
    runtime: {
      sendMessage(msg) {
        return Promise.resolve({ ok: 'firefox', type: msg.type });
      },
    },
  };
  delete globalThis.chrome;
  try {
    assert.equal(br(), globalThis.browser);
    const response = await sendToBackground({ type: GET_STATE });
    assert.deepEqual(response, { ok: 'firefox', type: GET_STATE });
  } finally {
    if (savedBrowser === undefined) delete globalThis.browser;
    else globalThis.browser = savedBrowser;
    globalThis.chrome = savedChrome;
  }
});

test('messages: runtime.lastError rejects', async () => {
  const savedBrowser = globalThis.browser;
  const savedChrome = globalThis.chrome;
  delete globalThis.browser;
  globalThis.chrome = {
    runtime: {
      lastError: { message: 'boom' },
      sendMessage(_msg, cb) {
        cb(undefined);
      },
    },
  };
  try {
    await assert.rejects(sendToBackground({ type: ANALYZE }), /boom/);
  } finally {
    globalThis.chrome = savedChrome;
    if (savedBrowser === undefined) delete globalThis.browser;
    else globalThis.browser = savedBrowser;
  }
});
