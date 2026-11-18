import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { parseBurpRaw, appendLive, getTrafficSummary, clearTraffic } from '../lib/burp.mjs';
import { redactObject, slug, nowIso } from '../lib/util.mjs';
import { analyze, matchesWhen, resolvePath, mapOwasp, OWASP_CATEGORIES } from '../lib/analyze.mjs';
import { crawlSite } from '../lib/crawl.mjs';

test('parseBurpRaw parses namespaced Burp XML without keeping values', () => {
  const raw = `<?xml version="1.0"?>
<burp:siteMap xmlns:burp="urn:burp">
  <burp:item method="GET" url="https://example.com/search?q=test&amp;lang=en" host="https://example.com" status="200" mimeType="text/html" length="123">
    <burp:parameter name="q" value="secret-query-value" />
    <burp:parameter name="lang" value="en" />
  </burp:item>
  <item>
    <method>POST</method>
    <url>https://example.com/login</url>
    <host>https://example.com</host>
    <status>302</status>
    <mimeType>text/html</mimeType>
    <length>88</length>
    <parameter name="username" value="secret-password" type="body" />
  </item>
</burp:siteMap>`;

  const { items } = parseBurpRaw({ source: 'burp-xml', raw, host: 'example.com' });
  assert.equal(items.length, 2);

  assert.equal(items[0].method, 'GET');
  assert.equal(items[0].host, 'example.com');
  assert.equal(items[0].status, 200);
  assert.equal(items[0].contentType, 'text/html');
  assert.ok(items[0].queryParams.includes('q'));
  assert.ok(items[0].queryParams.includes('lang'));
  assert.equal(items[0].url, 'https://example.com/search');

  assert.equal(items[1].method, 'POST');
  assert.ok(items[1].bodyParams.includes('username'));

  const serialised = JSON.stringify(items);
  assert.ok(!serialised.includes('secret-query-value'));
  assert.ok(!serialised.includes('secret-password'));
});

test('parseBurpRaw parses HAR entries', () => {
  const har = {
    log: {
      entries: [
        {
          request: {
            method: 'POST',
            url: 'https://api.example.com/v1/widgets?debug=1',
            queryString: [{ name: 'debug', value: '1' }],
            headers: [{ name: 'Content-Type', value: 'application/json' }],
            postData: { mimeType: 'application/json', params: [{ name: 'csrf', value: 'topsecret' }] },
          },
          response: { status: 201, headers: [], content: { mimeType: 'application/json', size: 42 } },
        },
      ],
    },
  };

  const { items } = parseBurpRaw({ source: 'har', raw: JSON.stringify(har) });
  assert.equal(items.length, 1);
  assert.equal(items[0].method, 'POST');
  assert.equal(items[0].status, 201);
  assert.equal(items[0].contentType, 'application/json');
  assert.equal(items[0].length, 42);
  assert.ok(items[0].queryParams.includes('debug'));
  assert.ok(items[0].bodyParams.includes('csrf'));
  assert.deepEqual(items[0].headers, [{ name: 'content-type', value: '' }]);
  assert.ok(!JSON.stringify(items).includes('topsecret'));
});

test('parseBurpRaw parses curl commands, keeping only header and param names', () => {
  const raw = [
    "curl -X POST 'https://api.example.com/v1/items?debug=1' \\",
    "  -H 'Content-Type: application/json' \\",
    "  -H 'Cookie: session=abc123' \\",
    "  -d '{\"name\":\"widget\",\"qty\":\"2\"}' \\",
    "  -d 'x=1&y=2'",
  ].join('\n');

  const { items } = parseBurpRaw({ source: 'curl', raw });
  assert.equal(items.length, 1);
  assert.equal(items[0].method, 'POST');
  assert.equal(items[0].url, 'https://api.example.com/v1/items');
  assert.ok(items[0].queryParams.includes('debug'));
  for (const name of ['name', 'qty', 'x', 'y']) assert.ok(items[0].bodyParams.includes(name));
  assert.ok(items[0].headers.some((h) => h.name === 'content-type'));
  assert.ok(!items[0].headers.some((h) => h.name === 'cookie'));
  const serialised = JSON.stringify(items);
  assert.ok(!serialised.includes('abc123'));
  assert.ok(!serialised.includes('widget'));
});

test('parseBurpRaw parses newline-separated URLs', () => {
  const raw = 'https://a.example.com/p?one=1\nhttps://b.example.com/q?two=2\nnot a url';
  const { items } = parseBurpRaw({ raw });
  assert.equal(items.length, 2);
  assert.ok(items[0].queryParams.includes('one'));
  assert.ok(items[1].queryParams.includes('two'));
  assert.equal(items[0].method, 'GET');
});

test('redactObject removes sensitive keys and truncates strings', () => {
  const out = redactObject({
    token: 'abc',
    authorization: 'Bearer xyz',
    name: 'keep',
    nested: { password: 'p', keep: 'v' },
    arr: [{ secret: 's', id: 1 }],
    long: 'x'.repeat(500),
  });
  assert.ok(!('token' in out));
  assert.ok(!('authorization' in out));
  assert.equal(out.name, 'keep');
  assert.ok(!('password' in out.nested));
  assert.equal(out.nested.keep, 'v');
  assert.ok(!('secret' in out.arr[0]));
  assert.ok(out.long.length < 500);
});

test('util helpers behave predictably', () => {
  assert.equal(slug('Hello World!'), 'hello-world');
  assert.ok(nowIso().endsWith('Z'));
});

test('dotted-path matcher resolves arrays and evaluates when clauses', () => {
  const observation = {
    signals: { hasForm: true, hasGraphql: false },
    queryParams: [{ name: 'id' }],
    cookies: [{ name: 'session', httpOnly: true }],
    technologies: [{ name: 'PHP' }],
    domSinks: [{ type: 'innerHTML' }],
  };
  assert.deepEqual(resolvePath(observation, 'queryParams[].name'), ['id']);
  assert.deepEqual(resolvePath(observation, 'cookies[].name'), ['session']);
  assert.equal(matchesWhen({ any: ['signals.hasForm'] }, observation).matched, true);
  assert.equal(matchesWhen({ all: ['signals.hasGraphql'] }, observation).matched, false);
  assert.equal(matchesWhen({ any: ['domSinks[].type=innerHTML'] }, observation).matched, true);
});

test('analyze builds local cards from a tiny fake KB', async () => {
  const kb = {
    generatedAt: '2026-01-01T00:00:00.000Z',
    skills: [
      {
        id: 'sqli',
        name: 'SQL Injection',
        description: 'Injection testing guidance',
        categories: ['injection'],
        sections: [
          {
            heading: 'Manual tests',
            bullets: [
              'Send a benign marker in the parameter and observe the response.',
              'Compare response length with the baseline.',
              'Try a quoted variant and note error behaviour.',
            ],
          },
        ],
        codeBlocks: ["' OR 1=1-- "],
        sourcePath: '/skills/offensive-sqli/SKILL.md',
      },
    ],
    rules: [
      {
        id: 'rule-sqli',
        when: { any: ['signals.hasForm', 'queryParams[].name'] },
        skillIds: ['sqli'],
        category: 'injection',
        priority: 10,
      },
    ],
  };

  const observation = {
    url: 'https://example.com/items',
    host: 'example.com',
    path: '/items',
    signals: { hasForm: true },
    queryParams: [{ name: 'id' }],
    technologies: [{ name: 'PHP' }],
    cookies: [],
    headers: [],
    domSinks: [],
  };

  const result = await analyze({ observation, traffic: [], options: { ai: false, maxCards: 5 }, kb });
  assert.equal(result.cards.length, 1);
  assert.equal(result.cards[0].source, 'local');
  assert.equal(result.cards[0].skillId, 'sqli');
  assert.equal(result.cards[0].category, 'injection');
  assert.equal(result.cards[0].severityHint, 'high');
  assert.ok(result.cards[0].steps.length >= 3);
  assert.ok(result.cards[0].payloads.length >= 1);
  assert.ok(result.summary.tech.includes('PHP'));
  assert.ok(result.summary.surface.queryParamNames.includes('id'));
  assert.equal(result.aiUsed, false);
  assert.ok(result.generatedAt.endsWith('Z'));

  // v2: every card and the summary carry OWASP Top 10 mapping.
  assert.deepEqual(result.cards[0].owasp, { id: 'A03', name: 'Injection' });
  assert.equal(result.summary.owasp.length, 10);
  assert.ok(result.summary.owasp.every((c) => typeof c.cardCount === 'number'));
  assert.equal(result.summary.owasp.find((c) => c.id === 'A03').cardCount, 1);
  assert.equal(result.summary.owasp.find((c) => c.id === 'A10').cardCount, 0);
});

test('mapOwasp resolves categories, skill ids and signals deterministically', () => {
  assert.equal(OWASP_CATEGORIES.length, 10);
  assert.deepEqual(mapOwasp('idor', 'offensive-idor'), { id: 'A01', name: 'Broken Access Control' });
  assert.deepEqual(mapOwasp('sqli', 'offensive-sqli'), { id: 'A03', name: 'Injection' });
  assert.deepEqual(mapOwasp('jwt', 'offensive-jwt'), { id: 'A07', name: 'Auth Failures' });
  assert.deepEqual(mapOwasp('ssrf', 'offensive-ssrf'), { id: 'A10', name: 'SSRF' });
  assert.equal(mapOwasp('', 'offensive-deserialization').id, 'A08');
  assert.equal(mapOwasp('', '', { hasUrlParam: true }).id, 'A10');
  assert.equal(mapOwasp('', '', { hasDomSink: true }).id, 'A03');
  assert.equal(mapOwasp('', '').id, 'A05');
});

test('appendLive retains passive/live sources and summarises by source', () => {
  clearTraffic('source-test.example');
  appendLive('source-test.example', { url: 'http://source-test.example/a', source: 'browser-passive' });
  appendLive('source-test.example', { url: 'http://source-test.example/b', source: 'live' });
  const summary = getTrafficSummary('source-test.example');
  assert.equal(summary.total, 2);
  assert.equal(summary.bySource['browser-passive'], 1);
  assert.equal(summary.bySource.live, 1);
  clearTraffic('source-test.example');
});

test('crawlSite obeys same-host, risky-link and value-safety rules', async (t) => {
  const home = `<!doctype html>
<html><head><title>Home Page</title></head><body>
  <form action="/search" method="post">
    <input type="text" name="q" id="search-q" placeholder="Search here" required>
    <input type="file" name="avatar">
  </form>
  <a href="/about?debug=true&secret=TOPSECRETVALUE#section">About</a>
  <a href="/logout">Log out</a>
  <a href="http://example.invalid/outside">Outside</a>
  <a href="/?secret=other&q=other">Home again</a>
  <script src="/app.js"></script>
  <script>fetch('/api/items'); axios.get('/graphql');</script>
</body></html>`;
  const about = `<!doctype html>
<html><head><title>About Us</title></head><body><h1>About</h1></body></html>`;

  const server = http.createServer((req, res) => {
    const path = new URL(req.url || '/', 'http://127.0.0.1').pathname;
    res.setHeader('content-type', 'text/html; charset=utf-8');
    if (path === '/') res.end(home);
    else if (path === '/about') res.end(about);
    else {
      res.statusCode = 404;
      res.end('<html><title>Missing</title></html>');
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  t.after(() => new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(resolve);
  }));

  const result = await crawlSite({
    url: `http://127.0.0.1:${port}/?secret=TOPSECRETVALUE&q=QVALUE123`,
    maxPages: 5,
    maxDepth: 2,
    delayMs: 0,
  });

  assert.equal(result.host, '127.0.0.1');
  assert.ok(result.startUrl.includes('/?secret&q'));
  assert.equal(result.pages.length, 2);
  assert.equal(result.stats.pagesCrawled, 2);
  assert.deepEqual(
    result.pages.map((p) => p.title).sort(),
    ['About Us', 'Home Page'],
  );
  assert.ok(result.stats.skipped >= 2, 'risky and off-host links are skipped');
  assert.ok(result.pages.every((p) => !/logout|example\.invalid/.test(p.url)));

  const form = result.inventory.forms.find((f) => f.action === '/search');
  assert.ok(form, 'form inventory contains the observed form');
  assert.equal(form.method, 'POST');
  assert.ok(form.selector && form.xpath);
  assert.ok(form.fields.some((f) => f.name === 'q' && f.type === 'text'));
  assert.ok(form.fields.some((f) => f.name === 'avatar' && f.type === 'file'));

  const input = result.inventory.inputs.find((i) => i.name === 'q');
  assert.ok(input, 'flattened inputs are present');
  assert.equal(input.formSelector, form.selector);
  assert.ok(input.selector && input.xpath);

  const paramNames = result.inventory.urlParams.map((p) => p.name);
  for (const name of ['secret', 'q', 'debug']) assert.ok(paramNames.includes(name));
  assert.ok(result.inventory.urlParams.every((p) => p.page));

  const endpointUrls = result.inventory.endpoints.map((e) => e.url);
  assert.ok(endpointUrls.some((u) => u.endsWith('/api/items')));
  assert.ok(endpointUrls.some((u) => u.endsWith('/graphql')));
  assert.ok(result.inventory.endpoints.every((e) => e.page && e.source));

  const serialised = JSON.stringify(result);
  assert.ok(!serialised.includes('TOPSECRETVALUE'), 'query values are never stored');
  assert.ok(!serialised.includes('QVALUE123'), 'query values are never stored');

  const storedUrls = [
    result.startUrl,
    ...result.pages.map((p) => p.url),
    ...result.pages.flatMap((p) => p.links.map((l) => l.href)),
    ...result.inventory.endpoints.map((e) => e.url),
  ];
  assert.ok(storedUrls.every((u) => !u.includes('#')), 'fragments are never preserved');
});

test('crawlSite discovers SPA routes from same-host JavaScript bundles', async (t) => {
  const shell = `<!doctype html><html><head><title>SPA Shell</title>
  <script type="module" crossorigin src="/assets/app.js"></script>
  <link rel="modulepreload" href="/assets/vendor.js">
  </head><body><div id="root"></div></body></html>`;
  const bundle = `
    const routes = [
      { path: "/about/history", component: History },
      { path: '/contact-us', component: Contact },
      { path: "/logout", component: Logout },
      { path: "/assets/logo.svg", component: Logo },
      { path: "/api/items", component: Items },
      { path: "/user/:id/profile", component: Profile },
    ];
    const SECRET_BUNDLE_VALUE = "NEVER-EMIT-THIS";
  `;

  const server = http.createServer((req, res) => {
    const path = new URL(req.url || '/', 'http://127.0.0.1').pathname;
    if (path === '/assets/app.js' || path === '/assets/vendor.js') {
      res.setHeader('content-type', 'application/javascript');
      res.end(bundle);
      return;
    }
    res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(shell);
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  t.after(() => new Promise((resolve) => {
    server.closeAllConnections?.();
    server.close(resolve);
  }));

  const result = await crawlSite({
    url: `http://127.0.0.1:${port}/`,
    maxPages: 5,
    maxDepth: 2,
    delayMs: 0,
  });

  assert.ok(result.pages.length >= 3, 'routes from the JS bundle were crawled');
  assert.ok(result.stats.jsBundlesFetched >= 1);
  assert.ok(result.stats.jsRoutesDiscovered >= 2);
  const urls = result.pages.map((p) => p.url);
  assert.ok(urls.some((u) => u.endsWith('/about/history')));
  assert.ok(urls.some((u) => u.endsWith('/contact-us')));
  assert.ok(!urls.some((u) => /logout|\/api\/|\.svg/.test(u)), 'risky, API and static routes are skipped');
  assert.ok(!JSON.stringify(result).includes('NEVER-EMIT-THIS'), 'bundle source is never stored');
});

test('crawlSite never throws for invalid or non-http URLs', async () => {
  const invalid = await crawlSite({ url: 'not a url' });
  assert.equal(invalid.pages.length, 0);
  assert.ok(invalid.warnings.length > 0);

  const unsupported = await crawlSite({ url: 'ftp://example.com/file' });
  assert.equal(unsupported.pages.length, 0);
  assert.ok(unsupported.warnings.some((w) => /http/i.test(w)));
});
