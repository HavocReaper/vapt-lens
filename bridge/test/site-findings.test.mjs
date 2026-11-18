import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSiteFindings,
  buildTrafficFindings,
  OWASP_SCAN_CATEGORIES,
  EMPTY_OWASP_COUNTS,
} from '../lib/site-findings.mjs';

const FINDING_KEYS = [
  'id',
  'owasp',
  'severity',
  'title',
  'possibleVulnerability',
  'url',
  'point',
  'evidence',
  'manualCheck',
  'source',
];

function fullCrawl() {
  const url = 'http://target.example.test/login';
  return {
    startUrl: 'http://target.example.test/',
    host: 'target.example.test',
    pages: [
      {
        url,
        status: 200,
        title: 'Login',
        forms: [
          {
            action: '',
            method: 'POST',
            selector: '#login',
            xpath: "//form[@id='login']",
            fields: [
              { name: 'username', type: 'text', id: 'u', selector: '#u', formSelector: '#login' },
              { name: 'password', type: 'password', id: 'p', selector: '#p', formSelector: '#login' },
              { name: 'role', type: 'hidden', id: 'r', selector: '#r', formSelector: '#login' },
            ],
          },
          {
            action: '/go',
            method: 'GET',
            selector: '#pwGet',
            xpath: "//form[@id='pwGet']",
            fields: [
              { name: 'password', type: 'password', id: 'pg', selector: '#pg', formSelector: '#pwGet' },
            ],
          },
          {
            action: '/upload',
            method: 'POST',
            selector: '#upload',
            xpath: "//form[@id='upload']",
            fields: [{ name: 'file', type: 'file', id: 'f', selector: '#f', formSelector: '#upload' }],
          },
        ],
        inputs: [
          { name: 'username', type: 'text', id: 'u', selector: '#u', formSelector: '#login' },
          { name: 'password', type: 'password', id: 'p', selector: '#p', formSelector: '#login' },
          { name: 'role', type: 'hidden', id: 'r', selector: '#r', formSelector: '#login' },
          { name: 'password', type: 'password', id: 'pg', selector: '#pg', formSelector: '#pwGet' },
          { name: 'file', type: 'file', id: 'f', selector: '#f', formSelector: '#upload' },
          { name: 'q', type: 'search', id: 'q', selector: '#q', formSelector: '#search' },
        ],
        queryParams: [
          { name: 'id', valueLength: 2, location: 'query', page: url },
          { name: 'q', valueLength: 4, location: 'query', page: url },
          { name: 'debug', valueLength: 1, location: 'query', page: url },
          { name: 'url', valueLength: 12, location: 'query', page: url },
          { name: 'sort', valueLength: 4, location: 'query', page: url },
        ],
        links: [],
        scripts: [
          { src: 'http://target.example.test/js/jquery-1.8.js', inlineLength: 0 },
          { src: 'https://cdn.other.test/lib.js', inlineLength: 0 },
          { src: '', inlineLength: 42 },
        ],
        endpoints: [
          { url: 'http://target.example.test/admin/', source: 'fetch' },
          { url: 'http://target.example.test/api/items?q', source: 'fetch' },
        ],
        signals: {
          hasForm: true,
          hasTextInput: true,
          hasLogin: true,
          hasUpload: true,
          hasDebugParam: true,
          hasIdParam: true,
          hasUrlParam: true,
          hasInlineScript: true,
          hasCsrfTokenField: false,
          hasApiBase: true,
        },
        headers: [
          { name: 'server', value: 'Apache/2.4.1' },
          { name: 'strict-transport-security', value: 'max-age=300' },
          { name: 'referrer-policy', value: 'unsafe-url' },
        ],
        domSinks: ['innerHTML', 'eval', 'location.href'],
      },
    ],
    inventory: { forms: [], inputs: [], urlParams: [], endpoints: [] },
    stats: { pagesCrawled: 1, skipped: 0, maxPagesReached: false },
    warnings: [],
  };
}

test('buildSiteFindings maps passive crawl metadata to OWASP categories with exact points', () => {
  const result = buildSiteFindings(fullCrawl());
  const url = 'http://target.example.test/login';
  const points = result.findings.map((f) => f.point);

  assert.ok(result.findings.length > 0);
  assert.equal(result.summary.total, result.findings.length);
  assert.equal(result.summary.pagesCovered, 1);
  assert.equal(result.summary.high + result.summary.medium + result.summary.low, result.summary.total);

  for (const finding of result.findings) {
    assert.deepEqual(Object.keys(finding).sort(), [...FINDING_KEYS].sort());
    assert.equal(finding.url, url);
    assert.ok(['high', 'medium', 'low'].includes(finding.severity));
    assert.deepEqual(Object.keys(finding.owasp).sort(), ['id', 'name']);
    assert.ok(['query', 'form', 'header', 'endpoint', 'script', 'dom', 'signal'].includes(finding.source));
    assert.match(finding.possibleVulnerability, /may|could|possible|might/i);
  }

  const expected = [
    ['A01', 'query parameter "id" in URL'],
    ['A01', 'form #login -> input[name="role"]'],
    ['A01', 'form #login (method POST)'],
    ['A01', 'endpoint http://target.example.test/admin/ (source: fetch)'],
    ['A02', 'page URL (http:// login form)'],
    ['A02', 'response header Content-Security-Policy'],
    ['A02', 'response header Strict-Transport-Security'],
    ['A02', 'response header Referrer-Policy'],
    ['A03', 'form #search -> input[name="q"]'],
    ['A03', 'query parameter "q" in URL'],
    ['A03', 'query parameter "sort" in URL'],
    ['A03', 'endpoint http://target.example.test/api/items?q (source: fetch)'],
    ['A04', 'form #upload -> input[name="file"]'],
    ['A04', 'query parameter "debug" in URL'],
    ['A05', 'response header Server'],
    ['A05', 'inline script on page'],
    ['A06', 'script src http://target.example.test/js/jquery-1.8.js'],
    ['A07', 'form #login (login flow)'],
    ['A07', 'form #pwGet'],
    ['A08', 'DOM sink: innerHTML'],
    ['A08', 'DOM sink: eval'],
    ['A08', 'script src https://cdn.other.test/lib.js'],
    ['A10', 'query parameter "url" in URL'],
  ];
  for (const [owaspId, point] of expected) {
    assert.ok(
      result.findings.some((f) => f.owasp.id === owaspId && f.point === point && f.url === url),
      `missing finding ${owaspId} at ${point}`,
    );
  }

  // domSinks also contained location.href, which has no passive rule here.
  assert.ok(!points.includes('DOM sink: location.href'));
  assert.ok(result.findings.some((f) => f.id === 'A03-injection-0-1'));

  for (const { id } of OWASP_SCAN_CATEGORIES) {
    assert.ok(Object.hasOwn(result.byOwasp, id), `byOwasp must include ${id}`);
  }
  assert.equal(result.byOwasp.A09, 0);
  assert.ok(!result.findings.some((f) => f.owasp.id === 'A09'));
  assert.equal(
    Object.values(result.byOwasp).reduce((a, b) => a + b, 0),
    result.findings.length,
  );
  assert.match(result.scope, /^Passive inference only/);
  assert.match(result.scope, /manual verification required\.$/);
});

test('buildSiteFindings never emits parameter, header or URL values', () => {
  const url = 'https://target.example.test/search?q=SECRET&debug=SECRET#SECRET';
  const crawl = {
    host: 'target.example.test',
    pages: [
      {
        url,
        status: 200,
        queryParams: [
          { name: 'q', valueLength: 6, location: 'query', page: url },
          { name: 'debug', valueLength: 6, location: 'query', page: url },
        ],
        signals: {},
        headers: [{ name: 'server', value: 'Apache/2.4.1' }],
        scripts: [{ src: 'https://cdn.other.test/lib.js?token=SECRET', inlineLength: 0 }],
        endpoints: [{ url: 'https://target.example.test/api/x?url=SECRET', source: 'fetch' }],
        domSinks: [],
      },
    ],
  };

  const result = buildSiteFindings(crawl);
  const serialised = JSON.stringify(result);
  assert.ok(!serialised.includes('SECRET'), 'serialized findings must not contain the fake secret');
  for (const finding of result.findings) {
    assert.ok(!finding.url.includes('SECRET'));
    assert.ok(!finding.point.includes('SECRET'));
    assert.ok(!finding.evidence.includes('SECRET'));
    assert.ok(!finding.manualCheck.includes('SECRET'));
  }
  assert.ok(result.findings.some((f) => f.url === 'https://target.example.test/search?q&debug'));
  assert.ok(result.findings.some((f) => f.point === 'script src https://cdn.other.test/lib.js?token'));
  assert.ok(result.findings.some((f) => f.point === 'endpoint https://target.example.test/api/x?url (source: fetch)'));
});

test('buildSiteFindings tolerates empty and malformed input', () => {
  for (const input of [undefined, {}, null, 'not-an-object', { pages: [null, 42] }]) {
    const result = buildSiteFindings(input);
    assert.deepEqual(result.byOwasp, EMPTY_OWASP_COUNTS());
    assert.deepEqual(result.summary, { total: 0, high: 0, medium: 0, low: 0, pagesCovered: 0 });
    assert.deepEqual(result.findings, []);
    assert.equal(typeof result.scope, 'string');
  }
  assert.equal(OWASP_SCAN_CATEGORIES.length, 10);
  assert.equal(OWASP_SCAN_CATEGORIES[0].id, 'A01');
  assert.equal(OWASP_SCAN_CATEGORIES[9].id, 'A10');
});

test('buildSiteFindings dedupes identical url + point + owasp occurrences', () => {
  const result = buildSiteFindings({
    host: 'dup.example.test',
    pages: [
      {
        url: 'https://dup.example.test/p?id=ignored',
        queryParams: [
          { name: 'id', valueLength: 7, location: 'query' },
          { name: 'id', valueLength: 7, location: 'query' },
          { name: 'id', valueLength: 7, location: 'query' },
        ],
        signals: {},
      },
    ],
  });

  assert.equal(result.findings.length, 1);
  assert.equal(result.byOwasp.A01, 1);
  assert.equal(result.findings[0].point, 'query parameter "id" in URL');
  assert.ok(!JSON.stringify(result).includes('ignored'));
});

test('buildSiteFindings caps the total number of findings at 80', () => {
  const pages = Array.from({ length: 100 }, (_, i) => ({
    url: `https://cap.example.test/p/${i}?id`,
    queryParams: [{ name: 'id', valueLength: 1, location: 'query' }],
    signals: {},
  }));
  const result = buildSiteFindings({ host: 'cap.example.test', pages });

  assert.equal(result.findings.length, 80);
  assert.equal(result.summary.total, 80);
  assert.equal(result.summary.pagesCovered, 80);
  assert.equal(result.byOwasp.A01, 80);
});

test('buildSiteFindings prioritizes high-severity findings within the cap', () => {
  const pages = Array.from({ length: 100 }, (_, i) => ({
    url: `https://priority.example.test/p/${i}`,
    status: 200,
    signals: {},
    headers: [{ name: 'server', value: `nginx/${i}.0` }],
  }));
  pages[99].queryParams = [{ name: 'id', valueLength: 2, location: 'query' }];

  const result = buildSiteFindings({ host: 'priority.example.test', pages });
  assert.equal(result.findings.length, 80);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0].owasp.id, 'A01');
  assert.ok(!result.findings.some((f) => f.severity === 'low' && f.url.includes('/p/0')));
});

function trafficItems() {
  return [
    {
      method: 'GET',
      url: 'http://traffic.example.test/login?id=SECRET&debug=SECRET',
      path: '/login',
      host: 'traffic.example.test',
      queryParams: ['id', 'debug'],
      bodyParams: [],
      headers: [{ name: 'server', value: '' }],
      status: 200,
      source: 'live',
    },
    {
      method: 'POST',
      url: 'https://traffic.example.test/api/items?id=SECRET&q=SECRET&sort=SECRET',
      path: '/api/items',
      host: 'traffic.example.test',
      queryParams: ['id', 'q', 'sort'],
      bodyParams: ['url', 'role'],
      headers: [{ name: 'content-security-policy', value: '' }],
      status: 200,
      source: 'live',
    },
    {
      method: 'POST',
      url: 'https://traffic.example.test/admin/users',
      path: '/admin/users',
      host: 'traffic.example.test',
      queryParams: [],
      bodyParams: ['userid', 'csrf-token'],
      headers: [],
      status: null,
      source: 'live',
    },
  ];
}

test('buildTrafficFindings maps captured request metadata to exact OWASP locations', () => {
  const result = buildTrafficFindings(trafficItems());
  const find = (owaspId, point) =>
    result.findings.find((f) => f.owasp.id === owaspId && f.point === point);

  assert.ok(result.findings.length > 0);
  assert.equal(result.summary.total, result.findings.length);
  assert.equal(
    result.summary.high + result.summary.medium + result.summary.low,
    result.summary.total,
  );
  for (const finding of result.findings) {
    assert.deepEqual(Object.keys(finding).sort(), [...FINDING_KEYS].sort());
    assert.ok(finding.url.startsWith('http'));
    assert.ok(finding.point.includes('Burp traffic'));
    assert.ok(String(finding.source).startsWith('burp'));
    assert.match(finding.possibleVulnerability, /may|could|possible|might/i);
  }

  assert.ok(find('A01', 'captured GET /login -> query parameter "id" (Burp traffic)'));
  assert.ok(find('A01', 'captured POST /api/items -> query parameter "id" (Burp traffic)'));
  assert.ok(find('A01', 'captured POST /admin/users (Burp traffic)'));
  assert.ok(find('A02', 'captured GET /login -> request URL uses http:// (Burp traffic)'));
  assert.ok(find('A02', 'captured GET /login -> response header Content-Security-Policy (Burp traffic)'));
  assert.ok(find('A03', 'captured POST /api/items -> query parameter "sort" (Burp traffic)'));
  assert.ok(find('A04', 'captured GET /login -> query parameter "debug" (Burp traffic)'));
  assert.ok(find('A10', 'captured POST /api/items -> body parameter "url" (Burp traffic)'));

  const idor = find('A01', 'captured POST /api/items -> query parameter "id" (Burp traffic)');
  assert.equal(idor.url, 'https://traffic.example.test/api/items?id&q&sort');
  assert.equal(result.byOwasp.A09, 0);
  assert.ok(!result.findings.some((f) => f.owasp.id === 'A09'));
  assert.match(result.scope, /^Passive inference only from captured Burp traffic metadata/);
  assert.ok(!JSON.stringify(result).includes('SECRET'), 'traffic values must never be emitted');
});

test('buildTrafficFindings dedupes request/response pairs and tolerates malformed items', () => {
  const item = {
    method: 'POST',
    url: 'https://dup-traffic.example.test/api/items?search',
    path: '/api/items',
    queryParams: ['search'],
    bodyParams: [],
    headers: [{ name: 'server', value: '' }],
    status: 200,
    source: 'live',
  };
  const result = buildTrafficFindings([
    item,
    { ...item, status: null },
    null,
    42,
    'noise',
    { method: '', url: '' },
  ]);

  const points = result.findings.map((f) => f.point);
  const searchPoints = points.filter((p) => p.includes('query parameter "search"'));
  assert.equal(searchPoints.length, 1, 'duplicate request metadata collapses to one finding');
  assert.equal(result.findings.filter((f) => f.owasp.id === 'A05').length, 1, 'response-only header check is not duplicated');

  for (const input of [undefined, {}, null, 'not-an-object', [null, 42]]) {
    const empty = buildTrafficFindings(input);
    assert.deepEqual(empty.byOwasp, EMPTY_OWASP_COUNTS());
    assert.deepEqual(empty.summary, { total: 0, high: 0, medium: 0, low: 0, pagesCovered: 0 });
    assert.deepEqual(empty.findings, []);
  }
});

test('buildTrafficFindings keeps high-severity observations within the 80-finding cap', () => {
  const items = Array.from({ length: 100 }, (_, i) => ({
    method: 'POST',
    url: `https://cap-traffic.example.test/p/${i}`,
    path: `/p/${i}`,
    bodyParams: ['role'],
    headers: [{ name: 'server', value: '' }],
    status: 200,
    source: 'live',
  }));
  items[99].queryParams = ['id'];

  const result = buildTrafficFindings(items);
  assert.equal(result.findings.length, 80);
  assert.equal(result.findings[0].severity, 'high');
  assert.equal(result.findings[0].owasp.id, 'A01');
  assert.ok(!result.findings.some((f) => f.severity === 'low' && f.url.includes('/p/0')));
});
