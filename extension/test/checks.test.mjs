import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluateSecurityHeaders, buildSecurityChecks, SECURITY_HEADER_KEYS } from '../src/core/checks.js';

const GOOD_HEADERS = [
  { name: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; object-src 'none'" },
  { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { name: 'X-Frame-Options', value: 'DENY' },
  { name: 'X-Content-Type-Options', value: 'nosniff' },
  { name: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { name: 'Permissions-Policy', value: 'camera=(), geolocation=()' },
];

test('evaluateSecurityHeaders accepts an allowlisted set of strong headers', () => {
  const result = evaluateSecurityHeaders({ headers: GOOD_HEADERS });
  assert.equal(result.available, true);
  assert.equal(result.summary.ok, 6);
  assert.equal(result.summary.weak, 0);
  assert.equal(result.summary.missing, 0);
  assert.ok(result.results.every((r) => r.status === 'ok'));
  assert.ok(result.results.every((r) => r.owasp?.id));
});

test('evaluateSecurityHeaders flags missing and weak headers', () => {
  const result = evaluateSecurityHeaders({
    headers: [
      { name: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'" },
      { name: 'Strict-Transport-Security', value: 'max-age=100' },
    ],
  });
  const byKey = Object.fromEntries(result.results.map((r) => [r.key, r]));
  assert.equal(byKey['content-security-policy'].status, 'weak');
  assert.equal(byKey['strict-transport-security'].status, 'weak');
  assert.equal(result.summary.weak, 2);
  assert.equal(result.summary.missing, 4);
  assert.equal(byKey['x-frame-options'].status, 'missing');
  assert.ok(byKey['x-frame-options'].manualCheck.length > 0);
  assert.equal(SECURITY_HEADER_KEYS.length, 6);
});

test('buildSecurityChecks produces copy-only port and TLS guidance for the current host', () => {
  const checks = buildSecurityChecks({
    url: 'https://target.example.test:8443/login?id=7',
    host: 'ignored.example.test',
    headers: GOOD_HEADERS,
  });
  assert.equal(checks.targetHost, 'target.example.test');
  assert.ok(checks.guidance.some((g) => g.tool === 'nmap' && g.command.includes('--top-ports')));
  assert.ok(checks.guidance.some((g) => g.tool === 'testssl.sh' && g.command.includes('target.example.test:443')));
  assert.ok(checks.guidance.some((g) => g.tool === 'openssl' && g.command.includes('-tls1_2')));
  assert.ok(checks.guidance.every((g) => typeof g.command === 'string' && !g.command.includes('ignored.example.test')));
  assert.match(checks.scope, /Guidance only[\s\S]*does not run these commands/);
  assert.ok(checks.guidance.every((g) => ['ports', 'tls'].includes(g.area)));
});

test('buildSecurityChecks never emits executable scanning code or secret values', () => {
  const checks = buildSecurityChecks({
    url: 'https://target.example.test/',
    headers: [{ name: 'authorization', value: 'Bearer SECRET-SHOULD-NOT-LEAK' }],
  });
  const text = JSON.stringify(checks);
  assert.ok(!text.includes('SECRET-SHOULD-NOT-LEAK'));
  assert.ok(!/\b(fetch|net\.connect|createConnection|http\.request)\s*\(/.test(text));
});
