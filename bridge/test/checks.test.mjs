import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../lib/analyze.mjs';

test('analyze response includes passive security checks', async () => {
  const result = await analyze({
    observation: {
      url: 'https://target.example.test/login',
      headers: [{ name: 'X-Frame-Options', value: 'DENY' }],
      signals: { hasForm: true },
    },
    traffic: [],
    options: { ai: false, maxCards: 4 },
    kb: { skills: [], rules: [] },
  });

  assert.ok(result.checks, 'checks should be present in the analysis response');
  assert.equal(result.checks.headers.available, true);
  assert.equal(result.checks.headers.summary.ok, 1);
  assert.equal(result.checks.targetHost, 'target.example.test');
  assert.ok(result.checks.guidance.some((g) => g.area === 'ports'));
  assert.ok(result.checks.guidance.some((g) => g.area === 'tls'));
});
