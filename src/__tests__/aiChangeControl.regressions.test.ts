/**
 * Regression tests for two defects fixed in PR B2. They import ONLY exports that existed before the fix, so
 * against the pre-fix code they fail on the assertion that describes the defect, not on an import error.
 *
 *  N1  A finding in a file whose path holds 8+ consecutive digits (every Supabase migration) made ci-scan-result
 *      reject the WHOLE post (looksUnmasked). The Action now groups such runs in POSTED evidence.
 *  R14 A schema-2 post refused with 400 was retried in the legacy shape; when that succeeded, the other
 *      frameworks' verdicts were dropped with no trace. The outcome now names them.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildSchema2Payload, postResults } from '../report.js';
import { scan } from '../scan.js';
import type { FrameworkRuleset } from '../types.js';

const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const eu: FrameworkRuleset = {
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [],
  rules: [{ id: 'eaa-ci-ai-endpoint', name: 'Endpoint', articles: [], relevance: ['assessment'], action: 'review', tier: 2,
    detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Hosted model endpoint' } }],
};
const dc: FrameworkRuleset = { ...eu, framework: 'Data Compliance', ruleset_version: 3, ruleset_hash: 'a'.repeat(64), rules: [],
  signatures: { 'telemetry-sdks': [], 'pii-datastore-credentials': [], 'processor-jurisdiction': [] } };
// Built at runtime: no literal 8+ digit run in a committed fixture.
const MIGRATION = `supabase/migrations/${['2026', '1007', '0900', '00'].join('')}_x.sql`;
const diff = [`diff --git a/${MIGRATION} b/${MIGRATION}`, `--- a/${MIGRATION}`, `+++ b/${MIGRATION}`, '@@ -1,1 +1,2 @@', ' --', "+VALUES ('https://api.openai.com');"].join('\n');

describe('N1: posted evidence holds no 8+ digit run', () => {
  it('a finding in a timestamped migration is posted without the raw timestamp', () => {
    const result = scan(eu, { diff });
    expect(result.findings).toHaveLength(1);
    const body = buildSchema2Payload({ repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' },
      [{ framework: 'EU AI Act', ruleset: eu, result, advisory: true }]);
    for (const f of body.results[0].findings) expect(f.masked_evidence).not.toMatch(/\d{8,}/);
  });
});

describe('R14: a partial record is reported', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('400 on the schema-2 post + legacy retry OK → the EU AI Act verdict is named as not recorded', async () => {
    let n = 0;
    vi.stubGlobal('fetch', vi.fn(async () => (++n === 1
      ? { ok: false, status: 400, json: async () => ({ error: { code: 'bad_request' } }) }
      : { ok: true, status: 200, json: async () => ({}) }) as unknown as Response));
    const none = { verdict: 'pass' as const, findings: [], warnings: [] };
    const post = await postResults('https://pc.example', 't', { repo: 'Acme/App', pr_number: 1, commit_sha: 'abc' },
      [{ framework: 'Data Compliance', ruleset: dc, result: none, advisory: false }, { framework: 'EU AI Act', ruleset: eu, result: none, advisory: true }],
      'schema2');
    expect(post.ok).toBe(true);
    expect((post as { notRecorded?: string[] }).notRecorded).toEqual(['EU AI Act']);
  });
});
