/**
 * PR E: the baseline walker (AI usage inventory). Pure: the file lister/reader and the clock are injected.
 *
 * Self-contained on purpose: this file is mirrored to the public Action repository, which has no `supabase/`, so
 * the rules below are small stand-ins carrying the shipped rules' ids, path globs and flags. The shipped patterns
 * themselves are exercised by baselineShippedRules.test.ts (excluded from the mirror). What matters most is at the
 * bottom: no code line, no matched text and no file content can reach the payload.
 */
import { describe, expect, it } from 'vitest';
import {
  BASELINE_LIMITS,
  SIGNATURE_FAMILIES,
  aggregateObservations,
  runBaselineScan,
  selectBaselineRules,
  signatureKeyFor,
  type BaselineFileSource,
  type BaselineOptions,
} from '../baseline.js';
import { BASELINE_RULE_IDS, INVENTORY_LIMITS, SIGNATURE_KEYS, type SignatureKey } from '../inventoryContract.js';
import type { FrameworkRuleset, Rule } from '../types.js';

const MANIFEST = 'eaa-ci-ai-sdk-manifest', IMPORT = 'eaa-ci-ai-import', ENDPOINT = 'eaa-ci-ai-endpoint', EMOTION = 'eaa-ci-emotion-biometric';
/** The shipped rules' exclusion list for the import, endpoint and emotion rules (copied from the migration). */
const CODE_EXCLUDES = ['^docs/', '/docs/', '.md$', '.mdx$', '.markdown$', '.rst$', '__tests__/', '__fixtures__/', '^fixtures/', '/fixtures/', '^tests/', '/tests/', '^test/', '/test/', '.test.', '.spec.', '_test.go$', '_test.py$', '^testdata/', '/testdata/'];
const rule = (id: string, detect: Partial<Rule['detect']>): Rule => ({
  id, name: id, articles: [], relevance: ['assessment'], action: 'review', tier: 2, baseline: true,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', mask: id, ...detect },
});
const RULES: Rule[] = [
  rule(MANIFEST, {
    pattern: '(?i)^\\s*"(?:openai|@anthropic-ai/sdk)"\\s*:\\s*"[~^]?\\d|^\\s*openai\\s*[<>=]',
    file_scope: ['package.json$', 'requirements*.txt$'],
    exclude_paths: ['__fixtures__/', '^fixtures/', '/fixtures/', '^testdata/', '/testdata/'],
  }),
  rule(IMPORT, {
    pattern: '(?:\\bfrom\\s*["\\x27](?:openai|@anthropic-ai/sdk)["\\x27]|^\\s*from\\s+openai\\s+import\\b)',
    file_scope: ['.ts$', '.py$'],
    exclude_paths: CODE_EXCLUDES.filter((g) => !g.startsWith('.m') && g !== '.markdown$' && g !== '.rst$'),
  }),
  rule(ENDPOINT, { pattern: '(?i)(?:api\\.openai\\.com|api\\.anthropic\\.com|api\\.mistral\\.ai)', exclude_paths: CODE_EXCLUDES }),
  rule(EMOTION, { pattern: '(?:\\bDeepFace\\.analyze\\s*\\(|^\\s*import\\s+face_recognition\\b)', exclude_paths: CODE_EXCLUDES }),
];
const RULESET: FrameworkRuleset = {
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules: RULES,
  allowlist: { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] }, signatures: {} as FrameworkRuleset['signatures'], dropped_rules: [],
};

type Entry = string | Uint8Array | { size: number } | null;
function memSource(files: Record<string, Entry>, opts: { failRead?: string[] } = {}) {
  const reads: string[] = [];
  const sized: string[] = [];
  const enc = new TextEncoder();
  const source: BaselineFileSource = {
    async listFiles() { return Object.keys(files); },
    async size(p) {
      sized.push(p);
      const e = files[p];
      if (e === null || e === undefined) return null;
      if (typeof e === 'string') return enc.encode(e).length;
      if (e instanceof Uint8Array) return e.length;
      return e.size;
    },
    async read(p) {
      reads.push(p);
      if (opts.failRead?.includes(p)) throw new Error('EACCES');
      const e = files[p];
      if (typeof e === 'string') return enc.encode(e);
      if (e instanceof Uint8Array) return e;
      throw new Error('not readable');
    },
  };
  return { source, reads, sized };
}
const OPTS: BaselineOptions = { repo: 'Acme/App', commitSha: 'c0ffee', samplePaths: false };
const counts = (obs: Array<{ rule_id: string; signature_key: string; count: number }>) =>
  Object.fromEntries(obs.map((o) => [`${o.rule_id}|${o.signature_key}`, o.count]));

describe('selectBaselineRules', () => {
  it('needs BOTH the served flag and an allowlisted id', () => {
    const base = RULES.find((r) => r.id === ENDPOINT)!;
    const rs = (rules: Rule[]): FrameworkRuleset => ({ ...RULESET, rules });
    expect(selectBaselineRules(rs([{ ...base, baseline: undefined }]))).toEqual([]); // old server: no flag
    expect(selectBaselineRules(rs([{ ...base, baseline: 'true' as unknown as boolean }]))).toEqual([]); // not literally true
    expect(selectBaselineRules(rs([{ ...base, id: 'eaa-ci-model-changed', baseline: true }]))).toEqual([]); // flagged, not allowlisted
    expect(selectBaselineRules(rs([{ ...base, baseline: true }])).map((r) => r.id)).toEqual([ENDPOINT]);
  });

  it('tolerates a ruleset with no rules array entries that are not objects', () => {
    expect(selectBaselineRules({ ...RULESET, rules: [null, 'x'] as unknown as Rule[] })).toEqual([]);
  });
});

describe('signature family table', () => {
  it('names only contract signature keys, and reaches every AI key', () => {
    for (const [key] of SIGNATURE_FAMILIES) expect(SIGNATURE_KEYS as readonly string[]).toContain(key);
    const reachable = new Set<string>([...SIGNATURE_FAMILIES.map(([k]) => k), 'other-ai']);
    for (const key of SIGNATURE_KEYS) if (key !== 'emotion-biometric') expect(reachable).toContain(key);
    expect(SIGNATURE_FAMILIES.map(([k]) => k)).not.toContain('emotion-biometric');
  });

  it('the emotion rule always maps to emotion-biometric, whatever matched', () => {
    expect(signatureKeyFor(EMOTION, 'DeepFace.analyze(')).toBe('emotion-biometric');
    expect(signatureKeyFor(EMOTION, 'api.openai.com')).toBe('emotion-biometric');
  });

  it('an AI rule never maps to emotion-biometric, and an unknown match is other-ai', () => {
    expect(signatureKeyFor(IMPORT, 'import vllm')).toBe('other-ai');
    expect(signatureKeyFor(ENDPOINT, 'emotion')).toBe('other-ai');
  });
});

describe('runBaselineScan: aggregation', () => {
  it('counts matching LINES per (rule, key): two hits on one line count once, two lines count twice', async () => {
    const { source } = memSource({
      'src/a.ts': [
        'const a = "https://api.openai.com/v1"; const b = "https://api.openai.com/v2";',
        'const c = "https://api.openai.com/v3";',
        'const d = 1;',
      ].join('\n'),
      'src/b.ts': 'const x = "https://api.anthropic.com"; const y = "https://api.openai.com";\r\nconst z = 2;\r\n',
    });
    const { payload } = await runBaselineScan(RULES, source, OPTS);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|anthropic`]: 1, [`${ENDPOINT}|openai`]: 3 });
    expect(payload.files_scanned).toBe(2);
    expect(payload.truncated).toBe(false);
  });

  it('sorts observations by rule_id, then signature_key, and omits zero counts', async () => {
    const { source } = memSource({
      'package.json': '{\n  "dependencies": {\n    "openai": "^4.0.0",\n    "@anthropic-ai/sdk": "^0.27.0"\n  }\n}\n',
      'src/a.ts': "import OpenAI from 'openai';\nconst u = 'https://api.mistral.ai';\n",
      'app/face.py': 'import face_recognition\n',
    });
    const { payload } = await runBaselineScan(RULES, source, OPTS);
    expect(payload.observations.map((o) => `${o.rule_id}|${o.signature_key}`)).toEqual([
      `${ENDPOINT}|mistral`,
      `${IMPORT}|openai`,
      `${MANIFEST}|anthropic`,
      `${MANIFEST}|openai`,
      `${EMOTION}|emotion-biometric`,
    ]);
    expect(payload.observations.every((o) => o.count > 0)).toBe(true);
  });

  it('builds exactly the InventoryResultPayload shape', async () => {
    const { source } = memSource({ 'src/a.ts': 'const u = "https://api.openai.com";\n' });
    const { payload } = await runBaselineScan(RULES, source, OPTS);
    expect(payload).toEqual({
      repo: 'Acme/App', provider: 'github', commit_sha: 'c0ffee', files_scanned: 1, truncated: false,
      observations: [{ rule_id: ENDPOINT, signature_key: 'openai', count: 1 }],
    });
  });

  it('an empty tree posts no observations and is not truncated', async () => {
    const { payload } = await runBaselineScan(RULES, memSource({}).source, OPTS);
    expect(payload).toMatchObject({ files_scanned: 0, truncated: false, observations: [] });
  });

  it('no rules at all: nothing is read', async () => {
    const { source, reads } = memSource({ 'src/a.ts': 'const u = "https://api.openai.com";\n' });
    const { payload } = await runBaselineScan([], source, OPTS);
    expect(reads).toEqual([]);
    expect(payload.observations).toEqual([]);
  });
});

describe('aggregateObservations', () => {
  it('clamps a count to maxCount and caps the rows at maxObservations, keeping the sort', () => {
    const acc = new Map<string, { ruleId: string; key: SignatureKey; count: number; paths: string[] }>();
    for (let r = 0; r < 6; r++) {
      for (const key of SIGNATURE_KEYS) acc.set(`r${r}|${key}`, { ruleId: `r${r}`, key, count: INVENTORY_LIMITS.maxCount + 5, paths: [] });
    }
    const out = aggregateObservations(acc, false);
    expect(out).toHaveLength(INVENTORY_LIMITS.maxObservations);
    expect(out.every((o) => o.count === INVENTORY_LIMITS.maxCount)).toBe(true);
    const keys = out.map((o) => `${o.rule_id}|${o.signature_key}`);
    expect([...keys].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))).toEqual(keys);
  });
});

describe('runBaselineScan: what is read', () => {
  it('never reads ALWAYS_EXCLUDE paths (lockfiles, build output, vendored deps, minified bundles)', async () => {
    const hit = 'const u = "https://api.openai.com";\n';
    const { source, reads } = memSource({
      'node_modules/openai/index.js': hit,
      'web/node_modules/x/a.js': hit,
      'dist/index.js': hit,
      'build/out.js': hit,
      'vendor/lib.js': hit,
      'public/app.min.js': hit,
      'package-lock.json': '    "openai": "^4.0.0",\n',
      'yarn.lock': hit,
      'src/real.ts': hit,
    });
    const { payload } = await runBaselineScan(RULES, source, OPTS);
    expect(reads).toEqual(['src/real.ts']);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
  });

  it("applies each rule's file_scope and exclude_paths with the PR scan's semantics", async () => {
    const { source, reads } = memSource({
      // manifest rule is scoped to manifests: a .ts file with the same text is not a manifest hit
      'src/deps.ts': '    "openai": "^4.0.0",\n',
      'package.json': '    "openai": "^4.0.0",\n',
      // import rule excludes tests and docs; the endpoint rule excludes markdown
      'src/__tests__/a.test.ts': "import OpenAI from 'openai';\n",
      'tests/a.ts': "import OpenAI from 'openai';\n",
      'docs/guide.md': 'see https://api.openai.com\n',
      'README.md': 'see https://api.openai.com\n',
      // anchored exclude `^fixtures/` must not exclude `myfixtures/` (substring semantics with anchors)
      'myfixtures/a.ts': "import OpenAI from 'openai';\n",
    });
    const { payload } = await runBaselineScan(RULES, source, OPTS);
    expect(counts(payload.observations)).toEqual({ [`${MANIFEST}|openai`]: 1, [`${IMPORT}|openai`]: 1 });
    // A file no rule covers is not even opened.
    expect(reads).not.toContain('src/__tests__/a.test.ts');
    expect(reads).not.toContain('docs/guide.md');
  });

  it('skips a binary file (NUL in the first 8 KB) but not a NUL past 8 KB', async () => {
    const enc = new TextEncoder();
    const hit = enc.encode('const u = "https://api.openai.com";\n');
    const early = new Uint8Array([...hit, 0, 65]);
    const late = new Uint8Array([...hit, ...new Uint8Array(BASELINE_LIMITS.binarySniffBytes).fill(32), 0]);
    const { source } = memSource({ 'src/early.bin.ts': early, 'src/late.ts': late });
    const { payload, stats } = await runBaselineScan(RULES, source, OPTS);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
    expect(stats.skippedBinary).toBe(1);
    expect(payload.files_scanned).toBe(1);
  });

  it('skips a file over 512 KB without reading it, and a non-regular path (symlink, submodule)', async () => {
    const { source, reads } = memSource({
      'src/huge.ts': { size: BASELINE_LIMITS.maxFileBytes + 1 },
      'src/link.ts': null,
      'src/ok.ts': 'const u = "https://api.openai.com";\n',
    });
    const { payload, stats } = await runBaselineScan(RULES, source, OPTS);
    expect(reads).toEqual(['src/ok.ts']);
    expect(stats.skippedSize).toBe(1);
    expect(stats.skippedUnreadable).toBe(1);
    expect(payload.files_scanned).toBe(1);
    expect(payload.truncated).toBe(false);
  });

  it('a file of exactly 512 KB is still scanned', async () => {
    const line = 'const u = "https://api.openai.com";\n';
    const body = line + ' '.repeat(BASELINE_LIMITS.maxFileBytes - line.length);
    const { payload } = await runBaselineScan(RULES, memSource({ 'src/edge.ts': body }).source, OPTS);
    expect(payload.files_scanned).toBe(1);
    expect(payload.observations).toHaveLength(1);
  });

  it('a file that cannot be read is skipped, not fatal', async () => {
    const hit = 'const u = "https://api.openai.com";\n';
    const { source } = memSource({ 'src/a.ts': hit, 'src/b.ts': hit }, { failRead: ['src/a.ts'] });
    const { payload, stats } = await runBaselineScan(RULES, source, OPTS);
    expect(stats.skippedUnreadable).toBe(1);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
  });

  it('a very long line is clamped (like the PR scan) and counted in stats, never scanned past the clamp', async () => {
    const long = `${'x'.repeat(9000)} https://api.openai.com`;
    const { payload, stats } = await runBaselineScan(RULES, memSource({ 'src/a.ts': `${long}\n` }).source, OPTS);
    expect(stats.clampedLines).toBe(1);
    expect(payload.observations).toEqual([]);
  });
});

describe('runBaselineScan: budgets (never a silent pass)', () => {
  const hit = 'const u = "https://api.openai.com";\n';
  const tree = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`src/f${i}.ts`, hit]));

  it('stops at the file cap and marks the result truncated', async () => {
    const { source, reads } = memSource(tree(7));
    const { payload } = await runBaselineScan(RULES, source, { ...OPTS, limits: { maxFiles: 5 } });
    expect(reads).toHaveLength(5);
    expect(payload).toMatchObject({ files_scanned: 5, truncated: true });
    expect(payload.observations[0].count).toBe(5);
  });

  it('exactly the cap is not truncated', async () => {
    const { payload } = await runBaselineScan(RULES, memSource(tree(5)).source, { ...OPTS, limits: { maxFiles: 5 } });
    expect(payload).toMatchObject({ files_scanned: 5, truncated: false });
  });

  it('files no rule covers do not count toward the cap', async () => {
    const files = { ...tree(5), 'node_modules/a.js': hit, 'dist/b.js': hit };
    const { payload } = await runBaselineScan(RULES, memSource(files).source, { ...OPTS, limits: { maxFiles: 5 } });
    expect(payload.truncated).toBe(false);
  });

  it('the default limits are 5000 files, 512 KB, 8 KB binary sniff and 60 s', () => {
    expect(BASELINE_LIMITS).toEqual({ maxFiles: 5000, maxFileBytes: 512 * 1024, binarySniffBytes: 8192, budgetMs: 60_000 });
  });

  it('stops at the wall-clock budget and marks the result truncated', async () => {
    let t = 0;
    const now = () => t;
    const { source } = memSource(tree(10));
    const origRead = source.read.bind(source);
    source.read = async (p) => { t += 25; return origRead(p); }; // each file costs 25 ms
    const { payload } = await runBaselineScan(RULES, source, { ...OPTS, now, limits: { budgetMs: 100 } });
    expect(payload.truncated).toBe(true);
    expect(payload.files_scanned).toBe(4);
  });

  it('checks the budget inside a long file too', async () => {
    let t = 0;
    const now = () => { t += 1; return t; };
    const body = Array.from({ length: 12_000 }, () => 'const u = "https://api.openai.com";').join('\n'); // ~430 KB, under the size cap
    const { payload } = await runBaselineScan(RULES, memSource({ 'src/a.ts': body }).source, { ...OPTS, now, limits: { budgetMs: 10 } });
    expect(payload.truncated).toBe(true);
    expect(payload.observations[0].count).toBeLessThan(12_000);
  });
});

describe('runBaselineScan: rule problems are loud, not silent', () => {
  const endpoint = RULES.find((r) => r.id === ENDPOINT)!;
  const hit = 'const u = "https://api.openai.com";\n';

  it('a rule whose pattern does not compile is named in a warning, the other rules still run, and the scan is incomplete', async () => {
    const broken: Rule = { ...RULES.find((r) => r.id === IMPORT)!, detect: { ...RULES.find((r) => r.id === IMPORT)!.detect, pattern: '(?x)foo' } };
    const { payload, warnings } = await runBaselineScan([broken, endpoint], memSource({ 'src/a.ts': hit }).source, OPTS);
    expect(warnings.join('\n')).toMatch(/eaa-ci-ai-import.*could not be compiled/);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
    expect(payload.truncated).toBe(true);
  });

  it('a glob the PR scan refuses (matches every path) is warned about here too', async () => {
    const blanket: Rule = { ...endpoint, detect: { ...endpoint.detect, exclude_paths: ['*'] } };
    const { warnings } = await runBaselineScan([blanket], memSource({ 'src/a.ts': hit }).source, OPTS);
    expect(warnings.join('\n')).toMatch(/glob/i);
  });

  it('honours exclude_pattern / require_pattern on a non-tier-1 rule, statelessly', async () => {
    const gated: Rule = { ...endpoint, detect: { ...endpoint.detect, exclude_pattern: '(?gi)SKIPME' } };
    const body = Array.from({ length: 4 }, () => 'const u = "https://api.openai.com"; // skipme').join('\n') + `\n${hit}`;
    const { payload } = await runBaselineScan([gated], memSource({ 'src/a.ts': body }).source, OPTS);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
    const required: Rule = { ...endpoint, detect: { ...endpoint.detect, require_pattern: 'const' } };
    const r2 = await runBaselineScan([required], memSource({ 'src/a.ts': `${hit}url: https://api.openai.com\n` }).source, OPTS);
    expect(counts(r2.payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
  });

  it('a tier-1 rule cannot be gated away (same refusal as the PR scan), with a warning', async () => {
    const tier1: Rule = { ...endpoint, tier: 1, detect: { ...endpoint.detect, exclude_pattern: '.' } };
    const { payload, warnings } = await runBaselineScan([tier1], memSource({ 'src/a.ts': hit }).source, OPTS);
    expect(counts(payload.observations)).toEqual({ [`${ENDPOINT}|openai`]: 1 });
    expect(warnings.join('\n')).toMatch(/tier-1/i);
  });

  it('a non-pattern rule (no pattern) contributes nothing and is warned about', async () => {
    const noPattern: Rule = { ...endpoint, detect: { ...endpoint.detect, pattern: undefined } };
    const { payload, warnings } = await runBaselineScan([noPattern], memSource({ 'src/a.ts': hit }).source, OPTS);
    expect(payload.observations).toEqual([]);
    expect(warnings.join('\n')).toMatch(/eaa-ci-ai-endpoint/);
  });
});

describe('runBaselineScan: never a "complete and clean" scan when nothing could be read', () => {
  const hit = 'const u = "https://api.openai.com";\n';
  const quiet = 'const n = 1;\n';

  it('every rule uncompilable: truncated, with a warning, nothing read', async () => {
    const broken = RULES.map((r) => ({ ...r, detect: { ...r.detect, pattern: '(?x)nope' } }));
    const { source, reads } = memSource({ 'src/a.ts': hit, 'package.json': '{}\n' });
    const { payload, warnings } = await runBaselineScan(broken, source, OPTS);
    expect(reads).toEqual([]);
    expect(payload).toMatchObject({ truncated: true, files_scanned: 0, observations: [] });
    expect(warnings.join('\n')).toMatch(/incomplete/i);
  });

  it('every file in scope unreadable (not a regular file, read failure, sparse checkout): truncated, with a warning', async () => {
    const { source } = memSource({ 'src/gone.ts': null, 'src/denied.ts': quiet, 'package.json': null }, { failRead: ['src/denied.ts'] });
    const { payload, warnings, stats } = await runBaselineScan(RULES, source, OPTS);
    expect(stats.skippedUnreadable).toBe(3);
    expect(payload).toMatchObject({ truncated: true, files_scanned: 0, observations: [] });
    expect(warnings.join('\n')).toMatch(/eaa-ci-ai-endpoint.*none could be read/);
  });

  it('only the manifest is in the manifest rule scope and it is over the size cap: truncated, naming that rule', async () => {
    const { source } = memSource({ 'package.json': { size: BASELINE_LIMITS.maxFileBytes + 1 }, 'src/a.ts': quiet });
    const { payload, warnings } = await runBaselineScan(RULES, source, OPTS);
    expect(payload).toMatchObject({ truncated: true, files_scanned: 1, observations: [] });
    expect(warnings.join('\n')).toMatch(/eaa-ci-ai-sdk-manifest.*none could be read/);
    expect(warnings.join('\n')).not.toMatch(/eaa-ci-ai-endpoint.*none could be read/);
  });

  it('a file_scope glob the scanner refuses narrows the scan silently otherwise: truncated', async () => {
    const manifest = RULES.find((r) => r.id === MANIFEST)!;
    const refused: Rule = { ...manifest, detect: { ...manifest.detect, file_scope: ['*', 'package.json$'] } };
    const { payload } = await runBaselineScan([refused], memSource({ 'package.json': '{}\n' }).source, OPTS);
    expect(payload.truncated).toBe(true);
  });

  it('a binary file was read (and judged binary): that is not "unreadable"', async () => {
    const { payload } = await runBaselineScan(RULES, memSource({ 'src/a.ts': new Uint8Array([0, 1, 2]) }).source, OPTS);
    expect(payload.truncated).toBe(false);
  });

  it('the normal clean scan: files read, nothing found, truncated:false and files_scanned > 0 (the server may clear)', async () => {
    const { payload, warnings } = await runBaselineScan(RULES, memSource({ 'src/a.ts': quiet, 'package.json': '{}\n', 'app/main.py': quiet }).source, OPTS);
    expect(payload).toMatchObject({ truncated: false, observations: [] });
    expect(payload.files_scanned).toBeGreaterThan(0);
    expect(warnings).toEqual([]);
  });
});

describe('sample paths', () => {
  const hit = 'const u = "https://api.openai.com";\n';
  const files = {
    'src/a.ts': hit + hit,
    'src/b.ts': hit,
    'src/c.ts': hit,
    'src/d.ts': hit,
  };

  it('off (the default): the key is ABSENT from every observation', async () => {
    const { payload } = await runBaselineScan(RULES, memSource(files).source, OPTS);
    expect(payload.observations.length).toBeGreaterThan(0);
    for (const o of payload.observations) expect(Object.prototype.hasOwnProperty.call(o, 'sample_paths')).toBe(false);
    expect(JSON.stringify(payload)).not.toContain('src/');
  });

  it('on: at most 3 DISTINCT repo-relative paths per observation, in walk order', async () => {
    const { payload } = await runBaselineScan(RULES, memSource(files).source, { ...OPTS, samplePaths: true });
    expect(payload.observations).toEqual([{ rule_id: ENDPOINT, signature_key: 'openai', count: 5, sample_paths: ['src/a.ts', 'src/b.ts', 'src/c.ts'] }]);
  });

  it('on: a path longer than 300 characters is never sent (not even cut)', async () => {
    const longPath = `src/${'d/'.repeat(150)}x.ts`;
    expect(longPath.length).toBeGreaterThan(INVENTORY_LIMITS.maxPathChars);
    const { payload } = await runBaselineScan(RULES, memSource({ [longPath]: hit, 'src/ok.ts': hit }).source, { ...OPTS, samplePaths: true });
    expect(payload.observations[0].sample_paths).toEqual(['src/ok.ts']);
    expect(payload.observations[0].count).toBe(2);
  });
});

describe('no code line, matched text or file content ever reaches the payload', () => {
  // Built at runtime so this file itself is not a secret-shaped literal.
  const MARKER = ['ZZ', 'SECRET', 'MARKER', '7f3a'].join('_');
  const files = {
    'package.json': `{\n  "dependencies": {\n    "openai": "^4.0.0", "x": "${MARKER}"\n  }\n}\n`,
    'requirements.txt': `openai>=1.30  # ${MARKER}\n`,
    'src/a.ts': `import OpenAI from 'openai'; const k = '${MARKER}';\nconst u = "https://api.openai.com/${MARKER}";\n`,
    'app/face.py': `result = DeepFace.analyze(img)  # ${MARKER}\n`,
    'src/b.ts': `const k2 = '${MARKER}'; // no AI here\n`,
  };

  it.each([false, true])('with sample paths %s', async (samplePaths) => {
    const { payload, warnings, stats } = await runBaselineScan(RULES, memSource(files).source, { ...OPTS, samplePaths });
    expect(payload.observations.length).toBeGreaterThanOrEqual(4);
    const wire = JSON.stringify(payload);
    expect(wire).not.toContain(MARKER);
    expect(wire).not.toContain('OpenAI from');
    expect(wire).not.toContain('>=1.30');
    expect(wire).not.toContain('api.openai.com');
    expect(wire).not.toContain('DeepFace');
    expect(JSON.stringify({ warnings, stats })).not.toContain(MARKER);
    // Only contract keys, only allowlisted values.
    for (const o of payload.observations) {
      expect(Object.keys(o).sort()).toEqual(samplePaths ? ['count', 'rule_id', 'sample_paths', 'signature_key'] : ['count', 'rule_id', 'signature_key']);
      expect(BASELINE_RULE_IDS as readonly string[]).toContain(o.rule_id);
      expect(SIGNATURE_KEYS as readonly string[]).toContain(o.signature_key);
      expect(Number.isInteger(o.count)).toBe(true);
    }
    expect(Object.keys(payload).sort()).toEqual(['commit_sha', 'files_scanned', 'observations', 'provider', 'repo', 'truncated']);
  });
});
