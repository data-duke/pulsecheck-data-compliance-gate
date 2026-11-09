/**
 * Where a finding was seen (file and line), kept OUT of `ScanResult` so that nothing posted or published can change.
 *
 * PR D (GitLab Code Quality) needs `location.path` and `location.lines.begin` for every issue it lists, but the
 * Action's `Finding` carries only the rule, the action and the masked evidence, and that shape is the wire contract of
 * `ci-scan-result`. The scanner always knew the file and line; `findingLocations(result)` hands them to the one caller
 * that needs them, through a WeakMap keyed by the result object: no new field on the result, none in JSON, none in a
 * `toEqual`, none in what the check run or the post reads.
 */
import { describe, expect, it } from 'vitest';
import { scan, findingLocations } from '../scan.js';
import { buildSchema2Payload } from '../report.js';
import { scanFrameworks } from '../orchestrate.js';
import type { FrameworkRuleset, Rule } from '../types.js';

const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };

const endpointRule = (): Rule => ({
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
});
const descriptionRule = (): Rule => ({
  id: 'eaa-ci-description', name: 'AI mentioned in the PR description', articles: ['Art. 50'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'pr_description', pattern: 'uses GPT', mask: 'Description mention' },
});

const ruleset = (rules: Rule[]): FrameworkRuleset => ({
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules,
  allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [],
});

/** One context line (new line 1) then the added lines, which therefore start at line 2. */
const diffOf = (file: string, ...added: string[]) =>
  [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -1,1 +1,${added.length + 1} @@`, ' ctx', ...added.map((l) => `+${l}`)].join('\n') + '\n';

describe('findingLocations', () => {
  it('returns the file and new-file line of each finding, in the order of result.findings', () => {
    const diff = diffOf('src/ai/client.ts', 'const a = 1;', 'const url = "https://api.openai.com/v1/chat";', 'const b = 2;');
    const result = scan(ruleset([endpointRule()]), { diff, prDescription: '', truncated: false });
    expect(result.findings).toHaveLength(1);
    expect(findingLocations(result)).toEqual([{ file: 'src/ai/client.ts', line: 3 }]);
  });

  it('keeps the locations aligned with the findings after the scanner drops a duplicate', () => {
    // Two identical masked findings collapse to one; the surviving finding keeps the FIRST one's location.
    const diff = diffOf('src/ai/client.ts', 'fetch("https://api.openai.com/v1/chat");', 'fetch("https://api.openai.com/v1/chat");');
    const result = scan(ruleset([endpointRule()]), { diff, prDescription: '', truncated: false });
    expect(findingLocations(result).length).toBe(result.findings.length);
  });

  it('gives a finding from the pull request description no file and no line', () => {
    const result = scan(ruleset([descriptionRule()]), { diff: '', prDescription: 'This change uses GPT for triage.', truncated: false });
    expect(result.findings).toHaveLength(1);
    expect(findingLocations(result)).toEqual([{ file: null, line: null }]);
  });

  it('returns an empty list for a result it did not produce', () => {
    expect(findingLocations({ verdict: 'pass', findings: [], warnings: [] })).toEqual([]);
  });

  it('adds nothing to the result, to its JSON or to the posted body', () => {
    const diff = diffOf('src/ai/client.ts', 'const url = "https://api.openai.com/v1/chat";');
    const rs = ruleset([endpointRule()]);
    const result = scan(rs, { diff, prDescription: '', truncated: false });

    expect(Object.keys(result).sort()).toEqual(['findings', 'verdict', 'warnings']);
    // The masked evidence already names the file today; what must not appear is a structured field for it.
    expect(JSON.stringify(result)).not.toMatch(/"(locations|file|line|path)"\s*:/);
    expect(JSON.stringify(Object.keys(result.findings[0]))).toBe(JSON.stringify(['rule_id', 'articles', 'action', 'masked_evidence']));

    const outcomes = scanFrameworks([rs], { diff, prDescription: '', truncated: false }, ['EU AI Act']);
    const payload = buildSchema2Payload({ repo: 'acme/app', pr_number: 7, commit_sha: 'abc123' }, outcomes);
    expect(Object.keys(payload).sort()).toEqual(['commit_sha', 'pr_number', 'provider', 'repo', 'results']);
    expect(Object.keys(payload.results[0]).sort()).toEqual(['findings', 'framework', 'ruleset_hash', 'ruleset_version', 'verdict']);
    expect(Object.keys(payload.results[0].findings[0])).not.toContain('file');
    expect(Object.keys(payload.results[0].findings[0])).not.toContain('line');
  });
});
