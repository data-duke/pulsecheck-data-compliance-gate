/**
 * GitLab merge-request context and the Code Quality report (PR D).
 *
 * Every variable name and rule below was read from GitLab's own documentation on 2026-10-15, not recalled (see
 * docs/plans/ai-change-control-pr-d-plan.md): the merge request variables exist only in merge request pipelines;
 * `CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` is EMPTY there, so the head is `CI_COMMIT_SHA`; the description is cut at 2,700
 * characters and `CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED` says so; a Code Quality report is one JSON array whose issues
 * need description, check_name, fingerprint, severity (info|minor|major|critical|blocker), location.path (relative, no
 * "./") and location.lines.begin, with no byte order mark.
 */
import { describe, expect, it } from 'vitest';
import { readGitlabMr, renderCodeQuality, toCodeQualityReport } from '../gitlab.js';
import { scanFrameworks } from '../orchestrate.js';
import type { FrameworkRuleset, Rule } from '../types.js';

const MR_ENV = {
  GITLAB_CI: 'true',
  CI_PIPELINE_SOURCE: 'merge_request_event',
  CI_MERGE_REQUEST_IID: '12',
  CI_MERGE_REQUEST_PROJECT_PATH: 'acme/platform/api',
  CI_PROJECT_PATH: 'acme/platform/api',
  CI_COMMIT_SHA: 'a'.repeat(40),
  CI_MERGE_REQUEST_DIFF_BASE_SHA: 'b'.repeat(40),
  CI_MERGE_REQUEST_DESCRIPTION: 'Adds the summariser.',
  CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED: 'false',
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main',
};

describe('readGitlabMr', () => {
  it('reads a merge request pipeline: head is CI_COMMIT_SHA, base is the diff base, nested groups are kept', () => {
    const r = readGitlabMr(MR_ENV);
    expect(r).toEqual({
      ok: true,
      mr: {
        repo: 'acme/platform/api',
        iid: 12,
        headSha: 'a'.repeat(40),
        baseSha: 'b'.repeat(40),
        targetBranch: 'main',
        description: 'Adds the summariser.',
        descriptionTruncated: false,
      },
    });
  });

  it('in a merged results pipeline the head is the source branch sha, not GitLab\'s temporary merge commit', () => {
    const r = readGitlabMr({ ...MR_ENV, CI_COMMIT_SHA: 'c'.repeat(40), CI_MERGE_REQUEST_SOURCE_BRANCH_SHA: 'd'.repeat(40), CI_MERGE_REQUEST_EVENT_TYPE: 'merged_result' });
    expect(r).toMatchObject({ ok: true, mr: { headSha: 'd'.repeat(40), baseSha: 'b'.repeat(40) } });
  });

  it('refuses a short hex string as a commit id (git would read it as a ref name first)', () => {
    expect(readGitlabMr({ ...MR_ENV, CI_COMMIT_SHA: 'abc1234' }).ok).toBe(false);
    expect(readGitlabMr({ ...MR_ENV, CI_MERGE_REQUEST_DIFF_BASE_SHA: 'abc1234' }).ok).toBe(false);
  });

  it('is not GitLab CI when GITLAB_CI is absent', () => {
    expect(readGitlabMr({ ...MR_ENV, GITLAB_CI: undefined })).toMatchObject({ ok: false, reason: 'not-gitlab' });
    expect(readGitlabMr({})).toMatchObject({ ok: false, reason: 'not-gitlab' });
  });

  it('is inert in a branch pipeline: the merge request variables do not exist there', () => {
    const branch = { GITLAB_CI: 'true', CI_PIPELINE_SOURCE: 'push', CI_PROJECT_PATH: 'acme/platform/api', CI_COMMIT_SHA: 'a'.repeat(40) };
    expect(readGitlabMr(branch)).toMatchObject({ ok: false, reason: 'not-merge-request' });
    // A merge request IID without the merge_request_event source is not trusted either.
    expect(readGitlabMr({ ...MR_ENV, CI_PIPELINE_SOURCE: 'push' })).toMatchObject({ ok: false, reason: 'not-merge-request' });
  });

  it('records the MERGE REQUEST\'s project, not the pipeline\'s, for a merge request from a fork', () => {
    // The IID belongs to the target project; the pipeline may run in the fork. Posting the fork's path would file the
    // merge request under a repository that has no such number.
    const r = readGitlabMr({ ...MR_ENV, CI_PROJECT_PATH: 'someone/api-fork', CI_MERGE_REQUEST_PROJECT_PATH: 'acme/platform/api' });
    expect(r).toMatchObject({ ok: true, mr: { repo: 'acme/platform/api' } });
  });

  it('falls back to CI_PROJECT_PATH when CI_MERGE_REQUEST_PROJECT_PATH is empty', () => {
    expect(readGitlabMr({ ...MR_ENV, CI_MERGE_REQUEST_PROJECT_PATH: '' })).toMatchObject({ ok: true, mr: { repo: 'acme/platform/api' } });
  });

  it('flags a truncated description, which the gate must treat as a partial read', () => {
    const r = readGitlabMr({ ...MR_ENV, CI_MERGE_REQUEST_DESCRIPTION: 'x'.repeat(2700), CI_MERGE_REQUEST_DESCRIPTION_IS_TRUNCATED: 'true' });
    expect(r).toMatchObject({ ok: true, mr: { descriptionTruncated: true } });
  });

  it('names the missing variable instead of guessing', () => {
    for (const name of ['CI_MERGE_REQUEST_IID', 'CI_COMMIT_SHA', 'CI_MERGE_REQUEST_DIFF_BASE_SHA', 'CI_PROJECT_PATH']) {
      const env: Record<string, string | undefined> = { ...MR_ENV, [name]: '' };
      if (name === 'CI_PROJECT_PATH') env.CI_MERGE_REQUEST_PROJECT_PATH = '';
      const r = readGitlabMr(env);
      expect(r.ok).toBe(false);
      if (!r.ok && name !== 'CI_MERGE_REQUEST_IID') {
        expect(r.reason).toBe('missing');
        expect(r.detail).toContain(name);
      }
    }
  });

  it('refuses an IID that is not a positive whole number, and a path or SHA the server would refuse', () => {
    for (const iid of ['0', '-3', '12abc', '1.5', String(2 ** 40)]) {
      expect(readGitlabMr({ ...MR_ENV, CI_MERGE_REQUEST_IID: iid }).ok).toBe(false);
    }
    expect(readGitlabMr({ ...MR_ENV, CI_MERGE_REQUEST_PROJECT_PATH: 'bad path/with space' }).ok).toBe(false);
    expect(readGitlabMr({ ...MR_ENV, CI_COMMIT_SHA: 'not a sha' }).ok).toBe(false);
    expect(readGitlabMr({ ...MR_ENV, CI_MERGE_REQUEST_DIFF_BASE_SHA: '--upload-pack=evil' }).ok).toBe(false);
  });
});

// ── the Code Quality report ─────────────────────────────────────────────────────────────────────

const EMPTY_ALLOWLIST = { emails: [], names: [], domains: [], ip_ranges: [], ibans: [] };
const aiRule = (over: Partial<Rule> = {}): Rule => ({
  id: 'eaa-ci-endpoint', name: 'Hosted model endpoint', articles: ['Art. 15'], relevance: ['control'], action: 'review', tier: 2,
  detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' },
  ...over,
});
const blockRule = (): Rule => aiRule({ id: 'eaa-ci-block', name: 'Blocking rule', action: 'block', tier: 1, detect: { method: 'pattern', target: 'diff', diff_side: 'added', pattern: 'FORBIDDEN_MODEL', mask: 'Forbidden model' } });
const descRule = (): Rule => aiRule({ id: 'eaa-ci-description', name: 'In the description', detect: { method: 'pattern', target: 'pr_description', pattern: 'uses GPT', mask: 'Description mention' } });
const eu = (rules: Rule[]): FrameworkRuleset => ({
  framework: 'EU AI Act', ruleset_version: 1, ruleset_hash: 'b'.repeat(64), rules, allowlist: EMPTY_ALLOWLIST, signatures: {}, dropped_rules: [],
});
const diffOf = (file: string, ...added: string[]) =>
  [`diff --git a/${file} b/${file}`, `--- a/${file}`, `+++ b/${file}`, `@@ -1,1 +1,${added.length + 1} @@`, ' ctx', ...added.map((l) => `+${l}`)].join('\n') + '\n';

function outcomesFor(rules: Rule[], diff: string, prDescription = '', failOn: Array<'EU AI Act'> = []) {
  return scanFrameworks([eu(rules)], { diff, prDescription, truncated: false }, failOn);
}

describe('toCodeQualityReport, selection and removed lines', () => {
  it('keeps the most severe findings when there are more than the post cap, exactly as the post does', () => {
    const many = Array.from({ length: 205 }, (_, i) => `x${i} api.openai.com/${i}`);
    const diff = diffOf('src/many.ts', ...many, 'use(FORBIDDEN_MODEL);');
    const issues = toCodeQualityReport(outcomesFor([aiRule(), blockRule()], diff));
    expect(issues.length).toBeLessThanOrEqual(200);
    expect(issues.some((i) => i.severity === 'critical')).toBe(true); // the blocking finding is the LAST one scanned
  });

  it('puts a finding on a removed line at line 1, not at its old-file line number', () => {
    const diff = ['diff --git a/src/a.ts b/src/a.ts', '--- a/src/a.ts', '+++ b/src/a.ts', '@@ -40,2 +40,1 @@', ' keep', '-fetch("https://api.openai.com/x");'].join('\n') + '\n';
    const removedRule = aiRule({ detect: { method: 'pattern', target: 'diff', diff_side: 'removed', pattern: 'api\\.openai\\.com', mask: 'Model endpoint' } });
    const issues = toCodeQualityReport(outcomesFor([removedRule], diff));
    expect(issues).toHaveLength(1);
    expect(issues[0].location.lines.begin).toBe(1);
  });
});

describe('toCodeQualityReport', () => {
  const diff = diffOf('src/ai/client.ts', 'const a = 1;', 'fetch("https://api.openai.com/v1/chat");', 'use(FORBIDDEN_MODEL);');
  const issues = toCodeQualityReport(outcomesFor([aiRule(), blockRule()], diff));

  it('is one issue per finding with every field GitLab requires', () => {
    expect(issues).toHaveLength(2);
    for (const i of issues) {
      expect(typeof i.description).toBe('string');
      expect(i.description.length).toBeGreaterThan(0);
      expect(typeof i.check_name).toBe('string');
      expect(i.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(['info', 'minor', 'major', 'critical', 'blocker']).toContain(i.severity);
      expect(Number.isInteger(i.location.lines.begin)).toBe(true);
      expect(i.location.lines.begin).toBeGreaterThanOrEqual(1);
    }
  });

  it('puts each finding on the file and new-file line the scanner saw', () => {
    const endpoint = issues.find((i) => i.check_name.endsWith('eaa-ci-endpoint'))!;
    expect(endpoint.location).toEqual({ path: 'src/ai/client.ts', lines: { begin: 3 } });
    const forbidden = issues.find((i) => i.check_name.endsWith('eaa-ci-block'))!;
    expect(forbidden.location).toEqual({ path: 'src/ai/client.ts', lines: { begin: 4 } });
  });

  it('maps the action to a severity: block is critical, review major, advise minor', () => {
    expect(issues.find((i) => i.check_name.endsWith('eaa-ci-block'))!.severity).toBe('critical');
    expect(issues.find((i) => i.check_name.endsWith('eaa-ci-endpoint'))!.severity).toBe('major');
    const advise = toCodeQualityReport(outcomesFor([aiRule({ action: 'advise', tier: 3 })], diff));
    expect(advise[0].severity).toBe('minor');
  });

  it('has a stable fingerprint: the same finding twice is the same issue, a different line is a different one', () => {
    const again = toCodeQualityReport(outcomesFor([aiRule(), blockRule()], diff));
    expect(again.map((i) => i.fingerprint)).toEqual(issues.map((i) => i.fingerprint));
    const moved = toCodeQualityReport(outcomesFor([aiRule()], diffOf('src/ai/client.ts', 'const a = 1;', 'const b = 2;', 'fetch("https://api.openai.com/v1/chat");')));
    expect(new Set([...issues, ...moved].map((i) => i.fingerprint)).size).toBe(3);
  });

  it('never prefixes the path with "./" or "/"', () => {
    const r = toCodeQualityReport(outcomesFor([aiRule()], diffOf('./src/x.ts', 'fetch("https://api.openai.com/v1/chat");')));
    for (const i of r) expect(i.location.path).not.toMatch(/^(\.\/|\/)/);
  });

  it('lists a finding from the merge request description too, on a clearly non-file path, so the report matches the verdict', () => {
    const r = toCodeQualityReport(outcomesFor([descRule()], '', 'This change uses GPT.'));
    expect(r).toHaveLength(1);
    expect(r[0].location).toEqual({ path: 'MERGE_REQUEST_DESCRIPTION', lines: { begin: 1 } });
  });

  it('is an empty array, not an error, when there is nothing to report', () => {
    expect(toCodeQualityReport(outcomesFor([aiRule()], diffOf('a.ts', 'const a = 1;')))).toEqual([]);
    expect(renderCodeQuality([])).toBe('[]\n');
  });

  it('carries only what the masked evidence already carries: no source line leaves the report', () => {
    const secret = 'const key = "sk-live-ABCDEFGHIJKLMNOP"; fetch("https://api.openai.com/v1/chat");';
    const r = toCodeQualityReport(outcomesFor([aiRule()], diffOf('src/k.ts', secret)));
    expect(JSON.stringify(r)).not.toContain('sk-live-ABCDEFGHIJKLMNOP');
  });

  it('renders valid JSON with no byte order mark', () => {
    const text = renderCodeQuality(issues);
    expect(text.charCodeAt(0)).not.toBe(0xfeff);
    expect(Array.isArray(JSON.parse(text))).toBe(true);
    expect(text.endsWith('\n')).toBe(true);
  });
});
