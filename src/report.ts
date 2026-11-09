/**
 * Posts the masked verdict back to PulseCheck. Best-effort by design: a failure
 * here never blocks the pipeline and never changes the already-published check
 * run. The body contains ONLY masked findings, never raw evidence.
 *
 * Two body shapes exist. A legacy server (which answered the ruleset request with
 * the single legacy ruleset) only understands the original one-verdict body, so
 * that is what it gets, for the Data Compliance outcome. A schema-2 server gets one
 * result per framework. If a schema-2 post is refused with HTTP 400 (a mixed
 * deployment where the ruleset function is newer than the ingest function), or with a
 * 5xx while it carries another framework's verdict (an EU AI Act verification that could
 * not read the registry answers 503 for the WHOLE post), it is retried ONCE in the legacy
 * shape so the GDPR verdict is still recorded, and the frameworks that were dropped are
 * named (notRecorded) so the loss is loud. A server that stores part of a post itself
 * says so with `not_recorded` in its 200 body; that is surfaced the same way.
 */
import { DEFAULT_PROVIDER, PROVIDER_LABEL, type GateProvider } from './provider.js';
import { DEFAULT_FRAMEWORK, FRAMEWORK_INFO, POST_LIMITS, isFramework, type FrameworkId } from './frameworks.js';
import { groupLongDigitRuns } from './mask.js';
import type { FrameworkOutcome } from './orchestrate.js';
import type { ServerShape } from './ruleset.js';
import type { Finding, ScanResultPayload, ScanResultPayloadV2 } from './types.js';

export interface PostResultOutcome {
  ok: boolean;
  status?: number;
  error?: string;
  /** The server's error code on a refused post (`error.code` of its JSON body), when it gave a plain one. */
  code?: string;
  /**
   * Frameworks whose verdict was NOT recorded although the post as a whole succeeded: a schema-2 post refused
   * with 400 or 5xx and retried in the legacy shape records the Data Compliance verdict only, and a server may
   * itself store part of a post and list the rest in `not_recorded`.
   */
  notRecorded?: FrameworkId[];
  /** The HTTP status of the refused schema-2 post that led to the legacy retry (absent: the server split the post). */
  refusedStatus?: number;
}

/** What identifies the PR being reported on. */
export interface PostBase {
  repo: string;
  pr_number: number;
  commit_sha: string;
  /** Absent = GitHub. Only the schema-2 body carries it (the legacy body has no such field). */
  provider?: GateProvider;
}

const SEVERITY: Record<string, number> = { block: 0, review: 1, advise: 2 };
const clampText = (v: string) => (v.length > POST_LIMITS.maxFieldChars ? v.slice(0, POST_LIMITS.maxFieldChars) : v);
const clampList = (v?: string[]) => v?.slice(0, POST_LIMITS.maxListItems).map(clampText);

/**
 * What of a result is POSTED. The server stores at most POST_LIMITS.maxFindings findings
 * per framework and clamps long fields; a post over those limits used to be rejected
 * outright, which would have recorded NOTHING for the very largest (failing) scans. So
 * the Action keeps the most severe findings (block, then review, then advise) and trims
 * long fields itself. An ordinary scan is returned unchanged, element for element, except that
 * 8+ digit runs in masked_evidence are grouped (N1).
 * The verdict is never touched, and the check run still shows the full result.
 */
export function clampFindingsForPost(findings: readonly Finding[]): Finding[] {
  const kept =
    findings.length > POST_LIMITS.maxFindings
      ? findings
          .map((f, i) => ({ f, i }))
          .sort((a, b) => (SEVERITY[a.f.action] ?? 3) - (SEVERITY[b.f.action] ?? 3) || a.i - b.i)
          .slice(0, POST_LIMITS.maxFindings)
          .map((x) => x.f)
      : findings;
  return kept.map((f) => ({
    ...f,
    rule_id: clampText(f.rule_id),
    // Grouped BEFORE clamping: grouping lengthens the string, and a cut can never create a digit run.
    masked_evidence: clampText(groupLongDigitRuns(f.masked_evidence)),
    ...(f.gdpr_article ? { gdpr_article: clampList(f.gdpr_article) } : {}),
    ...(f.articles ? { articles: clampList(f.articles) } : {}),
  }));
}

/** The original one-verdict body. Field order matches what the Action has always sent. */
export function buildLegacyPayload(base: PostBase, outcome: FrameworkOutcome): ScanResultPayload {
  return {
    repo: base.repo,
    pr_number: base.pr_number,
    commit_sha: base.commit_sha,
    ruleset_version: outcome.ruleset.ruleset_version,
    ruleset_hash: outcome.ruleset.ruleset_hash,
    verdict: outcome.result.verdict,
    findings: clampFindingsForPost(outcome.result.findings),
  };
}

/** The multi-framework body: one independent result per framework. */
export function buildSchema2Payload(base: PostBase, outcomes: readonly FrameworkOutcome[]): ScanResultPayloadV2 {
  return {
    repo: base.repo,
    pr_number: base.pr_number,
    commit_sha: base.commit_sha,
    provider: base.provider ?? DEFAULT_PROVIDER,
    results: outcomes.map((o) => ({
      framework: o.framework,
      ruleset_version: o.ruleset.ruleset_version,
      ruleset_hash: o.ruleset.ruleset_hash,
      verdict: o.result.verdict,
      findings: clampFindingsForPost(o.result.findings),
      ...(o.ruleset.context && o.ruleset.context_hash ? { context: o.ruleset.context, context_hash: o.ruleset.context_hash } : {}),
    })),
  };
}

const CODE_PATTERN = /^[a-z_]{1,40}$/;
const plainCode = (v: unknown): string | undefined => (typeof v === 'string' && CODE_PATTERN.test(v) ? v : undefined);

/** `not_recorded` of a 2xx body: the known frameworks the server did not store, and the first plain code. */
function readNotRecorded(body: unknown): Pick<PostResultOutcome, 'notRecorded' | 'code'> {
  const list = (body as { not_recorded?: unknown } | null)?.not_recorded;
  if (!Array.isArray(list)) return {};
  const entries = list.filter((e): e is { framework: FrameworkId; code?: unknown } =>
    typeof e === 'object' && e !== null && isFramework((e as { framework?: unknown }).framework));
  if (entries.length === 0) return {};
  const code = entries.map((e) => plainCode(e.code)).find((c) => c !== undefined);
  return { notRecorded: entries.map((e) => e.framework), ...(code ? { code } : {}) };
}

/** POST `${url}/functions/v1/ci-scan-result` with a bearer token. Never throws. */
async function postBody(url: string, token: string, payload: unknown): Promise<PostResultOutcome> {
  const base = url.replace(/\/+$/, '');
  const endpoint = `${base}/functions/v1/ci-scan-result`;
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const body = await Promise.resolve().then(() => res.json()).then((b: unknown) => b, () => undefined);
    if (!res.ok) {
      const code = plainCode((body as { error?: { code?: unknown } } | null | undefined)?.error?.code);
      return {
        ok: false,
        status: res.status,
        error: `ci-scan-result returned HTTP ${res.status}`,
        ...(code ? { code } : {}),
      };
    }
    return { ok: true, status: res.status, ...readNotRecorded(body) };
  } catch (err) {
    return { ok: false, error: (err as Error)?.message ?? String(err) };
  }
}

/** A refused schema-2 post worth retrying in the legacy shape: 400 (an older ingest), or 5xx with more to lose. */
const shouldRetryLegacy = (status: number | undefined, hasOtherFrameworks: boolean): boolean =>
  status === 400 || (status !== undefined && status >= 500 && hasOtherFrameworks);

/** Post every framework's verdict in the shape the server understands. Never throws. */
export async function postResults(
  url: string,
  token: string,
  base: PostBase,
  outcomes: readonly FrameworkOutcome[],
  shape: ServerShape,
): Promise<PostResultOutcome> {
  const gdpr = outcomes.find((o) => o.framework === DEFAULT_FRAMEWORK);
  const provider = base.provider ?? DEFAULT_PROVIDER;

  // The legacy body has no provider field, and the server reads an absent provider as GitHub: posting a GitLab merge
  // request that way would store it as a GitHub pull request of the same path, shadowing a real one. So for any other
  // provider a legacy-only server gets nothing, and a refused schema-2 post is never retried in the legacy shape.
  if (provider !== DEFAULT_PROVIDER && shape === 'legacy') {
    return {
      ok: false,
      error: `This PulseCheck server predates ${PROVIDER_LABEL[provider]} support, so the verdict was not recorded. ` +
        'Nothing was sent, because the older request format would have stored it as a GitHub pull request',
    };
  }

  if (shape === 'legacy') {
    // A legacy server has only the GDPR stream; there is nothing else it could store.
    return gdpr ? postBody(url, token, buildLegacyPayload(base, gdpr)) : { ok: true };
  }

  // The legacy body can only carry the GDPR verdict: name the frameworks it drops, so a refused schema-2 post
  // (a context mismatch, an unmasked string, a registry that could not be read) is never a SILENT loss.
  const notRecorded = outcomes.map((o) => o.framework).filter((f) => f !== DEFAULT_FRAMEWORK);
  const first = await postBody(url, token, buildSchema2Payload(base, outcomes));
  // A 5xx is retried only when another framework rode along: a GDPR-only post would just be re-sent as it was
  // (and a 5xx raised after the row was stored would store it twice).
  if (first.ok || !gdpr || provider !== DEFAULT_PROVIDER || !shouldRetryLegacy(first.status, notRecorded.length > 0)) return first;
  const retry = await postBody(url, token, buildLegacyPayload(base, gdpr));
  if (!retry.ok || notRecorded.length === 0) return retry;
  return { ...retry, notRecorded, refusedStatus: first.status, ...(first.code ? { code: first.code } : {}) };
}

/** The warning for a partial record, or null. */
export function notRecordedWarning(post: PostResultOutcome): string | null {
  if (!post.notRecorded || post.notRecorded.length === 0) return null;
  const names = post.notRecorded.map((f) => FRAMEWORK_INFO[f].title).join(', ');
  if (post.refusedStatus === undefined) {
    return `PulseCheck recorded the verdict post only in part${post.code ? ` (${post.code})` : ''}. NOT recorded: ${names}.`;
  }
  return `PulseCheck refused the multi-framework verdict post (HTTP ${post.refusedStatus}${post.code ? ` ${post.code}` : ''}); ` +
    `only the Data Compliance verdict was recorded. NOT recorded: ${names}.`;
}
