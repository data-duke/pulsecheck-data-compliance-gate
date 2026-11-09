/**
 * The optional GitLab merge request note (PR F3): one comment with the verdict per framework and the masked findings, kept
 * up to date in place instead of adding a new comment per pipeline.
 *
 * Opt-in by variable: the PulseCheck token cannot write to GitLab and `CI_JOB_TOKEN` cannot create notes, so the customer
 * adds a project access token (scope `api`, with a role that may comment on merge requests) as `PULSECHECK_GITLAB_TOKEN`. Without it nothing here
 * runs. Everything is best effort: a note that cannot be posted is a warning, never a different verdict or exit code.
 *
 * What goes in the note is exactly what is already posted to PulseCheck (masked evidence, rule ids): no source line, no raw
 * evidence. Text from findings is placed in code spans so a masked string containing `@name` cannot mention anyone.
 */
import { FRAMEWORK_INFO, POST_LIMITS } from './frameworks.js';
import type { FrameworkOutcome } from './orchestrate.js';

/** Hidden marker that identifies our note among the merge request's notes. */
export const NOTE_MARKER = '<!-- pulsecheck-gate -->';
/** Findings shown per framework; the rest are counted. */
export const NOTE_MAX_FINDINGS = 25;
const MAX_EVIDENCE_CHARS = 200;
const NOTES_PAGE_SIZE = 100;
const NOTES_MAX_PAGES = 5;
const REQUEST_TIMEOUT_MS = 20_000;

type Env = Record<string, string | undefined>;
type NoteOutcome = Pick<FrameworkOutcome, 'framework' | 'result'>;

export interface NoteTarget {
  /** The instance's REST root, e.g. `https://gitlab.example.com/api/v4`, without a trailing slash. */
  apiUrl: string;
  projectId: string;
  iid: number;
}

/** Where to post, read from the pipeline's variables. Null when anything needed is missing or malformed. */
export function readNoteTarget(env: Env): NoteTarget | null {
  const apiUrl = (env.CI_API_V4_URL ?? '').trim().replace(/\/+$/, '');
  const projectId = (env.CI_MERGE_REQUEST_PROJECT_ID ?? '').trim();
  const iid = Number((env.CI_MERGE_REQUEST_IID ?? '').trim());
  // https only: the token travels in a header, so a cleartext instance URL is refused rather than used.
  if (!/^https:\/\/[^\s/]+(?:\/[^\s?#]*)?$/.test(apiUrl)) return null;
  if (!/^\d{1,12}$/.test(projectId)) return null;
  if (!Number.isSafeInteger(iid) || iid < 1) return null;
  return { apiUrl, projectId, iid };
}

const VERDICT_LABEL: Record<string, string> = { pass: 'passed', needs_review: 'needs review', fail: 'failed' };
const VERDICT_MARK: Record<string, string> = { pass: '✅', needs_review: '⚠️', fail: '❌' };
const RANK: Record<string, number> = { block: 0, review: 1, advise: 2 };

/** Text safe to place inside a markdown code span: no backticks, no line breaks, bounded. */
function codeSpan(text: string, max = MAX_EVIDENCE_CHARS): string {
  // `|` is escaped: GitHub-flavoured markdown splits a table row on an unescaped pipe BEFORE it reads inline content, even
  // inside a code span, which would end the span early and render what follows (mentions, links, images) as live markdown.
  const flat = text.replace(/[`\r\n]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/\|/g, '\\|');
  const cut = flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
  return `\`${cut === '' ? ' ' : cut}\``;
}

/** The note's markdown. Always starts with {@link NOTE_MARKER}. */
export function buildNoteBody(outcomes: readonly NoteOutcome[]): string {
  const lines: string[] = [NOTE_MARKER, '### PulseCheck Data Compliance Gate', ''];
  if (outcomes.length === 0) {
    lines.push('No framework was scanned in this pipeline.');
  }
  for (const outcome of outcomes) {
    const title = FRAMEWORK_INFO[outcome.framework].title;
    const verdict = outcome.result.verdict;
    lines.push(`**${title}:** ${VERDICT_MARK[verdict] ?? ''} ${VERDICT_LABEL[verdict] ?? verdict}`.trim(), '');
    const findings = outcome.result.findings
      .map((finding, index) => ({ finding, index }))
      .sort((a, b) => (RANK[a.finding.action] ?? 3) - (RANK[b.finding.action] ?? 3) || a.index - b.index)
      .map((x) => x.finding)
      .slice(0, POST_LIMITS.maxFindings);
    if (findings.length === 0) continue;
    lines.push('| Action | Rule | Evidence (masked) |', '| --- | --- | --- |');
    for (const f of findings.slice(0, NOTE_MAX_FINDINGS)) {
      lines.push(`| ${f.action} | ${codeSpan(f.rule_id, 80)} | ${codeSpan(f.masked_evidence)} |`);
    }
    if (findings.length > NOTE_MAX_FINDINGS) lines.push('', `…and ${findings.length - NOTE_MAX_FINDINGS} more finding(s). Open the gate in PulseCheck for the full list.`);
    lines.push('');
  }
  lines.push('_Updated on every pipeline. Details: PulseCheck → Compliance Gates._');
  return lines.join('\n');
}

export type NoteResult = { ok: true; action: 'created' | 'updated' } | { ok: false; error: string };

/** Remove the token from any text before it can reach a log. */
function scrub(message: string, token: string): string {
  return (token ? message.split(token).join('[token]') : message).slice(0, 300);
}

async function api(
  url: string,
  token: string,
  init: { method: 'GET' | 'POST' | 'PUT'; body?: unknown },
): Promise<{ status: number; json: unknown }> {
  const res = await fetch(url, {
    method: init.method,
    headers: { 'PRIVATE-TOKEN': token, Accept: 'application/json', ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    // Never follow a redirect: fetch would forward the PRIVATE-TOKEN header (and replay a POST/PUT body on 307/308) to
    // whatever host answered.
    redirect: 'error',
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const json = await res.json().catch(() => undefined);
  return { status: res.status, json };
}

/**
 * Create the note, or update our previous one. "Ours" means: carries the marker AND was written by the user the token
 * belongs to, so a comment someone else wrote with the marker in it is never overwritten. Never throws.
 */
export async function postMergeRequestNote(target: NoteTarget, token: string, body: string): Promise<NoteResult> {
  const base = `${target.apiUrl}/projects/${encodeURIComponent(target.projectId)}/merge_requests/${target.iid}/notes`;
  try {
    // Find OUR previous note. A note is only added when both lookups SUCCEEDED and found none: a failed or incomplete lookup
    // must not turn into one more comment per pipeline.
    let existingId: number | null = null;
    const me = await api(`${target.apiUrl}/user`, token, { method: 'GET' });
    const myId = me.status === 200 ? (me.json as { id?: unknown } | undefined)?.id : undefined;
    if (typeof myId !== 'number') return { ok: false, error: 'could not tell which GitLab user the token belongs to' };
    for (let page = 1; page <= NOTES_MAX_PAGES && existingId === null; page += 1) {
      const list = await api(`${base}?sort=desc&order_by=updated_at&per_page=${NOTES_PAGE_SIZE}&page=${page}`, token, { method: 'GET' });
      if (list.status !== 200 || !Array.isArray(list.json)) return { ok: false, error: 'could not read the merge request notes' };
      const notes = list.json as Array<{ id?: unknown; body?: unknown; system?: unknown; author?: { id?: unknown } }>;
      const mine = notes.find((n) => n.system !== true && typeof n.id === 'number' && n.author?.id === myId && typeof n.body === 'string' && n.body.includes(NOTE_MARKER));
      if (mine) existingId = mine.id as number;
      else if (notes.length < NOTES_PAGE_SIZE) break;
    }
    const res = existingId !== null
      ? await api(`${base}/${existingId}`, token, { method: 'PUT', body: { body } })
      : await api(base, token, { method: 'POST', body: { body } });
    if (res.status >= 200 && res.status < 300) return { ok: true, action: existingId !== null ? 'updated' : 'created' };
    return { ok: false, error: `GitLab answered HTTP ${res.status}` };
  } catch (e) {
    return { ok: false, error: scrub((e as Error)?.message ?? String(e), token) };
  }
}
