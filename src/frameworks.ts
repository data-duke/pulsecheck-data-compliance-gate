/**
 * The CI scan frameworks (streams) this Action understands.
 *
 * This is a deliberate COPY of supabase/functions/_shared/ciFrameworks.ts, not an
 * import: the Action is published as a standalone mirror and cannot reach into
 * `supabase/`. The root test `ciFrameworks.actionParity.test.ts` fails if the ids,
 * check-run names or articles labels ever disagree, so the copy cannot drift.
 *
 * A framework id is the gate-framework category string.
 */
export const FRAMEWORKS = ['Data Compliance', 'EU AI Act'] as const;
export type FrameworkId = (typeof FRAMEWORKS)[number];

/** The original GDPR stream: what every pre-schema-2 server and Action means. */
export const DEFAULT_FRAMEWORK: FrameworkId = 'Data Compliance';

export interface FrameworkInfo {
  /** Name of the GitHub check run. 'Data Compliance Gate' is unchanged on purpose: branch protection may require it. */
  checkRunName: string;
  /** Header of the article-references column in the check-run summary. */
  articlesLabel: string;
  /** Check-run title prefix, e.g. "Data Compliance: fail". */
  title: string;
}

export const FRAMEWORK_INFO: Record<FrameworkId, FrameworkInfo> = {
  'Data Compliance': { checkRunName: 'Data Compliance Gate', articlesLabel: 'GDPR', title: 'Data Compliance' },
  'EU AI Act': { checkRunName: 'PulseCheck · AI change control', articlesLabel: 'May be relevant to', title: 'AI change control' },
};

/**
 * How much of a framework's result the Action POSTS. A copy of the server's ingest
 * limits (`MAX_FINDINGS_PER_RESULT` etc. in _shared/ciFrameworks.ts; parity-tested).
 * The check run still shows its own (smaller) summary; this only bounds the post.
 */
export const POST_LIMITS = { maxFindings: 200, maxFieldChars: 500, maxListItems: 20 } as const;

/** Detect capabilities this Action can evaluate, announced to the server via `?caps=`. */
export const SUPPORTED_CAPS: readonly string[] = ['context'];

export function isFramework(value: unknown): value is FrameworkId {
  return typeof value === 'string' && (FRAMEWORKS as readonly string[]).includes(value);
}

export interface FailOn {
  failOn: FrameworkId[];
  unknown: string[];
}

/**
 * Parse the `fail-on` input: a comma list of framework names, case-insensitive.
 * Empty -> only the original GDPR stream (today's behaviour). `none` -> no
 * framework fails the step. Names we do not know are returned separately so the
 * caller can warn about a typo; a list made ONLY of unknown names falls back to the
 * default rather than silently disabling failing.
 */
export function parseFailOn(raw: string | null | undefined): FailOn {
  const tokens = (raw ?? '').split(',').map((t) => t.trim()).filter(Boolean);
  if (tokens.length === 0) return { failOn: [DEFAULT_FRAMEWORK], unknown: [] };
  if (tokens.length === 1 && tokens[0].toLowerCase() === 'none') return { failOn: [], unknown: [] };

  const wanted = new Set<FrameworkId>();
  const unknown: string[] = [];
  for (const token of tokens) {
    const match = FRAMEWORKS.find((f) => f.toLowerCase() === token.toLowerCase());
    if (match) wanted.add(match);
    else unknown.push(token);
  }
  if (wanted.size === 0) return { failOn: [DEFAULT_FRAMEWORK], unknown };
  return { failOn: FRAMEWORKS.filter((f) => wanted.has(f)), unknown };
}
