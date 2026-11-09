/**
 * Ruleset retrieval. The Action bakes in NO rules: it is a dumb sensor. The
 * authoritative rulesets are pulled from PulseCheck at run time so policy can
 * change centrally without re-releasing the Action.
 *
 * It asks for the multi-framework "schema 2" response. An OLD server ignores the
 * unknown query parameter and returns the single legacy ruleset; that is read as
 * one 'Data Compliance' ruleset, so this Action keeps working against a server
 * that has not been redeployed yet (our own PR CI runs exactly that mix).
 */
import { DEFAULT_PROVIDER, type GateProvider } from './provider.js';
import { DEFAULT_FRAMEWORK, isFramework, SUPPORTED_CAPS } from './frameworks.js';
import type { FrameworkRuleset, Ruleset } from './types.js';

/** Typed error for any failure obtaining the ruleset (network or HTTP). */
export class RulesetFetchError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'RulesetFetchError';
    this.status = status;
  }
}

/** Which response shape the server answered with; decides how the verdict is posted back. */
export type ServerShape = 'legacy' | 'schema2';

export interface FetchedRulesets {
  shape: ServerShape;
  rulesets: FrameworkRuleset[];
  /** Frameworks the server says it could not serve this time (schema 2 only), already sanitised. */
  unavailable: Array<{ framework: string; reason: string }>;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const REASON = /^[a-z_]{1,40}$/;
const MAX_UNAVAILABLE = 8;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The registry context of one schema-2 ruleset. Both fields or neither: a context without a valid 64-hex hash
 * (or the reverse) is REJECTED, so the Action never grades with, or posts, a context the server would refuse.
 */
function readContext(e: Record<string, unknown>): Pick<FrameworkRuleset, 'context' | 'context_hash' | 'context_rejected'> {
  const hasContext = e.context !== undefined && e.context !== null;
  const hasHash = e.context_hash !== undefined && e.context_hash !== null;
  if (!hasContext && !hasHash) return {};
  if (hasContext && hasHash && isPlainObject(e.context) && typeof e.context_hash === 'string' && SHA256_HEX.test(e.context_hash)) {
    return { context: e.context, context_hash: e.context_hash };
  }
  return { context_rejected: true };
}

function readUnavailable(raw: unknown): FetchedRulesets['unavailable'] {
  if (!Array.isArray(raw)) return [];
  const out: FetchedRulesets['unavailable'] = [];
  for (const item of raw.slice(0, MAX_UNAVAILABLE)) {
    if (!isPlainObject(item)) continue;
    const { framework, reason } = item;
    if (typeof framework !== 'string' || framework.length === 0 || framework.length > 64) continue;
    if (typeof reason !== 'string' || !REASON.test(reason)) continue;
    out.push({ framework: framework.replace(/[^A-Za-z0-9 ._-]/g, ''), reason });
  }
  return out;
}

/**
 * GET `${url}/functions/v1/ci-ruleset?schema=2[&caps=...]` with a bearer token.
 *
 * Throws `RulesetFetchError` on any network error, non-2xx status, invalid JSON or
 * unusable payload. Callers must treat that as "cannot scan" and fall back to
 * needs_review/neutral, never a silent pass.
 */
export async function fetchRulesets(
  url: string,
  token: string,
  caps: readonly string[] = SUPPORTED_CAPS,
  repo?: string,
  provider: GateProvider = DEFAULT_PROVIDER,
): Promise<FetchedRulesets> {
  const base = url.replace(/\/+$/, '');
  const query = new URLSearchParams({ schema: '2' });
  if (caps.length > 0) query.set('caps', caps.join(','));
  // The registry context is per repository. The server normalises the path; nothing here stores it.
  if (repo) query.set('repo', repo);
  // The server reads an absent provider as GitHub, so GitHub sends none: its request stays byte-identical.
  if (provider !== DEFAULT_PROVIDER) query.set('provider', provider);
  const endpoint = `${base}/functions/v1/ci-ruleset?${query.toString()}`;

  let res: Response;
  try {
    res = await fetch(endpoint, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });
  } catch (err) {
    throw new RulesetFetchError(
      `Network error fetching ruleset from ${endpoint}: ${(err as Error)?.message ?? err}`,
    );
  }

  if (!res.ok) {
    throw new RulesetFetchError(
      `Ruleset fetch returned HTTP ${res.status} from ${endpoint}` +
        (res.status === 403
          ? ' (this token may lack the ruleset:read scope, or be limited to other repositories or providers: create one for this repository in PulseCheck, Organization Settings, CI Gate)'
          : ''),
      res.status,
    );
  }

  let json: unknown;
  try {
    json = await res.json();
  } catch (err) {
    throw new RulesetFetchError(
      `Ruleset response was not valid JSON: ${(err as Error)?.message ?? err}`,
      res.status,
    );
  }

  if (!json || typeof json !== 'object') {
    throw new RulesetFetchError(`Ruleset response from ${endpoint} was not an object.`);
  }
  const obj = json as Record<string, unknown>;

  // Legacy server: a single ruleset at the top level.
  if (obj.schema !== 2) {
    return { shape: 'legacy', rulesets: [{ ...validateRuleset(obj), framework: DEFAULT_FRAMEWORK }], unavailable: [] };
  }

  if (!Array.isArray(obj.rulesets)) {
    throw new RulesetFetchError(`Schema-2 ruleset response is missing a "rulesets" array.`);
  }
  const rulesets: FrameworkRuleset[] = [];
  for (const entry of obj.rulesets) {
    if (!entry || typeof entry !== 'object') {
      throw new RulesetFetchError(`Schema-2 ruleset response contains a non-object entry.`);
    }
    const e = entry as Record<string, unknown>;
    // A framework this Action predates (a newer server) is skipped, not fatal.
    if (!isFramework(e.framework)) continue;
    rulesets.push({
      ...validateRuleset(e),
      framework: e.framework,
      dropped_rules: Array.isArray(e.dropped_rules) ? (e.dropped_rules as FrameworkRuleset['dropped_rules']) : [],
      ...readContext(e),
    });
  }
  if (rulesets.length === 0) {
    throw new RulesetFetchError(`Schema-2 ruleset response held no framework this Action understands.`);
  }
  return { shape: 'schema2', rulesets, unavailable: readUnavailable(obj.unavailable) };
}

/** Minimal shape validation so a malformed payload fails loudly, not silently. */
function validateRuleset(obj: Record<string, unknown>): Ruleset {
  if (typeof obj.ruleset_version !== 'number') {
    throw new RulesetFetchError(`Ruleset is missing a numeric "ruleset_version".`);
  }
  if (typeof obj.ruleset_hash !== 'string') {
    throw new RulesetFetchError(`Ruleset is missing a string "ruleset_hash".`);
  }
  if (!Array.isArray(obj.rules)) {
    throw new RulesetFetchError(`Ruleset is missing a "rules" array.`);
  }
  return {
    ruleset_version: obj.ruleset_version,
    ruleset_hash: obj.ruleset_hash,
    rules: obj.rules as Ruleset['rules'],
    allowlist: (obj.allowlist as Ruleset['allowlist']) ?? {
      emails: [],
      names: [],
      domains: [],
      ip_ranges: [],
      ibans: [],
    },
    signatures: (obj.signatures as Ruleset['signatures']) ?? {
      'telemetry-sdks': [],
      'pii-datastore-credentials': [],
      'processor-jurisdiction': [],
    },
  };
}
