/**
 * Ruleset retrieval. The Action bakes in NO rules — it is a dumb sensor. The
 * authoritative ruleset is pulled from PulseCheck at run time so policy can
 * change centrally without re-releasing the Action.
 */
import { Ruleset } from './types.js';

/** Typed error for any failure obtaining the ruleset (network or HTTP). */
export class RulesetFetchError extends Error {
  readonly status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = 'RulesetFetchError';
    this.status = status;
  }
}

/**
 * GET `${url}/functions/v1/ci-ruleset` with a bearer token.
 * Returns the parsed, lightly-validated ruleset.
 *
 * Throws `RulesetFetchError` on any network error, non-2xx status, or invalid
 * JSON. Callers must treat that as "cannot scan" and fall back to
 * needs_review/neutral — never a silent pass.
 */
export async function fetchRuleset(url: string, token: string): Promise<Ruleset> {
  const base = url.replace(/\/+$/, '');
  const endpoint = `${base}/functions/v1/ci-ruleset`;

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
      `Ruleset fetch returned HTTP ${res.status} from ${endpoint}`,
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

  return validateRuleset(json, endpoint);
}

/** Minimal shape validation so a malformed payload fails loudly, not silently. */
function validateRuleset(json: unknown, endpoint: string): Ruleset {
  if (!json || typeof json !== 'object') {
    throw new RulesetFetchError(`Ruleset response from ${endpoint} was not an object.`);
  }
  const obj = json as Record<string, unknown>;
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
