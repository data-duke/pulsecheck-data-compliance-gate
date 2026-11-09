/**
 * Source-control providers this client can scan for. The server's enum is wider (`ciFrameworks.ts` CI_SCAN_PROVIDERS also
 * lists Azure DevOps and Bitbucket); only the two with an adapter are accepted here, so a typo in `--provider` is an
 * error and not a silent GitHub scan.
 *
 * GitHub is the default everywhere. The server also defaults an absent provider to `github`, which is why a GitHub
 * request carries no provider at all (its bytes are what they always were) and why every path that would drop the
 * provider (the legacy post shape) is closed for any other provider (report.ts).
 */
export const GATE_PROVIDERS = ['github', 'gitlab'] as const;
export type GateProvider = (typeof GATE_PROVIDERS)[number];
export const DEFAULT_PROVIDER: GateProvider = 'github';

export const PROVIDER_LABEL: Record<GateProvider, string> = { github: 'GitHub', gitlab: 'GitLab' };

export function isGateProvider(value: unknown): value is GateProvider {
  return typeof value === 'string' && (GATE_PROVIDERS as readonly string[]).includes(value);
}
