/**
 * Posts the masked verdict back to PulseCheck. Best-effort by design: a failure
 * here never blocks the pipeline and never changes the already-published check
 * run. The body contains ONLY masked findings — never raw evidence.
 */
import { ScanResultPayload } from './types.js';

export interface PostResultOutcome {
  ok: boolean;
  status?: number;
  error?: string;
}

/** POST `${url}/functions/v1/ci-scan-result` with a bearer token. Never throws. */
export async function postResult(
  url: string,
  token: string,
  payload: ScanResultPayload,
): Promise<PostResultOutcome> {
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
    if (!res.ok) {
      return { ok: false, status: res.status, error: `ci-scan-result returned HTTP ${res.status}` };
    }
    return { ok: true, status: res.status };
  } catch (err) {
    return { ok: false, error: (err as Error)?.message ?? String(err) };
  }
}
