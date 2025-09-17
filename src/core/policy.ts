import { OPA_URL } from '../config.js';

export async function evaluatePolicy(input: any): Promise<{ allowed: boolean; reason?: any }> {
  if (!OPA_URL) return { allowed: true }; // policy disabled
  try {
    const res = await fetch(OPA_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input })
    });
    const data = await res.json();
    // For the sample policy, OPA returns { result: true|false }
    const allowed = !!data.result;
    return { allowed, reason: allowed ? undefined : data };
  } catch (e) {
    return { allowed: false, reason: String(e) };
  }
}
