import canonicalizeOrig from 'canonicalize';

/**
 * RFC 8785-style canonicalization.
 * We rely on the 'canonicalize' npm package for JCS.
 */
export function canonicalize(obj: any): string {
  // Ensure we don't accidentally include undefined fields
  const pruned = JSON.parse(JSON.stringify(obj));
  const c = canonicalizeOrig(pruned);
  if (!c) throw new Error('canonicalize failed');
  return c;
}

// Helper to strip signature/log fields before signing
export function stripForSigning(obj: any): any {
  const { sig, log_inclusion, ...rest } = obj;
  return rest;
}
