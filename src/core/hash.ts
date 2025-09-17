import { createHash } from 'node:crypto';

export function sha256(data: Uint8Array | string): Uint8Array {
  const h = createHash('sha256');
  h.update(data);
  return h.digest();
}

export function toBase64Url(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

export function fromBase64Url(s: string): Uint8Array {
  return Buffer.from(s, 'base64url');
}
