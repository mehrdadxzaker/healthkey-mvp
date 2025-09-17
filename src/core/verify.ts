import { CompactVerify, importSPKI } from 'jose';
import { InclusionProofStep, SignedSTH } from './log/interface.js';
import { canonicalize, stripForSigning } from './canonicalize.js';
import { createHash } from 'node:crypto';

function sha256(buf: Uint8Array): Buffer {
  const h = createHash('sha256');
  h.update(buf);
  return h.digest();
}

function b64u(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

function deb64u(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

function leafHash(data: Uint8Array): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(data)]));
}

function nodeHash(left: Uint8Array, right: Uint8Array): Buffer {
  return sha256(Buffer.concat([Buffer.from([0x01]), Buffer.from(left), Buffer.from(right)]));
}

export async function verifyJwsAgainstObject(obj: any, jws: string, publicKeyPem: string): Promise<boolean> {
  const expected = new TextEncoder().encode(canonicalize(stripForSigning(obj)));
  const spki = await importSPKI(publicKeyPem, 'EdDSA');
  const { payload } = await CompactVerify(jws, spki);
  return Buffer.compare(Buffer.from(payload), Buffer.from(expected)) === 0;
}

export function verifyInclusion(leafData: Uint8Array, proof: InclusionProofStep[], sthRootB64u: string): boolean {
  // Recompute root from leaf + proof
  let acc = leafHash(leafData);
  for (const step of proof) {
    const sib = deb64u(step.hash_b64u);
    if (step.side === 'left') acc = nodeHash(sib, acc);
    else acc = nodeHash(acc, sib);
  }
  const computedRoot = b64u(acc);
  return computedRoot === sthRootB64u;
}

export async function verifySTH(sth: SignedSTH, logPublicKeyPem: string): Promise<boolean> {
  const spki = await importSPKI(logPublicKeyPem, 'EdDSA');
  const json = canonicalize(sth.body);
  const { payload } = await CompactVerify(sth.sig.jws, spki);
  return Buffer.compare(Buffer.from(payload), Buffer.from(new TextEncoder().encode(json))) === 0;
}
