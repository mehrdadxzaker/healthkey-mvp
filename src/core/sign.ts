import { CompactSign, CompactVerify, importPKCS8, importSPKI, JWSHeaderParameters } from 'jose';
import { canonicalize, stripForSigning } from './canonicalize.js';
import { sha256 } from './hash.js';

export interface SignOptions {
  kid: string;              // signer kid (usually same as actor.id)
  privateKeyPem: string;    // Ed25519 PKCS#8 PEM
}

export interface VerifyOptions {
  publicKeyPem: string;     // Ed25519 SPKI PEM
}

export function payloadForSigning(obj: any): Uint8Array {
  const s = canonicalize(stripForSigning(obj));
  return new TextEncoder().encode(s);
}

export async function signLinkTx(obj: any, opts: SignOptions): Promise<{ jws: string; header: JWSHeaderParameters }> {
  const payload = payloadForSigning(obj);
  const pkcs8 = await importPKCS8(opts.privateKeyPem, 'EdDSA');
  const jws = await new CompactSign(payload)
    .setProtectedHeader({ alg: 'EdDSA', kid: opts.kid })
    .sign(pkcs8);
  const header = { alg: 'EdDSA', kid: opts.kid };
  return { jws, header };
}

export async function verifyLinkTx(obj: any, jws: string, publicKeyPem: string): Promise<boolean> {
  const expected = payloadForSigning(obj);
  const spki = await importSPKI(publicKeyPem, 'EdDSA');
  const { payload } = await CompactVerify(jws, spki);
  // payload must exactly equal canonicalized object (without sig/log_inclusion)
  return Buffer.compare(Buffer.from(payload), Buffer.from(expected)) === 0;
}
