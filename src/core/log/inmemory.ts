import { createHash } from 'node:crypto';
import { TransparencyLog, InclusionProofStep, LogInclusion, STHBody, SignedSTH } from './interface.js';
import { LOG_ID, LOG_PUBLIC_KID, LOG_PRIVATE_KEY_PATH } from '../../config.js';
import { canonicalize } from '../canonicalize.js';
import { signLinkTx } from '../sign.js';
import fs from 'node:fs';

function sha256(buf: Uint8Array): Buffer {
  const h = createHash('sha256');
  h.update(buf);
  return h.digest();
}

function b64u(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64url');
}

function leafHash(data: Uint8Array): Buffer {
  // RFC 6962: leaf hash = H(0x00 || data)
  return sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(data)]));
}

function nodeHash(left: Uint8Array, right: Uint8Array): Buffer {
  // RFC 6962: node hash = H(0x01 || left || right)
  return sha256(Buffer.concat([Buffer.from([0x01]), Buffer.from(left), Buffer.from(right)]));
}

function buildLevels(leaves: Buffer[]): Buffer[][] {
  if (leaves.length === 0) return [];
  const levels: Buffer[][] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) next.push(nodeHash(current[i], current[i+1]));
      else next.push(current[i]);
    }
    levels.push(next);
    current = next;
  }
  return levels;
}

function merkleRoot(leaves: Buffer[]): Buffer {
  const levels = buildLevels(leaves);
  if (levels.length === 0) return Buffer.alloc(0);
  return levels[levels.length - 1][0];
}

function inclusionPath(leaves: Buffer[], index: number): InclusionProofStep[] {
  const levels = buildLevels(leaves);
  const proof: InclusionProofStep[] = [];
  let idx = index;
  for (let lvl = 0; lvl < levels.length - 1; lvl++) {
    const level = levels[lvl];
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;
    if (siblingIdx < level.length) {
      const side: 'left' | 'right' = isRight ? 'left' : 'right';
      proof.push({ side, hash_b64u: b64u(level[siblingIdx]) });
    }
    idx = Math.floor(idx / 2);
  }
  return proof;
}

function signSTHBody(body: STHBody): SignedSTH {
  const privateKeyPem = fs.readFileSync(LOG_PRIVATE_KEY_PATH, 'utf8');
  const toSign = { ...body }; // keep stable ordering via canonicalization
  const payload = canonicalize(toSign);
  // Reuse the same JWS helper with a raw JSON payload (we treat it as a generic object).
  const fakeTx = { sth: { body: toSign } };
  return {
    body,
    // signLinkTx expects an object and strips sig/log fields. We'll sign `fakeTx.sth.body` via its canonical form.
    // To keep it simple, sign the pure body object:
    sig: { kid: LOG_PUBLIC_KID, jws: '' }
  };
}

// Instead of reusing signLinkTx (which strips fields), implement a tiny JWS signer for STH:
import { CompactSign, importPKCS8 } from 'jose';
async function signSTH(body: STHBody): Promise<SignedSTH> {
  const privateKeyPem = fs.readFileSync(LOG_PRIVATE_KEY_PATH, 'utf8');
  const pkcs8 = await importPKCS8(privateKeyPem, 'EdDSA');
  const json = canonicalize(body);
  const payload = new TextEncoder().encode(json);
  const jws = await new CompactSign(payload).setProtectedHeader({ alg: 'EdDSA', kid: LOG_PUBLIC_KID }).sign(pkcs8);
  return { body, sig: { kid: LOG_PUBLIC_KID, jws } };
}

export class InMemoryTransparencyLog implements TransparencyLog {
  private leaves: Buffer[] = [];
  private txIndex: Map<string, number> = new Map(); // tx_id -> index
  private leafMap: Map<number, Buffer> = new Map(); // index -> leaf

  constructor() {}

  size(): number { return this.leaves.length; }

  async append(leafData: Uint8Array): Promise<{ index: number; inclusion: LogInclusion }> {
    const leaf = leafHash(leafData);
    const index = this.leaves.length;
    this.leaves.push(leaf);
    this.leafMap.set(index, leaf);
    const root = merkleRoot(this.leaves);
    const proof = inclusionPath(this.leaves, index);
    const sth = await signSTH({ size: this.leaves.length, root_b64u: b64u(root), timestamp: new Date().toISOString(), log_id: LOG_ID });
    const inclusion: LogInclusion = { log: LOG_ID, leaf_index: index, proof, sth };
    return { index, inclusion };
  }

  async prove(index: number): Promise<LogInclusion | null> {
    if (index < 0 || index >= this.leaves.length) return null;
    const root = merkleRoot(this.leaves);
    const proof = inclusionPath(this.leaves, index);
    const sth = await signSTH({ size: this.leaves.length, root_b64u: b64u(root), timestamp: new Date().toISOString(), log_id: LOG_ID });
    return { log: LOG_ID, leaf_index: index, proof, sth };
  }
}
