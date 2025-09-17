import { FastifyInstance } from 'fastify';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import schema from '../core/schema/linktx-v1.schema.json' assert { type: 'json' };
import { LinkTx } from '../core/types.js';
import { canonicalize, stripForSigning } from '../core/canonicalize.js';
import { nowIso } from '../core/time.js';
import { signLinkTx, verifyLinkTx } from '../core/sign.js';
import { InMemoryTransparencyLog } from '../core/log/inmemory.js';
import { verifyInclusion, verifyJwsAgainstObject, verifySTH } from '../core/verify.js';
import { evaluatePolicy } from '../core/policy.js';
import { readPem, PRIVATE_KEY_PATH, PUBLIC_KEY_KID, LOG_PRIVATE_KEY_PATH, LOG_PUBLIC_KID } from '../config.js';
import { StaticResolver } from '../core/did/staticResolver.js';
import { saveTx, readTx } from '../storage/fileStore.js';
import { ulid } from 'ulid';
import fs from 'node:fs';

const ajv = new Ajv({ allErrors: true, allowUnionTypes: true });
addFormats(ajv);
const validate = ajv.compile(schema as any);

const log = new InMemoryTransparencyLog();
const did = new StaticResolver();

export default async function txRoutes(app: FastifyInstance) {

  app.post('/tx', async (req, reply) => {
    const body = req.body as LinkTx;
    // 1) Validate basic shape
    if (!validate(body)) {
      return reply.code(400).send({ ok: false, error: 'validation', details: validate.errors });
    }
    // 2) Fill server fields
    const tx: LinkTx = { ...body };
    tx.tx_id = tx.tx_id || ulid();
    tx.created_at = tx.created_at || nowIso();
    tx.audit = { ...(tx.audit || {}), ts_source: 'system' };

    // 3) Policy check (pre-sign)
    const { allowed, reason } = await evaluatePolicy(tx);
    if (!allowed) {
      return reply.code(403).send({ ok: false, error: 'policy_denied', reason });
    }

    // 4) Sign
    const pem = readPem(PRIVATE_KEY_PATH);
    const { jws } = await signLinkTx(tx, { kid: PUBLIC_KEY_KID, privateKeyPem: pem });
    tx.sig = { suite: 'JOSE+EdDSA', kid: PUBLIC_KEY_KID, jws };

    // 5) Append to transparency log (leaf = canonicalized payload without sig/log)
    const leafPayload = new TextEncoder().encode(canonicalize(stripForSigning(tx)));
    const { inclusion } = await log.append(leafPayload);
    tx.log_inclusion = inclusion;

    // 6) Store
    saveTx(tx.tx_id!, tx);

    return { ok: true, tx };
  });

  app.post('/verify', async (req, reply) => {
    const tx = req.body as LinkTx;
    if (!tx || !tx.sig?.jws) return reply.code(400).send({ ok: false, error: 'missing_sig' });

    // 1) Resolve signer key
    const signerPem = await did.resolvePublicKeyPem(tx.sig.kid || tx.actor.id);
    if (!signerPem) return reply.code(400).send({ ok: false, error: 'unknown_signer' });

    // 2) Verify JWS payload matches canonical(tx without sig/log)
    let sigOk = false;
    try { sigOk = await verifyJwsAgainstObject(tx, tx.sig.jws, signerPem); } catch {}

    // 3) Verify inclusion (Merkle) and STH
    let inclOk = false;
    let sthOk = false;
    try {
      const inclusion = tx.log_inclusion as any;
      const leafPayload = new TextEncoder().encode(canonicalize(stripForSigning(tx)));
      inclOk = inclusion && verifyInclusion(leafPayload, inclusion.proof, inclusion.sth?.body?.root_b64u);
      // Verify STH signature using the log's public key
      const logPub = await did.resolvePublicKeyPem(inclusion?.sth?.sig?.kid || 'did:web:example.org#log-key');
      if (logPub) {
        sthOk = await verifySTH(inclusion.sth, logPub);
      }
    } catch {}

    // 4) Optional: re-run policy (purely informational)
    const { allowed } = await evaluatePolicy(tx);

    return { ok: sigOk && inclOk && sthOk, checks: { sig: sigOk, inclusion: inclOk, sth: sthOk, policy: allowed } };
  });

  app.get('/tx/:id', async (req, reply) => {
    const id = (req.params as any).id;
    const tx = readTx(id);
    if (!tx) return reply.code(404).send({ ok: false, error: 'not_found' });
    return { ok: true, tx };
  });

  app.get('/prove/:index', async (req, reply) => {
    const idx = Number((req.params as any).index);
    const inc = await log.prove(idx);
    if (!inc) return reply.code(404).send({ ok: false, error: 'not_found' });
    return { ok: true, inclusion: inc };
  });
}
