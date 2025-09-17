#!/usr/bin/env node
import fs from 'node:fs';
import { signLinkTx, verifyLinkTx } from '../core/sign.js';
import { readPem, PRIVATE_KEY_PATH, PUBLIC_KEY_KID } from '../config.js';
import { StaticResolver } from '../core/did/staticResolver.js';

const [, , cmd, file] = process.argv;

async function main() {
  if (!cmd || !file) {
    console.log('Usage: npm run sign -- sign <file.json>');
    console.log('       npm run verify -- verify <file.json>');
    process.exit(1);
  }
  const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (cmd === 'sign') {
    const pem = readPem(PRIVATE_KEY_PATH);
    const { jws } = await signLinkTx(obj, { kid: PUBLIC_KEY_KID, privateKeyPem: pem });
    obj.sig = { suite: 'JOSE+EdDSA', kid: PUBLIC_KEY_KID, jws };
    console.log(JSON.stringify(obj, null, 2));
  } else if (cmd === 'verify') {
    const did = new StaticResolver();
    const pem = await did.resolvePublicKeyPem(obj.sig?.kid || obj.actor?.id);
    if (!pem) {
      console.error('Unknown signer kid.');
      process.exit(2);
    }
    const ok = await verifyLinkTx(obj, obj.sig.jws, pem);
    console.log(JSON.stringify({ ok }, null, 2));
  } else {
    console.error('Unknown command');
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
