import 'dotenv/config';
import fs from 'node:fs';

export const PORT = Number(process.env.PORT || 8080);

export const PRIVATE_KEY_PATH = process.env.PRIVATE_KEY_PATH || './config/dev-ed25519-private.pem';
export const PUBLIC_KEY_KID = process.env.PUBLIC_KEY_KID || 'did:web:example.org#key-1';

export const LOG_PRIVATE_KEY_PATH = process.env.LOG_PRIVATE_KEY_PATH || './config/log-ed25519-private.pem';
export const LOG_PUBLIC_KID = process.env.LOG_PUBLIC_KID || 'did:web:example.org#log-key';
export const LOG_ID = process.env.LOG_ID || 'inmemory-log-1';

export const OPA_URL = process.env.OPA_URL || '';

export function readPem(path: string): string {
  return fs.readFileSync(path, 'utf8');
}

export function readKeysMap(): Record<string, string> {
  try {
    const raw = fs.readFileSync('./config/keys.json', 'utf8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}
