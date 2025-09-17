import fs from 'node:fs';
import path from 'node:path';

const DATA_DIR = path.join(process.cwd(), 'data', 'tx');
fs.mkdirSync(DATA_DIR, { recursive: true });

export function saveTx(txId: string, obj: any) {
  const p = path.join(DATA_DIR, `${txId}.json`);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8');
}

export function readTx(txId: string) {
  const p = path.join(DATA_DIR, `${txId}.json`);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}
