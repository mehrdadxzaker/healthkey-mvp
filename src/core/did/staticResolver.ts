import fs from 'node:fs';
import path from 'node:path';
import { DidResolver } from './interface.js';
import { readKeysMap } from '../../config.js';

export class StaticResolver implements DidResolver {
  private keyMap: Record<string, string>;
  constructor() {
    this.keyMap = readKeysMap();
  }
  async resolvePublicKeyPem(kid: string): Promise<string | null> {
    const p = this.keyMap[kid];
    if (!p) return null;
    const abs = path.isAbsolute(p) ? p : path.join(process.cwd(), p);
    if (!fs.existsSync(abs)) return null;
    return fs.readFileSync(abs, 'utf8');
  }
}
