export type Action = 'READ' | 'WRITE' | 'DISCLOSE' | 'DELETE';

export interface LinkTx {
  tx_id?: string;
  created_at?: string;
  actor: { id: string; role?: string };
  subject?: { id?: string };
  action: Action;
  resource_ref: { scheme: 'dbid' | 'cid' | 'zcap' | 'did-resource'; id: string; version?: string | number | null; cap_ref?: string | null; };
  hash_commitment: { alg: 'sha-256' | 'sha-512'; value: string; schema: string; };
  consent_snapshot?: {
    consent_id?: string;
    legal_basis?: string;
    purpose?: string;
    status?: string;
    valid_until?: string | null;
    notice_hash?: string;
    [k: string]: unknown;
  };
  audit?: Record<string, unknown>;
  prev_tx?: string | null;
  log_inclusion?: any;
  sig?: { suite: 'JOSE+EdDSA' | 'COSE+EdDSA'; kid: string; jws: string };
}
