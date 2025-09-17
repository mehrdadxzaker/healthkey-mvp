export interface InclusionProofStep {
  side: 'left' | 'right';
  hash_b64u: string;
}

export interface STHBody {
  size: number;
  root_b64u: string;
  timestamp: string;
  log_id: string;
}

export interface SignedSTH {
  body: STHBody;
  sig: { kid: string; jws: string };
}

export interface LogInclusion {
  log: string;
  leaf_index: number;
  proof: InclusionProofStep[];
  sth: SignedSTH;
}

export interface TransparencyLog {
  append(leafData: Uint8Array): Promise<{ index: number; inclusion: LogInclusion }>;
  prove(index: number): Promise<LogInclusion | null>;
  size(): number;
}
