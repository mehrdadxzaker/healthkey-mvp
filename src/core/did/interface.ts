export interface DidResolver {
  resolvePublicKeyPem(kid: string): Promise<string | null>;
}
