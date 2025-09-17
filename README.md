# HealthKey MVP — verifiable audit trail for database access

A tiny, lovable product that records **who did what to which data and why**, as cryptographically verifiable transactions.
Each transaction (**LinkTx**) is:
- Canonicalized (JCS-style),
- Hashed (SHA-256),
- Signed (JWS EdDSA/Ed25519),
- Appended to an append-only transparency log (in-memory Merkle log for the MVP),
- Optionally checked by a policy engine (OPA/Rego).

---

## Why TypeScript/Fastify for the MVP?

- **DX & speed**: easy JSON-first APIs, great libraries for JOSE/JWS, fast event loop.
- **Crypto libs**: `jose` for Ed25519 JWS; Node `crypto` for hashing.
- **Easy to swap**: You can later migrate the transparency log to **Rekor/Trillian** or port to **Go** for tighter Sigstore integration without changing the LinkTx schema.

If you prefer Go, see the **Go port roadmap** at the end of this README.

---

## Quick start

### 1) Requirements
- Node.js 20+
- Docker (optional, for running OPA as a sidecar)

### 2) Install
```bash
npm install
```

### 3) Generate dev keys
```bash
bash scripts/gen-keys.sh
# This writes ./config/dev-ed25519-private.pem and ./config/dev-ed25519-public.pem
```

### 4) Configure
```bash
cp .env.example .env
# Adjust values if needed
```

### 5) (Optional) Start OPA with the sample policy
```bash
docker compose -f docker/docker-compose.yml up -d opa
```

### 6) Run the API
```bash
npm run dev
# or
npm run build && npm start
```

### 7) Try it

Create a minimal LinkTx request (without `sig` and `log_inclusion`) and POST it:

```bash
curl -sX POST http://localhost:8080/tx   -H 'content-type: application/json'   -d @test/sample-tx-input.json | jq .
```

Verify a transaction you got back:
```bash
curl -sX POST http://localhost:8080/verify   -H 'content-type: application/json'   -d @test/sample-tx-verified.json | jq .
```

Health:
```bash
curl -s http://localhost:8080/health
```

---

## What’s in here

```
.
├── README.md
├── package.json
├── tsconfig.json
├── .env.example
├── scripts/
│   └── gen-keys.sh
├── config/
│   ├── keys.json                # maps a kid -> PEM path (demo resolver)
│   └── log-ed25519-private.pem  # created by script (ignored by git)
├── policy/
│   └── linktx.rego
├── docker/
│   └── docker-compose.yml
├── src/
│   ├── index.ts                 # Fastify server bootstrap
│   ├── config.ts                # env + key loading
│   ├── routes/
│   │   ├── health.ts
│   │   └── tx.ts                # /tx, /verify, /prove/:id, /tx/:id
│   ├── storage/
│   │   └── fileStore.ts
│   ├── core/
│   │   ├── schema/linktx-v1.schema.json
│   │   ├── types.ts
│   │   ├── canonicalize.ts
│   │   ├── hash.ts
│   │   ├── sign.ts
│   │   ├── verify.ts
│   │   ├── time.ts
│   │   ├── policy.ts            # OPA client (optional)
│   │   ├── did/
│   │   │   ├── interface.ts
│   │   │   └── staticResolver.ts
│   │   └── log/
│   │       ├── interface.ts
│   │       └── inmemory.ts      # Merkle log (CT-style hash prefixes)
│   └── cli/
│       └── sign-verify.ts       # CLI helper for local signing/verification
└── test/
    ├── sample-tx-input.json
    └── sample-tx-verified.json
```

---

## API (MVP)

### `POST /tx`
- Input: a partial LinkTx (no `tx_id`, `created_at`, `sig`, `log_inclusion`).
- Server:
  - Adds `tx_id` (ULID), `created_at` (RFC3339), `audit.ts_source="system"`,
  - Canonicalizes → hashes → **signs** (JWS Ed25519),
  - Appends to the **in-memory Merkle log** and returns inclusion proof + STH,
  - Returns the full, signed transaction with `log_inclusion`.
- Optional policy check: set `OPA_URL` to enforce Rego before logging.

### `POST /verify`
- Input: a signed LinkTx (the object returned by `/tx`).
- Server:
  - Verifies the JWS signature against the public key resolved via `kid`,
  - Verifies Merkle inclusion proof & STH signature of the in-memory log,
  - Returns `{ ok: true, checks: { sig: true, inclusion: true, policy: true|false } }`.

### `GET /tx/:id`
- Returns the stored LinkTx JSON (if present in the local file store).

### `GET /prove/:id`
- Returns the inclusion proof and STH for that transaction from the current log.

---

## Configuration

See `.env.example` for knobs and defaults. The defaults are secure for local dev. Use HSM/KMS in production (this repo only demonstrates file-based PEM).

---

## Go port roadmap (optional)

- Keep the JSON schema and HTTP shapes identical.
- Use Go's `crypto/ed25519` + `github.com/sigstore/rekor` for a Rekor-backed log,
- Swap the in-memory log for Rekor (append + get inclusion proof),
- Use `github.com/open-policy-agent/opa` as a library or sidecar.
- Reuse the Rego policy and LinkTx schema without changes.

---

## License

Apache-2.0 (feel free to adapt).
