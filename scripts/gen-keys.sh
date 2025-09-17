#!/usr/bin/env bash
set -euo pipefail

mkdir -p config

if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL is required."
  exit 1
fi

# Actor keys
if [ ! -f config/dev-ed25519-private.pem ]; then
  echo "Generating actor Ed25519 keypair..."
  openssl genpkey -algorithm ED25519 -out config/dev-ed25519-private.pem
  openssl pkey -in config/dev-ed25519-private.pem -pubout -out config/dev-ed25519-public.pem
fi

# Log keys
if [ ! -f config/log-ed25519-private.pem ]; then
  echo "Generating log Ed25519 keypair..."
  openssl genpkey -algorithm ED25519 -out config/log-ed25519-private.pem
  openssl pkey -in config/log-ed25519-private.pem -pubout -out config/log-ed25519-public.pem
fi

# Demo DID->key mapping (static resolver)
cat > config/keys.json <<JSON
{
  "did:web:example.org#key-1": "./config/dev-ed25519-public.pem",
  "did:web:example.org#log-key": "./config/log-ed25519-public.pem"
}
JSON

echo "Done. Keys in ./config. Update .env if needed."
