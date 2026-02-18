#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$PROJECT_ROOT/keys"

mkdir -p "$KEYS_DIR"

if [ -f "$KEYS_DIR/private.pem" ]; then
  echo "keys/private.pem already exists. Delete it first to regenerate."
  exit 1
fi

echo "Generating EC P-256 key pair..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/private.pem"
openssl ec -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"

echo "Done."
echo "  Private key: $KEYS_DIR/private.pem"
echo "  Public key:  $KEYS_DIR/public.pem"
echo ""
echo "Next: run ./scripts/generate-jwks.sh to publish the public key as JWKS."
