#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KEYS_DIR="$PROJECT_ROOT/keys"
JWKS_OUT="$PROJECT_ROOT/docs/.well-known/jwks.json"

if [ ! -f "$KEYS_DIR/public.pem" ]; then
  echo "Error: keys/public.pem not found. Run ./scripts/generate-keys.sh first."
  exit 1
fi

KID="key-1"

# Extract the raw EC public key point (x, y coordinates)
# EC P-256 public key is 65 bytes: 0x04 || x (32 bytes) || y (32 bytes)
RAW_HEX=$(openssl ec -pubin -in "$KEYS_DIR/public.pem" -text -noout 2>/dev/null \
  | sed -n '/^pub:/,/^ASN1/p' \
  | grep -v 'pub:' \
  | grep -v 'ASN1' \
  | tr -d ' :\n')

# Strip the leading "04" uncompressed point indicator
RAW_HEX="${RAW_HEX#04}"

# Split into x (first 64 hex chars = 32 bytes) and y (last 64 hex chars)
X_HEX="${RAW_HEX:0:64}"
Y_HEX="${RAW_HEX:64:64}"

# Convert hex to base64url
X=$(echo "$X_HEX" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=\n')
Y=$(echo "$Y_HEX" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=\n')

mkdir -p "$(dirname "$JWKS_OUT")"

jq -n \
  --arg kid "$KID" \
  --arg x "$X" \
  --arg y "$Y" \
  '{
    keys: [
      {
        kty: "EC",
        kid: $kid,
        use: "sig",
        alg: "ES256",
        crv: "P-256",
        x: $x,
        y: $y
      }
    ]
  }' > "$JWKS_OUT"

echo "JWKS written to $JWKS_OUT"
