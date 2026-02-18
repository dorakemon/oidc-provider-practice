#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PRIVATE_KEY="$PROJECT_ROOT/keys/private.pem"

# --- Configuration ---
ISSUER="https://dorakemon.github.io/oidc-provider"
AUDIENCE="sts.amazonaws.com"
SUBJECT="admin"
KID="key-1"
TOKEN_LIFETIME=3600  # seconds

# Role ARN must be set via environment variable or argument
ROLE_ARN="${1:-${ROLE_ARN:-}}"
if [ -z "$ROLE_ARN" ]; then
  echo "Usage: $0 <role-arn>" >&2
  echo "  or: ROLE_ARN=arn:aws:iam::123456789012:role/MyRole $0" >&2
  exit 1
fi

if [ ! -f "$PRIVATE_KEY" ]; then
  echo "Error: keys/private.pem not found. Run ./scripts/generate-keys.sh first." >&2
  exit 1
fi

# --- Helper: base64url encode (no padding) ---
base64url() {
  base64 | tr '+/' '-_' | tr -d '=\n'
}

# --- Helper: Convert DER signature (ASN.1) to fixed-size r||s for ES256 ---
# ECDSA DER: 0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>
# ES256 JWS requires raw r||s, each 32 bytes, zero-padded
der_to_raw_es256() {
  local der_hex
  der_hex=$(xxd -p | tr -d '\n')

  # Parse DER structure
  local offset=4  # skip 30 <total_len> 02
  local r_len_hex="${der_hex:$offset:2}"
  local r_len=$((16#$r_len_hex))
  offset=$((offset + 2))

  local r_hex="${der_hex:$offset:$((r_len * 2))}"
  offset=$((offset + r_len * 2 + 2))  # skip r bytes + 02

  local s_len_hex="${der_hex:$offset:2}"
  local s_len=$((16#$s_len_hex))
  offset=$((offset + 2))

  local s_hex="${der_hex:$offset:$((s_len * 2))}"

  # Strip leading zero padding (DER adds 0x00 if high bit is set)
  while [ ${#r_hex} -gt 64 ]; do r_hex="${r_hex:2}"; done
  while [ ${#s_hex} -gt 64 ]; do s_hex="${s_hex:2}"; done

  # Zero-pad to 32 bytes each
  while [ ${#r_hex} -lt 64 ]; do r_hex="00${r_hex}"; done
  while [ ${#s_hex} -lt 64 ]; do s_hex="00${s_hex}"; done

  echo "${r_hex}${s_hex}" | xxd -r -p
}

# --- Build JWT ---
NOW=$(date +%s)
EXP=$((NOW + TOKEN_LIFETIME))

HEADER=$(printf '{"alg":"ES256","kid":"%s","typ":"JWT"}' "$KID" | base64url)
PAYLOAD=$(printf '{"iss":"%s","sub":"%s","aud":"%s","iat":%d,"exp":%d}' \
  "$ISSUER" "$SUBJECT" "$AUDIENCE" "$NOW" "$EXP" | base64url)

SIGNING_INPUT="${HEADER}.${PAYLOAD}"

# Sign with ECDSA-SHA256, then convert DER to raw r||s
SIGNATURE=$(printf '%s' "$SIGNING_INPUT" \
  | openssl dgst -sha256 -sign "$PRIVATE_KEY" -binary \
  | der_to_raw_es256 \
  | base64url)

JWT="${SIGNING_INPUT}.${SIGNATURE}"

# --- Call STS ---
echo "Requesting temporary credentials..." >&2

RESULT=$(aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "oidc-session-$(date +%s)" \
  --web-identity-token "$JWT" \
  --output json)

# --- Output as export commands ---
ACCESS_KEY=$(echo "$RESULT" | jq -r '.Credentials.AccessKeyId')
SECRET_KEY=$(echo "$RESULT" | jq -r '.Credentials.SecretAccessKey')
SESSION_TOKEN=$(echo "$RESULT" | jq -r '.Credentials.SessionToken')
EXPIRATION=$(echo "$RESULT" | jq -r '.Credentials.Expiration')

echo "# Credentials expire at: $EXPIRATION" >&2
echo "# Run: eval \$($0 $ROLE_ARN)" >&2

echo "export AWS_ACCESS_KEY_ID=$ACCESS_KEY"
echo "export AWS_SECRET_ACCESS_KEY=$SECRET_KEY"
echo "export AWS_SESSION_TOKEN=$SESSION_TOKEN"
