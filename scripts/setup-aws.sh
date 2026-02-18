#!/bin/bash
set -euo pipefail

# --- Configuration ---
ISSUER_URL="https://dorakemon.github.io/oidc-provider"
ROLE_NAME="oidc-self-hosted-role"
SUBJECT="admin"

echo "=== Step 1: Get GitHub Pages TLS thumbprint ==="
# AWS requires the thumbprint of the top intermediate CA cert for the OIDC provider's TLS chain.
# For GitHub Pages (served via Fastly/GitHub CDN), we extract it here.
THUMBPRINT=$(openssl s_client -connect dorakemon.github.io:443 -servername dorakemon.github.io \
  </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -noout \
  | sed 's/.*=//;s/://g' \
  | tr 'A-F' 'a-f')

echo "Thumbprint: $THUMBPRINT"

echo ""
echo "=== Step 2: Create OIDC Identity Provider ==="
echo "Running: aws iam create-open-id-connect-provider"

aws iam create-open-id-connect-provider \
  --url "$ISSUER_URL" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "$THUMBPRINT"

echo "Done."

echo ""
echo "=== Step 3: Get AWS Account ID ==="
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
echo "Account ID: $ACCOUNT_ID"

echo ""
echo "=== Step 4: Create IAM Role with trust policy ==="

TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/dorakemon.github.io/oidc-provider"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "dorakemon.github.io/oidc-provider:aud": "sts.amazonaws.com",
          "dorakemon.github.io/oidc-provider:sub": "${SUBJECT}"
        }
      }
    }
  ]
}
EOF
)

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document "$TRUST_POLICY"

echo ""
echo "=== Step 5: Attach a policy (example: ReadOnlyAccess) ==="
aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/ReadOnlyAccess"

echo ""
echo "=== Done! ==="
echo ""
echo "Role ARN: arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
echo "Test with:"
echo "  ./scripts/get-credentials.sh arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo ""
echo "Or:"
echo "  eval \$(./scripts/get-credentials.sh arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME})"
echo "  aws sts get-caller-identity"
