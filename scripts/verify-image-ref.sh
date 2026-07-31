#!/usr/bin/env bash
# Validates the official prove-it image reference before promoting it into an
# Enclava hosted template. Mirrors enclava-paas/scripts/verify-debian-ssh-frp-image-ref.sh.
set -Eeuo pipefail

IMAGE_REPOSITORY="ghcr.io/aljazceru/prove-it"
IMAGE_REF_PATTERN='^ghcr[.]io/aljazceru/prove-it@sha256:[0-9a-f]{64}$'
SIGNER_SUBJECT="https://github.com/aljazceru/prove-it/.github/workflows/image.yml@refs/heads/main"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"
COSIGN_BIN="${COSIGN_BIN:-cosign}"

usage() {
  cat <<'USAGE'
Usage: scripts/verify-image-ref.sh [--cosign] <image-ref | PROVE_IT_IMAGE=... line | dist/prove-it-image.txt>

Validates the official prove-it image reference before using it as
PROVE_IT_IMAGE in an Enclava hosted template config.

Options:
  --cosign  Also run keyless cosign verification against the official GitHub
            Actions workflow identity. Requires network access and cosign.

On success, prints the exact config line:
  PROVE_IT_IMAGE=ghcr.io/aljazceru/prove-it@sha256:<64-hex>
USAGE
}

run_cosign=0
if [[ "${1:-}" == "--cosign" ]]; then
  run_cosign=1
  shift
fi

input="${1:-}"
if [[ -z "$input" ]]; then
  usage >&2
  exit 2
fi

# Accept a file (artifact), a CONFIG=line, or a bare ref.
if [[ -f "$input" ]]; then
  raw="$(grep -E "${IMAGE_REF_PATTERN}" "$input" | head -n1 || true)"
elif [[ "$input" == PROVE_IT_IMAGE=* ]]; then
  raw="${input#PROVE_IT_IMAGE=}"
else
  raw="$input"
fi

if [[ ! "$raw" =~ $IMAGE_REF_PATTERN ]]; then
  echo "error: image ref does not match ${IMAGE_REF_PATTERN}: ${raw:-<empty>}" >&2
  exit 1
fi

if [[ "$run_cosign" -eq 1 ]]; then
  echo "verifying keyless signature for ${raw}"
  "$COSIGN_BIN" verify "$raw" \
    --certificate-identity "$SIGNER_SUBJECT" \
    --certificate-oidc-issuer "$SIGNER_ISSUER"
fi

echo "PROVE_IT_IMAGE=${raw}"
