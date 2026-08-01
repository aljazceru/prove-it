#!/usr/bin/env bash
# Runtime contract test for the prove-it image, run by CI before publishing.
# Confirms the server boots as UID 10001, serves /livez, and renders the
# embedded dashboard. Does not require a confidential VM or attestation-proxy.
set -Eeuo pipefail

image="${1:?usage: smoke-runtime.sh <image>}"
host_port="${PROVE_IT_SMOKE_PORT:-18099}"

cid="$(docker run --rm -d --user 10001:10001 -p "${host_port}:8080" "$image")"
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT

# Wait for readiness.
for _ in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:${host_port}/livez" >/dev/null; then
    break
  fi
  sleep 0.25
done

echo "livez: $(curl -sf "http://127.0.0.1:${host_port}/livez")"

# Dashboard must be served and reference the app bundle.
html="$(curl -sf "http://127.0.0.1:${host_port}/")"
grep -q 'Prove-It' <<<"$html"
grep -q '/app.js' <<<"$html"
grep -q 'Binding proof ≠ hardware appraisal' <<<"$html"
grep -q 'The user workload is treated as hostile' <<<"$html"

headers="$(curl -sfD - -o /dev/null "http://127.0.0.1:${host_port}/")"
grep -qi '^Content-Security-Policy:' <<<"$headers"
grep -qi '^X-Content-Type-Options: nosniff' <<<"$headers"

# Static assets must resolve (app.css, app.js, verify.js).
curl -sf "http://127.0.0.1:${host_port}/app.css" >/dev/null
curl -sf "http://127.0.0.1:${host_port}/app.js" >/dev/null
curl -sf "http://127.0.0.1:${host_port}/verify.js" >/dev/null

# /api/info must report prove-it facts (attestation-proxy will be unreachable
# here, which is expected outside a confidential VM).
info="$(curl -sf "http://127.0.0.1:${host_port}/api/info")"
grep -q '"service"' <<<"$(curl -sf "http://127.0.0.1:${host_port}/livez")"
grep -q '"version"' <<<"$info"

echo "runtime contract OK"
