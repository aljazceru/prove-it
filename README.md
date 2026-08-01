# Prove-It

**A self-describing attestation playground for the Enclava confidential
applications platform.**

Prove-It is a small reference workload for exposing confidential-computing
verification to end users. It runs inside a confidential VM, returns evidence
and binding inputs instead of a trust badge, and independently checks the
nonce/domain/key binding in the browser.

```
              ┌─────────────────────────────────────────────────────┐
              │           AMD SEV-SNP confidential VM               │
              │   (Kata confidential container, runtime kata-qemu-snp)│
              │                                                     │
              │   ┌──────────────┐        ┌──────────────────────┐  │
              │   │  prove-it    │  HTTP  │ attestation-proxy    │  │
              │   │  (this app)  │───────▶│ :8081  /v1/attestation│ │
              │   │  Go binary   │        │ self-signed TLS :8443│  │
              │   └──────┬───────┘        └──────────┬───────────┘  │
              │          │                           │ SEV-SNP      │
              │          │ Caddy TLS :443            │ REPORT_DATA  │
              └──────────┼───────────────────────────┼──────────────┘
                         │                           │
   browser ◀────────────┘                           │
   1. generate nonce (32B)                          │
   2. POST /api/verify {nonce, domain} ────────────▶│
   3. TEE embeds nonce into REPORT_DATA ◀───────────┘
   4. browser re-derives REPORT_DATA from
      (domain, nonce, leaf_spki, receipt_pubkey)
   5. three-way match ⇒ evidence binding is fresh + consistent
```

## What the browser proves

When you click **Run live verification**, your browser:

1. Generates a cryptographically random 32-byte nonce that is sent nowhere
   except this one request.
2. Asks the workload to fetch fresh AMD SEV-SNP evidence whose `REPORT_DATA`
   field (via the guest attestation agent) carries
   a binding derived from `(domain, nonce, leaf_spki_sha256,
   receipt_pubkey_sha256)`.
3. **Independently re-derives** that same `REPORT_DATA` in the browser using the
   public CE-v1 hashing scheme (see [`web/verify.js`](web/verify.js), mirrored
   from [`binding.go`](binding.go) and the attestation-proxy).
4. Checks a three-way match: **browser recompute == server claim == evidence
   REPORT_DATA**.

Because the nonce was generated in your browser, a match shows that the returned
evidence is fresh for this request and bound to the nonce, requested domain, and
attestation-proxy TLS identity. That is the anti-replay and channel-binding
property demonstrated here.

The dashboard also surfaces the attested workload identity — image reference and
**digest**, signer, namespace, service account, `init_data_hash`, launch
measurement, TCB version, and the policy hash — straight from the attestation
claims.

> **Honest scope.** A matching hash is not, by itself, proof that AMD signed the
> report. The browser verifies the CE-v1 binding with WebCrypto. A production
> verifier must additionally validate the AMD VCEK chain, report signature, TCB,
> endorsement freshness, launch measurement, image identity, and policy before
> authorizing anything.

## Run it locally (no TEE required)

Requirements: Go 1.22+.

```sh
go run . -addr 127.0.0.1:8080 -config-dir /tmp/prove-it-cfg -state-path /tmp/prove-it-state
```

Open <http://127.0.0.1:8080>. You will see the **Not in a confidential VM** state:
no attestation-proxy is reachable, so no hardware attestation is available. This
is intentional — it is the contrast that makes the deployed-on-Enclava state
compelling. The browser **self-test** still runs and confirms the on-page CE-v1
crypto matches the golden vectors.

To preview the populated UI without a TEE, add `?demo=1`:

```
http://127.0.0.1:8080/?demo=1
```

This renders canned, **clearly-labeled SIMULATED** data using the golden vector,
so the verification UI can be demonstrated anywhere.

## Build the container

```sh
docker build -t prove-it:dev .
docker run --rm -p 8080:8080 prove-it:dev
```

The image follows Enclava conventions: non-root UID/GID `10001`, encrypted state
under `/state/app-data`, config handoff under `/state/.enclava/config`, and
readiness on `:8080/livez`.

## Tests

```sh
go vet ./...
go test ./...
```

`binding_test.go` pins the CE-v1 derivation to a golden vector produced by an
independent Python reference (the same vector `web/verify.js` checks at load
time), so the server and browser can never silently drift from the
attestation-proxy. `handlers_test.go` exercises the full `/api/verify` flow
against a fake attestation-proxy, including the match-reveals-secret and
mismatch-hides-secret paths.

## Configuration

### Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROVE_IT_ADDR` | `:8080` | HTTP listen address |
| `ENCLAVA_CONFIG_DIR` | `/state/.enclava/config` | Confidential config handoff directory |
| `ENCLAVA_STATE_PATH` | `/state/app-data` | Encrypted state volume path |
| `ATTESTATION_PROXY_URL` | `http://127.0.0.1:8081` | attestation-proxy HTTP base URL |
| `ATTESTATION_PROXY_TLS_URL` | `https://127.0.0.1:8443` | attestation-proxy TLS listener (used to read the leaf SPKI) |
| `ATTESTATION_PROXY_TLS_SPKI_SHA256` | _unset_ | Hex of the proxy TLS leaf SPKI; preferred over the TLS dial |
| `PROVE_IT_INSTANCE_LABEL` | `prove-it` | Fallback instance label if config lacks `INSTANCE_LABEL` |
| `PROVE_IT_TEE` | _unset_ | Extra TEE indicator to display |

### Confidential config keys (delivered to the TEE)

These are read from the config handoff directory (one file per key), exactly as
the platform delivers customer config through the short-lived config-token flow.
The control plane stores metadata only — plaintext values exist solely inside
the confidential VM.

| Key | Secret | Required | Purpose |
| --- | --- | --- | --- |
| `INSTANCE_LABEL` | no | no | Human label shown in the header |
| `DEMO_SECRET` | **yes** | yes | A value that demonstrates secret-to-TEE delivery. Its SHA-256 is always shown; the plaintext is revealed **only after** the browser confirms a live, bound attestation |

## HTTP API

| Route | Method | Purpose |
| --- | --- | --- |
| `/livez` | GET | Readiness for CAP (`{"ok":true,...}`) |
| `/` | GET | Dashboard (embedded HTML/CSS/JS) |
| `/api/info` | GET | Runtime facts + attestation-proxy metadata + resolved leaf SPKI |
| `/api/verify` | POST | `{nonce_b64, domain}` → live attestation + recomputed binding |
| `/api/proxy/info` | GET | Pass-through of the proxy `/v1/attestation/info` |

## Deploy on Enclava

See [`platform-integration/README.md`](platform-integration/README.md) for the
hosted-template registration (a drop-in `HostedTemplate` entry for
`enclava-paas/server/src/templates.rs`), the deploy descriptor, and the
verification commands.

## Verification integration pattern

Use Prove-It as a reference for an explainable verification API:

1. Generate the challenge in the verifier, never in the workload being checked.
2. Return raw signed evidence, endorsements, identity claims, binding inputs,
   policy output, and timestamps—not only `verified: true`.
3. Recompute the nonce/domain/key binding outside the workload.
4. Send evidence to an independent appraiser and require its signature, TCB,
   measurement, and policy verdict before granting access or releasing a real
   secret.
5. Show users which checks passed, which verifier performed them, and when the
   endorsements were refreshed.

`web/verify.js` is dependency-free browser code for step 3. `/api/verify` is the
example evidence envelope. Its `match`/`ok` fields mean the binding matched; they
do **not** replace hardware appraisal.

### Untrusted payload boundary

The application is deliberately not trusted with Enclava infrastructure:

- the app container runs non-root with a read-only root filesystem, no Linux
  capabilities, no privilege escalation, and no mounted service-account token;
- tenant network policy is default-deny with only platform-required destinations;
- confidential workloads run in Kata/SEV-SNP isolation and receive policy-scoped
  secrets rather than infrastructure credentials;
- the image is immutable, digest-pinned, and admitted by signer identity.

These are CAP/platform controls, not claims made by this application. A malicious
payload must remain confined even if every line of its own code is hostile.

## Security model

- **Secrets never touch the control plane.** `DEMO_SECRET` is delivered to the
  TEE config endpoint and stored on the LUKS-backed state volume; prove-it
  exposes only its SHA-256 until attestation is verified.
- **Binding verification happens in the browser.** The binding math is re-implemented in
  `web/verify.js` and pinned to a golden vector, so the page does not have to
  trust the server's arithmetic.
- **Hardware appraisal is separate.** The UI never turns a binding match into a
  claim that the AMD signature, TCB, endorsements, or workload policy were
  independently accepted.
- **Fail closed.** If the attestation-proxy is unreachable, the binding does not
  match, or the report cannot be parsed, the dashboard shows an unverified state
  and withholds the demo secret.

## License

MIT.
