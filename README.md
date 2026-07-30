# Prove-It

**A self-describing attestation playground for the Enclava confidential
applications platform.**

Prove-It is a tiny web workload that runs *inside* a confidential VM and proves,
in your browser, that it is live, attested, and bound to your session. It is the
"show, don't tell" of confidential computing: instead of trusting the operator's
claim that your data is safe, you cryptographically verify the hardware
attestation yourself.

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
   5. three-way match ⇒ attestation is fresh + bound
```

## What it proves

When you click **Run live verification**, your browser:

1. Generates a cryptographically random 32-byte nonce that is sent nowhere
   except this one request.
2. Asks the workload to fetch a live AMD SEV-SNP attestation report whose
   `REPORT_DATA` field the **hardware** (via the guest attestation agent) embeds
   a binding derived from `(domain, nonce, leaf_spki_sha256,
   receipt_pubkey_sha256)`.
3. **Independently re-derives** that same `REPORT_DATA` in the browser using the
   public CE-v1 hashing scheme (see [`web/verify.js`](web/verify.js), mirrored
   from [`binding.go`](binding.go) and the attestation-proxy).
4. Checks a three-way match: **browser recompute == server claim == hardware
   REPORT_DATA**.

Because the nonce was generated in your browser and the `REPORT_DATA` is produced
by SEV-SNP firmware — not by the application — a match proves the attestation
report is **live** (generated for *this* request, not replayed) and **bound** to
the session nonce, the tenant domain, and the in-TEE TLS identity. That is the
freshness/binding property that defeats replay of a stolen report.

The dashboard also surfaces the attested workload identity — image reference and
**digest**, signer, namespace, service account, `init_data_hash`, launch
measurement, TCB version, and the policy hash — straight from the attestation
claims.

> **Honest scope.** The nonce-freshness/binding check is fully verified in the
> browser with WebCrypto. The AMD VCEK signature chain and TCB appraisal are
> surfaced in the raw attestation response (see *Raw attestation response*) for
> independent verification with AMD KDS / Trustee; prove-it does not silently
> assert that the VCEK signature is valid.

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
under `/state/app-data`, config handoff under
`/state/app-data/.enclava/config`, readiness on `:8080/livez`.

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
| `ENCLAVA_CONFIG_DIR` | `/state/app-data/.enclava/config` | Confidential config handoff directory |
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

## Security model

- **Secrets never touch the control plane.** `DEMO_SECRET` is delivered to the
  TEE config endpoint and stored on the LUKS-backed state volume; prove-it
  exposes only its SHA-256 until attestation is verified.
- **Attestation is hardware-bound.** The nonce is embedded into the SEV-SNP
  `REPORT_DATA` by the firmware, so a match cannot be forged by the application
  or operator.
- **Verification happens in the browser.** The binding math is re-implemented in
  `web/verify.js` and pinned to a golden vector, so the page does not have to
  trust the server's arithmetic.
- **Fail closed.** If the attestation-proxy is unreachable, the binding does not
  match, or the report cannot be parsed, the dashboard shows an unverified state
  and withholds the demo secret.

## License

MIT.
