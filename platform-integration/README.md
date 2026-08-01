# Deploying Prove-It on Enclava

Prove-It is packaged as a normal OCI image and deploys through CAP exactly like
any confidential workload. To make it a one-click hosted template in the Enclava
PaaS console (alongside `debian-ssh-frp` and `mini-enclava-go`), drop the
`HostedTemplate` below into
`enclava-paas/server/src/templates.rs`.

## 1. Build and sign the image

The repo's [`../.github/workflows/image.yml`](../.github/workflows/image.yml)
builds, pushes, and keyless-signs the image on every push to `main`:

- Repository: `ghcr.io/aljazceru/prove-it`
- Signer subject (cosign keyless, GitHub OIDC):
  `https://github.com/aljazceru/prove-it/.github/workflows/image.yml@refs/heads/main`
- Signer issuer: `https://token.actions.githubusercontent.com`
- Artifact: `dist/prove-it-image.txt` (the digest-pinned ref)

Promote the published digest before configuring PaaS:

```sh
scripts/verify-image-ref.sh --cosign dist/prove-it-image.txt
# => PROVE_IT_IMAGE=ghcr.io/aljazceru/prove-it@sha256:<64-hex>
```

## 2. Register as a hosted template

Add these constants near the other template constants in
`enclava-paas/server/src/templates.rs`:

```rust
const PROVE_IT_SLUG: &str = "prove-it";
const PROVE_IT_VERSION: &str = "0.2.1";
const DEFAULT_PROVE_IT_IMAGE: &str = "ghcr.io/aljazceru/prove-it@sha256:14e3d024872542eba33aa8190778a96997991283522e916a9d5a4be0c47d588b";
const DEFAULT_PROVE_IT_REPOSITORY: &str = "aljazceru/prove-it";
const DEFAULT_PROVE_IT_SIGNER_SUBJECT: &str =
    "https://github.com/aljazceru/prove-it/.github/workflows/image.yml@refs/heads/main";
const PROVE_IT_TLS_POLICY: &str = "confidential_per_instance_tls";
```

Append to `list_templates`:

```rust
templates.push(prove_it_template(config));
```

And add the builder (modeled on `mini_enclava_go_template`):

```rust
fn prove_it_template(config: &AppConfig) -> HostedTemplate {
    HostedTemplate {
        slug: PROVE_IT_SLUG,
        name: "Prove-It",
        description: "Explainable attestation example: inspect and verify a fresh \
                      browser-to-evidence binding, then appraise the hardware evidence.",
        features: vec![
            "Live SEV-SNP attestation",
            "Browser-side nonce-freshness proof",
            "Secret-to-TEE delivery demo",
            "Encrypted persistent state",
        ],
        version: integration_value(config, "PROVE_IT_TEMPLATE_VERSION", PROVE_IT_VERSION),
        image: integration_value(config, "PROVE_IT_IMAGE", DEFAULT_PROVE_IT_IMAGE),
        source_provider: "github",
        source_repository: integration_value(
            config,
            "PROVE_IT_SOURCE_REPOSITORY",
            DEFAULT_PROVE_IT_REPOSITORY,
        ),
        signer_subject: integration_value(
            config,
            "PROVE_IT_SIGNER_SUBJECT",
            DEFAULT_PROVE_IT_SIGNER_SUBJECT,
        ),
        signer_issuer: integration_value(
            config,
            "PROVE_IT_SIGNER_ISSUER",
            DEFAULT_GITHUB_SIGNER_ISSUER,
        ),
        container_name: "web",
        command: vec!["/usr/local/bin/prove-it"],
        port: 8080,
        storage_paths: vec!["/state/app-data"],
        unlock_mode: "password",
        health_path: "/livez",
        health_interval: 30,
        health_timeout: 10,
        cpu: "1",
        memory: "512Mi",
        storage: "1Gi",
        persistence_path: Some("/state/app-data"),
        tls_policy: PROVE_IT_TLS_POLICY,
        workload_security_profile: None,
        security_notes: vec![
            "Runs behind per-instance confidential TLS terminated inside the TEE.",
            "The demo secret is delivered to the confidential runtime and revealed \
             only after a browser-verified nonce binding.",
            "The app requires no user-defined external egress; platform boot, KBS, \
             and certificate traffic remains policy-scoped.",
        ],
        // prove-it needs no outbound network. Egress stays default-deny.
        egress_allowlist: vec![],
        egress_mode: "restricted",
        paas_managed_config_keys: vec![],
        config_keys: vec![
            TemplateConfigKey {
                key: "INSTANCE_LABEL",
                label: "Instance label",
                description: "Human-readable label shown in the dashboard header.",
                input_type: "text",
                required: false,
                secret: false,
                generated: false,
                default_value: Some("prove-it"),
                validation: None,
            },
            TemplateConfigKey {
                key: "DEMO_SECRET",
                label: "Demo secret",
                description: "A value delivered to the TEE via the confidential config \
                             handoff. Its SHA-256 is always shown; the plaintext is \
                             revealed only after live attestation is verified.",
                input_type: "password",
                required: true,
                secret: true,
                generated: false,
                default_value: None,
                validation: Some(TemplateConfigValidation {
                    format: Some("single_token"),
                    example: None,
                    max_bytes: Some(4096),
                    max_items: None,
                    allowed_algorithms: vec![],
                }),
            },
        ],
    }
}
```

The CAP engine renders the pod with the standard confidential sidecars
(`enclava-init`, `attestation-proxy`, tenant `Caddy`). Prove-It's defaults already
point at the sidecars:

- `ATTESTATION_PROXY_URL=http://127.0.0.1:8081`
- `ATTESTATION_PROXY_TLS_URL=https://127.0.0.1:8443`

No additional wiring is required. If you prefer to inject the leaf SPKI directly
(the proxy enforces it anyway), set `ATTESTATION_PROXY_TLS_SPKI_SHA256` in the
template env.

## 3. Deploy and verify

Use the PaaS console so the template config form delivers `INSTANCE_LABEL` and
`DEMO_SECRET` through the confidential handoff. The current CLI template command
does not expose generic `--config`/`--secret` flags; do not document flags that
silently bypass or fail that delivery path.

Open the returned app domain in a browser and click **Run live verification**.
On a plain node you see the unverified banner; on an SEV-SNP node the page shows
**Fresh binding verified** and reveals the demo secret. The page still labels
AMD signature/TCB appraisal as a separate production requirement.

## 4. Direct CAP deploy (without the hosted template)

```sh
umask 077
openssl rand -hex 32 > demo-secret.txt
openssl rand -hex 32 > storage-password.txt

# enclava.toml supplies the app name and password unlock mode.
enclava create --image ghcr.io/aljazceru/prove-it@sha256:<digest> \
  --signer-subject \
  "https://github.com/aljazceru/prove-it/.github/workflows/image.yml@refs/heads/main"
enclava deploy --image ghcr.io/aljazceru/prove-it@sha256:<digest> \
  --set INSTANCE_LABEL=developer-example \
  --set-file DEMO_SECRET=demo-secret.txt \
  --storage-password-file storage-password.txt
enclava status
```

Keep both files mode `0600`, back up the recovery material, and never put secret
values in command arguments, Git, image layers, browser storage, or CI logs.
