# Deploying Prove-It on Enclava

Prove-It is packaged as a normal OCI image and deploys through CAP exactly like
any confidential workload. To make it a one-click hosted template in the Enclava
PaaS console (alongside `debian-ssh-frp` and `mini-enclava-go`), drop the
`HostedTemplate` below into
`enclava-paas/server/src/templates.rs`.

## 1. Build and sign the image

The repo's [`../.github/workflows/image.yml`](../.github/workflows/image.yml)
builds, pushes, and keyless-signs the image on every push to `main`:

- Repository: `ghcr.io/enclava-labs/prove-it`
- Signer subject (cosign keyless, GitHub OIDC):
  `https://github.com/enclava-labs/prove-it/.github/workflows/image.yml@refs/heads/main`
- Signer issuer: `https://token.actions.githubusercontent.com`
- Artifact: `dist/prove-it-image.txt` (the digest-pinned ref)

Promote the published digest before configuring PaaS:

```sh
scripts/verify-image-ref.sh --cosign dist/prove-it-image.txt
# => PROVE_IT_IMAGE=ghcr.io/enclava-labs/prove-it@sha256:<64-hex>
```

## 2. Register as a hosted template

Add these constants near the other template constants in
`enclava-paas/server/src/templates.rs`:

```rust
const PROVE_IT_SLUG: &str = "prove-it";
const PROVE_IT_VERSION: &str = "0.1.0";
const DEFAULT_PROVE_IT_IMAGE: &str = "ghcr.io/enclava-labs/prove-it:main";
const DEFAULT_PROVE_IT_REPOSITORY: &str = "enclava-labs/prove-it";
const DEFAULT_PROVE_IT_SIGNER_SUBJECT: &str =
    "https://github.com/enclava-labs/prove-it/.github/workflows/image.yml@refs/heads/main";
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
        description: "Self-describing attestation playground: prove, in your browser, \
                      that this workload is a live, attested AMD SEV-SNP confidential VM.",
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
        command: vec![
            "/bin/sh",
            "-c",
            "ENCLAVA_CONFIG_DIR=/state/app-data/.enclava/config \
             exec /usr/local/bin/prove-it",
        ],
        port: 8080,
        storage_paths: vec!["/state/app-data"],
        unlock_mode: "auto",
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
             only after a browser-verified, nonce-bound attestation.",
            "Zero external egress: the workload talks only to its co-located \
             attestation-proxy.",
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

```sh
enclava template list                                      # prove-it appears
enclava template deploy prove-it --name prove-demo \
    --config INSTANCE_LABEL=seattle-canary \
    --secret  DEMO_SECRET=$(openssl rand -hex 32)
enclava status --app prove-demo
```

Open the returned app domain in a browser and click **Run live verification**.
On a plain node you see the unverified banner; on an SEV-SNP node the banner
flips to **Attested — fresh and bound to this session** and the demo secret is
revealed. That contrast is the demo.

## 4. Direct CAP deploy (without the hosted template)

```sh
enclava create prove-demo --signer-subject \
  "https://github.com/enclava-labs/prove-it/.github/workflows/image.yml@refs/heads/main"
enclava deploy --image ghcr.io/enclava-labs/prove-it@sha256:<digest>
```
