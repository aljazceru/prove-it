# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Execution & Validation (Highest Priority)
1. **[2026-07-31] Deploy only the signed immutable image**
   Do instead: use the digest produced by the protected main-branch workflow and verify the signer subject before CAP deployment.

## Shell & Command Reliability

## Domain Behavior Guardrails
1. **[2026-07-31] CAP managed config lives at `/state/.enclava/config`**
   Do instead: keep `ENCLAVA_CONFIG_DIR` on that platform path; `/state/app-data` is application persistence, not the config handoff root.
2. **[2026-07-31] Hosted PaaS cannot complete the auto-unlock mode transition yet**
   Do instead: create this dev app in password mode and retain its mode-600 storage password and recovery mnemonic until the hosted transition route is implemented.

## User Directives
