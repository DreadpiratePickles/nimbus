# Session 2026-10-29 — first live cloud run (GCP, read-only)

Milestone: nimbus's native collector was pointed at a **real cloud account** for the
first time. Until now every collector had only ever run against fake SDK clients
(`internal/collector/gcp/TestGraph` et al.). This was a live GCP project, read-only.

This is **not** the Terraform cloud-lab apply→scan→score→destroy milestone
(`docs/benchmark.md#cloud-lab-validated-never-applied`), which remains blocked on lab
credentials. This run used the native GCP collector against an operator's own project.

## What ran

1. `make build` → `./bin/cloud-posture` (`0.1.0-dev`), Go 1.26, clean build.
2. Minimal `cloud-posture.yaml`: one `gcp` account, `tools: [native]`, crown jewels =
   storage buckets / SQL instances.
3. `cloud-posture doctor` — read-only credential + config check.
4. `cloud-posture scan --accounts <gcp> --tools native --output table`.
5. `cloud-posture prioritize --explain --no-network` and `cloud-posture paths`.

## Result

- Build, GCP authentication, collection, scoring and persistence all worked end to end
  against live data. No crashes, no partial-write corruption.
- **1 open finding:** `GCP_IAM_PRIMITIVE_ROLE` on `roles/owner` — HIGH, risk 6.9/10.
  The project owner holds the broad primitive Owner role. 9 other native checks passed.
- **0 attack paths.** Expected: small estate, and the GCP collector does not yet model
  IAM as permission edges (Phase 2). So this run exercised collection and finding-level
  scoring, **not** attack-path traversal, on live data.
- `prioritize --explain` reproduced the score factor-by-factor (base 5.50 HIGH ×
  identity 1.25 overprivileged → raw 6.88 → 6.9), matching `docs/scoring.md`.

## Gotcha worth recording

The GCP native collector authenticates as the **Application Default Credentials**
principal, which can differ from the active `gcloud config` account. Here the ADC
identity had no IAM binding on the project while a *different* account was owner, so the
first `doctor` returned `403: caller does not have permission`. Fix was least-privilege:
create the shipped read-only role from `docs/iam/readonly-role-gcp.json`
(`gcloud iam roles create`) and bind it to the ADC identity. Worth surfacing in
`onboard`/`doctor`: report *which* identity will scan, not just that credentials exist.

## Still never run live

AWS, Azure, Kubernetes, GitHub, Okta and M365 collectors have still never run against a
live account. No live run has exercised attack-path traversal. Treat all collector
output as beta until it has.
