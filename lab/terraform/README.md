# nimbus cloud lab (Terraform) — validated, never applied

Real-cloud twin of `lab/local/estate.yaml` (S01–S14). **Never planned or applied**: no lab credentials
exist yet (O1). Offline checks pass: `make lab-validate` (`validate.sh`: `fmt -check` + `init
-backend=false` + `validate` on temporary copies, no `.terraform/` left behind) succeeded for `aws/`,
`azure/` and `gcp/` with OpenTofu 1.13.1 on 2026-10-09. Validation proves the HCL is well-formed and
type-correct against the providers' schemas, nothing more: treat every resource as unproven until the
first `NIMBUS_E2E=1 make -C lab/terraform lab-up` succeeds. The P1-LAB L1 scenarios (S15–S30) are
local-only so far. Checkov/Trivy goldens of this directory: `lab/golden/`.

- `aws/` S01–S07, S12, S13 (EKS/S08 behind `enable_eks`, S14 SCP in `scp.tf` as a sketch: needs an Organization).
- `azure/` S10, S11 (VM left as a TODO). `gcp/` S09.
- Every resource is tagged `nimbus_lab_id` = the estate resource id; `aws` output `lab_id_map` maps real ARNs to lab ids so the
  same `lab/ground_truth.yaml` scores a cloud run.
- Cost ceiling: `cost_ceiling_usd` and `expires_at` tags on everything; `nightly-destroy.workflow.yml.example` destroys after each run.
- Local-only weaknesses: S05's 400-day key (cannot be back-dated; creating a key would put a secret in state), S08's CVE image.
