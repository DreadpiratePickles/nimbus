# Maintainers

How people become maintainers, and what maintainers decide, is in [GOVERNANCE.md](GOVERNANCE.md).
Ownership of review paths is in [`CODEOWNERS`](CODEOWNERS).

## Current maintainers

| Name | GitHub | Organisation | Areas | Since |
|---|---|---|---|---|
| Bobby Meher | [@DreadpiratePickles](https://github.com/DreadpiratePickles) | Independent (no company) | Everything; release signing; security response (founding maintainer, BDFL in stage 1) | 2026 |

## Reviewers

None yet. See [GOVERNANCE.md](GOVERNANCE.md#roles) for how to become one.

## Emeritus

None.

## Wanted

nimbus has **one maintainer from one organisation**. The project reaches governance stage 2, and can
apply to the CNCF sandbox, once there are at least two maintainers from at least two organisations
([ROADMAP.md](ROADMAP.md), Phase 3). Good areas for a second maintainer:

- **Adapters and interop**: Prowler, Checkov, Trivy, Kubescape, Cartography, OCSF/ASFF (`internal/adapters`, `internal/output`).
- **IaC fixes**: Terraform patching and fix templates (`internal/iac`, `internal/remediation`).
- **The benchmark lab**: estates, ground truth and scanner goldens (`lab/`, `tests/groundtruth`).
- **Azure / GCP / Kubernetes depth** (`internal/collector/{azure,gcp,k8s}`).

Start with the issues labelled `good first adapter` or `good first fix template`, once they exist,
or open an issue saying what you would like to own.
