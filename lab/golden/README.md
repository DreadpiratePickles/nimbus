# Third-party golden outputs for the lab (plan v3 §4 P1-LAB L2)

Raw scanner outputs for the lab, one directory per tool and pinned version:

```
<tool>/<version>/
  cmd.txt          command lines, tool version, run date, lab commit, exit codes, normalisation (if any)
  aws.json …       raw tool output, one file per lab/terraform root module (aws, azure, gcp)
  sha256.txt       checksums of the outputs (TestGoldenIntegrity verifies them)
expectations.yaml  per tool: the lab weaknesses it detects (native check + resource -> expected canonical id),
                   the ones it does not detect (with why) and the ones with no Terraform twin
regen.sh           regenerates both goldens (CHECKOV=/path TRIVY=/path lab/golden/regen.sh, or make lab-golden)
```

| tool | version | install | command (from the repo root) |
|---|---|---|---|
| Checkov | 3.3.26 | `pip install checkov==3.3.26` (own venv; Python 3.14) | `checkov -d lab/terraform/<cloud> -o json --skip-download` |
| Trivy | 0.75.0 | `brew install trivy` (0.75.0) | `trivy config --quiet --skip-check-update --cache-dir <tmp> -f json lab/terraform/<cloud>` |
| Prowler | — | — | needs the cloud lab (`prowler aws --output-formats json-ocsf`); blocked on O1 |

- Trivy runs with `--skip-check-update`, so it uses the checks embedded in the 0.75.0 binary: the check
  set is pinned by the Trivy version, not by a registry download on the day.
- Checkov's `file_abs_path` holds the runner's absolute checkout path; `regen.sh` rewrites that prefix to
  `/src` (recorded in `cmd.txt`). Nothing else is edited. Trivy output is unedited (`ReportID` and
  `CreatedAt` differ per run).
- Checkov exits 1 when it finds failed checks; that is expected for a deliberately vulnerable lab.
- `lab/terraform/aws/k8s/ci-deployer.yaml` (S07/S08 manifests) is scanned too: Checkov reports it as
  `check_type: kubernetes`, Trivy as a `Kubernetes Security Check` target.

`tests/groundtruth/golden_test.go` ingests every golden through `cloud-posture ingest --source <tool>`
into a temp DB and scores it against `expectations.yaml` (`make groundtruth-golden`); mapping gaps are in
`lab/known_gaps.yaml` `golden:`. Results: docs/benchmark.md "Scanner interop".

Not `testdata/golden/`: that directory holds the output formatters' goldens and belongs to another track.
