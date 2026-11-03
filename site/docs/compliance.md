# Compliance & reports

Every canonical check maps to controls in the frameworks below, so a scan is already a compliance assessment. Each control is **PASS** when only passing checks map to it, **FAIL** when any mapped check fails, and **NOT ASSESSED** when none of the tools that ran cover it. Controls nothing covers never show up as a pass.

## Built-in frameworks

| Key | Framework | Version |
|---|---|---|
| `cis_aws` | CIS Amazon Web Services Foundations Benchmark | 3.0 |
| `cis_azure` | CIS Microsoft Azure Foundations Benchmark | 2.1 |
| `cis_gcp` | CIS Google Cloud Platform Foundation Benchmark | 2.0 |
| `cis_k8s` | CIS Kubernetes Benchmark | 1.8 |
| `cis_github` | CIS GitHub Benchmark | 1.0 |
| `nist_800_53` | NIST SP 800-53 | Rev. 5 |
| `pci_dss` | PCI DSS | 4.0 |
| `hipaa` | HIPAA Security Rule | 45 CFR 164 |
| `gdpr` | EU General Data Protection Regulation | 2016/679 |
| `iso_27001` | ISO/IEC 27001 Annex A | 2022 |
| `soc2` | AICPA SOC 2 Trust Services Criteria | 2017 (rev. 2022) |

Aliases are accepted: `cis`, `nist`, `pci`, `iso`, `soc-2`. A custom framework is a YAML file: `--framework custom --custom acme-baseline.yaml`.

## Reports

```bash
cloud-posture report --framework cis --provider aws
cloud-posture report --framework soc2 --format html --out soc2.html     # audit-ready (Python layer)
nimbus report --framework soc2 --format pdf --out soc2.pdf
nimbus report --framework all --format html --out summary.html          # multi-framework summary
```

An audit report includes:

- an executive summary with a score gauge;
- control-by-control status;
- a remediation roadmap;
- the relevant attack paths;
- the methodology;
- an evidence appendix.

Formats are `md`, `json`, `html` and `pdf`.

## Evidence package

```bash
cloud-posture report --framework pci_dss --evidence-zip pci-evidence.zip
```

The ZIP follows the AWS Audit Manager layout. It has one folder per control holding the failing and passing findings as JSON, the markdown report, the scan metadata, and a manifest with a SHA-256 digest for every file.

## In SQL

Every framework is also a view, so you can slice compliance however you need:

```bash
cloud-posture query "SELECT control_id, status, reason FROM cis_aws_benchmark WHERE status = 'FAIL'"
cloud-posture query "SELECT * FROM soc2"
```
