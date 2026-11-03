# Quickstart

The path from nothing to your first attack path, the fix that breaks it, and a report.

## 1. Install

```bash
# binary (Linux / macOS / Windows)
curl -fsSL https://raw.githubusercontent.com/DreadpiratePickles/nimbus/main/install.sh | sh

# or from source (Go 1.26)
go install github.com/DreadpiratePickles/nimbus/cmd/cloud-posture@latest

# optional: the Python intelligence layer (compliance reports, AI copilot, boto3 checks, FastAPI)
pip install -e "python[all]"      # from a clone of the repo
```

If you'd rather install nothing locally, the container image bundles Prowler, Checkov, Trivy and Steampipe:

```bash
docker run --rm -v ~/.aws:/root/.aws -v $PWD:/work \
  ghcr.io/dreadpiratepickles/cloud-posture scan --accounts aws:default
```

## 2. Try it without a cloud account

The repo ships sample scanner output in `testdata/`. Ingest it and open the dashboard:

```bash
git clone https://github.com/DreadpiratePickles/nimbus && cd nimbus
cloud-posture ingest testdata -o summary
cloud-posture dashboard --out cloud-posture-report/index.html
```

## 3. Connect your accounts

```bash
cloud-posture onboard
```

`onboard` finds the credentials you already have (AWS, Azure, GCP, kubectl, plus `GITHUB_TOKEN`, `OKTA_API_TOKEN`, `M365_*`) and writes `cloud-posture.yaml`. For an AWS organisation, `--aws-org` prints a StackSet that creates a read-only role, with an External ID, in every member account. See [configuration](configuration.md).

!!! note "Credentials"
    nimbus never stores credentials. It uses your existing sessions or environment variables, and a `.env` / `nimbus.env` in the working directory is loaded automatically (and git-ignored).

## 4. Scan

```bash
cloud-posture scan --accounts aws-prod,azure-dev,gcp-staging --output dashboard
cloud-posture scan --iac ./infra --output sarif --sarif results.sarif --fail-on HIGH   # IaC only, for CI
```

## 5. Follow the attack paths

```bash
cloud-posture paths --fixes            # choke points, break-the-path vs lower-risk, min fix set
cloud-posture prioritize               # top risks, 1–10, with reasons, owner and SLA
```

## 6. Fix

```bash
cloud-posture fix --finding S3_PUBLIC_BUCKET --generate-terraform
cloud-posture fix --all --patch --iac ./infra --auto-pr
```

`--patch` rewrites the HCL block in place, validates it and never widens access. `--auto-pr` opens a PR that explains the change, the paths it closes, the risk and the rollback.

## 7. Ask, query, report

```bash
cloud-posture query "SELECT name, region FROM aws_s3_buckets WHERE public_access = 1"
cloud-posture ask "show me all public databases with no encryption"
cloud-posture report --framework soc2 --format html --out soc2.html
cloud-posture report --framework pci_dss --evidence-zip pci-evidence.zip
```

## 8. Keep it running

```bash
cloud-posture serve --scan-interval 24h --monitor     # http://localhost:8080
```

This gives you the live dashboard and JSON API over WebSocket, continuous compliance, and change detection from CloudTrail, the Azure Activity Log and GCP audit logs.
