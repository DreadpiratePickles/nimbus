# Commands

Every command is a subcommand of the single `cloud-posture` binary. Run `cloud-posture <cmd> --help` for the full set of flags.

| Command | What it does |
|---|---|
| `onboard` | Detects credentials for AWS, Azure, GCP, Kubernetes, GitHub, Okta and M365, then writes `cloud-posture.yaml`. `--aws-org` prints a StackSet that creates a read-only role (External ID) in every account. |
| `scan` | Runs the native SDK collectors plus Prowler, ScoutSuite, Checkov, Trivy, Steampipe, Python checks and plugins for each account. `--iac` covers Terraform, CloudFormation, Bicep, K8s, Helm, CDK, Pulumi and Ansible. Other flags: `--output table\|json\|sarif\|dashboard\|markdown`, `--fail-on`, `--alert`. |
| `ingest` | Imports existing scanner output files or directories (the format is auto-detected). `--source native` accepts native findings as a JSON array or JSON lines. |
| `paths` | Lists attack paths with likelihood × priority scores and MITRE tags. `--fixes` adds choke points, break vs lower-risk and the min fix set; also `--blast-radius` and `--format mermaid\|dot\|json`. |
| `prioritize` | Top-N risks (1–10, Critical ≥ 9) with their reasons, owner and SLA. |
| `fix` | Generates IaC remediation. `--patch` rewrites the HCL block in place (validated, never widens access), `--auto-pr` opens a PR, `--tfstate` maps cloud findings to code, and `--ai` asks an LLM for fixes. |
| `query` | SQL over `findings`, the `<type>s` inventory views, `attack_path_summary`, `cis_aws_benchmark`, `soc2`, `graph_nodes` and more. `--engine steampipe` queries live cloud tables; `--describe` shows the schema. |
| `report` | CIS, NIST 800-53, PCI DSS, SOC 2, HIPAA, GDPR, ISO 27001 or a custom YAML framework. `--format md\|json\|html\|pdf`, plus `--evidence-zip`. |
| `alert` | Sends to Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Splunk HEC, Microsoft Sentinel, Elastic, a webhook or syslog/CEF. Handles dedup, rules, suppressions with expiry, and auto-close on fix. |
| `serve` | Live dashboard, JSON API and WebSocket. `--scan-interval` gives continuous compliance, `--monitor` adds change detection, and `--copilot` wires in the Python API. |
| `monitor` | Change detection from CloudTrail, the Azure Activity Log and GCP audit logs: public buckets, open SGs, admin policies, root logins, disabled logging and more. |
| `cost` | Zombie resources, rightsizing, wins that improve both security and cost, and breach-risk ROI. |
| `graph` | `export --format json\|cypher\|mermaid\|dot`, or `push` to Neo4j (Cartography-style labels). |
| `ask` | Copilot for questions, investigations, remediation guidance and OPA/Rego policy generation. |
| `learn` | Tutorials built on your own findings: public buckets, open SSH, IMDSv1, admin policies, MFA, logging, privileged pods. |
| `hook install` / `action init` / `pr-comment` | Installs the pre-commit hook, writes a GitHub Actions workflow, or posts a sticky PR comment. |
| `dashboard` / `catalog` | Writes the static HTML report, or prints the 75-check canonical catalog. |

## Examples

```bash
# onboard
cloud-posture onboard --aws --azure --gcp --yes --scan
cloud-posture onboard --aws-org 123456789012 --external-id my-secret   # print the org-wide StackSet template

# scan
cloud-posture scan --accounts aws-prod,azure-dev,gcp-staging --output dashboard
cloud-posture scan --iac ./infra --output sarif --sarif results.sarif --fail-on HIGH
cloud-posture scan --from-dir ./prowler-output --output table
cloud-posture scan --accounts aws:prod-profile --tools native,python-checks

# paths
cloud-posture paths --fixes                 # break vs lower-risk, and the min fix set
cloud-posture paths --format mermaid > paths.md
cloud-posture paths --blast-radius arn:aws:iam::123:role/web-admin-role

# fix
cloud-posture fix --id 3f9c… --format cloudformation --out-dir ./remediation
cloud-posture fix --finding EC2_IMDSV1 --patch --iac ./infra      # rewrite the offending block
cloud-posture fix --all --patch --iac ./infra --auto-pr           # open a PR with every deterministic fix
cloud-posture fix --finding RDS_PUBLIC --ai --format terraform    # LLM fix via the Python layer

# query
cloud-posture query "SELECT entry_point, target, path_length FROM attack_path_summary WHERE target_type LIKE '%DATA%'"
cloud-posture query "SELECT control_id, status, reason FROM cis_aws_benchmark WHERE status = 'FAIL'"
cloud-posture query "select name from aws_s3_bucket" --engine steampipe   # live cloud via Steampipe

# report
cloud-posture report --framework cis --provider aws
cloud-posture report --framework soc2 --format html --out soc2.html
cloud-posture report --framework pci_dss --evidence-zip pci-evidence.zip
cloud-posture report --framework custom --custom acme-baseline.yaml

# alert
cloud-posture alert --to slack,github_issues --min-severity HIGH
cloud-posture alert --to pagerduty --only-attack-paths
cloud-posture alert --suppress suppressions.json --dry-run

# serve / monitor / ask
cloud-posture serve --scan-interval 24h --monitor
cloud-posture serve --copilot http://localhost:8081      # with: nimbus serve --port 8081
cloud-posture monitor --interval 60s --alert
cloud-posture ask "why did finding 3f9c fire and what is the blast radius"
cloud-posture ask "write an OPA policy to block public S3 buckets"
```

## Python commands

The Python layer installs a separate `nimbus` command. It works on the same database (`./.cloud-posture/posture.db`, `$CLOUD_POSTURE_DB`, or `--db PATH`).

| Command | What it does |
|---|---|
| `nimbus report --framework soc2 --format html\|pdf\|md\|json --out FILE` | Audit report: executive summary, control status, remediation roadmap, attack paths, methodology and evidence appendix. `--framework all` writes a multi-framework summary. |
| `nimbus frameworks` | Lists the built-in frameworks. |
| `nimbus risk [--top 50] [--json] [--model weights.json]` | Context-aware prioritisation. |
| `nimbus ask "which buckets are public?"` | Turns a plain-English question into read-only SQL and answers it. |
| `nimbus explain <finding-id \| attack-path-id>` | Writes an "an attacker could …" narrative. |
| `nimbus investigate <finding-id>` | Shows the finding, its attack paths and its blast radius. |
| `nimbus fix <finding-id> --format terraform\|cloudformation\|bicep\|kubernetes` | Generates an IaC fix. |
| `nimbus policy "deny public S3 buckets"` | Generates an OPA/Rego policy. |
| `nimbus query --list` / `--named NAME` / `"SELECT …"` | Runs a query from the library or ad-hoc read-only SQL. |
| `nimbus serve` | FastAPI dashboard API and WebSocket. |
| `nimbus plugin run PATH` | Runs a plugin and prints its native findings. |

Everything works offline with rule-based fallbacks. Set `ANTHROPIC_API_KEY` and Claude writes the explanations, fixes, SQL and policies instead.
