# ROADMAP

## Phase 1 — Foundation (done 2026-10-08)
- [x] Unified finding model + canonical catalog (75 checks, 5 tool alias sets)
- [x] Adapters: Prowler (OCSF+v3), ScoutSuite, Checkov, Trivy, Steampipe, native JSON
- [x] SQLite zero-ETL store + inventory/compliance/attack-path SQL views
- [x] CLI: scan, ingest, fix, query, paths, graph, report, alert, serve, monitor, cost, prioritize, onboard, learn, hook, action, pr-comment, ask, catalog, dashboard

## Phase 2 — Attack paths (done)
- [x] Security graph (Go) with Cartography/BloodHound-style labels, Cypher export, Neo4j push
- [x] Rule chains + 6-hop traversal, likelihood × priority scoring (0–10), AND/OR semantics
- [x] Choke points, break-the-path vs lower-risk recommendations, cheapest fix set (set cover)
- [x] Interactive Cytoscape graph in the dashboard

## Phase 3 — Auto-remediation (done)
- [x] 38 typed templates (Terraform, CloudFormation, Bicep, Kubernetes) + generic fallback
- [x] Native HCL scanner + in-place hclwrite patcher, cloud-to-code via tfstate / yor_trace
- [x] Guardrails: never-widen-access check, re-scan validation; auto-PR (GitHub/GitLab) with explanation, risk, rollback, diff
- [x] LLM fix generation (Python, Claude) with template fallback

## Phase 4 — Enterprise (done, hardening ongoing)
- [x] Collectors: AWS, Azure, GCP, Kubernetes, GitHub, Okta, M365 (SDKs, concurrent, partial-failure tolerant)
- [x] 58 Prowler-style boto3 CIS checks with moto tests
- [x] Compliance packs: CIS (AWS/Azure/GCP/K8s/GitHub), NIST 800-53, PCI DSS, SOC 2, HIPAA, GDPR, ISO 27001 + custom YAML; evidence ZIP; HTML/PDF audit reports
- [x] Alert sinks: Slack, Teams, PagerDuty, Jira, GitHub Issues, Datadog, Splunk HEC, Sentinel, ELK, webhook, syslog; rules, suppressions, auto-close
- [x] Real-time monitor: CloudTrail, Azure Activity Log, GCP audit logs → events, alerts, dashboard push
- [x] Cost: zombies, rightsizing, security+cost wins, breach-cost ROI
- [x] AI copilot: NL→SQL, explanations, investigation/blast radius, Rego policy generation
- [x] DevX: onboard (+org StackSet), VS Code extension (inline + quick fix), pre-commit, GitHub Action, SARIF, tutorials

## Next
- [ ] Live validation against real AWS/Azure/GCP accounts (only moto/fakes so far)
- [ ] Release pipeline (goreleaser), Homebrew tap, signed binaries
- [ ] Steampipe mod bundling + `query --named` directly in Go
- [ ] EPSS/KEV enrichment for CVE exploitability on attack edges
- [ ] Attack-path diff in PR comments (paths a PR would open)
- [ ] OIDC onboarding for Azure/GCP; GitHub push-protection check; Alibaba/DigitalOcean/Snowflake/Slack collectors
