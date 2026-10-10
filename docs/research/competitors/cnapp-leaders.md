# CNAPP Leaders: Deep Competitive Research (cluster 1)

_Research date: 2026-10-09. This file extends [`../competitors.md`](../competitors.md) and does not repeat what it already covers. Topics already covered there: Wiz Issues vs Findings and toxic combinations, Wiz Code TF-state mapping, AI remediation 2.0, AskAI, Mika/Issues/SecOps agents, the MCP server, Defend grouping; Orca's 0-99 path score and 1-10 risk score; Prisma attack-path policies, Checkov commit suggestions, Yor drift and Cortex issue sync; Lacework Polygraph and composite alerts._

**Vendors, in order:** Wiz · Orca Security · Palo Alto Prisma Cloud / Cortex Cloud · Lacework (Fortinet FortiCNAPP) · CrowdStrike Falcon Cloud Security · SentinelOne Singularity Cloud Security (PingSafe) · Sysdig Secure · Aqua Security · Upwind · Sweet Security.

**How to read this file**
- Every claim is tagged **[sourced: URL]** or **[inferred]**. "Not public", "unknown" and "not found" mean we found no evidence. They do not mean the feature is missing.
- Prices are list prices from AWS Marketplace or vendor documents only. Third-party estimates are labeled as such.

**Evidence gaps**
- The web-search budget for the session ran out partway through. After that, research used direct fetches of official docs, release notes, AWS Marketplace listings and reviews, PeerSpot, and GitHub.
- G2, Gartner Peer Insights and BusinessWire returned HTTP 403, and Reddit could not be reached. Review quotes therefore come mostly from PeerSpot and AWS Marketplace reviews (some of which are syndicated from G2), plus a few aggregators.
- Some docs need a login: Sweet (docs.sweet.security) and Aqua (docs.aquasec.com). Those vendors have more "not public" entries.

**Status changes that matter (2024-2026)**
- **Wiz:** Google closed its acquisition of Wiz on 2026-03-11.
- **Lacework:** Fortinet closed the Lacework acquisition on 2024-08-01; the product is now FortiCNAPP.
- **Prisma Cloud:** became Cortex Cloud on 2025-02-13. Cortex Cloud 2.0 shipped 2025-10-28, then 2.2 on 2026-07-28.
- **PingSafe:** SentinelOne bought PingSafe in 2024-02; it became Cloud Native Security.
- **Aqua:** changed CEO on 2025-11-05.
- **Trivy:** the open-source scanner had a supply-chain compromise in 2026-03.

---

## Wiz

### Positioning & pricing model
- **Ownership:** Google closed the $32B all-cash acquisition on **2026-03-11**, exactly one year after the announcement. Wiz "joined Google Cloud" but keeps its brand and its multi-cloud commitment (AWS/Azure/OCI). The deal was cleared unconditionally by the US, EC, Australia, Israel and others [sourced: https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz] [sourced: https://techcrunch.com/2026/03/11/google-completes-32b-acquisition-of-wiz].
- **Re-positioning in 2026:** Wiz now calls itself the "AI Application Protection Platform (AI-APP)" (launched 2026-03-23), not just a CNAPP [sourced: https://www.wiz.io/blog/introducing-wiz-ai-app].
- **AWS Marketplace list prices** ("WIZ Cloud Infrastructure Security Platform (Plus Consumption)", 12-month contract) [sourced: https://aws.amazon.com/marketplace/pp/prodview-5geds7fc2wk7m]:
  - Wiz Essential: **$24,000 per 100 workloads** (about $240 per workload per year).
  - Wiz Advanced: **$38,000 per 100 workloads** (about $380 per workload per year).
  - Wiz Sensor add-on: **$28,000 per 100 sensors**.
  - Wiz Code add-on: **$58,500 per 100 licenses**.
  - Wiz Defend add-on: **$18,000 per 300 GB/month of log ingestion**.
  - Consumption Billing Units: **$0.01/unit** for usage beyond the contract.
  - Billable "cloud workload" = "a running compute resource that Wiz scans, such as a virtual machine, container, or serverless function".
- **Third-party estimates (not official):**
  - Median annual contract is about $149k; reported deal range $29.4k–$484k; average negotiated discount about 22%; multi-year deals 20–35% off list [sourced: https://cipherssecurity.com/wiz-pricing-guide-2026-cnapp-cost/ — cites Vendr].
- **MSP channel (2026-09):**
  - Wiz launched the Partner Alliance MSP Program with **Wiz Tenant Manager** and consumption-based billing. MSPs need no upfront annual commitment and get just-in-time tenant provisioning. Status: public preview [sourced: https://www.channelinsider.com/security/news-wiz-msp-program-managed-cloud-ai-security/].

### Deployment
- **Agentless by default:** cloud API connectors plus snapshot-based workload scanning. The optional **Wiz Runtime Sensor** is eBPF-based, runs as a DaemonSet on K8s and on Linux hosts, and also supports Windows [sourced: https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-runtime-sensor/] [sourced: https://www.wiz.io/ja-jp/solutions/runtime-sensor].
- **Clouds and identity platforms (per the CIEM page):** AWS, Azure, GCP, Oracle, Kubernetes, GitHub, GitLab, Okta, Snowflake, Google Workspace [sourced: https://www.wiz.io/solutions/ciem].
- **SaaS and other coverage:**
  - **Microsoft 365 connector**: agentless; covers OneDrive/SharePoint sensitive data and risky sharing links. Announced at Wizdom 2025 [sourced: https://wiz.io/blog/wizdom-product-launches-2025].
  - **Databricks** coverage [sourced: https://www.wiz.io/blog/wiz-at-google-cloud-next].
  - Agent platforms: AWS AgentCore, Gemini Enterprise Agent Platform, Azure Copilot Studio, Salesforce Agentforce.
  - Edge: Cloudflare, Akamai, Vercel, Apigee [sourced: https://siliconangle.com/2026/04/22/google-cloud-next-new-security-operations-agents-wiz-integrations-agent-governance-tools/].
- **On-prem/hybrid:** "Sensor Workload Scanner" [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **Wiz Sensor for Developer Workstations** (Windows/macOS, private preview, 2026-08): inventories packages, IDE extensions and AI tools, and detects supply-chain attacks on developer laptops [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **Defend Agentless Workload Detection:** threat detection on workloads without a sensor, using logs, runtime signals and control-plane data [sourced: https://wiz.io/blog/wizdom-product-launches-2025].

### Inventory & graph
- **Data model:** Wiz Security Graph — typed nodes (e.g. `VIRTUAL_MACHINE`, `VOLUME`) joined by typed relationships (e.g. `USES`), each carrying properties and attached findings.
- **Query format:** the graph query language is JSON-structured. Example from a third-party source [sourced: https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-security-graph-wiz/]:
  `{"type":["VIRTUAL_MACHINE"],"relationships":[{"type":[{"type":"USES"}],"with":{"type":["VOLUME"],"where":{"encrypted":{"EQUALS":false}}}}]}`
- **Natural-language queries:** AskAI translates text into this query format (already covered) [sourced: https://wiz.io/blog/askai-text-to-security-graph-query].
- **CIEM Explorer:** a dedicated query view by identity × access type × resource [sourced: https://www.wiz.io/solutions/ciem].
- **AI inventory:**
  - **AI-BOM** (dynamic): AI frameworks, models, IDE extensions, shadow AI [sourced: https://siliconangle.com/2026/04/22/google-cloud-next-new-security-operations-agents-wiz-integrations-agent-governance-tools/].
  - **MCP discovery**: GA since Wizdom 2025 [sourced: https://wiz.io/blog/wizdom-product-launches-2025].
  - **Wiz Workload Explainer**: uses AI to work out how a self-hosted AI app is built [sourced: https://www.wiz.io/blog/introducing-wiz-ai-app].
- **Other inventory features:**
  - **Wiz Service Catalog** groups resources into services and owners [inferred from blog title https://www.wiz.io/blog/wiz-service-catalog-updates — not fetched].
  - **Technology Intel Center**: aggregates feature releases, migrations and end-of-life notices across cloud and AI providers [sourced: https://www.wiz.io/blog/wiz-at-google-cloud-next].

### Attack paths & toxic combinations
- The core toxic-combination model (Issues) is already covered and not repeated here.
- **New in 2026: AI attack paths.** AI-APP chains layers: external exposure → auth-bypass vuln → prompt injection → agent tool action → sensitive data. These map to the OWASP LLM Top 10 [sourced: https://www.wiz.io/blog/introducing-wiz-ai-app].
  - Agent tools are classified by capability: data access, code execution, API interaction, infrastructure modification.
- **Red Agent:** validates exploitability of app and API logic flaws (OWASP API Top 10, authorization bypass). It feeds proven-exploitable signals into the graph. Status: public preview at Next 2026, GA by Black Hat 2026 [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026] [sourced: https://www.wiz.io/blog/wiz-at-google-cloud-next].

### Risk prioritization
- **Signals:**
  - CISA KEV and other exploit-intel sources are attached to vulnerability findings [sourced: https://www.wiz.io/blog/detect-and-prioritize-cisa-known-exploited-vulnerabilities-kev-with-wiz].
  - Google Threat Intelligence (Mandiant plus VirusTotal) enrichment ships out of the box to all customers since 2026-08 [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **Missing detail:** I found no public numeric risk-score scale beyond Issue severities (Critical/High/Medium/Low/Info) [inferred]. EPSS use was not confirmed in an official source [inferred].
- **AI SAST de-duplication:** findings are deduplicated "using security context rather than line numbers" and re-tested, so AI-found issues stay stable [sourced: https://www.wiz.io/blog/introducing-wiz-ai-sast].

### CIEM/identity
- **Effective access map:**
  - Covers human and non-human identities against resources, and evaluates permission boundaries, ACLs, **SCPs and RCPs**.
  - Auto-generates **least-privilege policies**.
  - Detects unused admin permissions, no-MFA principals, inactive users and excessive permissions.
  - Includes a **Non-Human Identities dashboard** [sourced: https://www.wiz.io/solutions/ciem].
- **IdP and SaaS mapping:** Okta, Snowflake permissions and Google Workspace [sourced: https://www.wiz.io/solutions/ciem].
- **JIT:** I found no native JIT access feature [inferred].

### DSPM
- **Classification:** agentless, with built-in classifiers for PII/PHI/PCI/secrets plus **custom classifiers**.
- **Coverage:** buckets, managed DBs (MySQL, PostgreSQL, MongoDB, MariaDB), Snowflake and OpenAI.
- **Correlation and compliance:** findings are linked to exposure, identities, vulns, malware and lateral movement. Includes data-sovereignty location tracking and maps to PCI/GDPR/HIPAA/HITRUST [sourced: https://www.wiz.io/solutions/dspm].
- **Not public:** sampling method and classifier count [sourced: https://www.wiz.io/solutions/dspm — not stated].

### Vulnerability & secrets
- **Workload scanning:** agentless snapshot scanning of VMs, containers and serverless, plus secrets scanning [inferred from the general product, consistent with https://www.wiz.io/solutions/dspm].
- **Unified Vulnerability Management (2026-08):** ingests third-party findings into one queue [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **Atlas:** an autonomous AI vulnerability researcher. Wiz reports "#1 on CyberGym", 90.9% success. Not commercially available [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **WizOS Helm Charts (2026-09-30):** hardened, signed, CVE-scanned Helm charts, extending WizOS hardened images [sourced: https://www.wiz.io/blog/tag/news via search snippet].

### Code-to-cloud / IaC
- **Wiz Code scope:** SCA, SAST, secrets, IaC, and supply-chain posture [sourced: https://wiz.io/academy/application-security/best-code-analysis-tools].
- **Wiz AI SAST** (public preview, 2026-10-06, for Wiz Code customers) [sourced: https://www.wiz.io/blog/introducing-wiz-ai-sast]:
  - Built on the "Atlas harness".
  - Finds business-logic flaws such as broken access control, input validation and crypto issues.
  - Grounded in the Security Graph, so it can flag flaws that exist only at the app-plus-infrastructure intersection.
- **Guardrails for AI coding** [sourced: https://www.wiz.io/blog/wiz-at-google-cloud-next] [sourced: https://siliconangle.com/2026/04/22/google-cloud-next-new-security-operations-agents-wiz-integrations-agent-governance-tools/]:
  - **Secure Guardrails / inline AI security hooks** check prompts and scan generated code before commit, in IDEs and agent workflows.
  - **Lovable** integration shows Wiz findings inside Lovable's security view.
  - **Agentic Remediation Skills** for Claude Code and Cursor.

### Remediation
- **Green Agent** (public preview at Next 2026) [sourced: https://www.wiz.io/blog/introducing-wiz-agents] [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026]:
  - Root-causes the highest-risk issues using the graph, code-to-cloud links, identity ownership and **historical remediation patterns**.
  - Picks the safest fix and surfaces "tailored response actions from pre-built templates" that run with one click.
- **Wiz Workflows** (GA 2026-08) [sourced: https://www.wiz.io/blog/introducing-wiz-agents]:
  - High-confidence verdicts can auto-trigger remediation (e.g. block S3 public access).
  - Lower-confidence verdicts go to the owner in Slack for approval, a human-in-the-loop routing by confidence.
- **Runtime Response Policies:** run in "Simulate" or "Block" mode (kills the malicious process). They fire on custom runtime rule matches or on threat categories such as malware and IoCs [sourced: https://www.wiz.io/ja-jp/blog/custom-runtime-rules-and-response-policies].

### Compliance
- **Frameworks:** 100+ built-in cloud frameworks (NIST, HIPAA, CIS, HITRUST, SOC 2, ...) plus 60+ host-configuration benchmarks (CIS RHEL, Ubuntu, NGINX, Windows Server) [sourced: https://wiz.io/blog/compliance-made-easy-with-wiz].
- **Custom frameworks:** build from scratch or duplicate a built-in one [sourced: https://wiz.io/blog/compliance-made-easy-with-wiz].
- **Compliance heatmap:** a per-framework score plus a cross-framework heatmap [sourced: https://wiz.io/blog/compliance-made-easy-with-wiz].

### Detection & response / real-time
- **Wiz Defend (CDR):** cross-layer detections across control-plane auth/API events and the runtime sensor [sourced: https://support.expel.io/hc/en-us/articles/43299823455379-Wiz-Defend-Detection-Strategy].
- **Custom runtime rules:**
  - Built from Boolean, string and regex operators over five event types: process exec, outbound network, DNS, listening sockets, actor.
  - "Hundreds of rules by default".
  - Can be scoped to projects, with per-rule severity [sourced: https://www.wiz.io/ja-jp/blog/custom-runtime-rules-and-response-policies].
- **Blue Agent** (GA): replaces the "SecOps Agent" name. Gathers cloud, runtime and identity evidence into a severity verdict [sourced: https://www.wiz.io/blog/introducing-wiz-agents].
- **Google SecOps:** Defend detections flow into Google Security Operations and Mandiant Threat Defense [sourced: https://itwire.com/business-it-news/security/google-cloud-unveils-agentic-defence-innovations-at-next-2026.html].
- **AI-DR (inside AI-APP):** a three-layer model:
  - Model layer: prompts and outputs.
  - Workload layer: agent execution and tool use.
  - Cloud layer: identity and API calls [sourced: https://www.wiz.io/blog/introducing-wiz-ai-app].

### Integrations & workflow
- **Native integrations:** Slack; Jira and ServiceNow ticketing; SIEM; Google SecOps; Cloudflare, TrojAI and Pillar Security feeding findings into the graph [sourced: https://www.wiz.io/blog/introducing-wiz-ai-app] [sourced: https://www.wiz.io/blog/introducing-wiz-agents].
- **Workflows** orchestrate actions across agents and integrations [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **Known friction:** reviewers report Splunk and ServiceNow API friction (see weaknesses).

### Dashboards & reporting UX
- **Dashboards:** customizable, widget-based [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-vbf35nay6mnuy?page=35 via search snippet]. Plus the Compliance heatmap and the NHI dashboard.
- **Executive reporting gaps:** reviewers ask for exec-style dashboards and PDF exports (see weaknesses).
- **Not found publicly:** home-screen widget names and MTTR/SLA report specifics.

### AI assistant
- **Agent lineup in 2026:** Red / Blue / Green agents plus Workflows, building on the AskAI, Mika and MCP features already covered [sourced: https://www.wiz.io/blog/introducing-wiz-agents].
- **Guardrails:**
  - "every action is backed by visible evidence".
  - Remediation actions are gated by confidence level.
  - Lower-confidence actions route to a human in Slack.

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- **API:** GraphQL API; MCP server (already covered).
- **CLI:** wizcli for CI scanning [inferred — general knowledge, not re-verified this session].
- **Multi-tenant:** Wiz Tenant Manager (blog: "Multi-Tenant Management for Federated Organizations") [sourced: https://www.wiz.io/ko-kr/blog/wiz-tenant-manager-multi-tenant-security] [sourced: https://www.channelinsider.com/security/news-wiz-msp-program-managed-cloud-ai-security/]:
  - Centralized dashboard and "smart tenant groups".
  - Global baseline policies with local overrides.
  - One-click, **audited** tenant access.

### Unique "wow" features released 2025-2026
- **Red / Blue / Green Agents + Wiz Workflows** with confidence-based auto vs. approve routing (2026-03 → GA 2026-08) [sourced: https://www.wiz.io/blog/introducing-wiz-agents].
- **Wiz AI SAST:** graph-grounded LLM SAST with context-based dedupe and retesting (2026-10) [sourced: https://www.wiz.io/blog/introducing-wiz-ai-sast].
- **AI-APP:** AI attack paths, agent-tool capability classification, Workload Explainer (2026-03) [sourced: https://www.wiz.io/blog/introducing-wiz-ai-app].
- **Developer workstation sensor** for IDE extensions and AI tools (2026-08) [sourced: https://www.wiz.io/blog/wiz-at-black-hat-2026].
- **Runtime rules with Simulate→Block mode** [sourced: https://www.wiz.io/ja-jp/blog/custom-runtime-rules-and-response-policies].
- **Technology Intel Center** for provider EOL and migration notices [sourced: https://www.wiz.io/blog/wiz-at-google-cloud-next].

### Documented weaknesses/complaints
- **Price:**
  - "the pricing model is a little bit hefty on the pocket" — AVP, NatWest Group (PeerSpot) [sourced: https://www.peerspot.com/products/wiz-pros-and-cons].
  - "pricing is a bit higher than the market rate" (PeerSpot) [sourced: https://www.peerspot.com/products/wiz-pros-and-cons].
- **Stability and accuracy:**
  - "results changed radically from one day to the next" — CISO (PeerSpot) [sourced: https://www.peerspot.com/products/wiz-pros-and-cons].
  - "suggested fixes for vulnerabilities are not always accurate based on our code compatibility" (PeerSpot) [sourced: https://www.peerspot.com/products/wiz-pros-and-cons].
- **Performance:** "loading time is taking a bit longer while loading the graph" (PeerSpot) [sourced: https://www.peerspot.com/products/wiz-pros-and-cons].
- **Reporting:** "reporting capabilities could be refined with more executive-style dashboards" (PeerSpot) [sourced: https://www.peerspot.com/products/wiz-pros-and-cons].
- **Noise and fix lag:** duplicate alerts appear for the same issue under different categories, and a fix takes about 24h to show in Wiz (G2 summary via search) [sourced: https://www.g2.com/products/wiz-wiz].
  - G2 rating was 4.7/5 from 794 reviews at search time.
- **Tuning effort:** "alert volume and noise can require ongoing tuning"; "large environments can produce too much signal" [sourced: https://www.rfp.wiki/cloud-computing/cloud-security-posture-management/wiz].
- **Wiz Code:**
  - "not yet at a level where I trust it without validation" [sourced: https://www.peerspot.com/products/wiz-code-pros-and-cons].
  - "Timely responses from customer support for Wiz Code are not being received" [sourced: https://www.peerspot.com/products/wiz-code-pros-and-cons].
- **Post-acquisition worry:** buyers fear GCP favoritism, which is pushing multi-cloud shops to evaluate alternatives [sourced: https://roboticsandautomationnews.com/2026/05/25/wiz-alternatives-in-2026-7-tools-compared-best-for-cloud-and-code-security/101861/].

### Sources
- https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz
- https://techcrunch.com/2026/03/11/google-completes-32b-acquisition-of-wiz
- https://aws.amazon.com/marketplace/pp/prodview-5geds7fc2wk7m
- https://cipherssecurity.com/wiz-pricing-guide-2026-cnapp-cost/
- https://wiz.io/blog/wizdom-product-launches-2025
- https://siliconangle.com/2026/04/22/google-cloud-next-new-security-operations-agents-wiz-integrations-agent-governance-tools/
- https://itwire.com/business-it-news/security/google-cloud-unveils-agentic-defence-innovations-at-next-2026.html
- https://www.wiz.io/blog/wiz-at-google-cloud-next
- https://www.wiz.io/blog/wiz-at-black-hat-2026
- https://www.wiz.io/blog/introducing-wiz-agents
- https://www.wiz.io/blog/introducing-wiz-ai-sast
- https://www.wiz.io/blog/introducing-wiz-ai-app
- https://www.wiz.io/solutions/ciem
- https://www.wiz.io/solutions/dspm
- https://wiz.io/blog/compliance-made-easy-with-wiz
- https://www.wiz.io/ja-jp/blog/custom-runtime-rules-and-response-policies
- https://www.wiz.io/blog/detect-and-prioritize-cisa-known-exploited-vulnerabilities-kev-with-wiz
- https://www.wiz.io/ko-kr/blog/wiz-tenant-manager-multi-tenant-security
- https://www.channelinsider.com/security/news-wiz-msp-program-managed-cloud-ai-security/
- https://support.expel.io/hc/en-us/articles/43299823455379-Wiz-Defend-Detection-Strategy
- https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-security-graph-wiz/
- https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-runtime-sensor/
- https://wiz.io/academy/application-security/best-code-analysis-tools
- https://www.peerspot.com/products/wiz-pros-and-cons
- https://www.peerspot.com/products/wiz-code-pros-and-cons
- https://www.g2.com/products/wiz-wiz
- https://www.rfp.wiki/cloud-computing/cloud-security-posture-management/wiz
- https://roboticsandautomationnews.com/2026/05/25/wiz-alternatives-in-2026-7-tools-compared-best-for-cloud-and-code-security/101861/

---

## Orca Security

### Positioning & pricing model
- Agentless-first CNAPP built on patented SideScanning. Since 2025 it has added an optional eBPF runtime sensor (Orca Sensor) and, in 2026, positions itself as "AI-first cloud defense" built around autonomous agents [sourced: https://orca.security/resources/press-releases/orca-advances-ai-first-cloud-defense/].
- AWS Marketplace listing "Orca Security CNAPP Cloud Security Platform" has four monthly bands: Small $7,000/mo, Small-Medium $12,000/mo, Medium $17,000/mo, Large $30,000/mo. There are 1-month and 12-month contract options, a free trial, and private offers for larger estates [sourced: https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc].
- Billing unit = workload = "a running EC2 host you protect during the month". Idle/stopped instances are discovered but not billed. Sizing uses concurrent running hosts [sourced: https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc]. A secondary source says the Small band = up to 100 concurrent EC2 workloads, with no per-seat pricing and no free tier [sourced: https://comparedge.com/tools/orca-security/pricing]. Workload counts for the other bands: not found.
- Acquisitions/funding events in 2025-2026: not verified (search budget exhausted) [inferred: unknown].

### Deployment
- SideScanning reads workload block storage out of band (snapshot-based) and rebuilds a read-only virtual filesystem. It covers Linux/Windows VMs, containers, container images and serverless, with no agents and no packets sent [sourced: https://orca.security/platform/agentless-sidescanning/].
- Clouds: AWS, Azure, Google Cloud, Oracle Cloud, Alibaba Cloud, Kubernetes [sourced: https://orca.security/resources/blog/dynamic-reachability-analysis/].
- Orca Sensor (launched 2025-01-15): lightweight eBPF sensor for Kubernetes clusters, VMs and ECS clusters, with auto-update and local decision-making [sourced: https://orca.security/resources/blog/meet-orca-sensor-runtime-visibility-protection-cloud-detection-response/; https://orca.security/resources/press-releases/orca-security-unveils-orca-sensor/]. Install mechanism (Helm/DaemonSet) is not documented publicly in the sources found.
- Claimed deployment time: "<30 minutes" (CDR page) [sourced: https://orca.security/platform/detect-and-respond/]. One AWS Marketplace reviewer said full rollout took "approximately two months" [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/B082M5LVJF?page=5].
- Shift-left: Orca CLI, GitHub App, GitLab App and Azure DevOps integrations [sourced: https://orca.security/platform/shift-left-security/].

### Inventory & graph
- **Unified Data Model** combines cloud control plane, SideScanning results (Linux/Windows workloads and apps), flow logs, audit logs and CI/CD scans in one correlated graph. Orca AI, risk scoring and attack paths all run on it [sourced: https://orca.security/resources/blog/orca-sonar-data-query-builder/].
- **Discovery** has two modes: "Discovery mode" for browsing inventory, and a guided graph-based **Query Builder** with color-coded folders by category/subcategory, so users don't have to write SQL by hand. Example: AWS users without MFA and with keys older than 60 days; VMs with unencrypted SSH keys + outdated OS + malware + Log4j. It supports saved views, shareable folders, custom columns, CSV/JSON export, shareable URLs and scheduled exports [sourced: https://orca.security/resources/blog/orca-sonar-data-query-builder/]. The underlying query language was historically called "Sonar" (URL slug) [inferred].
- Event data stream can be filtered with cloud-agnostic parameters or SQL queries [sourced: https://www.businesswire.com/news/home/20240805615901/en (via search summary)].
- AI-driven search over the same model is backed by Azure OpenAI + Elasticsearch [sourced: https://www.elastic.co/blog/orca-search-ai; https://orca.security/resources/press-releases/orca-security-delivers-first-ai-driven-cloud-asset-search-to-further-enable-cloud-security-democratization].

### Attack paths & toxic combinations
- (Business Impact Score 0-99 and top-5 paths are already covered in earlier research.) Each attack vector inside a path also gets its own score. Inputs: vuln severity + accessibility, lateral movement risk, access to sensitive data, and "crown jewel" location [sourced: https://scmagazine.com/news/orca-security-to-offer-scoring-system-for-attack-paths-on-cloud-native-apps].
- The CSPM page highlights "which risks break multiple attack paths", i.e. choke-point remediation [sourced: https://orca.security/platform/cloud-security-posture-management-cspm/]. The risk page describes this as "fix one node on the path instead of chasing every finding" [sourced: https://orca.security/?p=73466].
- New 2026: **offensive validation agents**. Orca's "Red Pod" agents (Attack Surface agent, Code Security Auditor) test what is exposed and exploitable from an attacker's view [sourced: https://orca.security/platform/orca-ai/].

### Risk prioritization
- Signals: CVSS + EPSS, exploitability, public exposure and lateral movement, asset criticality, PII presence/adjacency, and reachability [sourced: https://orca.security/?p=73466]. KEV was not explicitly named in the sources found [inferred: likely but unverified].
- **Reachability now covers three dimensions** (2026):
  1. **Agentless reachability**: from SideScanning, flags packages that "could be executed in runtime". Claims a 90% cut in vulns to fix (press release 2025-04-22) [sourced: https://orca.security/resources/press-releases/orca-security-reduce-vulnerabilities-agentless-analysis/].
  2. **Dynamic reachability**: from Orca Sensor, packages actually loaded/executed in production.
  3. **Code reachability**: whether the specific vulnerable function is invoked in source (announced 2026-03-16) [sourced: https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/].
- Vuln UI filter fields: detection method (agentless vs dynamic), verification status (verified/unverified in runtime), application/service using the package, loaded file path, runtime execution context [sourced: https://orca.security/resources/blog/dynamic-reachability-analysis/].
- The dashboard shows the risk factors behind each score. Scoring is customizable. The **Orca Security Score** is used for peer benchmarking and exec reporting [sourced: https://orca.security/?p=73466].

### CIEM/identity
- Inventories all identities, roles, groups, permissions and policies, and answers questions like "which human and machine identities can access this GCS bucket" [sourced: https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/].
- **Unused permissions**: compares IAM policies against **the last 90 days** of usage and flags inactive admin roles and unattached privileged policies [sourced: same].
- **Least-privilege generation** computes the "largest security improvements with least policy changes" and outputs **ready-to-use config files** [sourced: same].
- **JIT access for AWS**: time-bound, role-specific grants with **two-way Slack** request/approve flow and full audit log [sourced: same].

### DSPM
- Agentless (SideScanning) classification of databases (managed + self-hosted), S3, Azure Blob, GCS, VM files and storage containers [sourced: https://orca.security/platform/data-security-posture-management-dspm/].
- Categories: PII, PCI, PHI, financial, IP. **OCR** finds PII in JPG/PNG/PDF (IDs, passports, driver's licenses). Findings show **redacted samples** [sourced: same]. Sampling rate/strategy: not public.

### Vulnerability & secrets
- Agentless package inventory mapped to NVD: APT/YUM/RPM plus pip, npm, Go modules, Maven [sourced: https://orca.security/?p=73466 (search summary)].
- Code side: SAST, SCA (Ruby, Python, PHP, Node.js, .NET, Java, Go), and secrets detection with "dynamic alert scoring" plus a pre-commit hook option [sourced: https://orca.security/platform/shift-left-security/].
- 2026: **AppSec Triage Agent** marks SAST false positives with a confidence level and adjusts risk scores. Users can roll back designations. Auto-dismiss above a confidence threshold is optional [sourced: https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/].
- SBOM export: not confirmed in sources found [inferred: unknown].

### Code-to-cloud / IaC
- IaC: Terraform, CloudFormation, ARM, Google Deployment Manager, Ansible, Kubernetes. Customizable IaC policies/guardrails run on every PR [sourced: https://orca.security/platform/shift-left-security/].
- "Cloud-to-Dev tracing" links cloud risks to source and produces AI code fixes plus **one-click PRs** [sourced: same].

### Remediation
- Three modes per alert: **auto-remediation** (configurable automation rules), **guided** AI-generated instructions, and copy/paste CLI/IaC code [sourced: https://orca.security/platform/cloud-security-posture-management-cspm/].
- **Orca Missions** (2026-03): groups related findings into a goal-based initiative with defined completion criteria. A mission counts as complete "only when the predefined objective is technically verified as complete". The UI shows expected security-score impact during the mission and the result at the end (e.g. "12.5% security score increase" + alert reduction count) [sourced: https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/].
- "Green Pod" agents handle ownership resolution and fix generation [sourced: https://orca.security/platform/orca-ai/].
- Jira bi-directional sync: Orca shows ticket status, and closing a ticket triggers an automatic rescan to confirm the fix [sourced: https://orca.security/partners/technology/jira-by-atlassian/].

### Compliance
- Framework count varies by page: "150+" (CSPM page), "180+" (2025 datasheet per search summary), and "**185+** regulatory frameworks and CIS benchmarks" (CIEM page, latest) [sourced: https://orca.security/platform/cloud-security-posture-management-cspm/; https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/].
- **2,500+ configuration controls** in 10+ categories (authentication, data protection, logging, network, K8s, system integrity), plus a proprietary "Orca Best Practices" framework [sourced: https://orca.security/platform/cloud-security-posture-management-cspm/].
- Custom frameworks and evidence export: not verified in fetched pages [inferred: custom frameworks are commonly supported; unverified]. One reviewer says compliance details are "not always easy to find in the UI" [sourced: https://www.rfp.wiki/vendors/orca-security].

### Detection & response / real-time
- CDR uses cloud provider logs + threat intel in real time, plus Orca Sensor for containers/K8s/AI workloads [sourced: https://orca.security/platform/detect-and-respond/].
- Orca Sensor: **30+ runtime detections** across DNS/files/network/process (malware execution, malicious domains/IPs, binary drift, webshell execution, fileless/memory persistence). It has a built-in policy library and custom policies with scope and enforcement, including **terminate process** [sourced: https://orca.security/resources/blog/meet-orca-sensor-runtime-visibility-protection-cloud-detection-response/].
- **Threat Investigation Agent** (2026-03) rebuilds context and event sequence, finds the root cause, and outputs an investigation report with transparent reasoning and proposed containment actions [sourced: https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/].
- **Runtime AI Threat Detection** (2026-03, via Sensor) detects actual LLM calls regardless of provider/language. It maps which workload/identity/process calls which model, whether sensitive data reaches models, MCP server usage/location (internal vs external), and prompt-injection exposure [sourced: same].
- MITRE mapping: not stated in sources found.

### Integrations & workflow
- Ticketing: Jira (bi-directional + rescan on close), ServiceNow (incidents and change requests), monday.com [sourced: https://orca.security/partners/technology/jira-by-atlassian/; https://orca.security/partners/technology/servicenow/; https://www.silicon.co.uk/press-release/orca-security-integrates-with-monday-com-to-streamline-security-remediation].
- Slack with per-channel team routing. SIEM: Splunk, QRadar, Sentinel, Sumo Logic, AWS Security Hub, Amazon Security Lake [sourced: https://orca.security/partners/technical-alliance-partners/; https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/].
- "20+" third-party integrations (SOAR, notification, ticketing) [sourced: https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/].

### Dashboards & reporting UX
- Orca Security Score for benchmarking and exec reporting. Custom dashboards are manageable via Terraform. Scheduled exports come from Discovery [sourced: https://orca.security/?p=73466; https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/].
- Missions show score delta and alert-reduction outcome, effectively a progress/SLA view [sourced: https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/]. MTTR/SLA dashboard specifics: not found.

### AI assistant
- Orca AI: NL search ("public-facing log4j?"), code fixes with open-PR option, follow-up refinement. Privacy claim: "anonymizing requests and masking any sensitive data" [sourced: https://orca.security/platform/orca-ai/].
- **Agent pods** (2026): Red Pod (Code Security Auditor, Attack Surface agent), Blue Pod (AppSec Triage, Threat Investigation), Green Pod (ownership + fix generation), and **Custom Agents** built from templates/frameworks or from scratch [sourced: https://orca.security/platform/orca-ai/].
- **Orca MCP Server** (2025-04-03): exposes Unified Data Model to Claude/other chat clients locally on desktop. AI search supports 50+ languages. Now also wired into Codex, Cursor and VS Code [sourced: https://www.silicon.co.uk/press-release/orca-becomes-first-cloud-security-platform-to-deliver-universal-access-to-any-genai-model-through-support-for-model-context-protocol; https://orca.security/platform/orca-ai/].
- Guardrails: transparent reasoning reports, user rollback of AI verdicts, confidence-threshold auto-dismiss [sourced: https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/]. Underlying LLM vendors are not disclosed on the AI page.

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- REST API docs in OpenAPI/Swagger, HTML and PDF. Orca CLI for pipelines [sourced: https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/; https://orca.security/platform/shift-left-security/].
- **Terraform provider** manages users, **Business Units** (scoped tenancy for departments/apps), saved views, custom dashboards, alert rules, automations, AppSec config and RBAC [sourced: https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/].
- SAML SSO and Okta integration for roles/permissions [sourced: https://www.okta.com/en-nl/integrations/orca-security/].

### Unique "wow" features released 2025-2026
- 2025-01-15 Orca Sensor (eBPF, terminate-process enforcement) [sourced: https://orca.security/resources/press-releases/orca-security-unveils-orca-sensor/].
- 2025-04-03 Orca MCP Server [sourced: silicon.co.uk link above].
- 2025-04-22 Agentless reachability ("90%" vuln reduction claim) [sourced: https://orca.security/resources/press-releases/orca-security-reduce-vulnerabilities-agentless-analysis/].
- 2026-03-16 Threat Investigation Agent, AppSec Triage Agent, Orca Missions, Runtime AI Threat Detection, Code Reachability [sourced: https://orca.security/resources/press-releases/orca-advances-ai-first-cloud-defense/].
- 2026-07-29 **Orca AI AppGen Security** (finds and secures apps built on Claude/Supabase/Lovable outside the SDLC: who built them, API/integration risk, data access) and **AI Code Security Auditor** (cross-file dataflow SAST for broken authz/privesc/business logic). Both slated for GA later in 2026 [sourced: https://itbrief.co.uk/story/orca-launches-ai-security-tools-for-all-software-builders; https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/].
- State of AI Security Report 2026: telemetry from 1,200+ production cloud environments, and 52% of orgs build custom AI apps [sourced: https://itbrief.co.uk/story/orca-launches-ai-security-tools-for-all-software-builders].

### Documented weaknesses/complaints
- Ratings (aggregated by rfp.wiki): G2 4.6 (252), Gartner PI 4.6 (239), Capterra 4.8 (60) [sourced: https://www.rfp.wiki/vendors/orca-security].
- Noise at onboarding: "Alert volume and noisy initial scans can make early triage cumbersome" (rfp.wiki synthesis of reviews) [sourced: https://www.rfp.wiki/vendors/orca-security].
- UI density: "Some dashboards feel dense or overwhelming for newcomers", and "compliance details are not always easy to find in the UI" (rfp.wiki) [sourced: same].
- AWS Marketplace reviewers [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/B082M5LVJF?page=5]:
  - "It took approximately two months to fully deploy Orca Security"
  - "In a large environment, the attack path graphs can hold a lot of detail"
  - "We spent some time defining suppression rules for the test credentials in our sandboxes"
  - "The main follow-on work was organizing the findings to match how our teams and business units are structured"
- Comparisons: users suggest Orca improve integrations, and one reviewer moved from Orca to Wiz for reporting/usability [sourced: https://g2.com/compare/orca-security-vs-wiz-wiz (via search summary)].

### Sources
- https://orca.security/resources/press-releases/orca-advances-ai-first-cloud-defense/
- https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/
- https://orca.security/resources/blog/dynamic-reachability-analysis/
- https://orca.security/resources/press-releases/orca-security-reduce-vulnerabilities-agentless-analysis/
- https://orca.security/resources/press-releases/orca-security-unveils-orca-sensor/
- https://orca.security/resources/blog/meet-orca-sensor-runtime-visibility-protection-cloud-detection-response/
- https://orca.security/platform/detect-and-respond/
- https://orca.security/platform/cloud-security-posture-management-cspm/
- https://orca.security/platform/agentless-sidescanning/
- https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/
- https://orca.security/platform/data-security-posture-management-dspm/
- https://orca.security/platform/shift-left-security/
- https://orca.security/platform/orca-ai/
- https://orca.security/?p=73466
- https://orca.security/resources/blog/orca-sonar-data-query-builder/
- https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/
- https://orca.security/partners/technology/jira-by-atlassian/
- https://orca.security/partners/technology/servicenow/
- https://orca.security/partners/technical-alliance-partners/
- https://www.silicon.co.uk/press-release/orca-becomes-first-cloud-security-platform-to-deliver-universal-access-to-any-genai-model-through-support-for-model-context-protocol
- https://itbrief.co.uk/story/orca-launches-ai-security-tools-for-all-software-builders
- https://scmagazine.com/news/orca-security-to-offer-scoring-system-for-attack-paths-on-cloud-native-apps
- https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc
- https://aws.amazon.com/marketplace/reviews/reviews-list/B082M5LVJF?page=5
- https://www.rfp.wiki/vendors/orca-security
- https://comparedge.com/tools/orca-security/pricing
- https://www.okta.com/en-nl/integrations/orca-security/
- https://www.elastic.co/blog/orca-search-ai

---

## Palo Alto Networks Prisma Cloud -> Cortex Cloud

### Positioning & pricing model
- **Rebrand:** Cortex Cloud was announced on 2025-02-13 as "the next version of Prisma Cloud". It merges the CNAPP with CDR on the Cortex platform, and it is also available inside Cortex XSIAM [sourced: https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-introduces-cortex-cloud-future-real-time].
- **Migration timing:** one third-party source says the migration of existing Prisma customers "wrapped up" in PANW fiscal Q3 2025 [sourced: https://distribuee.com/en/insights/prisma-cloud-cortex-cloud-smb-cnapp/].
- **Releases:**
  - Cortex Cloud 2.0 went GA on 2025-10-28 [sourced: https://www.paloaltonetworks.com/blog/cloud-security/cloud-security-platform-cortex-cloud-2-0/].
  - Automated customer upgrades to 2.0 were scheduled for H1 2026 [sourced: https://seekingalpha.com/pr/20282604-palo-alto-networks-ushers-in-autonomous-ai-workforce-for-cloud-security-with-cortex-cloud-2_0].
  - 2.1 followed, then 2.2 (blog dated 2026-07-28) [sourced: https://www.paloaltonetworks.com/blog/cloud-security/cortex-cloud-2-2/].
- **Two license plans** [sourced: https://cortex-docs.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Runtime-Security-Documentation/Understand-license-plans]:
  - **Cloud Posture Management** (agentless): CSPM, CIEM, ASPM, DSPM, AI-SPM, ASM, KSPM, CI/CD posture and agentless workload scanning.
  - **Cloud Runtime Security:** Posture plus CWP and WAAS.
- **Metering unit is the "protected workload"**, averaged over 90 days to smooth out ephemeral spikes [sourced: same]:
  - 1 VM = 1
  - 1 endpoint = 1
  - 10 managed containers (CaaS) = 1
  - 10 buckets = 1
  - 2 PaaS DBs = 1
  - 1 TB of DBaaS storage = 1
  - 10 SaaS users = 1
  - 4 unmanaged ASM assets = 1
  - Container images: 10 free scans per deployed workload
- **Add-ons** [sourced: same]:
  - Security: Data Ingestion, AppSec (IaC/SCA/Secrets), Enterprise Runtime (XDR), ITDR, Forensics, XTH, XTI, DLP.
  - Capacity: Data Retention per dataset, Query Capacity in compute units.
- **Legacy Prisma Cloud credits:** search snippets of the AWS Marketplace listing show $18,000 for 100 credits over 12 months for Enterprise Edition. The listing page itself would not render, so this is unverified [sourced: https://aws.amazon.com/marketplace/pp/prodview-fhoptf6o4hcyu].
- **Third-party estimates** (not vendor-published) [sourced: https://distribuee.com/en/insights/prisma-cloud-cortex-cloud-smb-cnapp/]:
  - About $18k/yr for CSPM only.
  - About $45k/yr for CSPM + CWPP + CIEM.
- **No public Cortex Cloud rate card** [sourced: https://work-management.org/network-security/cortex-cloud-review/].

### Deployment
- **Agentless side:** posture, CIEM, DSPM, and agentless workload/disk scanning are all agentless.
- **Agent:** runtime uses the unified Cortex XDR agent, called the "CDR agent".
  - Cortex Cloud 2.0 added a one-click "performance-optimized mode" that claims up to 50% less resource use. It switches between full and optimized modes without reinstalling [sourced: https://www.paloaltonetworks.com/blog/cloud-security/cloud-security-platform-cortex-cloud-2-0/].
- **Runtime coverage:**
  - VMs, containers, Kubernetes and serverless [sourced: https://www.paloaltonetworks.com/blog/2025/02/announcing-innovations-cortex-cloud].
  - ECS-on-EC2 agent installer (Feb 2026) [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/february-2026/release-highlights].
  - ECS Fargate CaaS, with the XDR agent embedded in the image (May 2026) [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/may-2026/release-highlights].
- **Kubernetes connector:** agentless K8s image and drift scans (Feb 2026), plus "Expanded Agentless Kubernetes Security" for AWS (May 2026) [sourced: same two URLs].
- **Clouds:** AWS, Azure and GCP. Identity permission graph support covers all three [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/july-2026/release-highlights].
- **Broader estate:**
  - SaaS DSPM (Google Drive, M365, Teams, Salesforce, Claude).
  - On-prem databases via the Broker VM applet (May 2026) [sourced: same two URLs].
- **Cloud API coverage:** "approximately 10x new cloud provider APIs per month" [sourced: July 2026 highlights URL above].

### Inventory & graph
- **XQL asset dataset:** the asset inventory can be queried in XQL as the `asset_inventory` dataset, using normalized XDM fields [sourced: https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/asset-management/query-the-asset-inventory-via-xql]:
  - `xdm.asset.id`, `xdm.asset.name`
  - `xdm.asset.type.class` (Compute/Identity/AI/Network…)
  - `xdm.asset.type.category`
  - `xdm.asset.provider`, `xdm.asset.realm`
  - `xdm.cloud.region`
- **Graph Search** lives at Investigation & Response -> Search -> Query Builder -> Graph Search [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/graph-search/how-to-build-graph-search-queries]:
  - It is a guided query builder with `FIND <node types>` (multiple nodes are ORed), then `WHERE` conditions, then relationship edges.
  - Asset nodes are drawn as circles and Finding nodes as diamonds.
  - Results show as a Graph or Table view and export to PNG/SVG/TSV.
  - There is a Query Library with built-in PANW queries [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/graph-search/what-is-graph-search].
  - Detection rules can be created from graph searches [sourced: graph-search/create-detection-rules-based-on-graph-search page, listed in the docs sitemap].
- **RQL to XQL:**
  - Legacy Prisma used RQL (`config from cloud.resource where …`, `event from cloud.audit_logs …`, `network from vpc.flow_record …`, `config from iam …`) [inferred, from prior Prisma Cloud knowledge; the RQL docs page could not be fetched].
  - Since Feb 2026, Cortex Cloud lets you author "XQL-based Cloud Security rules", with a quick flow for common cases plus a free-form XQL editor [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/february-2026/feature-enhancements/cspm].
  - Reviews repeatedly called RQL "not intuitive" [sourced: https://www.peerspot.com/questions/what-needs-improvement-with-prisma-cloud-by-palo-alto-networks-147313].
- **Command Center widget "Asset Class Distribution":** classes AI, Compute, Identity, API, Data, Network, each showing total and at-risk counts [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/dashboards-and-reports/monitor-dashboards-and-reports/dashboard-reference/command-center-reference/cortex-cloud-command-center].
- **Kubernetes Graph:** an interactive K8s risk map (July 2026) [sourced: July 2026 highlights URL].
- **Unified human identities (May 2026):** one virtual identity per person that links accounts across directories, cloud IdPs and SaaS [sourced: May 2026 highlights URL].

### Attack paths & toxic combinations
- **Legacy rules:** asset type plus findings rules (already covered in existing research) are now labelled "Attack Path (Legacy)" rules [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/rules-and-policies/cloud-security-rules-and-policies/create-and-manage-cloud-security-rules/create-an-attack-path-rule]:
  - Example: `FIND EC2 Instance WHERE Finding = "Public Internet Exposure" AND Finding = "Overly Permissive IAM Role" AND Vulnerability = "Critical Severity"`.
  - Vulnerability conditions filter by CVE ID, severity, or CVSS ≥ N.
  - A **Search** button tests the rule against the live environment before you save it.
- **New in Cortex Cloud 2.2 (July 2026): "Graph-Powered Attack Path Detections"** [sourced: https://www.paloaltonetworks.com/blog/cloud-security/cortex-cloud-2-2/]:
  - Combines "user access rules, AI pathfinding, and Unit 42 threat intelligence" to reveal "multi-hop pathways".
  - Path nodes span identities, code, data, workloads and cloud resources.
  - Identity permission chains are shown in Graph Search across AWS, Azure and GCP [sourced: July 2026 highlights URL].
- **Cases:** related issues, assets and attack paths are consolidated into "Cases" with AI-driven grouping [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/get-started/readme-1/key-features].
- **Attack story (Feb 2026):** LLMs synthesize an "attack story and graph visualization" answering "what, why, and how" [sourced: Feb 2026 highlights URL].
- **Vulnerability Exposure Graph:** in the issue panel it shows K8s Namespace -> Cluster -> Workload -> Image relationships [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/vunerability-management/investigate-and-remediate-vulnerabilities].

### Risk prioritization
- **CVRS (Cortex Vulnerability Risk Score):** 0-100, updated daily [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/vunerability-management/cortex-vulnerability-risk-score].
  - Factors:
    - Vulnerability Context (CVSS base)
    - Exploit Intelligence (EPSS, CISA KEV, exploited-in-the-wild, exploit maturity)
    - Asset Risk (public internet exposure)
    - Environment Risk (package-in-use via attack-surface testing)
    - Compensating Controls (needs the Exposure Management add-on)
  - UI: a `CVRS` column, plus an Overview -> **Evidence** summary and a **Risk Details** tab that breaks down each factor.
- **AppSec urgency hierarchy:** the "Top Urgent" bucket = high EPSS + KEV-listed + reachable vulnerable function + deployed, internet-exposed production asset + critical application criticality. Contextual "prioritization labels" are shown on issues [sourced: https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud-Posture-Management/Cortex-Cloud-Application-Security/Investigate-and-remediate-CVE-vulnerability-issues (search snippet; the page itself returned 404 on fetch)].
- **Case scoring** [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/cases-and-issues/case-concepts/case-scoring]:
  - **Rule-based:** user scoring rules on hostnames, asset name/class/category/group/provider, business application, IP, user or AD group. Sub-rule hierarchies are aggregated.
  - **Manual.**
  - **SmartScore** (ML), which has a "Give feedback" control. Severity is Critical/High/Medium/Low [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cases-and-issues/analyze-and-resolve-cases/establish-case-context/assess-case-severity-and-score].
  - **Starring configurations** automatically star cases that touch chosen assets or apps.
- **Identity/host risk scores** (ITDR add-on): typically 10-100, the sum of case/alert scores. They feed into SmartScore [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/asset-managment/manage-asset-scores].
- **CVSS recast:** you can override CVSS scores and severities [sourced: vunerability-management/recast-cvss-scores-and-cvss-severities, listed in the sitemap].

### CIEM/identity
- **"Review Unused Permissions"** [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cortex-cloud-identity-security/achieve-the-principle-of-least-privilege-access]:
  - Uses audit logs plus AWS IAM Access Advisor over a user-selected lookback.
  - Supported entities: AWS roles/groups, Azure SPs/groups, GCP groups/service accounts.
  - The Permission Checkup Results screen shows Remove (red) and Keep (blue) counts.
  - **Adjust Policy** emits a right-sized policy as JSON / Terraform / CloudFormation (AWS) to download or copy.
  - Caveat: if audit logs are turned off, accuracy takes 90 days to recover.
- **API-level LPA recommendations** [sourced: https://cortex-docs.paloaltonetworks.com/xsiam-api/cloud-infrastructure-entitlement-management-ciem/ciem]:
  - Keep every action the asset performed in the lookback window while minimizing the number of policies.
  - Return config snippets.
- **New coverage:**
  - Okta integration for identities and groups (Feb 2026).
  - NHI / cloud-managed secrets posture covering unrotated and overexposed secrets (Feb 2026).
  - Unified human identity (May 2026).
  [sourced: Feb/May 2026 highlights URLs]
- **JIT:** no JIT access feature found [inferred].

### DSPM
- **Licensing:** DSPM is included in the Cloud Posture license. DLP and DDR (Data Detection & Response) need the Data Security add-on [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/cortex-data-security/what-is-cortex-cloud-data-security].
- **Classification** [sourced: https://cortex-docs.paloaltonetworks.com/cortex-xsiam/cloud-security/cortex-cloud-data-classification]:
  - "Hundreds" of built-in patterns.
  - 6 built-in data profiles: Developer Secrets, Financial, PCI, PHI, PII, Sensitive.
  - Custom patterns and profiles, and false-positive reporting.
  - OCR on images is on by default.
  - "Masks three samples per classified data pattern per object", and "data does not leave your environment before it is masked".
  - The legacy Prisma DSPM claimed 100+ classifiers [sourced: https://www.paloaltonetworks.com/cortex/cloud/data-security-posture-management.md].
- **2026 coverage additions:**
  - Databricks on AWS/Azure/GCP (Feb).
  - On-prem databases (May).
  - SaaS: Google Drive, M365, Teams, Salesforce and Claude (July).
  - AWS S3 Vectors / Bedrock AI datasets (July).
  - AI "file topic classification" by business topic (July).
  [sourced: 2026 highlights URLs]

### Vulnerability & secrets
- **Scanning:** agentless disk scanning plus agent-based scanning across hosts, containers and serverless [sourced: https://www.paloaltonetworks.com/cortex/cloud/vulnerability-management.md].
- **Registry scanning** [sourced: July 2026 highlights URL]:
  - Agentless malware sandboxing via Advanced WildFire detonates unknown files in container registries.
  - Base-image "upgrade recommendation".
- **Vulnerability Issues panel:** Overview / Evidence (fix available, CVSS/EPSS, Package in Use, Findings Sources) / Exposure Graph / Resolution (Work Plan playbook or LLM step-by-step Remediation Guidance) / Risk Details / War Room [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/vunerability-management/investigate-and-remediate-vulnerabilities].
- **AppSec:** native SCA with reachability of vulnerable functions [sourced: urgency snippet above]. Third-party SAST/SCA can be ingested (Checkmarx in July 2026, Snyk in May 2026) [sourced: 2.2 blog, May 2026 highlights].
- **AI-BOM:** for Azure AI Foundry and GCP Vertex Model Garden [sourced: Feb/May 2026 highlights].
- **SBOM:** SBOM export was not confirmed in the fetched docs [inferred].

### Code-to-cloud / IaC
- **Code-to-Cloud Coverage dashboard (2.2)** [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/code-to-cloud/code-to-cloud/execute-remediation-workflows]:
  - Shows SDLC stages with "Untraced" areas (for example Deploy -> Build).
  - An Insights region gives call-to-action buttons such as "Onboard CI/CD instances".
  - Per-asset **Code to Cloud** tab with buttons like **Add Data Source** / **Onboard Pipeline**.
  - "Enable Tagging Bot" for **Yor** tags, needed for IaC-to-runtime lineage.
- **Unified AppSec policy (May 2026):** one policy engine across code, build, registry and deploy (`/public_api/appsec/v1/policies`). It adds CI-build and registry image scan triggers and pipeline blocking [sourced: May 2026 highlights].
- **Supply chain (Feb/July 2026):**
  - Artifact Trust Scoring, which scores the tools, identities and pipelines that produced an artifact [sourced: 2.2 blog].
  - Automated Application Creation from VCS structure [sourced: Feb 2026 highlights].
- Checkov PR fixes and Yor drift are already covered in existing research.

### Remediation
- **Earlier releases:** the 2025 launch introduced "guided fixes to resolve multiple risks with a single action" and automated remediation [sourced: https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-introduces-cortex-cloud-future-real-time]. Cortex Cloud 2.0 added one-click playbooks plus natural-language-generated automations [sourced: Cortex Cloud 2.0 blog].
- **New CSPM playbooks and quick actions (May 2026):** one-click fixes for internet-exposed compute and misconfigurations on AWS, Azure and GCP [sourced: May 2026 highlights].
- **Resolution Center** in cases: remediation tasks with pending / in-progress / completed tracking across issues [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cases-and-issues/overview-of-cases/resolving-cases-with-ai].
- **AppSec AI agent (Feb 2026):** opens pull requests for fixes and helps write security policies [sourced: Feb 2026 highlights].
- **Approvals:** AgentiX actions marked sensitive "require explicit user approval before execution and are never run automatically" [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/get-started/agentic-ai-in-cortex-cloud/agentic-assistant-security].

### Compliance
- **Standards Catalog** (Posture Management -> Compliance -> Standards Catalog) [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/compliance/monitor-and-track-compliance-adherence/choose-compliance-standards-from-the-compliance-catalog/standards-catalog]:
  - The built-in standards table lists **151 rows** (counted from the doc, including versions and levels such as ACSC Essential Eight L1-L3, AESCSF, APRA CPS 234, LGPD, AWS FSBP, CIS GKE…).
  - Controls are filterable (for example `Created by != Palo Alto`).
- **Custom standards and controls:** built-in standards are read-only; you duplicate one or build your own [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/compliance/monitor-and-track-compliance-adherence/choose-compliance-standards-from-the-compliance-catalog/use-a-built-in-or-custom-standard.md].
- **Rule customization (July 2026):** compliance-based rule customization lets you change rule severities and toggle single or multiple rules within a policy [sourced: July 2026 highlights].
- **"Audit ready compliance reporting" (May 2026):** a unified evidence framework that automates evidence collection across the XDR agent, agentless scanning and the K8s connector, for SOC 2, PCI-DSS and HIPAA [sourced: May 2026 highlights].
- **Command Center compliance widgets:** "Compliance Summary" (overall score) and "Standards Status" (assessment % and controls assessed per framework) [sourced: Command Center reference URL].

### Detection & response / real-time
- **CDR:** XDR agent with "over 7,000 detectors and 2,400+ ML models" (vendor claim) [sourced: https://www.paloaltonetworks.com/blog/2025/02/announcing-innovations-cortex-cloud].
- **Threat intel (July 2026):** Extended Threat Intel (XTI) adds Unit 42 threat-actor and vulnerability catalogs inside case investigations [sourced: July 2026 highlights].
- **AI Detection & Response:** collects LLM prompt logs from AWS and Azure (Event Hub) [sourced: threat-management/analytics/ai-detection-and-response-in-cortex-cloud, listed in the docs sitemap].
- **Supply Chain Attack Threat Center (2.2):** a feed of compromised tools and malicious packages, plus an automatic check for affected assets [sourced: 2.2 blog].
- **CaaS drift detection:** real time [sourced: July 2026 highlights].
- **Identity response:** identity- and privilege-based response via CyberArk EPM (May 2026) [sourced: May 2026 highlights].

### Integrations & workflow
- "Thousands of third-party integrations" (XSOAR heritage) and playbooks [sourced: key-features URL].
- Issue sync modes are already covered in existing research.
- **Slack:** chat with the Agentic Assistant from Slack. The Slack email must match the Cortex user so RBAC is enforced [sourced: agentic-assistant-security URL].
- **MCP:** the Agentic Assistant can call third-party MCP servers and auto-generate actions from their tools (Feb 2026) [sourced: https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/february-2026/feature-enhancements/cortex-agentix-assistant].
- **Third-party AppSec ingestion:** Checkmarx, Snyk [sourced: above].

### Dashboards & reporting UX
- **Cloud Command Center widgets** (reimagined in Feb 2026) [sourced: Command Center reference URL; Feb 2026 highlights]:
  - Provider Health Summary (account counts and % health per CSP)
  - Asset Class Distribution
  - Active Threat Cases (by severity, with created-vs-resolved trend)
  - Posture Cases (by severity, with manual/automated remediation indicators)
  - Vulnerability Summary (critical/high, weaponized, fix-available counts)
  - Top Risky Vulnerabilities (sorted by CVSS + EPSS, with impacted asset count)
  - Compliance Summary
  - Standards Status
  - Deep links: "Manage Vulnerabilities", "View Compliance Center"
- **Other command centers:** an ASPM Command Center and the Code-to-Cloud Coverage dashboard [sourced: 2.0 blog; 2.2 blog].
- **Cortex Agentic Assistant dashboard:** exists in the Command Center reference [sourced: sitemap entry dashboard-reference/command-center-reference/cortex-agentic-assistant-dashboard].
- **SLA/MTTR:** vendor claims "90% reduction in MTTR (4 days to 1-2 hours)". No SLA widget was found in the docs [sourced: 2025 launch blog; inferred for the absence].

### AI assistant
- **Product names:** Cortex AgentiX, called the "Agentic Assistant" in the docs.
  - System agents plus custom agents. "Actions" wrap integration commands.
  - Agents Hub (manage/build agents, register actions, knowledge sources (preview), MCP integrations).
  - Automation Engineer Agent writes Python with the AgentiX Automation SDK (Feb 2026).
  - Case Investigation Agent.
  - Help Center agent.
  - NL -> XQL "create and run XQL queries", and NL query-and-visualize.
  - Gemini 3.5 Flash is listed as available in CA/DE regions (Sept 2026).
  [sourced: https://cortex-docs.paloaltonetworks.com/cortex-agentix/learn-about-cortex-agentix/key-components-and-concepts; Feb 2026 agentix-assistant RN; https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/september-6-2026]
- **Guardrails** [sourced: agentic-assistant-security URL]:
  - Agents run with the invoking user's RBAC/SBAC permissions.
  - Agents can only use the actions assigned to them.
  - Sensitive actions need explicit approval.
  - The plan view shows how input was interpreted, the planned steps, the actions used, and JSON artifacts.
  - All agent actions go to an audit dataset recording which agent, which action and which user.
  - Prompts are not used for training; data residency is per region.
- **Marketing claim:** "trained on 1.2 billion real-world responses" [sourced: seekingalpha 2.0 PR].
- **Other AI features:**
  - AI-generated case summaries.
  - "AI Prompts" tasks in playbooks, with prompt RBAC [sourced: cpm sitemap entries automation/ai-prompts*].

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- **Public API:** includes `/public_api/appsec/v1/...`, compliance-controls APIs and CIEM APIs [sourced: May 2026 highlights; https://cortex-docs.paloaltonetworks.com/cortex-cloud-api/compliance-controls/compliance-controls-overview].
- **Access control:**
  - RBAC permissions are granular per feature (for example Graph Search View vs View/Edit under Investigation & Response -> Search) [sourced: what-is-graph-search URL].
  - User scope / SBAC [sourced: sitemap manage-user-scope; AgentiX key components].
- **Onboarding:** Terraform/ARM onboarding at management-group/tenant scope for Azure [sourced: sitemap entries].
- **SSO / multi-tenant:** details not fetched [unknown].

### Unique "wow" features released 2025-2026
- **Graph-powered attack path detections** using AI pathfinding plus Unit 42 intel (2.2, July 2026) [sourced: 2.2 blog].
- **Code-to-Cloud Coverage dashboard:** shows *where lineage is missing* (untraced SDLC stage) with one-click onboarding calls to action [sourced: execute-remediation-workflows URL].
- **Supply Chain Attack Threat Center:** a news feed of compromised packages/tools with an automatic "am I affected" check [sourced: 2.2 blog].
- **Unused-permission checkup:** emits a right-sized policy as Terraform/CFN/JSON [sourced: least-privilege URL].
- **Audit-ready evidence framework** for SOC 2/PCI/HIPAA [sourced: May 2026 highlights].
- **CDR agent performance mode:** -50% resources, toggled without reinstalling [sourced: 2.0 blog].
- **MCP client in the agent platform**, with auto-generated actions [sourced: Feb 2026 AgentiX RN].
- **AI dataset security for S3 Vectors/Bedrock**, and DSPM for SaaS including Claude [sourced: July 2026 highlights].

### Documented weaknesses/complaints
- False positives: "I notice multiple false positives, which is one weakness I found." (IT Engineer, DXC, 2026-06-30, PeerSpot) [sourced: https://www.peerspot.com/questions/what-needs-improvement-with-prisma-cloud-by-palo-alto-networks-147313].
- Cost: "The cost of Prisma Cloud by Palo Alto Networks is too high." (Principal Cloud Architect, 2025-04-10, PeerSpot) [sourced: same].
- Slow policy changes: "It takes time to implement a policy...it takes 20 to 30 minutes even for a small change." (Network & Security Engineer, 2024-04, PeerSpot) [sourced: same].
- Inconsistent UI across modules: "The Application Security dashboard was not as user-friendly as the Cloud Security dashboard." (2024-09, PeerSpot) [sourced: same].
- Integration gaps: "they integrate with some and not with others." (2026-02-23, PeerSpot) [sourced: same].
- RQL is hard to use: "RQL not intuitive" / "RQL language is still not very flexible" (review aggregators) [sourced: https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-reviews; https://www.cybersectool.com/tools/prisma-cloud].
- Third-party assessment: "The highest operational complexity of the three major CNAPPs" and "an opaque pricing grid" [sourced: https://distribuee.com/en/insights/prisma-cloud-cortex-cloud-smb-cnapp/].
- Alert volume: Gartner reportedly notes higher alert volume than Wiz/Orca for some customers. This is second-hand, via an aggregator [sourced: https://research.aimultiple.com/prisma-cloud-alternatives/].

### Sources
- https://investors.paloaltonetworks.com/news-releases/news-release-details/palo-alto-networks-introduces-cortex-cloud-future-real-time
- https://www.paloaltonetworks.com/blog/2025/02/announcing-innovations-cortex-cloud
- https://www.paloaltonetworks.com/blog/cloud-security/cloud-security-platform-cortex-cloud-2-0/
- https://seekingalpha.com/pr/20282604-palo-alto-networks-ushers-in-autonomous-ai-workforce-for-cloud-security-with-cortex-cloud-2_0
- https://www.paloaltonetworks.com/blog/?p=358043 (Cortex Cloud 2.1)
- https://www.paloaltonetworks.com/blog/cloud-security/cortex-cloud-2-2/
- https://cortex-docs.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Runtime-Security-Documentation/Understand-license-plans
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/february-2026/release-highlights
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/may-2026/release-highlights
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/july-2026/release-highlights
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/february-2026/feature-enhancements/cortex-agentix-assistant
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security-rn/cortex-cloud-runtime-security-release-information/features-introduced-in-2026-cloud/february-2026/feature-enhancements/cspm
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/dashboards-and-reports/monitor-dashboards-and-reports/dashboard-reference/command-center-reference/cortex-cloud-command-center
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/vunerability-management/cortex-vulnerability-risk-score
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/graph-search/what-is-graph-search
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/graph-search/how-to-build-graph-search-queries
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/rules-and-policies/cloud-security-rules-and-policies/create-and-manage-cloud-security-rules/create-an-attack-path-rule
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cortex-cloud-identity-security/achieve-the-principle-of-least-privilege-access
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/get-started/agentic-ai-in-cortex-cloud/agentic-assistant-security
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cases-and-issues/overview-of-cases/resolving-cases-with-ai
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/asset-managment/manage-asset-scores
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/cases-and-issues/case-concepts/case-scoring
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/code-to-cloud/code-to-cloud/execute-remediation-workflows
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/compliance/monitor-and-track-compliance-adherence/choose-compliance-standards-from-the-compliance-catalog/standards-catalog
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/vunerability-management/investigate-and-remediate-vulnerabilities
- https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/cortex-data-security/what-is-cortex-cloud-data-security
- https://cortex-docs.paloaltonetworks.com/cortex-xsiam/cloud-security/cortex-cloud-data-classification
- https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/asset-management/query-the-asset-inventory-via-xql
- https://cortex-docs.paloaltonetworks.com/cortex-agentix/learn-about-cortex-agentix/key-components-and-concepts
- https://cortex-docs.paloaltonetworks.com/xsiam-api/cloud-infrastructure-entitlement-management-ciem/ciem
- https://aws.amazon.com/marketplace/pp/prodview-fhoptf6o4hcyu
- https://distribuee.com/en/insights/prisma-cloud-cortex-cloud-smb-cnapp/
- https://www.peerspot.com/questions/what-needs-improvement-with-prisma-cloud-by-palo-alto-networks-147313
- https://work-management.org/network-security/cortex-cloud-review/

---

## Lacework -> Fortinet FortiCNAPP

### Positioning & pricing model
- **Acquisition:** Fortinet completed the Lacework acquisition on **2024-08-01**. It brought 225 patents and applications. The product is now "FortiCNAPP" (docs still say "Lacework FortiCNAPP"), tied into the Fortinet Security Fabric [sourced: https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2024/fortinet-completes-acquisition-of-lacework].
- **Ordering Guide (rev. 2026-08-19): two independently purchasable parts**, "Cloud Security Platform" and "Code Security" [sourced: https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/og-forticnapp.pdf].
  - **Primary model: resource-based "Risk & Threat" license.** All capabilities are included, and it is the only model eligible for discounts.
    - SKU `FC1-10-CNAPP-1334-02-DD` covers 250-2,499 resources (MOQ 250).
    - FC2 covers 2,500-4,999; FC3 covers 5,000+.
  - **Retention add-on:** `...-1338` extends retention to 180 days (default 90).
  - **DSPM add-on:** `FC1-10-DSPM-1407` sells DSPM by protected data capacity, per 1 TB.
  - **FortiDAST add-on:** 5 apps.
  - **Legacy per-vCPU tiers** (renewals only): Standard (MOQ 500 vCPU), Professional (MOQ 375), Enterprise (MOQ 250). DSPM and AWLS are excluded from the vCPU count.
  - **Code Security:** priced per code-contributing developer (MOQ 20), with one DAST app per developer included [sourced: https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/forticnapp.pdf].
  - **Channels:** AWS Marketplace and Google Cloud Marketplace.
  - **List prices:** not public in either document [sourced: same].
- **Legacy tier feature matrix** [sourced: Ordering Guide]:
  - Standard lacks IaC, CIEM, attack path, runtime FIM, and DSPM classification.
  - Attack Path Analysis ("Exposure Polygraph") needs Professional or above.

### Deployment
- **Hybrid model:** "combined agentless and agent-based approach". Agentless covers the multicloud inventory plus CSP logs (CloudTrail / Azure Activity / GCP Audit). The agent collects compute telemetry [sourced: forticnapp.pdf].
- **Clouds:** AWS, Azure, GCP, plus OCI integration [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide (TOC: "Integrate OCI Manually")]. Kubernetes support covers EKS/GKE audit logs, node/cluster collectors, and a Helm/Terraform compliance integration [sourced: admin guide TOC].
- **Agentless Workload Scanning (AWLS)** scans vulnerabilities and secrets across hosts and container images. It can be onboarded org-wide, and Windows is supported [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/849196/agentless-workload-scanning-overview].
  - An **Agentless dashboard** (Aug 2026) has Accounts and Resources tabs, showing per-host/container scan success and the *reason* a scan failed [sourced: https://docs.fortinet.com/document/forticnapp/latest/release-notes/499403/august-2026-platform-releases].
- **Agents:** Linux agent 8.4.0 (2026-09-01) and a Windows agent [sourced: https://docs.fortinet.com/document/forticnapp/latest/release-notes].
- **Onboarding UX:** onboarding uses Terraform, CloudFormation, Control Tower or the CLI.
  - The "Automated Configuration" workflow (Aug 2026) adds pre-flight checks, deployment status and **rollback**.
  - "Cloud account rollback and deployment history" (July 2026) lets Delete on an integration undo the changes it deployed [sourced: Aug and July 2026 RN].
  - [July 2026 RN: https://docs.fortinet.com/document/forticnapp/latest/release-notes/163169/july-2026-platform-releases]

### Inventory & graph
- **LQL (Lacework Query Language)** [sourced: https://docs.fortinet.com/document/forticnapp/latest/lql-reference/598361/lql-overview]:
  - SQL-like, with `{ source { DATASOURCE } filter { ... } return distinct { ... } }`.
  - Types: String, Timestamp, Number, Json, Boolean, Null.
  - JSON path access, e.g. `RESOURCE_CONFIG:EbsEncryptionByDefault`.
  - 72,000-character limit.
  - Datasources are named like `LW_CFG_AWS_IAM_USERS`.
  - Query types: single datasource, join (`source { A a with B b }`), and semi-join (`in`/`not in` a sub-query) [sourced: https://docs.fortinet.com/document/forticnapp/latest/lql-reference/842922/query-types].
  - LQL queries back policies that alert.
- **Explorer** is a graph inventory with a guided "QBL" builder, saved queries, an Explorer graph and an Explorer risk score [sourced: admin guide TOC].
  - **Natural-language search (June 2026)** [sourced: https://docs.fortinet.com/document/forticnapp/latest/release-notes/794745/june-2026-platform-releases]:
    - Phrases like "aws critical vulns" / "exposed mongodb" map keywords to filters (provider, severity, resource type, ports/services, CIDR) and show a filter preview with inferred values highlighted.
    - Pasted CVE IDs, IPs, CIDRs, ARNs and ports are auto-detected for one-click lookup.
    - Built on 4 templates: Vulns by Cloud & Severity; Hosts affected by CVE; Storage assets with compliance violations accessible by identities; High-risk hosts with open ports exposed to a CIDR.
  - **Query Catalog:** LQL and QBL queries live in one place [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/613114/unified-risk-management].
- **Data platform:** "Polygraph Data Platform". There is also a Snowflake data share and S3 data export [sourced: admin guide TOC].

### Attack paths & toxic combinations
- **Exposure Polygraph** = attack paths built from vulns, network reachability, secrets and IAM roles, using config, activity and runtime data [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/853651/attack-path-analysis].
  - **Requirements:** a config integration plus either an agent or AWLS.
  - **Refresh:** every 24h.
  - **Limits:** the AWS target must be EC2-backed (EC2/ECS/EKS); NACLs are ignored; IAM roles list only trust policies; Azure has no secrets detection.
- **Supported path templates** [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/151458/supported-attack-paths]:
  - Admin path: `Internet -> IGW -> SG -> Host -> IAM role (admin)`. Expansion stops at an admin role. SCPs are applied when available.
  - Non-admin path: `... -> EC2 -> IAM role -> S3 bucket cluster`, which needs GetObject and no blocking bucket policy.
  - Container images, data assets (RDS, S3, Azure Blob, Azure SQL/PostgreSQL, Cloud SQL) and hosts.
  - AWS supports **two-hop** paths; Azure and GCP are **single-hop** only.
  - "Clusters" of assets reachable through a role are FortiCNAPP-defined groupings.
- **Path risk** combines target asset type, the asset types along the path, and per-node risk scores. Impact ranking: Admin privilege > object storage > cloud DB > host/image/K8s service [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/659119/attack-path-risk-calculation].
- **UX:**
  - "Top Work Items", "Path Investigation" and "Top risky paths with admin privilege role" [sourced: admin guide TOC; https://docs.fortinet.com/document/forticnapp/latest/administration-guide/605450/top-identity-risks].
  - Alerts have an **Exposure** tab and an "Internet Exposure = yes/no/unknown" filter [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/812745/exposure-polygraph].
- **FortiGate in the graph (Mar 2026):**
  - FortiGates appear in the Explorer graph and attack paths.
  - Edge color shows whether a resource is FortiGate-protected.
  - It flags resources reachable via *alternate* paths that bypass the FortiGate.
  - Supported topologies: AWS TGW/HA, GCP HA, Azure single/Active-Passive [sourced: https://docs.fortinet.com/document/forticnapp/latest/release-notes/494868/march-2026-platform-releases].
- **Composite alerts:** see existing research; new 2026 details are under Detection.

### Risk prioritization
- **Explorer Risk Score** is 0-10, and severity bands are explicit [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/630805/explorer-risk-score]:
  - Critical 9.7-10.0, High 8.0-9.7, Medium 6.8-8.0, Low 2.0-6.8, None 0.0-2.0.
  - A resource's risk = the max risk of any attack or internet-reachable path it is on.
  - A **Factors** control shows 3 icons (Attack Path / Identities / Vulnerability) for the marginal contribution of each.
  - The **Risk Explainability dialog** shows up to 3 highest-risk paths, with per-node breakdowns and "View risk score details".
  - In Explorer an image is high-risk only if it is actually on an attack path; the Vulnerability page scores it in isolation.
  - No data means no score, rather than a zero.
- **Vulnerability risk score** (host/image/package/CVE) [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/903844/risk-score]:
  - Per-vulnerability exploit probability, weighted by active package or container status.
  - Combined as P(at least one exploit succeeds), reduced by internet-exposure status, ×10.
  - Factors: CVSS, known exploits, exploits in the wild, internet exposure, active packages, and prevalence.
  - Factors can be toggled ("Configure Risk Scores", preview).
- **Inline NGFW adjustment (Sept 2026):** if a FortiGate or other NGFW is inline on the exposure path, the workload score is reduced, with an explainability entry "inline NGFW protection adjustment" [sourced: https://docs.fortinet.com/document/forticnapp/latest/release-notes/959740/september-2026-platform-releases].
- **RiskWatch (Mar 2026):** runtime probes of binaries, libraries and processes, plus CVE data and network reachability, to prioritize exploitable runtime vulns. Shown in the **Agents > Probes** dashboard [sourced: March 2026 RN].
- **EPSS/KEV:** not explicitly named in the fetched docs [inferred: "known exploits / active exploits in the wild" covers similar ground].
- **Data sensitivity:** comes into the Risk Insights "Data impact" column when DSPM is enabled [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/28442/risk-center-insights-and-dspm].

### CIEM/identity
- **Top identity risks:** Identities -> Top identity risks shows each identity's overall severity (= its highest-severity open risk), with info icons explaining each risk, CSV export and saved views [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/605450/top-identity-risks].
- **Excessive Privilege Risk Remediation** [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/625353/excessive-privilege-risk-remediation]:
  - Remediation types: **Detach policy**, **Remove identity entitlements** (or add an explicit Deny), and **Remove policy entitlements**. Each is based on **180 days** of non-use.
  - Each remediation shows the entitlements removed as a count and percent (e.g. "Detach policy AdministratorAccess 361 (64.12%)").
  - Panels: Suggestion / Rationale / **Risk reduction** (before vs after table) / statement index pinpointing the offending policy statement / **Create ticket** (Jira).
- **Identity sources:** AWS, Azure, Google Cloud Identity/Workspace. Identity risk exceptions are supported. There is also a "CIEM critical identity risk" alert type [sourced: admin guide TOC; alerts-reference index].
- **JIT:** none found [inferred].

### DSPM
- **Status:** private preview as of March 2026 [sourced: March 2026 RN].
- **How it works** [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/80769/dspm]:
  - Uses an AWLS-like in-account architecture, deployed with Terraform modules `lacework/terraform-aws-dspm` and `lacework/terraform-azure-dspm`.
  - Scans S3 and Azure Blob.
  - **Full-text scan** of text, structured text and CSV files, plus zip/tar/gz contents, detected by MIME type. This is *not* sampling.
  - Detects credit card, IBAN/SWIFT, and PII (SSN variants, email, phone, DOB).
  - FortiGuard AV detects malware and ransomware.
  - Settings: regions, scan frequency, max file size, bucket selection.
  - The first scan runs within 1h; later scans are incremental (new or changed files). Results appear 3-24h later.
  - Data policies are pre-configured and **not editable/viewable** in this version.
- **Ordering Guide figure:** "40+ FortiGuard patterns for classification (PII, PCI, HIPAA)" [sourced: Ordering Guide].

### Vulnerability & secrets
- **Coverage:** host and container vulnerability scanning via agent, AWLS, inline scanner, registry, and on-demand image scans (Jan 2026). Base-image vulns arrived Feb 2026 [sourced: release notes index].
- **Open-source inline scanner:** `lacework-vulnerability-scanner` v0.29.0 on GitHub/Docker Hub [sourced: June 2026 RN].
- **New OS coverage (Sept 2026):**
  - Google COS (node-image-version semantics, OVAL feed refreshed every 8h).
  - Ubuntu 25.04-26.10, with a warning that findings will jump because previously missing data appears.
  - Earlier: AlmaLinux and Chainguard Wolfi (May 2026).
  [sourced: Sept 2026 RN; release notes index]
- **Software Packages scan API** (`POST /api/v2/Vulnerabilities/SoftwarePackages/scan`) moved to the unified evaluation engine in Sept 2026 [sourced: Sept 2026 RN].
- **Secrets:** AWLS detects secrets (SSH keys, API keys, passwords), logging metadata only, never the content [sourced: exposure-polygraph URL]. AI-vendor secret detection is in preview (Apr 2026) [sourced: release notes index].
- **SCA/SBOM:** SCA, SBOM, license risk, and lock-file generation when a repo has no lockfile (June 2026) [sourced: Ordering Guide; June 2026 RN].
- **Reachability:** "Detection of Vulnerable Code Execution" (runtime) [sourced: Ordering Guide], plus RiskWatch.

### Code-to-cloud / IaC
- **Code Security** [sourced: Aug 2026 RN; June 2026 RN]:
  - IaC, SCA, SAST (Windows too), secrets.
  - CI/CD with PR commenting on GitHub, GitLab, Bitbucket and Azure DevOps; Atlantis/Jenkins for IaC only.
  - Configuration lives in a **`codesec.yaml`** per-repo file that overrides the UI settings (global -> codespace -> repo).
- **IaC engine:** dynamic Terraform support (Feb 2026). tfsec policies were deprecated (Jan 2026) [sourced: release notes index].
- **Claude Code plug-in (GA Aug 2026)** [sourced: Aug 2026 RN]:
  - Setup via `/fortinet:cli-setup`.
  - Runs IaC+SCA scans inside Claude Code.
  - "Critical and high findings trigger Claude to fix issues without prompting".
  - Scans only files changed in the task; caches dependencies.
  - **Blocks the commit** on findings.
  - A Cursor IDE extension shipped in Mar 2026.
- **LLM Skills Scanner (public preview, June 2026):** SAST of `skill.md` agent-skill files for CWEs and "OWASP Agentic Skills (AST)" [sourced: June 2026 RN].
- **Code-to-cloud mapping:** no explicit lineage feature found [inferred].

### Remediation
- **Risk Insights (private preview):**
  - Insights are generated by **Explorer policies**, which are saved QBL queries turned into policies, max 40 active, producing insights within 24h [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/477600/creating-explorer-policies].
  - Categories: Compliance / Data exposure / Identity and access / Vulnerability [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/749416/risk-categories].
  - AI Assist gives tailored remediation [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/42129/risk-insights].
- **Remediation tickets:** select only findings with Detection status *Active*, edit the summary, and create the ticket via a Jira alert channel [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/508764/creating-remediation-tickets].
- **CIEM fixes:** remediation tickets from the excessive-privilege page (above).
- **Automated enforcement:** FortiGate tag-based enforcement via EventBridge + Lambda (`github.com/lacework/terraform-aws-fortigate-tagging`). Alerts tag workloads (tag key `fcnappalert`) so FortiGate policies can quarantine them [sourced: Sept 2026 RN].
- **Auto-remediation:** no general auto-remediation of cloud misconfigurations found [inferred].

### Compliance
- **Frameworks:** "hundreds of compliance policies" across built-in frameworks: SOC2, ISO 27001, HIPAA, HITRUST, PCI, NIST, FISMA, PII, CIS Benchmarks (AWS/GCP/Azure, plus K8s compliance). An exact framework count is not published [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/348624/managing-policy-frameworks; Ordering Guide].
- **Custom frameworks** (Governance -> Frameworks -> Add Framework):
  - Clone an existing framework, then add sections and policies, including custom LQL compliance policies.
  - Frameworks double as "burndown lists".
  - A report can contain only one cloud type [sourced: same].
- **Reports:**
  - Built from any framework, scoped by resource group or account and filtered by severity and status.
  - Delivered by email channel on a schedule; evaluated daily at 12 PM GMT by default.
  - PDF download; history kept for 90 days.
  - Daily config audit [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/789865/reports; forticnapp.pdf].
- **Exceptions:** compliance exceptions can be managed via the console, API and **Terraform** [sourced: admin guide TOC "Manage policy exceptions with Terraform"].

### Detection & response / real-time
- **Polygraph** (behavior baselines) and composite alerts are covered in existing research.
- **New: Polygraph v2 (GA July 2026)** [sourced: July 2026 RN]:
  - A "resource-aware graph neural network" that models identities, API actions, resources and source IPs.
  - Each anomaly carries its contributing relationships, rendered visually in the alert.
  - Categories: anomalous resource creation, data manipulation, discovery activity, resource deletion.
  - Feeds Incident Reports and AI Assist.
  - v1 keeps running alongside it.
- **Composite alert types** [sourced: https://docs.fortinet.com/document/forticnapp/latest/alerts-reference/986450/composite-alerts-reference]:
  - Potentially Compromised AWS Keys / Azure / GCP / Host / K8s (High).
  - "Suspicious Activity" variants (Medium).
  - Potential Penetration Test.
  - Tabs: Details (Description, Supporting Facts) and Observations (Primary Entities, **Intrusion Graph**, **Observation Timeline**).
- **Other 2026 detections:**
  - Low-latency EKS and GKE audit-log policy evaluation (May/June 2026).
  - "Anomalous cloud API discovery spikes" for compromised AWS keys (Apr 2026).
  - FortiGuard IoC feed with FortiGuard tags on alerts (June 2026).
  - Unified cloud activity page `/investigation/cloudActivity?provider=aws|azure|gcp` (June 2026).
  [sourced: release notes index; June 2026 RN]
- **Runtime:** FIM, snapshots, K8s admission control [sourced: Ordering Guide].

### Integrations & workflow
- **Ticketing:** Jira alert channel, plus "Security in Jira" (migrating to Atlassian Forge).
- **SIEM/observability:** ServiceNow store apps (Infra Vuln Response, Container Vuln Response, Config Compliance; recertified June 2026 for Yokohama/Zurich/Australia), Datadog, Slack, Splunk.
- **Cloud-native:** AWS Security Hub, GuardDuty, GCP Pub/Sub.
- **Fortinet Security Fabric:** FortiGate, FortiAnalyzer, FortiSIEM, FortiSOAR.
- **Data out:** Snowflake data share and S3 export.
[sourced: admin guide TOC; June 2026 RN; Ordering Guide FAQ]

### Dashboards & reporting UX
- **Alerts page** [sourced: Feb/Mar/June/July 2026 RN]:
  - Table view (Feb 2026) with CSV export, custom columns, 100 rows per page, and bulk actions.
  - Default sort by Severity, with Start Time always the secondary key (Mar 2026).
  - Alert frequency chart.
  - Grouping toggle: Severity / Category (Anomaly, Policy, Composite) / Sub-category (Application, Cloud Activity, File, Machine, User, Platform, K8s Activity, Registry, SystemCall, Host Vuln, Container Vuln, Threat Intel) (June 2026).
  - Click-to-filter on summary values (July 2026).
- **Navigation:** a split into **Threat Center** vs **Risk Center**, with Policy Manager categorized by threat vs risk (Aug 2026) [sourced: Aug 2026 RN].
- **Other dashboards:** Cloud Compliance, Vulnerabilities overview, Top items, Kubernetes, Agent coverage, Probes, Onboarding, and custom dashboard views [sourced: admin guide TOC].
- **Datasheet home screen:** an alert overview by severity, Compliance / Host vulnerability / Container vulnerability trend cards ("Risk change ±%"), and "Risk by resource groups" sparklines [sourced: forticnapp.pdf screenshot].
- **SLA/MTTR:** no SLA/MTTR widget found [inferred].

### AI assistant
- **FortiCNAPP AI Assist** [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/115781/forticnapp-ai-assist; Feb/Mar 2026 RN]:
  - Opt-in under Settings.
  - Quick actions: **Triage** (FP/TP verdict plus "score out of 10" for whether to act now), **Incident Report** (renamed from Summarize), and **Remediate**.
  - The summary structure is fixed across Composite, Policy and Anomaly alerts: what happened -> who/what is involved -> scope/impact -> next steps.
  - Remediation is "triage-first": verify and scope, then contain, eradicate, recover, harden.
- **Composite alert AI tabs (June 2026)** [sourced: June 2026 RN]:
  - **Incident Report** and **Remediation** tabs, generated on first open and streamed.
  - Cached, then auto-regenerated when the alert data changes.
  - Copy, export to **Markdown**, and an "Ask AI Assistant" follow-up.
- **API:** the `AiAssistants` API supports alert context (May 2026) [sourced: release notes index].
- **Guardrails:** there is an AI transparency appendix and a customer opt-in. No agentic write actions were found, so the assistant is advisory only [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/283047/appendix-b-ai-transparency-forticnapp-ai-assist; inferred for the absence].

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- **API, CLI, Terraform:** REST API v2 (docs moved to FNDN in Apr 2026), the Lacework CLI, and Terraform modules for integrations and exceptions [sourced: release notes index; admin guide TOC].
- **Multi-tenant:** Organizations are part of FortiCloud Organizations.
  - Max **100 accounts** per org.
  - Enrollment is **irreversible**.
  - Org admin / org user roles; resource groups scope access [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/68366/organization-overview].
- **Access control:** "FortiCloud integrated access control" vs legacy access control [sourced: https://docs.fortinet.com/document/forticnapp/latest/administration-guide/882573/access-control-and-authorization].
- **SSO:** SAML with Okta, Entra ID, Google Workspace and AWS [sourced: admin guide TOC].

### Unique "wow" features released 2025-2026
- **Polygraph v2:** GNN anomaly detection that explains itself with relationship graphs (July 2026) [sourced: July 2026 RN].
- **Inline-NGFW risk adjustment** with an explainability entry, and FortiGate edges in the attack-path graph that flag bypass paths (Mar/Sept 2026) [sourced: Mar/Sept 2026 RN].
- **AI Assist "Triage" verdict:** FP/TP with a 0-10 "act now" score [sourced: Mar 2026 RN].
- **Claude Code plug-in** that auto-fixes and blocks commits, plus an LLM skill.md scanner [sourced: Aug/June 2026 RN].
- **Integration rollback and deployment history**, plus an AWLS dashboard that shows *why* a resource wasn't scanned [sourced: July/Aug 2026 RN].
- **Explorer NL search** with an identifier-paste auto-lookup [sourced: June 2026 RN].

### Documented weaknesses/complaints
- Complex at the start: "the platform can feel complex at the start, especially for teams new to CNAP tooling" and "reporting and alert configuration might require time to tune properly" (Solutions Sales Specialist, 2026-06, PeerSpot) [sourced: https://www.peerspot.com/products/lacework-reviews].
- Clunky navigation: "navigating to certain details can feel clunky" (Client Manager, MLL Telecom, 2026-02, PeerSpot) [sourced: same].
- Vulnerability UI: "The vulnerability part is not systematically organized; it is all clumsy in the web UI" (Software Engineer, university, 2025-10, PeerSpot) [sourced: same].
- SIEM integrations: "Its integrations with third-party SIEMs can be better" (Cloud Security Director, Medallia, 2023-08, PeerSpot) [sourced: same].
- PeerSpot overall rating: 4.1/5 [sourced: same].
- Many headline 2025-26 features are **private preview** (DSPM, Unified risk management / Risk Insights, Explorer policies). Explorer policies are capped at 40, and a "Known Issues: data inconsistencies… incorrect insights" note appears in the docs [sourced: unified-risk-management URL; creating-explorer-policies URL].
- Attack path depth is limited: Azure and GCP paths are single-hop; AWS targets must be EC2-backed; paths refresh only every 24h [sourced: attack-path-analysis and supported-attack-paths URLs].

### Sources
- https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2024/fortinet-completes-acquisition-of-lacework
- https://www.fortinet.com/products/forticnapp
- https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/og-forticnapp.pdf
- https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/forticnapp.pdf
- https://docs.fortinet.com/document/forticnapp/latest/release-notes
- https://docs.fortinet.com/document/forticnapp/latest/release-notes/106112/february-2026-platform-releases
- https://docs.fortinet.com/document/forticnapp/latest/release-notes/494868/march-2026-platform-releases
- https://docs.fortinet.com/document/forticnapp/latest/release-notes/794745/june-2026-platform-releases
- https://docs.fortinet.com/document/forticnapp/latest/release-notes/163169/july-2026-platform-releases
- https://docs.fortinet.com/document/forticnapp/latest/release-notes/499403/august-2026-platform-releases
- https://docs.fortinet.com/document/forticnapp/latest/release-notes/959740/september-2026-platform-releases
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/853651/attack-path-analysis
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/151458/supported-attack-paths
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/659119/attack-path-risk-calculation
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/630805/explorer-risk-score
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/812745/exposure-polygraph
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/903844/risk-score
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/625353/excessive-privilege-risk-remediation
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/605450/top-identity-risks
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/613114/unified-risk-management
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/749416/risk-categories
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/42129/risk-insights
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/477600/creating-explorer-policies
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/508764/creating-remediation-tickets
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/115781/forticnapp-ai-assist
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/283047/appendix-b-ai-transparency-forticnapp-ai-assist
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/849196/agentless-workload-scanning-overview
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/80769/dspm
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/28442/risk-center-insights-and-dspm
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/348624/managing-policy-frameworks
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/789865/reports
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/68366/organization-overview
- https://docs.fortinet.com/document/forticnapp/latest/administration-guide/882573/access-control-and-authorization
- https://docs.fortinet.com/document/forticnapp/latest/lql-reference/598361/lql-overview
- https://docs.fortinet.com/document/forticnapp/latest/lql-reference/842922/query-types
- https://docs.fortinet.com/document/forticnapp/latest/alerts-reference/986450/composite-alerts-reference
- https://docs.fortinet.com/document/forticnapp/latest/alerts-reference/478734/composite-alerts
- https://www.peerspot.com/products/lacework-reviews

---

## CrowdStrike Falcon Cloud Security

### Positioning & pricing model
- Positioned as a "unified agent-based and agentless" CNAPP built on top of the Falcon EDR sensor and CrowdStrike threat intel. The current marketing claim is "281+ global adversaries" tracked [sourced: https://www.crowdstrike.com/en-us/platform/cloud-security/].
- Lineage: Falcon Horizon (CSPM) and Falcon Cloud Workload Protection were merged into "Falcon Cloud Security" [sourced: https://www.businesswire.com/news/home/20220427005358/en]. The ASPM came from the Bionic acquisition [sourced: https://www.sdxcentral.com/news/crowdstrike-buys-bionic-to-marry-app-security-and-cnapp-for-cloud-safety/]. AI security comes from the Pangea integration (Fall 2025 release) [sourced: https://www.crowdstrike.com/en-us/blog/crowdstrike-fall-2025-release-defines-agentic-soc-secures-ai-era].
- Published bundles (pricing page, with no prices shown) [sourced: https://www.crowdstrike.com/platform/cloud-security/pricing]:
  - **Proactive Security**: CSPM, DSPM, ASPM, AI-SPM, AI model scanning, CIEM, IaC scanning, cloud compliance insights, host vuln management.
  - **Cloud Detection and Response**: threat intel, CDR, workload runtime protection.
  - **CDR with Containers**: adds K8s protection.
  - **CDR with Managed Containers**: for EKS/AKS/GKE/Fargate-style managed containers.
  - **CNAPP**: Proactive Security plus CDR.
  - **CNAPP with Containers**.
- A 2024 Dell datasheet shows licensing as "RESERVE OR ON DEMAND" for Falcon Cloud Security and Falcon Cloud Security for Containers, and "ON DEMAND" only for Falcon for Managed Containers [sourced: https://www.delltechnologies.com/asset/en-us/solutions/business-solutions/technical-support/falcon-cloud-security-datasheet.pdf].
- **AWS Marketplace pay-as-you-go** and a **30-day free trial** for Falcon Cloud Security were announced around 2025-12 [sourced: https://www.streetinsider.com/Corporate+News/CrowdStrike+launches+pay-as-you-go+pricing+for+AWS+security+products/25679577.html; https://press.aboutamazon.com/aws/2025/12/crowdstrike-advances-next-gen-siem-and-cloud-security-access-on-aws-with-streamlined-onboarding-flexible-pricing-and-cost-efficient-data-access].
  - A search-engine snippet gave these rates: $0.023/hr per running host, $0.054/hr per K8s worker node, $0.01/hr per Fargate instance, and "$140–$280 per asset" for a CSPM add-on.
  - I could NOT verify these numbers on a listing page. Treat them as unverified.
  - The partner/PS listings I opened show only "custom pricing / request private offer" [sourced: https://aws.amazon.com/marketplace/pp/prodview-cjeuurzzkjtdc; https://aws.amazon.com/marketplace/pp/prodview-h22x647qpd67w].
- **Falcon Flex**: a pooled-credit enterprise licence that lets customers reallocate spend across endpoint, identity, cloud and SIEM.
  - It typically targets 2,000+ endpoints [sourced: https://www.redresscompliance.com/crowdstrike-falcon-licensing-guide.html].
  - It reportedly passed >$3.2B total contract value by late 2025 [sourced: https://cipherssecurity.com/crowdstrike-pricing-explained-2026/].
  - There is no public rate card [sourced: same].
  - "Flex for Services" extends the same model to services [sourced: https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-launches-flex-services-bringing-flexible].

### Deployment
- **Agentless (API) CSPM/CIEM** plus the **Falcon sensor** (the same single EDR agent) for CWP, runtime and NGAV/EDR on Windows, Linux, containers and serverless [sourced: Dell datasheet URL above].
- **Agentless snapshot scanning** finds vulns and installed apps where no agent can be installed. It started with AWS [sourced: Dell datasheet].
- **"One-Click XDR"**: agentless discovery finds workloads with no sensor and auto-deploys the Falcon agent to them [sourced: Dell datasheet].
- Clouds:
  - AWS, Azure and GCP are confirmed [sourced: Dell datasheet].
  - OCI is listed on the product page [sourced: https://www.crowdstrike.com/en-us/platform/cloud-security/].
- **Kubernetes Admission Controller** blocks misconfigured containers. It is marketed as working "without the need for complex Rego rules" [sourced: Dell datasheet].
- K8s misconfigurations, container drift detection and "lean OS and serverless containers" protection are only in the Containers SKUs [sourced: Dell datasheet].
- Registry integrations: ECR, ACR, GAR/GCR, Docker Hub, Docker Registry v2, JFrog Artifactory, Quay, OpenShift, Harbor, Nexus, GitLab, IBM Cloud, Oracle CR [sourced: Dell datasheet].
- **IaC**: "10+ IaC platforms" supported [sourced: Dell datasheet].
- 2026: the **Falcon Data Security for Cloud** early beta uses **eBPF** to watch sensitive data flowing through AI services, MCP servers and SageMaker at runtime [sourced: https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/].

### Inventory & graph
- **CrowdStrike Asset Graph** backs the cloud attack path visualisation ("host to cloud") [sourced: Dell datasheet].
- **CrowdStrike Enterprise Graph** (Fal.Con 2025) [sourced: https://www.crowdstrike.com/en-us/blog/crowdstrike-fall-2025-release-defines-agentic-soc-secures-ai-era]:
  - A unified data layer across endpoint, identity, cloud, SaaS, XIoT and third-party data.
  - Uses "a single query language built for AI".
  - The language itself is not named in the sources I reached. CrowdStrike's existing query language is CQL/LogScale [inferred].
- **Application Explorer** (GA as of 2026-03-24) maps business apps, their dependencies and the infra they run on, across cloud and on-prem [sourced: CNAPP blog URL above].
- **Third-Party App Insights** (blog dated 2026-10-05) [sourced: https://www.crowdstrike.com/en-us/blog/falcon-cloud-security-third-party-app-insights-ai-enhanced-remedation/]:
  - Code analysis detects integrations with external providers such as Stripe and PayPal.
  - It maps which API operations each app invokes.
  - Results appear in Application Explorer.
- **API data model** (as seen by the JupiterOne integration) [sourced: https://docs.jupiterone.io/integrations/directory/crowdstrike-fcs]:
  - Entities: `crowdstrike_cloud_account`, `crowdstrike_iom_finding`, `crowdstrike_iom_rule`, `crowdstrike_compliance_control`.
  - OAuth scopes: `cspm-registration:read`, `cloud-security-assets:read`, `cloud-security-detections:read`, `cloud-google-cloud-registration:read`.
- The CIEM brief supports "real-time point queries for incident response and broad analytical queries for security posture" [sourced: https://www.crowdstrike.com/wp-content/uploads/2024/02/crowdstrike-ciem-solution-brief.pdf].

### Attack paths & toxic combinations
- **"Complete Cloud Attack Path Visualization"** on the Asset Graph combines agent and agentless data into a single view from host to cloud [sourced: Dell datasheet].
- **Falcon Exposure Management "Client-side Attack Path Analysis"** "reveals how adversaries move from internet-exposed assets through internal systems and cloud workloads to reach sensitive data" [sourced: https://www.crowdstrike.com/en-us/blog/falcon-exposure-management-ai-driven-risk-prioritization-shows-what-to-fix-first].
- **Timeline Explorer** (beta, 2026) reconstructs how a cloud risk formed over time by linking config changes and app changes, which automates root-cause analysis [sourced: https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-industry-first-adversary-informed-cloud-risk-prioritization-to-stop-ai-powered-adversaries/].
- I did not find a public scoring formula for paths. CrowdStrike positions on adversary relevance rather than a 0–100 path score [inferred].

### Risk prioritization
- **Cloud Risk Engine / "Adversary Intelligence for Cloud Risks"** (announced 2026-03-24, beta) [sourced: CNAPP blog and press release URLs above]:
  - Maps each cloud risk detection against "more than 280 adversary groups" and the industries they target.
  - Examples given: LABYRINTH CHOLLIMA and SCATTERED SPIDER.
  - The aim is "proven exploitation rather than theoretical severity".
- **ExPRT.AI** vuln rating [sourced: Exposure Management blog URL above]:
  - Four tiers: Low / Medium / High / Critical.
  - Predicts the CVEs likely to be exploited, using real-time threat intel and AI models.
  - Enriched with cloud snapshots, container image scans, third-party vuln data and internal telemetry.
- **AI-powered Asset Criticality** [sourced: same]:
  - Three classes: Critical / High / Non-Critical.
  - Uses "firmographic, behavioral, and peer telemetry".
  - Two modes: "Falcon-recommended rules" (crowdsourced) or AI recommendations.
- **ASPM context on runtime detections** (2025-03-05) [sourced: https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-cloud-security-application-context-runtime-detections]:
  - Detections show the affected application(s), linkable ASPM violations and upstream/downstream dependencies.
  - Supported languages: Java, .NET, Node.js, Python, Go.
- I found no explicit EPSS or KEV fields in the public material. ExPRT.AI appears to replace them [inferred].

### CIEM/identity
- **"Identity Analyzer (CIEM)"** is included in Falcon Cloud Security and Falcon Cloud Security for Containers, but not in Managed Containers [sourced: Dell datasheet].
- Features [sourced: CIEM brief URL above]:
  - "IAM entitlement investigation", "streamlined remediations" and "pre-defined resource-based policies".
  - Monitoring of AWS IAM users, roles and permissions.
  - Monitoring of Entra ID users, groups and app registrations, including "potential abuse of secrets or certificates".
  - Detection of disabled MFA, excessive or unused permissions and suspicious permission escalations.
  - Per-resource/user/group/role audits of allowed actions.
- **"One-click auto remediation testing"** for CIEM fixes is called out by IDC [sourced: Dell datasheet quote; https://www.crowdstrike.com/blog/crowdstrike-extends-ciem-capabilities/].
- ITDR ties in via Falcon Identity: hybrid lateral movement and risk-based conditional access [sourced: CIEM brief].
- JIT access: no cloud-entitlement JIT found in public sources. The Fall '26 release mentions an "Agentic Identity Provider" [sourced: https://www.crowdstrike.com/en-gb/platform/quarterly-falcon-platform-release-highlights/], and its relation to cloud JIT is unknown.

### DSPM
- DSPM is listed in the Proactive Security bundle [sourced: pricing page]. CrowdStrike has a Gartner Peer Insights DSPM listing [sourced: https://www.gartner.com/reviews/market/data-security-posture-management/vendor/crowdstrike]. The DSPM originates from the Flow Security acquisition (2024) [inferred; not re-verified this session].
- Fall 2025 added "AI-Powered Classifications" that use LLMs to identify sensitive data types, plus GenAI data-flow protection [sourced: Fall 2025 release blog].
- 2026: **Falcon Data Security for Cloud** (early beta) gives eBPF runtime visibility of sensitive data moving through AI orchestration layers, MCP servers and SageMaker [sourced: CNAPP blog].
- Sampling approach: not public.

### Vulnerability & secrets
- Agentless snapshot scanning starts with AWS. Vulns and installed apps also come from the sensor [sourced: Dell datasheet].
- Image assessment via CI/CD, image assessment policies, and registry scanning [sourced: Dell datasheet].
- "Image and function assessment", "host vulnerability management" and "AI model scanning" are in Proactive Security, and SBOM is listed on the product page [sourced: pricing page; product page].
- Reachability: ASPM maps vulnerabilities to running applications (Java, .NET, Node.js, Python, Go) [sourced: ASPM runtime blog]. No explicit "reachable function" claim was found.
- Secrets scanning: not found in the sources reached [unknown].

### Code-to-cloud / IaC
- IaC scanning covers "10+ IaC platforms" [sourced: Dell datasheet].
- ASPM (from Bionic) discovers app services, APIs, data flows and third parties agentlessly [sourced: https://itdigest.com/cloud-computing-mobility/crowdstrike-to-acquire-bionic-to-extend-cloud-security-leadership-with-industrys-most-complete-code-to-runtime-cybersecurity-platform/].
- Third-Party App Insights uses application code analysis to map external API calls [sourced: Third-Party App Insights blog].
- Automatic PR fixes: not found. PeerSpot reviewers ask for better "automatic alerting with CI/CD scanning" [sourced: https://www.peerspot.com/products/crowdstrike-falcon-cloud-security-reviews].

### Remediation
- **AI-Enhanced Remediation** plans (2026-10-05) [sourced: Third-Party App Insights blog]. Each plan contains:
  - A risk summary of how attackers exploit the issue, and the threat actor when CrowdStrike has observed one.
  - An urgency level.
  - Steps ordered by risk reduction.
  - Time estimates and confidence indicators.
  - Console or CLI fix instructions.
  - The **permissions required** for each action.
  - **Validation checks** that confirm the risk went down.
  - **Compensating controls** to use when the permanent fix needs downtime.
  - Steps can be run through **Charlotte Agentic SOAR** workflows.
- Falcon Fusion (SOAR) workflows have automated AWS remediations since 2022 [sourced: https://www.businesswire.com/news/home/20220427005358/en].
- Falcon for IT "Risk-based Patching" with "patch safety scores" [sourced: Fall 2025 release blog].
- The partner Tamnoon pitches itself as filling a gap: Falcon "shows organizations what needs fixing, but doesn't handle the heavy lifting of actual remediation" [sourced: https://tamnoon.io/blog/better-together-how-crowdstrike-and-tamnoon-close-the-last-mile-of-cloud-security/].

### Compliance
- One **Compliance Dashboard** covers NIST, SOC2, PCI and CIS, with drill-down for audits and coverage of both cloud and endpoint [sourced: Dell datasheet].
- "Cloud compliance insights" are in Proactive Security [sourced: pricing page].
- The API exposes `crowdstrike_compliance_control` entities linked to IOM rules [sourced: JupiterOne doc].
- Total framework count and custom-framework support: not found publicly [unknown].
- Older figure: "over 250 out-of-the-box adversary-focused policies" (Horizon era) [sourced: https://www.businesswire.com/news/home/20211103005471/en; date is old].

### Detection & response / real-time
- **Cloud IOAs** ("Behavioral Indicators of Attack for cloud") are drawn from adversary intel and run alongside **IOMs** [sourced: Dell datasheet].
- **Unified Real-Time CDR**: "isolating compromised workloads and blocking malicious behavior in real time" [sourced: 2026-03 press release].
- Runtime is the Falcon sensor (NGAV/EDR), plus container drift detection [sourced: Dell datasheet].
- 24/7 cloud MDR and cloud threat hunting services (Falcon Complete) [sourced: Dell datasheet].
- Fall '26: blocks malicious npm and PyPI packages on endpoints before execution [sourced: quarterly release highlights].

### Integrations & workflow
- Falcon Fusion / Charlotte Agentic SOAR [sourced: Third-Party App Insights blog].
- Falcon Next-Gen SIEM streams vuln data in real time [sourced: Exposure Management blog].
- AWS onboarding pulls CloudTrail, Security Hub and GuardDuty [sourced: https://www.crowdstrike.com/en-us/blog/transform-aws-security-operations-with-falcon-next-gen-siem/ (via search snippet)].
- **Agentic gateway** (Fal.Con 2025): a bidirectional interface for Charlotte AI to reach third-party data. Partners include ServiceNow, Zscaler, Google, Salesforce, Proofpoint, Abnormal, Corelight, ExtraHop, GreyNoise and Rubrik [sourced: https://securitybrief.co.nz/story/crowdstrike-unveils-ai-powered-agents-to-automate-security-tasks].
- Specific Jira/ServiceNow bidirectional sync for cloud findings: not confirmed [unknown].

### Dashboards & reporting UX
- Common cloud activity dashboard (Horizon + CWP) [sourced: 2022 BusinessWire].
- Compliance dashboard [sourced: Dell datasheet].
- Entra ID dashboards [sourced: CIEM brief].
- Falcon platform "CISO-ready executive reports" [sourced: https://www.crowdstrike.com/en-us/blog/how-falcon-platform-delivers-fast-ciso-ready-executive-reports/ (title only)].
- MTTR/SLA widgets: not found [unknown].
- A PeerSpot reviewer: "menus in CrowdStrike Falcon Cloud Security are a little confusing" [sourced: PeerSpot URL above].

### AI assistant
- **Charlotte AI**, with **Charlotte AI AgentWorks** (no-code agent builder) [sourced: Fall 2025 release blog]. Seven "mission-ready" agents:
  - Exposure Prioritization
  - Malware Analysis
  - Hunt
  - Correlation Rule Generation
  - Search Analysis
  - Workflow Generation (NL to workflow)
  - Data Transformation
- Agents are "trained on millions of expert decisions from Falcon Complete Next-Gen MDR" [sourced: same].
- In cloud, AI produces the remediation plans with confidence indicators [sourced: Third-Party App Insights blog].
- Guardrails: Pangea-based prompt-injection blocking and AI guardrails for the AI that customers build [sourced: Fall 2025 blog]. Guardrails on Charlotte itself are not detailed in the sources reached [unknown].

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- OAuth2 API clients with granular scopes, e.g. `cspm-registration:read` and `cloud-security-detections:read` [sourced: JupiterOne doc].
- CLI-based fix instructions appear in AI remediation plans [sourced: Third-Party App Insights blog].
- Multi-tenant via Falcon Flight Control (MSSP/parent-child CIDs) [inferred; not verified this session].
- Terraform provider, RBAC and SSO details were not verified this session [unknown].

### Unique "wow" features released 2025-2026
- **Adversary-informed Cloud Risk Engine**: each cloud risk is tagged with the named threat-actor groups that use that technique and that target your industry (2026-03) [sourced: 2026-03 CNAPP blog].
- **Timeline Explorer**: a chronological reconstruction of how a cloud risk formed, used for automated root cause (2026-03) [sourced: same].
- **Application Explorer** plus **Third-Party App Insights**: app-centric views showing dependencies and which external SaaS APIs (e.g. Stripe or PayPal operations) each app calls (2026-03 / 2026-10) [sourced: same; Third-Party App Insights blog].
- **AI-Enhanced Remediation plans** that include required IAM permissions, validation checks and compensating controls (2026-10) [sourced: Third-Party App Insights blog].
- **Falcon Data Security for Cloud**: eBPF tracking of sensitive data through MCP servers and AI pipelines (beta, 2026) [sourced: 2026-03 CNAPP blog].
- **Charlotte AI AgentWorks** plus the agentic gateway (Fal.Con 2025) [sourced: Fall 2025 blog].

### Documented weaknesses/complaints
- Price:
  - "it is a little expensive. CrowdStrike Falcon Cloud Security is on the higher side" (Senior DevOps Engineer, PeerSpot) [sourced: https://www.peerspot.com/products/crowdstrike-falcon-cloud-security-reviews].
  - "its cost drives some to alternatives" (Security Specialist, PeerSpot) [sourced: same].
- UX: "menus in CrowdStrike Falcon Cloud Security are a little confusing" (Cyber Security Engineer, insurance, PeerSpot) [sourced: same].
- Containers: the "implementation process for container security is an issue" (PeerSpot) [sourced: same].
- Linux: detection is weak and needs custom rules (Senior Engineer, Frontdoor, PeerSpot; paraphrased by the fetch tool) [sourced: same].
- Requested features: "automatic alerting with CI/CD scanning" and "Falcon sensor health monitoring" [sourced: same].
- Remediation: the partner says Falcon "doesn't handle the heavy lifting of actual remediation" [sourced: Tamnoon URL].
- Many 2026 features (Adversary Intelligence, Timeline Explorer, Data Security for Cloud) were still beta at announcement [sourced: 2026-03 CNAPP blog].
- Ratings: Gartner Peer Insights CSPM rating 4.6/5 (search snippet) [sourced: https://www.gartner.com/reviews/market/cloud-security-posture-management-tools/vendor/crowdstrike]. CrowdStrike was named 2026 Customers' Choice for ASPM [sourced: https://www.businesswire.com/news/home/20260202380434/en (snippet)].

### Sources
- https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-industry-first-adversary-informed-cloud-risk-prioritization-to-stop-ai-powered-adversaries/
- https://www.crowdstrike.com/en-us/blog/falcon-cloud-security-third-party-app-insights-ai-enhanced-remedation/
- https://www.crowdstrike.com/en-us/blog/crowdstrike-falcon-cloud-security-application-context-runtime-detections
- https://www.crowdstrike.com/en-us/blog/crowdstrike-fall-2025-release-defines-agentic-soc-secures-ai-era
- https://www.crowdstrike.com/en-us/blog/falcon-exposure-management-ai-driven-risk-prioritization-shows-what-to-fix-first
- https://www.crowdstrike.com/en-us/platform/cloud-security/
- https://www.crowdstrike.com/platform/cloud-security/pricing
- https://www.crowdstrike.com/en-gb/platform/quarterly-falcon-platform-release-highlights/
- https://www.crowdstrike.com/wp-content/uploads/2024/02/crowdstrike-ciem-solution-brief.pdf
- https://www.crowdstrike.com/products/cloud-security/cloud-infrastructure-entitlement-management-ciem-features/
- https://www.delltechnologies.com/asset/en-us/solutions/business-solutions/technical-support/falcon-cloud-security-datasheet.pdf
- https://docs.jupiterone.io/integrations/directory/crowdstrike-fcs
- https://www.businesswire.com/news/home/20220427005358/en
- https://press.aboutamazon.com/aws/2025/12/crowdstrike-advances-next-gen-siem-and-cloud-security-access-on-aws-with-streamlined-onboarding-flexible-pricing-and-cost-efficient-data-access
- https://www.streetinsider.com/Corporate+News/CrowdStrike+launches+pay-as-you-go+pricing+for+AWS+security+products/25679577.html
- https://aws.amazon.com/marketplace/pp/prodview-cjeuurzzkjtdc
- https://aws.amazon.com/marketplace/pp/prodview-h22x647qpd67w
- https://www.redresscompliance.com/crowdstrike-falcon-licensing-guide.html
- https://cipherssecurity.com/crowdstrike-pricing-explained-2026/
- https://securitybrief.co.nz/story/crowdstrike-unveils-ai-powered-agents-to-automate-security-tasks
- https://www.sdxcentral.com/news/crowdstrike-buys-bionic-to-marry-app-security-and-cnapp-for-cloud-safety/
- https://tamnoon.io/blog/better-together-how-crowdstrike-and-tamnoon-close-the-last-mile-of-cloud-security/
- https://www.peerspot.com/products/crowdstrike-falcon-cloud-security-reviews

---

## SentinelOne Singularity Cloud Security

### Positioning & pricing model
- **PingSafe** was acquired in **February 2024** and became **Singularity Cloud Native Security (CNS)**, an agentless CNAPP. It was launched on 2024-05-08 with the **Offensive Security Engine** and **Verified Exploit Paths** [sourced: https://www.sentinelone.com/press/sentinelone-redefines-cloud-security/].
- Three products under "Singularity Cloud Security" [sourced: https://www.sentinelone.com/platform/cloud-security/]:
  - **Cloud Native Security**: agentless CSPM, KSPM, CIEM, IaC, secrets, AI-SPM, offensive engine.
  - **Cloud Workload Security**: an eBPF agent.
  - **Cloud Data Security**: malware scanning of storage.
- Related acquisitions:
  - **Prompt Security**, announced 2025-08-05 (CRN). It is now used for shadow-AI and agent/MCP governance [sourced: https://www.sentinelone.com/press/; https://www.sentinelone.com/blog/from-input-to-impact-secure-ai-where-it-runs/].
  - Observo AI (2025) is also commonly reported [inferred; not verified this session].
- **AWS Marketplace "Singularity Cloud Security – AI Powered CNAPP"** [sourced: https://aws.amazon.com/marketplace/pp/prodview-xsottodkjfawi]:
  - Contract-based pricing with 12/24/36-month terms.
  - The example 12-month contract dimension is **$20,000**; everything else is "pricing agreed based on your needs".
  - Free trial; listing rating 4.6/5 from 261 reviews.
- Public pricing page: endpoint tiers are Singularity Complete at $179.99/endpoint/yr and Commercial at $229.99, with CWPP included. There is no separate CNS price [sourced: https://www.sentinelone.com/pricing/].
- Claims "Only CNAPP product to earn a 4.9 out of 5 rating on G2" [sourced: https://www.sentinelone.com/platform/cloud-security/].

### Deployment
- **CNS** is agentless and API-based. It covers AWS, Azure, GCP "and many other cloud environments" and scans repositories, IaC templates and container images [sourced: https://www.sentinelone.com/platform/singularity-cloud-native-security/].
- **Kubernetes admission controller** prevents vulnerable deployments [sourced: same].
- **Cloud Workload Security** [sourced: https://www.sentinelone.com/platform/singularity-cloud-workload-security/]:
  - An **eBPF-based** agent ("reduces kernel dependency risk").
  - Platforms: Linux, Windows, K8s.
  - Workloads: servers/VMs, containers, CaaS, serverless, AI workloads.
  - Environments: AWS/Azure/GCP and private cloud.
- **Cloud Data Security** scans files on ingest [sourced: https://www.sentinelone.com/platform/singularity-cloud-data-security/]:
  - Cloud storage: S3, Azure Blob, GCS.
  - On-prem NAS: NetApp ONTAP, Dell, Hitachi, Pure, and ICAP.
- AWS integrations: CloudTrail, Security Hub, AWS Config, GuardDuty [sourced: AWS Marketplace listing].

### Inventory & graph
- Unified asset inventory and attack-path analysis "show how misconfigurations, excessive permissions, and vulnerabilities interconnect" [sourced: CNS page].
- The graph query language and data model are not public in the sources reached [unknown].
- Telemetry lands in the **Singularity Data Lake**, normalised to **OCSF**, and is queried via **PowerQuery** or Purple AI natural language [sourced: https://www.sentinelone.com/platform/purple/; PowerQuery name is inferred].

### Attack paths & toxic combinations
- The **Offensive Security Engine™** "safely simulates attacker methods to provide false positive-free insights into what assets in a cloud environment are verified to be exploitable" [sourced: 2024 press release]. It "mimic[s] a real outside attacker in order to validate which exposures are truly exploitable" [sourced: CNS page].
- **Verified Exploit Paths™** are a "prioritized, evidence-based list of exploit pathways" from initial access to sensitive data [sourced: 2024 press release; CNS page].
- UX example [sourced: CNS page]:
  - An issue titled "Critical git objects directory is publicly accessible".
  - **"Exploit Evidence"** and **"Finding"** tabs.
  - In other words, every verified issue carries the attacker-side proof, e.g. the HTTP response that shows exposure.
- Probe technique (how the probing is done, and its rate limits): not documented publicly. Probing appears limited to internet-facing assets [inferred].
- Secrets are "validated" for active use, not just pattern-matched [sourced: CNS page: "850+ secret types to validate active usage"].

### Risk prioritization
- Primary signal: verified exploitability. The pitch is "proof of exploitability with each alert" [sourced: https://www.sentinelone.com/blog/prioritizing-cves-in-the-cloud/].
- The blog's guest author argues for EPSS, CISA KEV and CWE class, with SSRF (CWE-918) weighted up for cloud [sourced: same]. Whether these appear as fields in the product UI was not confirmed [inferred].
- Severity scale and scoring formula: not public [unknown].
- Explainability: Purple AI produces "explainable attack stories" and a "Verdict Justification" for each AI decision [sourced: CNS page; Purple page].

### CIEM/identity
- CIEM for "identity and excessive permissions" is included in CNS [sourced: CNS page; AWS Marketplace listing].
- Automated fixes include "2FA enforcement, permission changes" [sourced: https://www.sentinelone.com/blog/sentinelone-sets-a-new-standard-truly-ai-driven-unified-cloud-security/].
- Wayfinder cloud hunting (2026-09-24) covers [sourced: https://www.sentinelone.com/press/sentinelone-extends-wayfinder-threat-huntings-continuous-coverage-to-aws-azure-and-google-cloud/]:
  - IAM privilege escalation and IAM user enumeration.
  - Suspicious IAM policy changes.
  - Cross-tenant delegation changes.
  - AKS cluster-admin credential access.
- Non-human identity: "decoy credentials and honeytokens" validate access against runtime behaviour [sourced: Aug 2026 AI blog].
- Effective-permission computation and JIT: not documented in the sources reached [unknown].

### DSPM
- DSPM is listed in the CNS capabilities [sourced: CNS page; cloud-security page].
- Cloud Data Security is explicitly "complementary to DSPM". It does malware/zero-day scanning on ingest using a static AI engine trained on ">1B malware samples", with auto-quarantine [sourced: Cloud Data Security page].
- Classification and sampling methods: not disclosed [sourced: same].

### Vulnerability & secrets
- Secrets:
  - "850+ secret types" on the current page [sourced: CNS page].
  - "750+" on an older SEO page [sourced: https://www.sentinelone.com/cybersecurity-101/cloud-security/cnapp-vendors/].
  - Secrets are scanned in repos and validated for active use.
- Container image and IaC scanning, and admission control [sourced: CNS page].
- Agentless VM snapshot scanning is not explicitly described in the sources reached. Workload vulns probably come via the agent or CNS [inferred].
- SBOM and reachability: not found [unknown].

### Code-to-cloud / IaC
- Continuous IaC template scanning plus repository and secrets scanning for "shift-left" [sourced: CNS page; Apr 2025 blog].
- PR auto-fix and code-to-cloud tracing: not found [unknown].

### Remediation
- **Singularity Hyperautomation** [sourced: https://www.sentinelone.com/platform/singularity-hyperautomation/]:
  - A no-code workflow builder with "Snippets" (reusable sub-flows).
  - **160+ integrations** and **130+ templates**.
  - Triggers: "exposures from the platform", high-severity alerts, console activity, and "governed LLM actions that dynamically select appropriate Snippets".
  - **Approval gates** for high-impact actions.
- Cloud workflow templates; findings are routed "enriched with evidence, to issue tracking systems" [sourced: CNS page; Apr 2025 blog].
- Purple AI suggests next steps; automated responses run "only within pre-approved policies, with every action logged" [sourced: Purple page].

### Compliance
- **"2,000+ out-of-the-box checks"** [sourced: cnapp-vendors page].
- **Custom Compliance** (2025-10-16) [sourced: https://www.sentinelone.com/blog/custom-compliance-for-cloud-security/]:
  - Compliance dashboard, then "Create framework".
  - Hierarchy: controls, then sub-controls, then rules.
  - You can pull rules/controls from "more than 45 existing compliance frameworks like HIPAA, CIS, NIST", blend them, and add custom rules.
  - Ownership can be assigned by business unit or geography.
  - Reports are scheduled from the **Reports** page.
- The EU AI Act framework is supported [sourced: CNS page].

### Detection & response / real-time
- CNS includes "cloud detection/response" [sourced: AWS Marketplace listing].
- CWS runtime [sourced: CWS page]:
  - Detects ransomware, cryptomining, fileless attacks, container drift and lateral movement.
  - "Autonomous mitigation" with rollback.
  - **Storyline** links workload, endpoint and identity events.
- **Wayfinder Threat Hunting for AWS/Azure/GCP** (GA 2026-09-24) [sourced: Wayfinder press]:
  - A managed human-plus-AI hunting service on cloud control-plane telemetry.
  - Hunts include root login, S3 bucket reconnaissance, AMI deregistration and telemetry destruction.
- eBPF runtime for K8s AI inference services flags unauthorised outbound connections [sourced: Aug 2026 AI blog].

### Integrations & workflow
- Via Hyperautomation: Slack, Microsoft Teams, Jira, ServiceNow and "100+" (blog) / "160+" (current page) [sourced: Apr 2025 blog; Hyperautomation page].
- AWS Security Hub, Config, GuardDuty, CloudTrail [sourced: AWS Marketplace].
- Bidirectional ticket sync: not confirmed [unknown].

### Dashboards & reporting UX
- Compliance dashboard plus scheduled reports [sourced: Custom Compliance blog].
- A PeerSpot reviewer: "dashboards are not customizable...cannot create dashboards according to your understanding" (Software Developer) [sourced: https://www.peerspot.com/products/sentinelone-singularity-cloud-security-reviews].
- A CISO asked for "more customizable dashboards, deeper reporting capabilities, and broader integrations" [sourced: same].
- MTTR/SLA views: not found [unknown].

### AI assistant
- **Purple AI** [sourced: https://www.sentinelone.com/platform/purple/]:
  - Natural-language questions ("answers without writing a query").
  - Agentic auto-investigation and **Auto-Triage** using a **"Community Verdict"** trained on Wayfinder MDR decisions.
  - **Investigation Notebooks** and a **Purple AI MCP Server**.
  - Reasons over OCSF-normalised first- and third-party data.
- **Purple AI Auto-Investigation** for the agentic SOC (2026-09-11) [sourced: https://www.sentinelone.com/blog/the-soc-just-gained-a-capability-it-never-had/].
- Guardrails [sourced: Purple page]:
  - "Customer data is never used to train models".
  - A "Verdict Justification" on every AI decision.
  - Actions only within pre-approved policies, with logging.
  - FedRAMP High.
- In cloud, Purple AI produces "explainable attack stories" for CNS issues [sourced: CNS page].

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Singularity has a public management API and an MSSP-style Account/Site/Group tenancy hierarchy [inferred from general platform knowledge; not verified this session].
- The Purple AI MCP server exposes data and workflows to customers' own agents [sourced: Purple page].
- Terraform/IaC-as-config: not found [unknown].

### Unique "wow" features released 2025-2026
- **Custom Compliance builder** that blends controls from 45+ frameworks with custom rules (2025-10) [sourced: Custom Compliance blog].
- **Hyperautomation triggered by CNS exposures** with LLM-selected Snippets and approval gates (2025-2026) [sourced: Hyperautomation page].
- **Purple AI MCP Server** plus Auto-Triage "Community Verdict" (2025-2026) [sourced: Purple page].
- **Agent/MCP governance** from Prompt Security: inventories agents and MCP servers, scores their "access reach", and inspects tool calls at execution to block injected instructions (2026-08) [sourced: Aug 2026 AI blog].
- **Wayfinder cloud control-plane hunting** across AWS, Azure and GCP (2026-09) [sourced: Wayfinder press].
- Carry-over differentiator (2024): **Verified Exploit Paths** with an "Exploit Evidence" tab, and **validated secrets** (850+ types) [sourced: CNS page].

### Documented weaknesses/complaints
- Dashboards: "dashboards are not customizable" (Software Developer, PeerSpot) [sourced: https://www.peerspot.com/products/sentinelone-singularity-cloud-security-reviews].
- Documentation: "availability of the document on the internet is on a lesser side" (Security Engineer, PeerSpot) [sourced: same].
- False positives: "I'd like...reduced false positives" (SOC Analyst, PeerSpot) [sourced: same].
- Price: "somewhat on the expensive side" (CISO), "on the costlier side" (Director, DevOps) and "SentinelOne was at the higher price end" (Security Engineer) [sourced: same].
- Public material is thin on graph/query, CIEM effective permissions, DSPM classification, SBOM/reachability and PR fixes. The 2025-2026 marketing focus moved to the AI SOC (Purple AI, AI SIEM) and AI security (Prompt Security) [inferred from what the cloud blog category contains].

### Sources
- https://www.sentinelone.com/press/sentinelone-redefines-cloud-security/
- https://www.sentinelone.com/platform/singularity-cloud-native-security/
- https://www.sentinelone.com/platform/singularity-cloud-workload-security/
- https://www.sentinelone.com/platform/singularity-cloud-data-security/
- https://www.sentinelone.com/platform/cloud-security/
- https://www.sentinelone.com/platform/purple/
- https://www.sentinelone.com/platform/singularity-hyperautomation/
- https://www.sentinelone.com/pricing/
- https://www.sentinelone.com/press/
- https://www.sentinelone.com/press/sentinelone-extends-wayfinder-threat-huntings-continuous-coverage-to-aws-azure-and-google-cloud/
- https://www.sentinelone.com/blog/custom-compliance-for-cloud-security/
- https://www.sentinelone.com/blog/prioritizing-cves-in-the-cloud/
- https://www.sentinelone.com/blog/sentinelone-sets-a-new-standard-truly-ai-driven-unified-cloud-security/
- https://www.sentinelone.com/blog/the-soc-just-gained-a-capability-it-never-had/
- https://www.sentinelone.com/blog/from-input-to-impact-secure-ai-where-it-runs/
- https://www.sentinelone.com/blog/category/cloud/
- https://www.sentinelone.com/cybersecurity-101/cloud-security/cnapp-vendors/
- https://aws.amazon.com/marketplace/pp/prodview-xsottodkjfawi
- https://www.businesswire.com/news/home/20240508947114/en/SentinelOne-Redefines-Cloud-Security
- https://www.peerspot.com/products/sentinelone-singularity-cloud-security-reviews

---

## Sysdig Secure

### Positioning & pricing model
- Sysdig positions itself as a "runtime-powered CNAPP". Its argument is that "runtime wins". It is built on open-source Falco (200M+ downloads, "trusted by 60% of Fortune 500") [sourced: https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense]
- Named a Leader in the Forrester Wave: CNAPP Q1 2026. It was one of only 3 Leaders out of 14 vendors and one of 3 rated above average for customer feedback. Forrester cites "pricing flexibility and community strategies" as strengths. Roadmap items Forrester mentions: a "semantic attack graph", role-specific workflows, and connecting posture with vulnerability and runtime telemetry [sourced: https://www.sysdig.com/press-releases/sysdig-named-leader-forrester-wave-cnapp-2026]
- Leadership: Hatem Naguib was appointed CEO in June 2026 [sourced: search summary of Sysdig 2026 press, https://www.sysdig.com/press-releases/sysdig-named-leader-forrester-wave-cnapp-2026 listing context; exact PR URL not fetched — treat as partially verified]
- Licensing units on the public pricing page:
  - CNAPP is licensed per host. CSPM counts compute instances.
  - Detection and response is licensed per host, or "per events processed" for cloud logs.
  - Prices are quote-only.
  [sourced: https://sysdig.com/pricing/]
- **AWS Marketplace list prices** ("Sysdig Cloud Security and Observability") [sourced: https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc]:
  - **CNAPP Enterprise: $72/host/month**, minimum 20 units, 1-month contract. A 12-month contract saves "up to 17%".
  - Overage rates:
    - CNAPP Enterprise: $0.13 per host-hour
    - CNAPP CaaS (serverless): $0.03 per serverless host-hour
    - Secure D&R CaaS: $0.02 per host-hour
    - Cloud Logs events: $2.50 per event unit. The unit size is not stated; it is probably per million [inferred].
  - Monitor Enterprise: $36/host/month.
- Third-party estimates put tiers at "$20 (Essentials)–$90 (Premium) per host/month". These figures are unverified [sourced: https://cubeapm.com/blog/sysdig-pricing-review/]
- **Sysdig Secure AI** reached GA on **2026-08-04**. It is an AI-native offering on top of the CNAPP and comes in three modes:
  1. **Agentic AI**: agents build prioritized risk lists and deliver remediations.
  2. **Headless Cloud Security**: works inside AI coding agents.
  3. **GenAI Assistant**: formerly **Sysdig Sage**.
  Packaging and price are not public [sourced: https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense]

### Deployment
- Hybrid model. Agentless covers CSPM, CIEM and vulnerability scanning; the kernel-level agent covers runtime, using Falco with eBPF.
  - Marketplace listing: "Agentless CSPM across multi-account AWS environments" [sourced: https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc]
  - The pricing page lists both agent-based and agentless vulnerability scanning [sourced: https://sysdig.com/pricing/]
- Agentless scanning additions in 2026 [sourced: https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes]:
  - Windows, Fedora and AWS Bottlerocket hosts (2026-04-15)
  - LVM and multi-partition root volumes (2026-01-24)
  - AWS Lambda ZIP functions (2026-01-19)
  - "Onboarding: Optional Workload and Host Scanning" (2026-07-14)
- Clouds: compliance covers AWS, GCP, Azure and OCI [sourced: https://docs.sysdig.com/en/sysdig-secure/compliance/]. The Identity module covers AWS, GCP and Azure.
- Account onboarding is either the `sfc-cloudbench` role via Terraform or `SysdigComplianceAgentlessRole` via CloudFormation [sourced: https://docs.sysdig.com/en/sysdig-secure/identity/]
- Runtime "In Use" signal covers Kubernetes workloads, Linux hosts, and non-K8s containers (Docker, Podman) [sourced: https://docs.sysdig.com/en/sysdig-secure/risk-spotlight/]
- Runtime threat coverage on AWS: EKS, ECS and Fargate [sourced: https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc]
- IaC scanning covers YAML, Kustomize, Helm and Terraform for K8s workloads. PR checks work on GitHub, GitLab, Bitbucket and Azure DevOps [sourced: https://www.sysdig.com/integrations/github ; search summary]
- Agent component names (Sysdig Shield / host shield / cluster shield) were not verified in this session [inferred]

### Inventory & graph
- **SysQL** is a Cypher-inspired graph query language over the Sysdig Secure datastore, where inventory and findings live together.
  - Clauses: `MATCH`, `OPTIONAL MATCH` and `WHERE`.
  - Query categories: Risk, Posture and Vulnerabilities.
  - The UI view is "Search" over GraphDB, with saved and out-of-the-box queries.
  - There is also a SysQL API.
  [sourced: https://docs.sysdig.com/en/sysdig-secure/sysql-reference/ ; https://docs.sysdig.com/en/developer-tools/sysql-api/]
- "Simplified SysQL" provides a lower-friction syntax [sourced: https://docs.sysdig.com/en/docs/sysdig-secure/inventory/search/simplified-sysql]
- **Sysdig Sage for Search** turns natural language into SysQL [sourced: https://docs.sysdig.com/en/sysdig-sage/sage-for-search/]
- **SysQL Skill** (blog dated 2026-07-30) is natural-language graph querying from AI agents. It runs through the "Sysdig Secure MCP server with read access to the security graph". The demo chain was:
  1. "Find the vulnerabilities with a known exploit"
  2. "How many workloads are affected by CVE-X?" The answer traces the CVE through graph relationships: image → workloads → images on quay.io.
  3. "Should I fix this CVE? Look for an available fix"
  [sourced: https://www.sysdig.com/blog/introducing-the-sysql-skill-ask-your-security-graph-anything]
- Cloud inventory search supports queries such as "in-use instances of a critical vulnerability or roles with unused credentials" [sourced: https://siliconcanals.com/?p=33901]
- The 2026-03-31 navigation redesign groups the product into Threat Intelligence, **Graph Search**, Attack Surface, and Detection & Response [sourced: https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes]

### Attack paths & toxic combinations
- **Cloud Attack Graph** (launched 2023-09) is the correlation core. It layers instant detections, in-use vulnerabilities and in-use permissions [sourced: https://www.businesswire.com/news/home/20230927006401/en]
- **Risks page** (Attack Surface) works as follows:
  - **Risk definitions** are SysQL queries that correlate CSPM, KSPM, CIEM, VM and threat-detection findings.
  - A match produces a "Risk Finding" with one **anchor resource**.
  - Definitions are **Managed** (written by Sysdig) or **Custom** (user-created in the UI). This is effectively user-authored toxic-combination rules in a graph query language.
  [sourced: https://docs.sysdig.com/en/sysdig-secure/risks/]
- Finding categories that feed risks: Exposed, Vulnerability, Configuration, Identity, Detection, AI, Sensitive Data [sourced: same]
- Risk statuses: Open, In Progress, and Closed. Closed is set automatically when the condition is no longer detected [sourced: same]
- Badges [sourced: same]:
  - **Live**: a high-confidence runtime event in the last 3 hours.
  - **New**: shown for 7 days after first detection.
- UX [sourced: same]:
  - Clicking a resource opens a detail drawer with an **Attack Path visualization** and a **Findings** tab.
  - A Risk Findings panel shows an attack-path preview and a finding summary.
  - Filters: Search, Zone, Severity, Context (In Use / Has Exploit), Resource Type, risk-definition tag.
- Attack path node types include containers (with container-escape events), EC2 hosts and IAM roles. Runtime detections are shown inline on the path, for example "xmrig execution or a container breakout" [sourced: https://sysdig.com/blog/real-time-attack-path]
- Sensitive data (DSPM) appears inside attack paths [sourced: https://www.sysdig.com/blog/defending-sensitive-data-with-sysdig-secure]

### Risk prioritization
- Risk severity is rule-based on 4 levels, not a numeric score [sourced: https://docs.sysdig.com/en/sysdig-secure/risks/]:
  - **Critical**: a high-confidence detection, OR a critical vulnerability in an **In Use** package.
  - **High**: a critical vulnerability with an exploit.
  - **Medium**: compute that can access storage, critical unused permissions, or insecure storage accepting HTTP.
  - **Low**: everything else.
- Tie-breaks within a severity [sourced: same]:
  1. Live risks rank first.
  2. Then by the number of component findings.
  3. Then by the number of affected resources.
  This is fully explainable but coarse [inferred].
- **In Use / Runtime Bill of Materials (RBOM)** [sourced: https://docs.sysdig.com/en/sysdig-secure/risk-spotlight/]:
  - Correlates three inputs: the image's runtime behavior profile (files, processes, syscalls), the SBOM, and the packages actually loaded.
  - Supported languages: Go, Java, JS/TS, Python, Ruby.
  - Not supported: .NET, PHP, Rust, Dart, Swift.
- Vulnerability Findings context [sourced: https://docs.sysdig.com/en/docs/sysdig-secure/vulnerabilities/vulnerability-findings/]:
  - **CISA KEV** flag and **EPSS score/percentile**.
  - Ransomware-campaign association.
  - Risk-factor filters `hasExploit`, `inUse`, `hasFix`, `AcceptedRisk`.
  - **Reachability tab** shows both image-level static reachability and runtime/container-level reachability.
- Marketing claims: in-use prioritization "reduce[s] noise up to 95%" [sourced: https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc]
- 2026 vulnerability-management additions [sourced: https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes]:
  - GitHub Advisory scores for non-OS packages (2026-10-05)
  - **Vulnerability Catalog**: CVE lookup across the environment (2026-10-02)
  - EOL visibility for OS and Go runtime (2026-06-09)
  - **Image Layer Analysis**: base-image layers vs app layers (2026-08-13)
  - **Threat Evaluation** with "Malicious to Benign" ratings (2026-09-29)
- "Hyperpersonalization based on organizational norms and asset criticality" in Secure AI. No explicit criticality-scoring scale was found [sourced: https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense]

### CIEM/identity
- Identity pages: **IAM Policies** (AWS only), **Users**, **Roles**, **Groups**, and **Service Identities** (GCP service accounts, Azure service principals) [sourced: https://docs.sysdig.com/en/sysdig-secure/identity/]
- There are two severity metrics, each on a Critical/High/Medium/Low scale [sourced: same]:
  - **Permission Criticality**: based on all permissions.
  - **Unused Permission Criticality**: based on unused permissions only.
- Remediation strategies offered in drawers [sourced: same]:
  - "Detach the role"
  - "Consolidate and Reduce Permissions" (into one custom role)
  - "Reduce Permissions with Existing Roles" (swap to less-privileged managed roles)
- Usage is built from cloud audit logs. Suggested least-privilege policies are generated from that usage profile, together with last-active dates [sourced: https://www.sysdig.com/solutions/cloud-infrastructure-entitlement-management-ciem]
- JIT access and IdP (Okta) federation analysis were not found [sourced: https://docs.sysdig.com/en/sysdig-secure/identity/ (absent)]
- Cloud Response Actions include IAM quarantine (see Detection & response) [sourced: https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes]

### DSPM
- "Data security findings" is an **add-on powered by Bedrock Security** (blog dated 2025-07-28) [sourced: https://www.sysdig.com/blog/defending-sensitive-data-with-sysdig-secure]:
  - Classifies PII, PHI and financial data.
  - Uses "continuous scanning and AI-powered fingerprinting".
  - Covers AWS S3, RDS and Azure Blob [sourced: search summary of https://sysdig.com/solutions/data-security-posture-management-dspm]
  - Findings feed Risks and attack paths as the "Sensitive Data" category [sourced: https://docs.sysdig.com/en/sysdig-secure/risks/]
- Sampling method and depth are not public.

### Vulnerability & secrets
- Agent-based and agentless scanning, plus a CLI scanner [sourced: https://sysdig.com/pricing/ ; https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes]
  - CLI scanner flag `--detect-unknown-executables` for standalone binaries (2026-09-16).
- Findings can be grouped by None (CVE × Package × Resource), CVE, Image, or Runtime Resource [sourced: https://docs.sysdig.com/en/docs/sysdig-secure/vulnerabilities/vulnerability-findings/]
- Vulnerability policies [sourced: release notes]:
  - **Base Image Allow/Deny List** rules (2026-08-13)
  - Reusable scope attributes (2026-08-03)
  - Policy results shown in the resource drawer
- **Supply Chain Findings** page covers license and EOL (2026-10-01) [sourced: release notes]
- Secrets scanning specifics were not verified for Sysdig [unknown]

### Code-to-cloud / IaC
- "Git Source Control Integration maps production deployments back to their IaC source files". It detects drift and "automatically generates pull requests with recommended fixes" [sourced: search summary of https://platform.softwareone.com/product/infrastructure-as-code-iac-security/PCP-5783-6317]
- The Compliance UI offers three actions per violation: "Remediate", "Accept the risk", and "Open a Pull Request in your code repository" [sourced: https://docs.sysdig.com/en/sysdig-secure/compliance/]
- Attack-path remediation can produce a PR, for example removing `privileged: true` [sourced: https://sysdig.com/blog/real-time-attack-path]
- Policy-as-code: posture controls are written in **OPA/Rego**. The control library exposes the Rego and its inputs, and custom controls are supported [sourced: https://docs.sysdig.com/en/sysdig-secure/posture-policies/posture_controls]

### Remediation
- Guided remediation in drawers, PRs for IaC, Jira tickets, and runtime response actions [sourced: multiple, above]
- **Sysdig Sage for VM** builds a two-layer remediation plan [sourced: https://docs.sysdig.com/en/sysdig-secure/sysdig-sage-vm/]:
  - App/language layer: dependency-aware upgrades for Java, Python and Node.js.
  - Base image / OS layer.
  - It can create a pre-filled Jira ticket.
  - Limitation: "Remediations persist only during the current browser session."
- Headless "vulnerability management" skill: "prioritize risk, generate fixes, assign ownership" [sourced: https://www.sysdig.com/press-releases/sysdig-headless-cloud-security]
- Secure AI's Agentic mode: "teams define objectives while AI executes", with "human-in-the-loop controls with full action auditing" [sourced: https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense]

### Compliance
- Compliance views: Compliance Overview, Compliance Findings, and Policy Compliance Reports. Metrics include [sourced: https://docs.sysdig.com/en/sysdig-secure/compliance/]:
  - "Passing Score" %
  - "Requirements Failing" (7-day trend)
  - "Controls to Fix"
  - Resource violations by severity
- Reports: PDF download, scheduled delivery to email or Slack, 14-day download history [sourced: same]
- Frameworks include CIS, PCI-DSS, HIPAA, GDPR "and others". Sysdig says "new standards are being added regularly". **No exact framework count was found** [sourced: https://docs.sysdig.com/en/sysdig-secure/compliance/ ; search summary]
- Custom policies and controls (Rego) are scoped by **Zones** [sourced: https://docs.sysdig.com/en/sysdig-secure/posture-policies/]
- A new Posture Overview and Findings pages shipped on 2026-02-03 [sourced: release notes]

### Detection & response / real-time
- Falco-based runtime detection for syscalls, plus cloud-log detection. "Cloud Detection and Response" was renamed **"Threat Detection"** on 2026-02-26 [sourced: https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes]
- **555 benchmark**: 5 seconds to detect, 5 minutes to triage, 5 minutes to respond (introduced at SANS CyberFest 2023) [sourced: https://sysdig.com/555-benchmark/ ; https://www.sysdig.com/press-releases/555-benchmark]
- Response features in 2026 [sourced: release notes]:
  - **Cloud Response Actions** for AWS: EBS snapshot, IAM quarantine, remove public access (2026-02-26)
  - Workload actions: kill container, file quarantine, K8s operations, with automation (2026-01-19)
  - **Response History** page (2026-05-05)
  - **Response Actions in the resource drawer** (2026-05-15)
- **Falco rules for AI coding agents** (Codex, Gemini CLI, Claude Code) with dedicated managed policies (2026-03-17) [sourced: release notes]
- Secure AI agents: real-time investigation, containment and remediation. Claimed "10x more investigations" and an "88% cost reduction" for vulnerability investigations [sourced: https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense]

### Integrations & workflow
- **Jira**: "Streamlined Jira integration with automatic status mapping" (2026-02-18). This implies status sync back to the Risk/finding state [sourced: release notes; bidirectionality inferred]
- Amazon Kinesis Data Streams and Firehose (2026-02-17). Custom Storage to multiple S3 / S3-compatible buckets (2026-07-16) [sourced: release notes]
- AWS Security Hub, GuardDuty and Security Lake [sourced: https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc]
- Slack and email for scheduled compliance reports [sourced: https://docs.sysdig.com/en/sysdig-secure/compliance/]
- SCM: GitHub, GitLab, Bitbucket, Azure DevOps [sourced: https://www.sysdig.com/integrations/github]

### Dashboards & reporting UX
- Risks is a stack-ranked list. Posture Overview (2026-02) and the Compliance Overview show trend charts [sourced: docs above]
- "Reporting: Column Customization" (2026-07-14) [sourced: release notes]
- No published exec/MTTR/SLA dashboard specifics were found [unknown]. G2 reviewers ask for "more customizable" dashboards and reporting (see weaknesses).

### AI assistant
- **Sysdig Sage** (now the "GenAI Assistant" mode in Secure AI) [sourced: https://docs.sysdig.com/en/sysdig-sage/ ; https://sysdig.com/blog/sysdig-sage-for-cdr-accelerate-analysis-investigation-and-response]:
  - Multi-step conversations.
  - Sage for Threats (Events Feed): event statistics, event explanation, suggested remediation, UI navigation.
  - Sage for Search: natural language to SysQL.
  - Sage for VM: remediation plans.
- RBAC permissions: "Sysdig Sage: Full Access", "Threats: Read only", "Captures/Investigate: Custom". There is an admin global toggle at Settings > Terms & Conditions > Activation and T&C [sourced: https://docs.sysdig.com/en/sysdig-sage/]
- The underlying LLM and data-retention policy are not documented on the overview page [sourced: same (absent)]
- Claimed outcomes: MTTR −76%, 80+ hours a week of triage reclaimed [sourced: https://www.sysdig.com/press-releases/sysdig-named-leader-forrester-wave-cnapp-2026]
- **Headless Cloud Security** (2026-05-06) [sourced: https://www.sysdig.com/press-releases/sysdig-headless-cloud-security ; search summary of https://docs.sysdig.com/en/sysdig-secure/secure-ai/headless-cloud-security/]:
  - Agent skills for vulnerability management, posture management, runtime threat investigation, and guided onboarding.
  - Delivered via plug-ins, CLIs, MCP and APIs, with "new agent skills released weekly".
  - Claude Code is the primary supported agent. Cursor, Codex and OpenCode work through `npx skills` but are not officially supported.
  - "Fully auditable" with enterprise trust boundaries.

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- APIs: SysQL API and Compliance Results API [sourced: https://docs.sysdig.com/en/developer-tools/sysql-api/ ; compliance docs]
- CLI scanner [sourced: release notes]
- MCP servers:
  - `sysdiglabs/sysdig-mcp-server` (Go, Apache-2.0, v3.0.4 on 2026-09-24). Transports: stdio, streamable-http, sse. It filters its tool list by the API token's permissions. Secure tools moved to the npm package **`@sysdig/secure-mcp-server`**.
  [sourced: https://github.com/sysdiglabs/sysdig-mcp-server]
- RBAC: custom roles with granular permissions. Sage permissions are listed above. Service accounts are recommended for MCP [sourced: same; https://docs.sysdig.com/en/sysdig-sage/]
- Multi-tenancy: Teams and **Zones** scope the data [sourced: compliance/risks docs]
- A Terraform provider is used for onboarding (`sfc-cloudbench`) [sourced: https://docs.sysdig.com/en/sysdig-secure/identity/]. Whether the provider covers full config-as-code was not verified [inferred]
- SSO: not verified in this session [unknown]

### Unique "wow" features released 2025-2026
- **Headless Cloud Security** (2026-05): CNAPP workflows packaged as agent skills that run inside Claude Code, distributed via `npx skills`, with weekly skill drops [sourced: https://www.sysdig.com/press-releases/sysdig-headless-cloud-security]
- **SysQL Skill** (2026-07): natural language → validated graph query → fix, through the read-only Secure MCP server [sourced: https://www.sysdig.com/blog/introducing-the-sysql-skill-ask-your-security-graph-anything]
- **Sysdig Secure AI** (GA 2026-08-04): three-mode AI (agentic, headless, assistant), human-in-the-loop, with audit of every action [sourced: https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense]
- **Custom risk definitions as SysQL** with an anchor resource, plus a "Live" (3-hour) badge on risks [sourced: https://docs.sysdig.com/en/sysdig-secure/risks/]
- **Falco rules that detect AI coding agents** (Claude Code, Codex, Gemini CLI) running on hosts (2026-03) [sourced: release notes]
- **Cloud Response Actions**: EBS snapshot, IAM quarantine, remove public access, with a Response History audit page (2026) [sourced: release notes]
- **Image Layer Analysis** and **Base Image Allow/Deny lists** (2026-08) [sourced: release notes]

### Documented weaknesses/complaints
- Setup complexity and learning curve. All from AWS Marketplace reviews [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-of3ndsfqn2cwc?page=2]:
  - "initial setup and configuration can be complex, especially for teams new to Kubernetes" (2026-04-29)
  - "initial setup is too complex" (2025-05-21)
  - "initial learning curve can be a bit steep for new users" and "documentation sometimes lags behind new feature releases" (2025-05-26)
- Dashboards and alerting: "some dashboard and reporting features could be more customizable" (2025-12-27) [sourced: same]
- Vulnerability UI bugs: "a few bugs in the UI to fix version filtering" and "sometimes there is no fix version shown" (2025-12-16) [sourced: same]
- Agent weight. G2 snippets in search results [sourced: https://www.g2.com/products/sysdig-platform/reviews?page=8 ; https://www.g2.com/products/sysdig-sysdig-secure/reviews/sysdig-secure-review-4412447]:
  - "the agent consumes too many resources and is much heavier than other equivalent agents"
  - "the UI needs a lot of improvement, it's confusing and not intuitive"
- Feature limits: G2 reviewers mention "incomplete functionalities such as agentless scanning" [sourced: search summary of G2 Sysdig Secure reviews, https://www.g2.com/products/sysdig-sysdig-secure/reviews/sysdig-secure-review-9977813]
- Product gaps:
  - "In Use" does not support .NET, PHP or Rust [sourced: https://docs.sysdig.com/en/sysdig-secure/risk-spotlight/]
  - Sage VM remediation plans do not persist across sessions [sourced: https://docs.sysdig.com/en/sysdig-secure/sysdig-sage-vm/]
  - DSPM is a partner add-on (Bedrock), not native [sourced: https://www.sysdig.com/blog/defending-sensitive-data-with-sysdig-secure]

### Sources
- https://sysdig.com/pricing/
- https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc
- https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-of3ndsfqn2cwc?page=2
- https://cubeapm.com/blog/sysdig-pricing-review/
- https://www.sysdig.com/press-releases/sysdig-launches-secure-ai-to-democratize-machine-speed-cloud-defense
- https://www.sysdig.com/press-releases/sysdig-named-leader-forrester-wave-cnapp-2026
- https://www.sysdig.com/press-releases/sysdig-headless-cloud-security
- https://docs.sysdig.com/en/sysdig-secure/secure-ai/headless-cloud-security/
- https://www.sysdig.com/blog/introducing-the-sysql-skill-ask-your-security-graph-anything
- https://docs.sysdig.com/en/sysdig-secure/risks/
- https://docs.sysdig.com/en/sysdig-secure/risk-spotlight/
- https://docs.sysdig.com/en/docs/sysdig-secure/vulnerabilities/vulnerability-findings/
- https://docs.sysdig.com/en/sysdig-secure/identity/
- https://docs.sysdig.com/en/sysdig-secure/compliance/
- https://docs.sysdig.com/en/sysdig-secure/posture-policies/posture_controls
- https://docs.sysdig.com/en/sysdig-secure/sysql-reference/
- https://docs.sysdig.com/en/developer-tools/sysql-api/
- https://docs.sysdig.com/en/sysdig-sage/
- https://docs.sysdig.com/en/sysdig-sage/sage-for-search/
- https://docs.sysdig.com/en/sysdig-secure/sysdig-sage-vm/
- https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes
- https://sysdig.com/blog/real-time-attack-path
- https://sysdig.com/blog/sysdig-sage-for-cdr-accelerate-analysis-investigation-and-response
- https://www.sysdig.com/blog/defending-sensitive-data-with-sysdig-secure
- https://www.sysdig.com/solutions/cloud-infrastructure-entitlement-management-ciem
- https://www.sysdig.com/integrations/github
- https://sysdig.com/555-benchmark/
- https://www.businesswire.com/news/home/20230927006401/en
- https://github.com/sysdiglabs/sysdig-mcp-server
- https://www.g2.com/products/sysdig-platform/reviews?page=8

---

## Aqua Security

### Positioning & pricing model
- Aqua positions itself as a runtime-first CNAPP. Its 2026 messaging is "Doubles Down on Runtime to Deliver Measurable Cloud Risk Reduction" (2026-02-12) [sourced: https://www.aquasec.com/news/aqua-security-doubles-down-on-runtime-to-deliver-measurable-cloud-risk-reduction/]
- Historically anti-agentless: former CEO Dror Davidoff said "agentless security is not security" [sourced: https://itbrief.com.au/story/the-agent-vs-agentless-debate-is-over-aqua-security]
- Company facts:
  - 500+ enterprises, "over 40% of the Fortune 100".
  - Founded 2015; based in Boston and Ramat Gan.
  - $325M raised in total; last round was a $60M Series E extension in Jan 2024.
  [sourced: https://www.aquasec.com/news/aqua-security-announces-leadership-transition-as-company-enters-its-next-phase-of-growth/ ; https://yespress.io/aqua-security.md]
- **Leadership change (2025-11-05/06)** [sourced: https://www.aquasec.com/news/aqua-security-announces-leadership-transition-as-company-enters-its-next-phase-of-growth/]:
  - Co-founders Dror Davidoff (CEO) and Amir Jerbi (CTO) moved to advisor roles.
  - **Mike Dube** (ex-CrowdStrike) became CEO.
  - Nir Makowski became CPTO.
  - Stated focus: CNAPP runtime, response, and vulnerability management.
- Pricing units [sourced: https://aquasec.com/pricing]:
  - **Dev Security**: per code repository.
  - **Cloud Security**: per workload (EC2 instances, Fargate containers, Lambda functions, etc.).
  - Prices are quote-only.
- AWS Marketplace "Aqua Cloud Native Application Protection Platform" plans: **Aqua Platform Shift Left (Standard)**, **Protect (Advanced)** and **Ultimate**. These are 12-month contracts with placeholder $1 unit prices, so real pricing comes through private offers. The listing also notes **FedRAMP High** [sourced: https://aws.amazon.com/marketplace/pp/prodview-kbyd6xjphbpiy]
- Reviewers report "licensing can be expensive at scale" and "licensing complexity" [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]

### Deployment
- Agent plus agentless: "See your cloud workload posture immediately, without deploying agents". Kernel-level enforcement can block "without killing the container itself" [sourced: https://www.aquasec.com/aqua-cloud-native-security-platform/]
- Runtime uses eBPF, behavioral plus signature detection, and Nautilus threat intelligence [sourced: https://www.aquasec.com/products/cwpp-cloud-workload-protection/]
- Platforms: K8s, OpenShift, AWS, Azure, GCP, VMware Tanzu, Docker, IBM Z / mainframe, plus serverless and VMs [sourced: same; https://www.aquasec.com/solutions/ibm-z-security/]
- Enforcer family names (Enforcer, KubeEnforcer, MicroEnforcer for Fargate/serverless containers, VM Enforcer, eBPF "Lightning Enforcer"):
  - MicroEnforcer and the eBPF Lightning Enforcer have their own news posts [sourced: https://www.aquasec.com/news/aqua-expands-container-security-platform-with-microenforcer/ ; https://www.aquasec.com/news/combats-rising-zero-day-attacks-with-ebpf-lightning-enforcer/]
  - The full current lineup was not verified on product pages [inferred]
- Delivery: SaaS and self-hosted. The platform includes Aqua Platform for Government (FedRAMP High) [sourced: https://www.aquasec.com/solutions/compliance/]
- CSPM covers AWS, Azure and GCP [sourced: https://www.aquasec.com/products/cspm/]
- OSS lineage: **Trivy** (scanner), **Tracee** (eBPF runtime), CloudSploit (CSPM origin) [sourced: https://www.aquasec.com/products/open-source-projects/ ; https://www.aquasec.com/blog/cspm-with-cloudsploit/]
  - **Tracee's last release was v0.24.1 on 2025-11-19.** No 2026 releases, which suggests reduced investment [sourced: `gh api repos/aquasecurity/tracee/releases`, https://github.com/aquasecurity/tracee/releases ; inference on investment]
  - Trivy remains very active: v0.70.0 (2026-04-17) through v0.75.0 (2026-10-01) [sourced: https://github.com/aquasecurity/trivy/releases]

### Inventory & graph
- "Unified cloud inventory view with search and drill-down" across containers, VMs, serverless and K8s [sourced: https://www.aquasec.com/blog/conquer-cloud-security-risk-real-time-cspm/ ; https://www.aquasec.com/aqua-cloud-native-security-platform/]
- **Kubernetes Risk Explorer** is a logical map with risk scores per node. It shows cluster → namespace → deployment → container → image, plus host/node views and inbound/outbound network-connection arrows [sourced: https://www.aquasec.com/blog/kubernetes-security-risk-explorer/]
- **Application Scopes** with `company.lob.*` labels map containers to business units [sourced: https://www.aquasec.com/blog/how-do-you-measure-fair-risk-in-the-mythos-era/]
- No public graph query language was found. Docs (docs.aquasec.com) require sign-in [sourced: https://docs.aquasec.com/ (login wall)]
- A reviewer says "Risk prioritization in security graphs is a point where Aqua... is less mature" [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]

### Attack paths & toxic combinations
- Real-Time CSPM (2023) correlates findings that require "multiple issues or dependencies to be exploitable", surfaces "top risks", and deduplicates findings [sourced: https://www.aquasec.com/blog/conquer-cloud-security-risk-real-time-cspm/]
- Aqua's attack-path framing is forensic. It "reconstructs compromise sequences using memory snapshots, process lineage and runtime telemetry" [sourced: https://www.aquasec.com/aqua-cloud-native-security-platform/]
- Detailed cloud attack-path UX and scoring are not public (docs are gated) [unknown]
- Reviewer: "cloud context visualization is an area for improvement" [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]

### Risk prioritization
- Signals: "reachability, EPSS, actively running packages, and available exploits", plus code and runtime context [sourced: https://www.aquasec.com/products/container-vulnerability-scanning/ ; https://www.aquasec.com/aqua-cloud-native-security-platform/]
- **Runtime reachability** (linking image scan results to packages the running app loads) is described as an upcoming capability as of 2026-10-06 [sourced: https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/]
- **FAIR Risk Dashboard** (2026-04) gives risk in dollars [sourced: https://www.aquasec.com/blog/how-do-you-measure-fair-risk-in-the-mythos-era/ ; https://www.aquasec.com/news/aqua-security-turns_runtime_intelligence_into_action_with_agentic_response_risk_daskboards/]:
  - Formula: Annual Loss Expectancy = frequency × cost per event.
  - Inputs: scan and runtime vulnerability data, Application Scopes / `company.lob.*` labels, and manually set asset values and loss estimates.
  - Control effect is modeled as 4 independent layers: image security, network enforcement, runtime behavior, access controls. Overlap coefficients apply within a layer, and the layers are multiplied together.
  - **Only Enforce-mode policies reduce risk; Audit mode does not.**
  - Example: a bank's base ALE of $12.6M drops to $2.5M residual.
  - Exposure is recalculated as controls are enforced.
- Risk Explorer uses per-object risk scores. The scale is not public [unknown]

### CIEM/identity
- No dedicated CIEM product page appears in the aquasec.com sitemap [sourced: https://www.aquasec.com/page-sitemap.xml ; inference that CIEM is shallow]
- There is a blog post on Okta identity management [sourced: https://www.aquasec.com/blog/okta-identity-management/ (not fetched)]
- The Orca partnership brings "identities" visibility from Orca [sourced: https://www.aquasec.com/integrations/orca-security/]
- Effective-permissions analysis, least-privilege recommendations and JIT: not found [unknown]

### DSPM
- No DSPM product was found [sourced: sitemap, absent]
- Image scanning detects "sensitive data" (data-leak detection) in images and code [sourced: https://www.aquasec.com/blog/integrate-aqua-and-jira-to-turn-security-findings-into-action/ ; https://www.aquasec.com/blog/security-that-speaks-your-language-trivy-mcp-server/]
- No cloud datastore classification was found [unknown]

### Vulnerability & secrets
- Scanning is based on **Trivy / Trivy Premium**. It covers vulnerabilities, OSS licenses, IaC misconfigurations, secrets and malware [sourced: https://www.aquasec.com/products/software-supply-chain-security/]
- **"next-gen SBOM"** with code signing and build provenance [sourced: same]. VEX Hub is a repository for VEX statements [sourced: https://www.aquasec.com/blog/introducing-vex-hub-unified-repository-for-vex-statements/ (title only)]
- **Smart rescan**: an "unchanged image is checked against newly published vulnerabilities without a rescan". Scans can be triggered on demand from the Aqua Hub or the API [sourced: https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/]
- **vShield** (patented virtual patching), described in a 2026-06-30 post [sourced: https://www.aquasec.com/blog/how-do-you-protect-a-workload-you-cannot-afford-to-patch-right-now/]:
  - Generates runtime policies for specific CVEs automatically, for example blocking a vulnerable protocol, a package, file access, or capabilities.
  - Defaults to **Audit** mode.
  - A scheduler promotes it to **Enforce** once validation criteria are met.
- Dynamic Threat Analysis (sandboxed image detonation) is listed as a platform feature [sourced: https://www.aquasec.com/news/aqua-security-turns_runtime_intelligence_into_action_with_agentic_response_risk_daskboards/]
- **Trivy supply-chain compromise (GHSA-69fq-xp46-6x23, Critical)** [sourced: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 ; https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/]:
  - Late Feb 2026: tokens were stolen from GitHub Actions.
  - Credential rotation after the 2026-03-01 disclosure was not atomic, so the attacker kept access.
  - 2026-03-19: the attacker published a malicious Trivy v0.69.4, force-pushed **76 of 77 `trivy-action` tags**, and replaced all 7 `setup-trivy` tags with credential-stealing malware.
  - 2026-03-22: malicious Docker Hub images v0.69.5 and v0.69.6 were published.
  - Aqua says its commercial products were not affected (separate repos, CI/CD, secrets and signing).
  - Lesson for OSS projects: immutable releases and SHA pinning.

### Code-to-cloud / IaC
- **Cloud-to-code tracing** (2023-09): a runtime CVE is traced to the repository, the Dockerfile and the exact line that introduced it, along with the owner [sourced: https://www.aquasec.com/blog/elevating-cloud-security-response-with-code-to-cloud-tracing/]
- CSPM findings are linked "to respective code repositories" with "risk ownership" [sourced: https://www.aquasec.com/blog/conquer-cloud-security-risk-real-time-cspm/]
- Developer touchpoints: IDE alerts, **PR comments**, CI warnings, and "automated pull request generation" [sourced: https://www.aquasec.com/products/software-supply-chain-security/ ; https://www.aquasec.com/products/container-vulnerability-scanning/]
- **Static Pipeline Analysis** of CI configs (GitHub Actions, GitLab CI, Jenkins, CircleCI) [sourced: https://www.aquasec.com/products/software-supply-chain-security/]
- Policy-as-code: Compass emits mitigations "as policy as code" [sourced: https://www.aquasec.com/blog/autonomous-runtime-security-turning-runtime-intelligence-into-agentic-response/]. Trivy uses Rego for its misconfiguration checks [inferred, well-known Trivy design]

### Remediation
- **AI-Guided Remediation** (2023-08) gives step-by-step fix instructions for vulnerabilities and misconfigurations. It uses **OpenAI ChatGPT via customer-configured API credentials** [sourced: https://www.aquasec.com/blog/ai-guided-remediation-unify-teams-and-speed-vulnerability-resolution/]
- Automated PRs, vShield compensating controls, drift prevention, and Compass-generated namespace-scoped runtime policies. Compass requires human approval before enforcement [sourced: pages above]
- CSPM response policies "automatically trigger actions, update ticketing systems, or notify teams" [sourced: https://www.aquasec.com/products/cspm/]
- There is a post on auto-remediation in Azure [sourced: https://www.aquasec.com/blog/auto-remediation-azure-cloud/ (title only)]
- Reviewers want "more details in remediation guidance and clearer prioritization of findings" [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]

### Compliance
- "More than 30 common regulatory standards", including NIST, PCI, HIPAA and GDPR [sourced: https://www.aquasec.com/products/cspm/]
- Compliance page names FedRAMP High, PCI DSS, HIPAA, GDPR, SOC 2, NIST, CIS and DORA [sourced: https://www.aquasec.com/solutions/compliance/]
- Evidence comes from records of scan results, policy decisions, admin actions and runtime events. **Container memory forensics** preserves malware evidence from ephemeral pods [sourced: same]
- Custom framework authoring was not verified [unknown]

### Detection & response / real-time
- eBPF runtime detection and drift prevention ("only original image executables... run"). **Selective memory dump** captures forensics at the moment of attack [sourced: https://www.aquasec.com/products/cwpp-cloud-workload-protection/ ; https://www.aquasec.com/blog/selective-memory-dump-for-deep-container-forensic-analysis/]
- **Aqua Compass** (2026-04-22) is an MCP server for agentic investigation, containment and remediation [sourced: https://www.aquasec.com/news/aqua-security-turns_runtime_intelligence_into_action_with_agentic_response_risk_daskboards/ ; https://www.aquasec.com/blog/autonomous-runtime-security-turning-runtime-intelligence-into-agentic-response/]:
  - Reconstructs events from eBPF syscalls and network traffic.
  - Identifies root cause and impact scope.
  - Analyzes live malware.
  - Recommends isolation.
  - Generates hardened runtime policies scoped to the namespace.
- Real-time CSPM claims it catches attacks that leave no footprint: "one in three do not leave a footprint" for snapshot scanners [sourced: https://www.aquasec.com/blog/conquer-cloud-security-risk-real-time-cspm/]
- Cloud-log CDR (CloudTrail-type detection): not verified [unknown]

### Integrations & workflow
- **Jira** (2026-10-02 post) [sourced: https://www.aquasec.com/blog/integrate-aqua-and-jira-to-turn-security-findings-into-action/]:
  - Auto-opens tickets on scan or rescan findings (vulnerabilities, sensitive data, malware).
  - Multiple routing blocks send tickets to different boards.
  - Fields: issue type, priority, assignee, versions, labels.
  - **Explicitly not bidirectional.**
- **ServiceNow Vulnerability Response** (2026-07-21) [sourced: https://www.aquasec.com/blog/integrate-aqua-and-servicenow-to-prioritize-vulnerabilities-by-runtime-reality/]:
  - Populates Container Vulnerable Items, Discovered Container Images, and Container Image Findings.
  - Has a **"running workload" filter**.
  - "Use Aqua Auto Close" closes items Aqua no longer sees.
  - Sync is one-way.
- Splunk, Datadog and VMware Tanzu integrations (2026 blog series) [sourced: https://www.aquasec.com/blog/integrate-aqua-and-splunk-for-full-visibility-into-runtime-threats/ ; https://www.aquasec.com/integrations/datadog/ (titles)]
- **Orca partnership**: Orca provides multi-cloud visibility and Aqua provides runtime telemetry, with alerts combined in one place [sourced: https://www.aquasec.com/integrations/orca-security/]
- Reviewer: "Aqua... could work on its SOAR integration" [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]

### Dashboards & reporting UX
- **Runtime Risk Dashboards** (2026-04): monetary exposure, recalculated as controls are enforced. They show control effectiveness and comparative impact [sourced: https://www.aquasec.com/blog/autonomous-runtime-security-turning-runtime-intelligence-into-agentic-response/]
- Reviewers [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]:
  - The UI is "more engineer-focused than executive-friendly".
  - "Simpler dashboards would help security teams quickly understand what needs attention."
- No SLA or MTTR dashboard specifics were found [unknown]

### AI assistant
- **Aqua Compass**: an MCP-based agent interface. Guardrails [sourced: https://www.aquasec.com/blog/autonomous-runtime-security-turning-runtime-intelligence-into-agentic-response/]:
  - Security-team review and approval before enforcement.
  - Mitigations shown as policy-as-code.
  - Customizable agent workflows.
- **Trivy MCP Server** (2025-10-28) [sourced: https://www.aquasec.com/blog/security-that-speaks-your-language-trivy-mcp-server/]:
  - Clients: VS Code, Cursor, JetBrains, Claude Desktop.
  - Natural-language scan queries.
  - Rules that auto-scan when `package.json`, `requirements.txt` or a Dockerfile changes.
  - `--use-aqua-platform` with `AQUA_KEY` / `AQUA_SECRET` adds assurance-policy validation.
- AI-Guided Remediation (OpenAI, BYO key; see Remediation) [sourced: https://www.aquasec.com/blog/ai-guided-remediation-unify-teams-and-speed-vulnerability-resolution/]
- AI workload security ("Aqua Secure AI", "full lifecycle security for AI applications") covers LLM governance and model-abuse detection [sourced: https://www.aquasec.com/news/aqua-security-unveils-industry-first-full-lifecycle-security-for-ai-applications/ (title) ; https://aws.amazon.com/marketplace/pp/prodview-kbyd6xjphbpiy]
- No general in-console chat assistant, comparable to Sage, was confirmed [unknown]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Scans can be triggered via the API, and the Hub has an API [sourced: https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/]
- Trivy CLI and Trivy Operator [sourced: https://www.aquasec.com/blog/vulnerability-scanning-trivy-vs-the-trivy-operator/ (title)]
- Application Scopes give scoped multi-tenancy by line of business [sourced: https://www.aquasec.com/blog/how-do-you-measure-fair-risk-in-the-mythos-era/]
- SaaS, self-hosted and FedRAMP High Government deployments [sourced: compliance page]
- RBAC, SSO and Terraform provider details sit behind gated docs [unknown]

### Unique "wow" features released 2025-2026
- **FAIR Risk Dashboard** (2026-04): risk in dollars (ALE), recalculated as runtime controls move from Audit to Enforce, with a layered control-effectiveness model [sourced: https://www.aquasec.com/blog/how-do-you-measure-fair-risk-in-the-mythos-era/]
- **Aqua Compass** (2026-04): an MCP agent that investigates incidents and proposes namespace-scoped runtime policies as code, applied only after approval [sourced: https://www.aquasec.com/blog/autonomous-runtime-security-turning-runtime-intelligence-into-agentic-response/]
- **vShield auto-promotion** from Audit to Enforce through a scheduler once validation criteria are met (2026-06 post) [sourced: https://www.aquasec.com/blog/how-do-you-protect-a-workload-you-cannot-afford-to-patch-right-now/]
- **Smart rescan**: check unchanged image digests against new CVEs without re-pulling them (2026-10) [sourced: https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/]
- **Trivy MCP Server** with file-change scan rules (2025-10) [sourced: https://www.aquasec.com/blog/security-that-speaks-your-language-trivy-mcp-server/]
- **ServiceNow VR integration with a "running workload" filter and auto-close** (2026-07) [sourced: https://www.aquasec.com/blog/integrate-aqua-and-servicenow-to-prioritize-vulnerabilities-by-runtime-reality/]

### Documented weaknesses/complaints
- All quotes in this list are from AWS Marketplace reviews, 2026 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy]:
  - UI and UX:
    - "the UI can feel rough to navigate, and sometimes finding the data I need has a really high learning curve" (2026-08-15)
    - "The UI needs some improvement as it is somewhat overwhelming" (2026-06-27)
    - "the GUI itself would sometimes be a little slow" (2026-06-16)
  - Cost and licensing:
    - "the licensing can be expensive at scale" (2026-06-27)
    - "licensing complexity and agent dependency are areas for improvement" (2026-07-04)
    - "pricing can be high depending on workload scale" (2026-05-28)
  - Noise and setup:
    - "Aqua generates a large number of initial alerts" (2026-05-28)
    - "streamlining the onboarding process and initial policy tuning" (2026-06-05)
  - Graph and cloud context:
    - "Risk prioritization in security graphs is a point where Aqua... is less mature" (2026-06-20)
    - "cloud context visualization is an area for improvement" (2026-07-04)
  - Operations: "we did not find an option to turn off logging or split logs" (2026-08-31)
- Workflow: the Jira and ServiceNow integrations are one-way [sourced: Jira / ServiceNow posts above]
- OSS trust: the March 2026 Trivy and trivy-action supply-chain compromise was caused by non-atomic credential rotation [sourced: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23]
- Tracee has had no release since 2025-11 [sourced: https://github.com/aquasecurity/tracee/releases]
- Product docs are behind a login [sourced: https://docs.aquasec.com/]
- No native DSPM or CIEM product page [inferred from sitemap]

### Sources
- https://aquasec.com/pricing
- https://aws.amazon.com/marketplace/pp/prodview-kbyd6xjphbpiy
- https://aws.amazon.com/marketplace/pp/prodview-ufoarzrbe2b5w
- https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-kbyd6xjphbpiy
- https://www.aquasec.com/news/
- https://www.aquasec.com/news/aqua-security-turns_runtime_intelligence_into_action_with_agentic_response_risk_daskboards/
- https://www.aquasec.com/news/aqua-security-doubles-down-on-runtime-to-deliver-measurable-cloud-risk-reduction/
- https://www.aquasec.com/news/aqua-security-announces-leadership-transition-as-company-enters-its-next-phase-of-growth/
- https://www.aquasec.com/blog/autonomous-runtime-security-turning-runtime-intelligence-into-agentic-response/
- https://www.aquasec.com/blog/how-do-you-measure-fair-risk-in-the-mythos-era/
- https://www.aquasec.com/blog/how-do-you-protect-a-workload-you-cannot-afford-to-patch-right-now/
- https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/
- https://www.aquasec.com/blog/integrate-aqua-and-jira-to-turn-security-findings-into-action/
- https://www.aquasec.com/blog/integrate-aqua-and-servicenow-to-prioritize-vulnerabilities-by-runtime-reality/
- https://www.aquasec.com/blog/security-that-speaks-your-language-trivy-mcp-server/
- https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- https://www.aquasec.com/blog/conquer-cloud-security-risk-real-time-cspm/
- https://www.aquasec.com/blog/ai-guided-remediation-unify-teams-and-speed-vulnerability-resolution/
- https://www.aquasec.com/blog/elevating-cloud-security-response-with-code-to-cloud-tracing/
- https://www.aquasec.com/blog/kubernetes-security-risk-explorer/
- https://www.aquasec.com/products/cspm/
- https://www.aquasec.com/products/software-supply-chain-security/
- https://www.aquasec.com/products/container-vulnerability-scanning/
- https://www.aquasec.com/products/cwpp-cloud-workload-protection/
- https://www.aquasec.com/aqua-cloud-native-security-platform/
- https://www.aquasec.com/solutions/compliance/
- https://www.aquasec.com/integrations/orca-security/
- https://www.aquasec.com/page-sitemap.xml
- https://itbrief.com.au/story/the-agent-vs-agentless-debate-is-over-aqua-security
- https://yespress.io/aqua-security.md
- https://github.com/aquasecurity/trivy/releases
- https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- https://github.com/aquasecurity/tracee/releases
- https://docs.aquasec.com/

---

## Upwind

### Positioning & pricing model
- **Positioning:** a runtime-first CNAPP — agentless scanning plus an eBPF sensor — marketed as an independent, cloud-neutral alternative now that Google owns Wiz [sourced: https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection].
- **Company claims:** "93% noise reduction", "15 seconds to detect", "live inventory refreshed every 30 seconds" [sourced: https://www.upwind.io/].
- **Funding:**
  - Series B: $250M at about $1.5B (2026-01-29).
  - Next round (reported 2026-09-02, not yet closed when reported): $300M at $3.8B, led by Bessemer.
  - Revenue: under $20M in 2025; an estimated $50–60M YTD in 2026 [sourced: https://runtimewire.com/article/upwind-raising-300m-3-8b-runtime-cloud-security] [sourced: https://en.globes.co.il/en/article-1001554301].
- **AWS Marketplace list prices** (12-month contract; 24-month saves up to 8%, 36-month up to 11%) [sourced: https://aws.amazon.com/marketplace/pp/prodview-ff3am62vjukrw]:
  - "Upwind Cloud Security Platform": **$30,000** per unit.
  - "Upwind Managed Detection & Response 24/7": **$6,000** per unit.
  - The listing does not define the unit size.
- **Licensing:** a single SKU (runtime, code, data all included). It counts **one workload per node regardless of container count** [sourced: https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection — a sponsored post].

### Deployment
- **Agentless "Cloud Scanner":**
  - Deployed into the customer's account with Terraform modules (GCP, OCI scanner modules).
  - Onboarding modules exist for AWS, Azure, GCP and OCI [sourced: https://github.com/upwindsecurity].
- **Runtime sensor:**
  - eBPF-based; the AWS listing describes an "osquery-based" agent option.
  - Covers VMs, containers/K8s (KSPM, admission controller) and serverless [sourced: https://aws.amazon.com/marketplace/pp/prodview-ff3am62vjukrw] [sourced: https://www.upwind.io/cnapp].
- **Clouds:** AWS, Azure, GCP, OCI, Kubernetes, on-prem [sourced: https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind].
- **Snowflake** (2026-10-01) [sourced: https://www.upwind.io/feed/upwind-now-secures-snowflake-from-ai-down-to-the-storage-underneath-it].
- **Product modules:** CSPM, CIEM, DSPM, AI-SPM, IaC, SCA/SBOM, Container Admission Controller, CDR, ASM, API Security, DAST, MDR [sourced: https://www.upwind.io/].

### Inventory & graph
- **Live inventory:** refreshed every 30s, built on a shared "runtime data model" that combines processes, network traffic and API activity [sourced: https://www.upwind.io/] [sourced: https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection].
- **Query Builder:** a visual expression builder. Choppy AI converts free text into editable Query Builder expressions [sourced: https://www.01net.it/upwind-launches-choppy-ai-introducing-transparent-natural-language-intelligence-across-its-runtime-first-cloud-security-platform].
- **Snowflake graph:**
  - Nested objects → schemas → roles → users, built "without a single SHOW GRANTS".
  - A "graph from role to bucket" through storage integrations [sourced: https://www.upwind.io/feed/upwind-now-secures-snowflake-from-ai-down-to-the-storage-underneath-it].
- **No public text query language found** [inferred].

### Attack paths & toxic combinations
- **What it maps:** lateral movement across services, identities, APIs and data. It identifies "critical choke points" and blast radius [sourced: https://www.upwind.io/attack-path-exposure-analysis].
- **Runtime validation:** a path counts only if services are actually reachable and in use, which removes non-threats [sourced: https://www.upwind.io/attack-path-exposure-analysis].
- **Not published:** a numeric path score.
- **Red agent** chains weaknesses into complete paths and "proves which risks are reachable in production" [sourced: https://www.upwind.io/agentic-security].

### Risk prioritization
- **Signals:**
  - Internet exposure confirmed from observed traffic.
  - **Function-level reachability**: "reachable through live code execution paths".
  - In-use packages.
  - Sensitive data nearby.
  - Attack paths [sourced: https://www.upwind.io/vulnerability-management].
- **Claims:** "the 5% of vulnerabilities that pose real risk"; "remediate 7x faster" [sourced: https://www.upwind.io/vulnerability-management].
- **Not confirmed:** EPSS/KEV usage [inferred].
- **Risk ownership — "Open Source Security Model" (2025-11-10):**
  - Users can **modify, accept, recast (re-score) and snooze** risks in-platform.
  - The detection and prioritization logic is visible and editable [sourced: https://businesswire.com/news/home/20251110175955/en/Upwind-Launches-Groundbreaking-Open-Source-Security-Model-Bringing-Extreme-Ownership-and-Flexibility-to-Cloud-Risk-Management].
  - The model is "open" in the sense of transparent and editable, not an OSS license [inferred].
- **Compliance remediation priority:** each config finding shows "potential impact on compliance score", resource count and **difficulty (Easy→Hard)** [sourced: https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind].

### CIEM/identity
- **Identity mapping:** Okta/Entra/Ping roles and groups → cloud permissions, including indirect and inherited access.
- **Least privilege:** finds stale and dormant entitlements and over-permissive identities [sourced: https://www.upwind.io/identity-security].
- **ITDR:** real-time permission-use tracking; privilege-escalation and lateral-movement alerts [sourced: https://www.upwind.io/identity-security].
- **No explicit JIT** [sourced: https://www.upwind.io/identity-security — not mentioned].
- **Research — AWS IAM request-context probing (2026-09):** a "session policy probing" technique that recovers every populated condition key for an API call, including undocumented ones. It points toward precise effective-permission evaluation [sourced: https://www.upwind.io/feed/aws-iam-full-request-context].

### DSPM
- **Classification:** "runtime-aware" for PII/PCI/PHI/secrets across storage, databases, file systems and unstructured stores [sourced: https://www.upwind.io/dspm].
- **Data in motion:** Layer-7 analysis of sensitive data flowing through APIs, with alerts when "sensitive data crosses unsafe boundaries" [sourced: https://www.upwind.io/api-security].
- **Views:** data asset catalog with sensitivity, data lineage/flow mapping, compliance views (PCI/HIPAA/GDPR/HITRUST) [sourced: https://www.upwind.io/dspm].
- **Sampling method:** not public.
- **Snowflake:** posture mapped to the **CIS Snowflake Benchmark** [sourced: https://www.upwind.io/feed/upwind-now-secures-snowflake-from-ai-down-to-the-storage-underneath-it].

### Vulnerability & secrets
- **Coverage:** agentless plus eBPF across VMs, containers and serverless; SCA/SBOM module; CI image scanning via the GitHub Action `shiftleft-create-image-scan-event-action` [sourced: https://www.upwind.io/vulnerability-management] [sourced: https://github.com/upwindsecurity].
- **Reachability:** function-level, runtime-observed [sourced: https://www.upwind.io/vulnerability-management].
- **Ownership:** root cause linked to the "exact developer and commit" [sourced: https://www.upwind.io/vulnerability-management].

### Code-to-cloud / IaC
- **IaC module** [sourced: https://www.upwind.io/iac-security]:
  - Blocks risky changes in CI/CD.
  - Validates IaC findings against runtime data.
  - Maps IaC changes to CIS, SOC 2 and HIPAA.
  - "Auto-map IaC to regulated data".
- **CI/CD:** GitHub, GitLab, CircleCI, Azure DevOps, Bitbucket, ArgoCD, plus CustomCI/CustomCD hooks [sourced: https://www.upwind.io/integrations].
- **Image build tracking:** the `create-image-build-event-action` GitHub Action links images to builds [sourced: https://github.com/upwindsecurity].
- **Not detailed publicly:** IaC formats.

### Remediation
- **Green agent:**
  - Root-causes thousands of findings together.
  - Finds **"hotspots where single changes fix multiple issues"**.
  - Delivers fixes as **pull requests** [sourced: https://www.upwind.io/agentic-security].
- **Ticketing and chat routing:** Jira/Slack with ownership [sourced: https://www.upwind.io/vulnerability-management].
- **Approvals:** no approval guardrails are documented publicly [sourced: https://www.upwind.io/agentic-security].
- **Bulk actions:** reviewers say bulk resolve/suppress is missing (see weaknesses).

### Compliance
- **New "Configurations" experience (2026-09-24)** [sourced: https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind]:
  - Live **Compliance Score** per framework and per cloud account.
  - **"Score Journey"** shows how remediation moved the score.
  - Rule detail with evaluation timestamps.
  - Separates "configuration findings" from "security issues".
  - Frameworks: CIS, NIST, ISO (including **ISO/IEC 42001**), **EU AI Act**, US-government and industry frameworks.
- **Evidence history:** 13-month data lookback for compliance (CIS, HIPAA, ISO 27001, NIST, PCI, SOC 2) [sourced: https://aws.amazon.com/marketplace/pp/prodview-ff3am62vjukrw].
- **Not public:** framework count.

### Detection & response / real-time
- **CDR detections:** privilege escalation, lateral movement, risky API usage, anomaly baselines.
- **Investigation timeline:** a single timeline unifying SSH logs, container events and user activity [sourced: https://www.upwind.io/cdr].
- **Sources:** cloud audit logs, network flows, container events, CI/CD activity [sourced: https://www.upwind.io/cdr].
- **Speed:** detection "within 15 seconds" (vendor claim) [sourced: https://www.upwind.io/].
- **API runtime protection:**
  - eBPF socket-level reconstruction of API calls, including encrypted traffic, with no sidecars or proxies.
  - Discovers shadow and unmanaged APIs and how exposed each endpoint is to the internet.
  - Automated containment against brute force and token misuse.
  - Launched 2024-03 [sourced: https://www.newswire.com/news/upwind-introduces-api-security-solution-with-real-time-insights-at-the-22261957] [sourced: https://www.upwind.io/api-security].
- **AI threat detection:**
  - **AI-DR** covers prompt injection, exfiltration and agent misuse.
  - An **AI Sensor** handles AI workloads and traffic.
  - **AI ASM** runs continuous offensive testing of models, agents and MCP servers [sourced: https://www.upwind.io/ai-security-platform].
- **Managed service:** MDR 24/7 add-on [sourced: https://aws.amazon.com/marketplace/pp/prodview-ff3am62vjukrw].

### Integrations & workflow
- **"The Lineup" partner program:** 100+ integrations (2026-10) [sourced: https://www.upwind.io/feed/what-ive-learned-building-a-technology-partner-ecosystem].
- **Named integrations** [sourced: https://www.upwind.io/integrations]:
  - Ticketing/alerting: Jira, ServiceNow ITSM, Linear, PagerDuty, Rootly.
  - Chat: Slack, MS Teams, Google Chat.
  - SIEM: Sentinel, Sumo Logic, Panther, Coralogix, Hunters, Sekoia, Microsoft Defender.
  - SOAR: Tines, Blinkops, Mindflow, Workato, **n8n**, Zest.
  - IdP/SSO: Okta, OneLogin, JumpCloud, Ping, Entra ID, Duo.
- **Bidirectional sync:** details not public.

### Dashboards & reporting UX
- **Dashboards:** Compliance Score dashboard, Score Journey, account-level scoring [sourced: https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind].
- **Executive reporting gaps:** reviewers say exec dashboards and reporting are limited (see weaknesses).
- **Not found:** MTTR/SLA reports.

### AI assistant
- **Choppy AI** (GA 2026-01-08) [sourced: https://www.01net.it/upwind-launches-choppy-ai-introducing-transparent-natural-language-intelligence-across-its-runtime-first-cloud-security-platform]:
  - NL → **editable Query Builder expressions**.
  - NL → transparent, editable detection/misconfiguration **rules**.
  - A conversational "AI Mode" in the Vulnerability module.
- **Choppy guardrails:**
  - Every output is visible logic the user can inspect, edit and reuse.
  - Dedicated monitoring of prompts and usage patterns.
- **"Agentic Pack":** Blue (incident investigation to verdict with an evidence trail), Red (exploit validation), Green (hotspot remediation as PRs), with Choppy as the "intelligent control plane" that dispatches them [sourced: https://www.upwind.io/agentic-security].
  - This mirrors Wiz's Red/Blue/Green naming [inferred].
  - Launch date not stated.

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- **Config as code:** `terraform-provider-upwind` (Go) manages "detection policies, custom rules, access scopes, and malware indicators as code" [sourced: https://github.com/upwindsecurity].
- **Onboarding as code:** Terraform modules per cloud; Nix packaging [sourced: https://github.com/upwindsecurity].
- **SSO:** via the IdPs listed above [sourced: https://www.upwind.io/integrations].
- **RBAC:** via "access scopes" (Terraform resource) [sourced: https://github.com/upwindsecurity].
- **Multi-tenant/MSSP console:** not found [inferred].

### Unique "wow" features released 2025-2026
- **Choppy AI:** NL compiled into visible, editable Query Builder logic and rules instead of opaque answers (2026-01) [sourced: https://www.01net.it/upwind-launches-choppy-ai-introducing-transparent-natural-language-intelligence-across-its-runtime-first-cloud-security-platform].
- **Open Source Security Model:** users can modify, accept, recast and snooze risk logic in-product (2025-11) [sourced: https://businesswire.com/news/home/20251110175955/en/Upwind-Launches-Groundbreaking-Open-Source-Security-Model-Bringing-Extreme-Ownership-and-Flexibility-to-Cloud-Risk-Management].
- **Compliance "Score Journey"** plus per-finding "impact on compliance score" and difficulty; EU AI Act and ISO 42001 packs (2026-09) [sourced: https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind].
- **Snowflake role→user→bucket graph** and Cortex AI-asset inventory (2026-10) [sourced: https://www.upwind.io/feed/upwind-now-secures-snowflake-from-ai-down-to-the-storage-underneath-it].
- **Green agent "hotspots":** one change fixes many findings [sourced: https://www.upwind.io/agentic-security].
- **Inside-Out AI Security** within the CNAPP (2025-12-01) [sourced: https://www.businesswire.com/news/home/20251201781624/en/Upwind-Introduces-Inside-Out-AI-Security-Within-its-Unified-CNAPP-Platform — title only, fetch blocked].

### Documented weaknesses/complaints
- **UI navigation:**
  - "its UI is a bit difficult to navigate. I find myself getting lost many times" — AWS customer, 2026-09-17 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
  - The same complaint appears on PeerSpot (4.8/5 from only 4 reviews) [sourced: https://www.peerspot.com/products/upwind-pros-and-cons].
- **Reporting:**
  - "reporting and exec‑friendly dashboards are limited" — G2 reviewer, 2026-03 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
  - "more customizable dashboards and reporting for different teams" — AWS customer, 2026-08 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
- **Finding volume and bulk actions:**
  - "large number of vulnerability findings, which can quickly become overwhelming" — G2 reviewer, 2025-10 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
  - "Unable to bulk resolve or suppress alerts" — G2 reviewer, 2025-10 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
- **Compliance coverage:** "work to be done on the compliance front for NIST or GDPR compliance checks" — G2 reviewer, 2025-10 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
- **Sensor overhead:** "runtime sensors may require resource allocation tuning" — G2 reviewer, 2025-09 [sourced: https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw].
- **Unverified claims:** the performance figures (93% noise reduction, 15s detection) are company-only, with no independent benchmark [sourced: https://runtimewire.com/article/upwind-raising-300m-3-8b-runtime-cloud-security].

### Sources
- https://www.01net.it/upwind-launches-choppy-ai-introducing-transparent-natural-language-intelligence-across-its-runtime-first-cloud-security-platform (mirror of businesswire.com/news/home/20260108566304)
- https://businesswire.com/news/home/20251110175955/en/Upwind-Launches-Groundbreaking-Open-Source-Security-Model-Bringing-Extreme-Ownership-and-Flexibility-to-Cloud-Risk-Management
- https://www.businesswire.com/news/home/20251201781624/en/Upwind-Introduces-Inside-Out-AI-Security-Within-its-Unified-CNAPP-Platform
- https://aws.amazon.com/marketplace/pp/prodview-ff3am62vjukrw
- https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ff3am62vjukrw
- https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection
- https://runtimewire.com/article/upwind-raising-300m-3-8b-runtime-cloud-security
- https://en.globes.co.il/en/article-1001554301
- https://www.upwind.io/
- https://www.upwind.io/cnapp
- https://www.upwind.io/attack-path-exposure-analysis
- https://www.upwind.io/vulnerability-management
- https://www.upwind.io/identity-security
- https://www.upwind.io/cdr
- https://www.upwind.io/dspm
- https://www.upwind.io/api-security
- https://www.upwind.io/iac-security
- https://www.upwind.io/agentic-security
- https://www.upwind.io/ai-security-platform
- https://www.upwind.io/integrations
- https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind
- https://www.upwind.io/feed/upwind-now-secures-snowflake-from-ai-down-to-the-storage-underneath-it
- https://www.upwind.io/feed/what-ive-learned-building-a-technology-partner-ecosystem
- https://www.upwind.io/feed/aws-iam-full-request-context
- https://www.newswire.com/news/upwind-introduces-api-security-solution-with-real-time-insights-at-the-22261957
- https://github.com/upwindsecurity
- https://www.peerspot.com/products/upwind-pros-and-cons

---

## Sweet Security

### Positioning & pricing model
- Israeli startup positioned as **"Runtime CNAPP"**: runtime-first (eBPF), focused on "what is happening" rather than "what could happen". Expanded into AI security (AISP) in 2025-2026 [sourced: https://www.sweet.security/blog/raising-75m-to-build-the-future-of-runtime-and-ai-security].
- Funding: **$75M Series B on 2025-11-12**, led by Evolution Equity Partners with Munich Re Ventures, Glilot Capital, Key1 Capital and CyberArk Ventures. Total funding is **$120M** per the press release and **$125M** per the company blog (inconsistent) [sourced: https://www.sweet.security/press-releases/sweet-security-raises-75m-series-b-and-unveils-the-first-unified-runtime-cnapp-for-cloud-and-ai-security; https://www.sweet.security/blog/raising-75m-to-build-the-future-of-runtime-and-ai-security].
- Traction claims: 6x ARR YoY, 10x enterprise customers, multiple Fortune 1000 customers [sourced: press release above]. Logos include Fireblocks, Kaltura, ShipStation, Cast & Crew, Hippo, Firebolt, SafeBreach [sourced: https://www.sweet.security/].
- Pricing: **unknown/not public**. No pricing or trial on the site, and no AWS Marketplace listing was verified [sourced: https://www.sweet.security/].
- Founders: Dror Kashti (CEO), Eyal Fisher (CPO), Orel Ben Ishay (VP R&D) [sourced: Series B press release].

### Deployment
- **eBPF sensor** on Linux ("lean and efficient", per the Kaltura CISO) plus cloud log ingestion from AWS, Azure and GCP [sourced: https://www.sweet.security/runtime-cnapp; https://www.sweet.security/product/detection-response].
- **Windows sensor** (2025-10-30), written in Rust. Detects DLL injection, registry manipulation, PowerShell abuse, and does L7 request/response monitoring [sourced: https://www.sweet.security/press-releases/sweet-security-brings-runtime-cnapp-power-to-windows].
- Clouds: AWS, Azure, Google Cloud [sourced: https://www.sweet.security/integrations]. Sensor install method (Helm/DaemonSet/ECS) and serverless coverage: not public (docs login-gated) [inferred].
- Claim: "secure an entire organization in 2 hours" [sourced: https://www.sweet.security/].
- FedRAMP Moderate is **in progress** (Coalfire 3PAO), announced 2026-06-10, and **not yet authorized** [sourced: https://www.sweet.security/press-releases/sweet-security-expands-into-u-s-federal-market-pursues-fedramp-moderate-authorization].

### Inventory & graph
- "Cloud Visibility" module: inventory of clusters, networks, databases, secrets and OS. Asset status (active/inactive) and per-asset risk [sourced: https://www.sweet.security/product/cloud-visibility].
- **Runtime topology**: observed internal + external communication map, with views for unauthorized ports, external entities, malicious DNS/IP and data connections [sourced: same].
- Query language: none documented publicly [inferred: no exposed query language].

### Attack paths & toxic combinations
- **Sweet Attack** (GA 2026-05-13): an AI red-team agent that enumerates and **executes** attack chains against production in a controlled way. Inputs: runtime topology, unencrypted L7 exposure, deployed source code, identity relationships, live app behavior. It probes vulns + identity paths + permissive scopes + exposed APIs + unauthenticated endpoints step by step. Output: reproducible evidence of validated chains, the runtime conditions that enabled them, and prioritized remediation. All API calls/identities/prompts are "indexed and replayable" [sourced: https://www.sweet.security/press-releases/sweet-security-launches-sweet-attack-to-debunk-the-myth-before-mythos-ships].
- Homepage claims ">99% accuracy" for AI-verified findings, plus the "Learning Loop™" (Attack. Fix. Defend.), which feeds red-team results back into defenses [sourced: https://www.sweet.security/].
- Static graph-based attack-path scoring like Wiz/Orca: not documented [inferred].

### Risk prioritization
- Vulns are prioritized by runtime signals (loaded into memory, actively executed, internet-exposed), LLM analysis of environmental relevance, and business impact [sourced: https://www.sweet.security/product/vulnerabilities-management].
- Runtime CSPM: misconfigs are risk-ranked by exploitability, impact and likelihood, using **East-West traffic analysis** for lateral movement [sourced: https://www.sweet.security/product/runtime-cspm].
- Numeric scale, EPSS/KEV usage: not public [inferred: unknown].

### CIEM/identity
- ITDR baselines identity behavior and alerts on unauthorized access, unusual privilege escalation and irregular usage [sourced: https://www.sweet.security/product/identities-security].
- NHI discovery (service accounts, IAM users, API keys, tokens). Flags unused/dormant identities. Recommends updating "privileges according to actual usage" [sourced: same].
- JIT access: not offered per sources found. Effective-permissions calculation: not documented [inferred].

### DSPM
- "Data Security (DSPM)" is listed as a capability on the Runtime CNAPP page with no detail [sourced: https://www.sweet.security/runtime-cnapp]. AISP detects sensitive data in prompts/agent flows [sourced: https://www.sweet.security/ai-security-platform-aisp]. Classification/sampling method: not public.

### Vulnerability & secrets
- **Runtime-powered SBOM** (packages actually used) plus package reputation checks. Open-source supply-chain partnership with Illustria (2025-01-08) [sourced: https://www.sweet.security/product/vulnerabilities-management; https://www.sweet.security/resources/latest?hsLang=en].
- Languages: Java, Python, Go, Node.js, .NET, Ruby, PHP. SDLC integration links vulns back to the PR that introduced them [sourced: https://www.sweet.security/product/vulnerabilities-management].
- Agentless/registry image scanning: not documented [inferred: sensor-centric].

### Code-to-cloud / IaC
- GitHub/GitLab integrations and a Jit (code security) integration. Vulns are linked to PRs [sourced: https://www.sweet.security/integrations; https://www.sweet.security/product/vulnerabilities-management].
- IaC scanning/policy-as-code: **not documented** [sourced: https://www.sweet.security/product/runtime-cspm (absence)].

### Remediation
- Runtime CSPM gives "step-by-step instructions or one-click fixes" [sourced: https://www.sweet.security/product/runtime-cspm].
- CADR "AI-Powered Playbooks" can terminate malicious processes, with manual or automatic response [sourced: https://www.sweet.security/product/detection-response].
- Context-aware remediation guidance, "not generic checklists" [sourced: https://www.sweet.security/product/vulnerabilities-management].

### Compliance
- Named standards: HIPAA, CIS Kubernetes Benchmark, GDPR, NIST, SOC2, "AWS MITRE ATTACKS", AWS PCI, plus "pre-built compliance rules". **No total framework count published** [sourced: https://www.sweet.security/product/runtime-cspm]. Compliance looks thin next to Orca's 185+ [inferred].

### Detection & response / real-time
- Core strength. CADR unifies **CDR + ADR + CWPP** (launched 2024-12-02) [sourced: https://www.sweet.security/press-releases/sweet-security-introduces-evolutionary-leap-in-cloud-detection-and-response-releasing-first-unified-detection-response-platform].
- **Patent-pending LLM detection engine** (2025-01-14/15): cross-correlates candidate attack patterns with application/workload/cloud baselines to find the "smoking gun". Claims detection noise of **0.04%** and **2-5 minute** MTTR [sourced: https://hackread.com/sweet-security-introduces-patent-pending-llm-powered-detection-engine-reducing-cloud-detection-noise-to-0-04/].
- **Three-tier incident labels**: **Malicious** (SecOps investigate), **Suspicious** (review), and **Bad Practice** (legitimate but unusual, routed to DevOps). Also "danger zone" heat maps and problem-owner identification [sourced: same].
- **AI-generated Storyline**: an ordered incident narrative mapping processes across workloads, app data, cloud identities and logs, with executed scripts/commands and "intent behind each step" [sourced: https://www.sweet.security/product/detection-response].
- Claims: ~30s detection and 90% MTTR reduction (Kaltura) [sourced: CADR press release]. Over 1B runtime events analyzed daily [sourced: https://www.sweet.security/].
- **Agentic AI Blocking** (2026-07-29): terminates unauthorized agent tool calls/sessions at runtime, blocks secrets/PII exfiltration via agents and stops live prompt injection. Enforcement principle: "do exactly what your creator intended and nothing more" [sourced: https://www.sweet.security/press-releases/sweet-security-brings-autonomous-protection-to-the-ai-enterprise-with-new-blocking-capabilities].

### Integrations & workflow
- SIEM: Splunk, Sentinel, Chronicle, Panther, Sumo Logic, AWS Security Hub. Ticketing: Jira, ServiceNow. Chat/notify: Slack, Teams, Opsgenie, email, syslog, webhook. SOAR: Torq, Siemplify, Intezer. CI/CD: GitHub, GitLab. PAM: CyberArk (Conjur, PAM, WPM). Plus generic SSO [sourced: https://www.sweet.security/integrations].
- Bi-directional ticket sync: not documented.

### Dashboards & reporting UX
- Asset Inventory dashboard, Network Connections view, Topology view, danger-zone heat maps, incident Storyline [sourced: https://www.sweet.security/product/cloud-visibility; hackread link above].
- Sweet Attack outputs "audit-ready" reports [sourced: Sweet Attack press release]. Executive/trend/SLA reporting: not documented.

### AI assistant
- LLM sits in the detection core (verdict labeling), vuln prioritization and storyline generation. "SweetX" AI agent for cloud security is referenced on the Runtime CNAPP page but not detailed [sourced: https://www.sweet.security/runtime-cnapp].
- **AISP** (2025-11) [sourced: https://www.sweet.security/ai-security-platform-aisp; Series B press release]:
  - Shadow-AI discovery and **AI-BOM** (models, dependencies, origins, versions)
  - Agent tracing across timelines
  - AIDR through an **AI Gateway** that inspects prompts before LLM execution
  - **MCP Gateway** for per-operation, intent-based enforcement
  - "<100ms" inline guardrail enforcement [sourced: https://www.sweet.security/]
- Guardrails on Sweet's own AI (human approval, rollback): not documented.

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- SSO is supported generically [sourced: https://www.sweet.security/integrations]. Public API, CLI, Terraform provider, multi-tenancy and RBAC: **not public** (docs behind login at docs.sweet.security) [sourced: https://docs.sweet.security/ (redirects to login)].

### Unique "wow" features released 2025-2026
- 2025-01: LLM detection engine with Malicious/Suspicious/Bad Practice triage and 0.04% noise [sourced: hackread link].
- 2025-10: Rust Windows runtime sensor [sourced: Windows press release].
- 2025-11: Unified Runtime CNAPP + AISP (AI-BOM, AI Gateway, MCP Gateway) [sourced: Series B press release].
- 2026-05: **Sweet Attack**, continuous in-production exploit-chain validation with replayable L7 evidence [sourced: Sweet Attack press release].
- 2026-07: **Agentic AI Blocking** [sourced: blocking press release].

### Documented weaknesses/complaints
- No public user reviews retrieved: G2 and Gartner Peer Insights returned 403, and the search budget was exhausted [inferred: gap in evidence, not a positive signal].
- From product evidence, not reviews:
  - Compliance coverage is thin and has no count [sourced: https://www.sweet.security/product/runtime-cspm]
  - No IaC/policy-as-code [sourced: same]
  - No query language or public API docs (login-gated) [sourced: https://docs.sweet.security/]
  - FedRAMP not yet authorized [sourced: FedRAMP press release]
  - Sensor-dependent coverage means assets without a sensor get only cloud-log/CSPM depth [inferred]
- Inconsistent public numbers: total funding $120M vs $125M, MTTR "5 minutes" vs "2-5 minutes" [sourced: Series B press release vs blog; runtime-cnapp vs hackread].

### Sources
- https://www.sweet.security/
- https://www.sweet.security/runtime-cnapp
- https://www.sweet.security/product/detection-response
- https://www.sweet.security/product/vulnerabilities-management
- https://www.sweet.security/product/identities-security
- https://www.sweet.security/product/runtime-cspm
- https://www.sweet.security/product/cloud-visibility
- https://www.sweet.security/product/api-security
- https://www.sweet.security/ai-security-platform-aisp
- https://www.sweet.security/integrations
- https://www.sweet.security/resources/latest?hsLang=en
- https://www.sweet.security/press-releases/sweet-security-raises-75m-series-b-and-unveils-the-first-unified-runtime-cnapp-for-cloud-and-ai-security
- https://www.sweet.security/blog/raising-75m-to-build-the-future-of-runtime-and-ai-security
- https://www.sweet.security/press-releases/sweet-security-brings-autonomous-protection-to-the-ai-enterprise-with-new-blocking-capabilities
- https://www.sweet.security/press-releases/sweet-security-launches-sweet-attack-to-debunk-the-myth-before-mythos-ships
- https://www.sweet.security/press-releases/sweet-security-brings-runtime-cnapp-power-to-windows
- https://www.sweet.security/press-releases/sweet-security-expands-into-u-s-federal-market-pursues-fedramp-moderate-authorization
- https://www.sweet.security/press-releases/sweet-security-introduces-evolutionary-leap-in-cloud-detection-and-response-releasing-first-unified-detection-response-platform
- https://hackread.com/sweet-security-introduces-patent-pending-llm-powered-detection-engine-reducing-cloud-detection-noise-to-0-04/
- https://www.businesswire.com/news/home/20251112389882/en
- https://docs.sweet.security/

---

## Best-in-class per capability (this cluster)

| Capability | Vendor | What makes it best | Source |
|---|---|---|---|
| Agentless workload scanning | Orca | SideScanning reads block storage out-of-band and rebuilds a read-only filesystem. It covers Linux/Windows VMs, containers and serverless on AWS/Azure/GCP/OCI/Alibaba with no agent. Agentless "could be executed" reachability is layered on top. | https://orca.security/platform/agentless-sidescanning/ ; https://orca.security/resources/press-releases/orca-security-reduce-vulnerabilities-agentless-analysis/ |
| Inventory query language | Sysdig (SysQL) | A Cypher-like `MATCH/OPTIONAL MATCH/WHERE` graph language over inventory and findings together. It has an API, a "Simplified SysQL" form, NL→SysQL (Sage), and a read-only MCP skill. Runner-up: Lacework LQL, which is SQL-like with joins and semi-joins and backs alerting policies. | https://docs.sysdig.com/en/sysdig-secure/sysql-reference/ ; https://docs.fortinet.com/document/forticnapp/latest/lql-reference/598361/lql-overview |
| User-defined toxic combinations | Sysdig | "Risk definitions" are SysQL queries with one **anchor resource**. Each comes in a Managed and a Custom variant, auto-closes when the condition clears, and carries "Live" (runtime event under 3h old) and "New" (under 7d old) badges. Cortex adds a "Search" button that tests a rule against the live estate before saving. | https://docs.sysdig.com/en/sysdig-secure/risks/ ; https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/rules-and-policies/cloud-security-rules-and-policies/create-and-manage-cloud-security-rules/create-an-attack-path-rule |
| Attack-path proof / validation | SentinelOne (Verified Exploit Paths) | The Offensive Security Engine safely probes exposures. Each verified issue has an **"Exploit Evidence"** tab beside "Finding". Sweet Attack (2026-05) goes further, running chains in production with replayable evidence, but it needs a sensor. | https://www.sentinelone.com/platform/singularity-cloud-native-security/ ; https://www.sweet.security/press-releases/sweet-security-launches-sweet-attack-to-debunk-the-myth-before-mythos-ships |
| Multi-hop attack paths | Cortex Cloud 2.2 | "Graph-powered attack path detections" combine access rules, AI pathfinding and Unit 42 intel across identities, code, data and workloads. Identity permission chains appear in Graph Search for AWS, Azure and GCP. | https://www.paloaltonetworks.com/blog/cloud-security/cortex-cloud-2-2/ |
| Risk-score explainability | FortiCNAPP | A 0-10 score with published bands (Critical ≥9.7, High ≥8.0, Medium ≥6.8, Low ≥2.0). Risk = the max over the paths the resource sits on. A **Factors** icon set and an explainability dialog show the top 3 paths with per-node breakdown. "No data" yields no score rather than 0. Since 2026-09 an inline NGFW lowers the score, with its own explainability entry. | https://docs.fortinet.com/document/forticnapp/latest/administration-guide/630805/explorer-risk-score ; https://docs.fortinet.com/document/forticnapp/latest/release-notes/959740/september-2026-platform-releases |
| Vulnerability prioritization score | Cortex (CVRS) | 0-100, refreshed daily. Factors: CVSS, EPSS, KEV, exploited-in-the-wild, exploit maturity, internet exposure, package-in-use and compensating controls. Each issue has an Evidence summary and a Risk Details breakdown. | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/vunerability-management/cortex-vulnerability-risk-score |
| Reachability | Orca | Three tiers: agentless (could execute), dynamic via the eBPF sensor (loaded or executed), and code (the vulnerable function is called; added 2026-03). Each is a filterable field, alongside the loaded file path. Sysdig "In Use"/RBOM is close but excludes .NET, PHP and Rust. | https://orca.security/resources/blog/dynamic-reachability-analysis/ ; https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/ ; https://docs.sysdig.com/en/sysdig-secure/risk-spotlight/ |
| Least-privilege generation | Cortex Cloud | "Review Unused Permissions" uses audit logs plus Access Advisor. It shows Remove and Keep counts, and **Adjust Policy** outputs a right-sized policy as JSON, Terraform or CloudFormation. FortiCNAPP adds a per-fix "% entitlements removed" and a before/after table. Sysdig offers three strategies: detach, consolidate, or swap role. | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cortex-cloud-identity-security/achieve-the-principle-of-least-privilege-access ; https://docs.fortinet.com/document/forticnapp/latest/administration-guide/625353/excessive-privilege-risk-remediation ; https://docs.sysdig.com/en/sysdig-secure/identity/ |
| JIT access | Orca | The only vendor in this cluster with documented JIT: time-bound, role-specific AWS grants with a two-way Slack request/approve flow and an audit log. | https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/ |
| DSPM | Cortex Cloud | Six built-in data profiles plus custom ones, and OCR on by default. It "masks three samples per pattern per object", and data is masked before it leaves the customer environment. Coverage includes SaaS (Drive, M365, Teams, Salesforce, Claude), Databricks, on-prem DBs, and S3 Vectors/Bedrock. | https://cortex-docs.paloaltonetworks.com/cortex-xsiam/cloud-security/cortex-cloud-data-classification |
| Secrets | SentinelOne | 850+ secret types, each **validated for active use** rather than only pattern-matched. | https://www.sentinelone.com/platform/singularity-cloud-native-security/ |
| Code-to-cloud lineage | Cortex Cloud | The **Code-to-Cloud Coverage** dashboard shows *where lineage is missing* (untraced SDLC stages) and offers one-click fixes ("Enable Tagging Bot" for Yor, "Onboard Pipeline"). | https://cortex-docs.paloaltonetworks.com/cortex-cloud-posture-management/code-to-cloud/code-to-cloud/execute-remediation-workflows |
| Security inside AI coding agents | Sysdig (Headless) / FortiCNAPP | Sysdig ships its workflows as `npx skills` for Claude Code, with weekly skill drops and an MCP server that hides tools the token can't use. FortiCNAPP's Claude Code plugin scans only changed files, auto-fixes critical and high findings, and blocks the commit. | https://www.sysdig.com/press-releases/sysdig-headless-cloud-security ; https://github.com/sysdiglabs/sysdig-mcp-server ; https://docs.fortinet.com/document/forticnapp/latest/release-notes/499403/august-2026-platform-releases |
| Remediation orchestration | Wiz (Workflows + Green Agent) | Fixes are gated by confidence. High-confidence verdicts auto-run (e.g. block S3 public access); lower-confidence ones go to the owner in Slack for approval. Runtime response policies use **Simulate→Block** modes. | https://www.wiz.io/blog/introducing-wiz-agents ; https://www.wiz.io/ja-jp/blog/custom-runtime-rules-and-response-policies |
| Remediation completeness | Orca (Missions) | Findings are grouped into goal-based missions with completion criteria. A mission closes only when a rescan verifies the objective, and it shows the projected and actual security-score delta. Closing the linked Jira ticket triggers a rescan. | https://orca.security/resources/blog/rsac-2026-agentic-ai-announcements/ ; https://orca.security/partners/technology/jira-by-atlassian/ |
| Remediation plan content | CrowdStrike | AI-Enhanced Remediation plans include: steps ordered by risk reduction, time estimates and confidence, the **permissions required** for each action, **validation checks**, and **compensating controls** for when the fix needs downtime. | https://www.crowdstrike.com/en-us/blog/falcon-cloud-security-third-party-app-insights-ai-enhanced-remedation/ |
| Fix grouping | Upwind (Green agent) | Root-causes findings into **"hotspots where single changes fix multiple issues"** and delivers each as a PR. | https://www.upwind.io/agentic-security |
| Compliance breadth | Orca | 185+ frameworks and CIS benchmarks, and 2,500+ controls. Cortex lists 151 standard rows; Wiz has 100+ cloud frameworks plus 60+ host benchmarks. | https://orca.security/platform/cloud-infrastructure-entitlement-management-ciem/ ; https://wiz.io/blog/compliance-made-easy-with-wiz |
| Custom compliance | SentinelOne | "Create framework" builds a control → sub-control → rule tree. You can blend controls from 45+ frameworks with custom rules, assign owners by business unit or geography, and schedule reports. | https://www.sentinelone.com/blog/custom-compliance-for-cloud-security/ |
| Compliance progress UX | Upwind | Each finding shows its "potential impact on compliance score", how many resources it affects, and its **difficulty (Easy→Hard)**. A **Score Journey** timeline tracks progress. EU AI Act and ISO 42001 packs are included. | https://www.upwind.io/feed/introducing-the-new-configurations-experience-in-upwind |
| Runtime CDR & response | Sysdig | Falco/eBPF detection with the 5/5/5 benchmark. Cloud Response Actions (EBS snapshot, IAM quarantine, remove public access) are available from the resource drawer, with a **Response History** audit page. | https://docs.sysdig.com/en/release-notes/saas-sysdig-secure-release-notes ; https://sysdig.com/555-benchmark/ |
| Alert noise handling | Sweet | An LLM detection engine labels every incident **Malicious / Suspicious / Bad Practice**. Bad Practice goes to DevOps, not the SOC. The vendor claims 0.04% noise. | https://hackread.com/sweet-security-introduces-patent-pending-llm-powered-detection-engine-reducing-cloud-detection-noise-to-0-04/ |
| Explainable anomaly detection | FortiCNAPP (Polygraph v2) | A graph neural network over identities, API actions, resources and IPs. Every anomaly renders the relationships that caused it. | https://docs.fortinet.com/document/forticnapp/latest/release-notes/163169/july-2026-platform-releases |
| Threat-intel context on posture | CrowdStrike | Each cloud risk is tagged with the 280+ named adversary groups that use that technique and that target your industry (beta, 2026-03). | https://www.crowdstrike.com/en-us/blog/crowdstrike-advances-cnapp-with-industry-first-adversary-informed-risk-prioritization/ |
| Root-cause over time | CrowdStrike (Timeline Explorer) | Rebuilds how a cloud risk formed by linking config and app changes over time (beta). | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-industry-first-adversary-informed-cloud-risk-prioritization-to-stop-ai-powered-adversaries/ |
| Home dashboard | Cortex (Cloud Command Center) | Widgets: Provider Health %, Asset Class Distribution (total vs at-risk), Active Threat Cases (created vs resolved trend), Posture Cases (manual/auto remediation markers), Vulnerability Summary (weaponized, fix-available), Top Risky Vulns (CVSS+EPSS), Compliance Summary, Standards Status. | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/dashboards-and-reports/monitor-dashboards-and-reports/dashboard-reference/command-center-reference/cortex-cloud-command-center |
| Executive / financial risk | Aqua (FAIR dashboard) | Annual loss expectancy in dollars per business unit, from a 4-layer control model. Only controls in Enforce mode reduce risk, and residual risk is recalculated as controls change. | https://www.aquasec.com/blog/how-do-you-measure-fair-risk-in-the-mythos-era/ |
| AI assistant transparency | Upwind (Choppy AI) | Natural language is compiled into **editable** Query Builder expressions and rules, never an opaque answer. | https://www.01net.it/upwind-launches-choppy-ai-introducing-transparent-natural-language-intelligence-across-its-runtime-first-cloud-security-platform |
| AI agent guardrails | Cortex AgentiX | Agents run with the invoking user's RBAC and SBAC and can use only the actions assigned to them. "Sensitive" actions always need explicit approval. A plan view shows the interpreted input, steps, actions and JSON artifacts, and every action lands in an audit dataset. | https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/get-started/agentic-ai-in-cortex-cloud/agentic-assistant-security |
| Coverage honesty / onboarding | FortiCNAPP | The Agentless dashboard shows per-account and per-resource scan status with a **failure reason**. Onboarding has pre-flight checks, a deployment history, and **rollback** that removes what was deployed. | https://docs.fortinet.com/document/forticnapp/latest/release-notes/499403/august-2026-platform-releases ; https://docs.fortinet.com/document/forticnapp/latest/release-notes/163169/july-2026-platform-releases |
| Config-as-code | Orca | A Terraform provider manages users, Business Units, saved views, custom dashboards, alert rules, automations and RBAC. Upwind's provider covers detection policies, rules and access scopes. | https://orca.security/resources/blog/expanding-cloud-security-automation-orca-terraform/ ; https://github.com/upwindsecurity |
| Multi-tenant / MSP | Wiz (Tenant Manager) | Smart tenant groups, global baseline policies with local overrides, and one-click **audited** tenant access. It also has a consumption-billed MSP program with no upfront commitment (preview). | https://www.wiz.io/ko-kr/blog/wiz-tenant-manager-multi-tenant-security ; https://www.channelinsider.com/security/news-wiz-msp-program-managed-cloud-ai-security/ |
| Vuln freshness | Aqua | **Smart rescan**: unchanged image digests are checked against newly published CVEs without re-pulling the image. | https://www.aquasec.com/blog/can-vulnerability-scanning-tell-you-what-youre-exposed-to-right-now/ |
| Pricing transparency | Cortex / Wiz | Cortex publishes its workload conversion ratios (e.g. 10 buckets = 1, 2 PaaS DBs = 1), averaged over 90 days. Wiz publishes AWS Marketplace list prices: Essential $24k and Advanced $38k per 100 workloads per year. | https://cortex-docs.paloaltonetworks.com/r/Cortex-CLOUD/Cortex-Cloud-Runtime-Security-Documentation/Understand-license-plans ; https://aws.amazon.com/marketplace/pp/prodview-5geds7fc2wk7m |

**Cross-cluster complaints**

These are the gaps nimbus can use. The same five complaints come up for almost every vendor:
1. **Price.** Reported for Wiz, Prisma, CrowdStrike, SentinelOne and Aqua.
2. **Noisy first scans and heavy tuning.** Reported for Wiz, Orca, Aqua and Prisma.
3. **Weak, uncustomizable executive dashboards and reports.** Reported for Wiz, Upwind, SentinelOne, Sysdig and Aqua.
4. **Confusing UI and navigation.** Reported for Upwind, CrowdStrike, Lacework, Sysdig and Aqua.
5. **Workflow gaps.** Reviewers mention missing bulk actions (Upwind), one-way ticketing (Aqua) and the hard-to-use RQL query language (Prisma).

A transparent, cheap, low-noise tool with good reports and a published query language competes directly on all five ([sourced: the per-vendor "Documented weaknesses" sections above]).

---

## Features nimbus should steal (ranked)

Ranking weighs (a) fit with nimbus's agentless, graph, IaC, SQL and copilot design, (b) user-visible impact, and (c) build cost. Items that only *extend* a decision already in `competitors.md` say so. Nothing here repeats min-cut, path-diff-in-PR, PR template, expiring mutes, Jira auto-close-on-fix, evidence bundles or Memories, which are already planned there.

| # | Feature | User-visible behaviour | From | Why it matters |
|---|---|---|---|---|
| 1 | **Risk explainability dialog** (extends competitors.md §2 chips) | `nimbus explain <issue>` and the UI "Why?" button show a factor breakdown and the **top 3 paths** behind the score, with per-node contributions. Compensating controls show as negative chips (e.g. `WAF in front −1.2`, `SG restricts to corp CIDR −2.0`). Missing data shows "not scored", never 0. | FortiCNAPP | The clearest public explainability model in the cluster. It turns nimbus's published-formula promise into a UX, and covers compensating controls, which nimbus's multiplier model lacks. |
| 2 | **User-authored toxic-combination rules** | Users drop `rules/risks/*.yaml` containing an openCypher/SQL graph query plus `anchor: <resource type>`. Matches become Issues with Open / In-Progress / auto-Closed status, a **New** badge (<7d) and a **Live** badge (an event in the last 3h). `nimbus risk test <file>` previews matches against the current snapshot before the rule is enabled. | Sysdig, plus the Cortex "Search before save" button | Toxic combinations become extensible community content, as Prowler did for checks. No closed vendor can match an open rule library. |
| 3 | **Unused-permission checkup → right-sized policy** | For each role, user or SA: Keep/Remove counts from CloudTrail and Access Advisor over 90 or 180 days, and **"% entitlements removed"** for each candidate fix (detach, remove actions, add explicit Deny, swap to a managed role). Output is policy JSON, a **Terraform/CFN diff**, or a PR. | Cortex, FortiCNAPP, Sysdig | CIEM least privilege is table stakes across the cluster. Emitting the fix as IaC is nimbus's core strength. |
| 4 | **Remediation hotspots** | A "Fix once, close many" view groups findings by shared root cause (Terraform module, base image, IAM policy, SG). It ranks them by findings closed × severity, with one PR per hotspot. | Upwind | It is what people actually want from a findings list, and it pairs naturally with the min-cut work. |
| 5 | **Reachability tier field** | Every vuln finding gets `reachability: installed \| potentially_loaded \| executed \| function_called` plus the evidence (loaded path, entrypoint). Agentless nimbus computes `potentially_loaded` from image entrypoint, service units and process manifests. Higher tiers are imported from runtime or SCA tools (Falco, Tetragon, SARIF). The default queue sorts by tier, then KEV, then EPSS. | Orca (3 tiers), Sysdig (In Use) | Reachability is the biggest noise-cut lever in vuln management. Agentless reachability is something an agentless tool can actually deliver. |
| 6 | **Validated secrets** | Secrets found in repos, images, IaC or user-data are checked with harmless identity calls (`sts:GetCallerIdentity`, GitHub `/user`, Slack `auth.test`). The result is `Active`, `Revoked` or `Unverifiable`. This is opt-in and rate-limited; the secret value is never stored and only a hash is logged. | SentinelOne | Dead keys stop wasting triage time, and a live key becomes a verified, critical attack-path entry point. |
| 7 | **Structured remediation plan** (extends competitors.md §3/§6 schema) | Every fix, whether from a template or AI, renders: ordered steps, **IAM actions required to apply**, a **post-fix validation query** that nimbus re-runs, a **temporary mitigation** for when the real fix needs downtime, an effort estimate and a confidence level. | CrowdStrike | Engineers need to know "can I even apply this, and how do I know it worked?". The validation query also closes the loop for Missions (#8). |
| 8 | **Missions with verified completion + ticket-close rescan** | Users group Issues into a goal (e.g. "no public buckets with PII"), see the projected score delta, and the mission closes only when nimbus re-verifies it. Moving a linked Jira ticket to Done triggers a targeted rescan; if the issue still fails, the ticket reopens with "still failing" and evidence. | Orca | Goal-oriented work gives managers a burndown and stops tickets from being closed without verification. |
| 9 | **Confidence-gated automation + simulate mode** | Each automation rule has a `mode: simulate \| approve \| auto` and a `min_confidence`. In simulate mode it logs what it *would* have done. Below the confidence threshold, it posts Approve/Reject buttons to Slack or Teams. Above it, it runs (only with `--apply` configured). Every action goes to an audit log. | Wiz (Workflows, Simulate→Block); Aqua (vShield Audit→Enforce) | This is how teams safely adopt auto-remediation, and it fits nimbus's "never write without consent" guardrails. |
| 10 | **Risk timeline / root cause** | Each Issue gets a timeline tab that merges CloudTrail, Activity Log and Audit Log write events with the IaC commits (via `nimbus_trace`) that created each condition in the toxic combination. The earliest change that introduced it is highlighted, with author and PR. | CrowdStrike (Timeline Explorer) | It answers "who or what caused this?", the first question in every review. nimbus already ingests these events (competitors.md §9). |
| 11 | **Code-to-cloud coverage gap view** | A dashboard shows the % of live resources traced to IaC at each stage (repo → plan/state → deployed). An "Untraced" list has one-click actions: add a `nimbus_trace` tag, connect a state backend, import a block for ClickOps. | Cortex | Makes the reliability of nimbus's fix PRs visible, and shows exactly how to raise it. |
| 12 | **Compliance impact + difficulty ranking and Score Journey** | Each failing control shows "+X% to <framework> if fixed", the number of resources affected, and an Easy/Med/Hard tag (derived from the fix template type). A per-framework timeline annotates which fixes moved the score. | Upwind | Turns compliance from a pass/fail wall into a prioritized plan. It answers the "weak reporting" complaints. |
| 13 | **Custom framework builder** (extends competitors.md §8 YAML mapping) | `nimbus framework new --from cis-aws-3.0,nist-800-53 --add rules/custom/*.sql` builds a control → sub-control → rule tree, with an owner per control and scheduled PDF/CSV. Built-in frameworks are read-only and you clone them to edit. | SentinelOne, FortiCNAPP, Cortex | Every enterprise has its own internal framework. Cloning plus blending is the pattern all three converge on. |
| 14 | **Scanner coverage with failure reasons + onboarding rollback** (extends competitors.md §5 honesty panel) | A per-account and per-resource scan status shows *why* a scan failed (AccessDenied on `ec2:CreateSnapshot`, KMS key policy, region disabled). `nimbus onboard` records a deployment manifest, and `nimbus offboard --rollback` removes every role, stack and trail it created. | FortiCNAPP | Builds trust for an agentless tool that needs cross-account roles. Clean rollback lowers the risk of trying nimbus. |
| 15 | **Agent skills + token-scoped MCP server** | Ship `nimbus-mcp` (read-only by default) whose tool list is filtered by the token's RBAC. Add Claude Code/Cursor skills: query the graph, explain an issue, draft a fix PR, and a pre-commit hook that scans only changed IaC and blocks on critical findings. | Sysdig (Headless, SysQL Skill), FortiCNAPP (Claude Code plugin) | Developers increasingly work inside agents, and the leaders shipped this in 2026. Being OSS is a natural advantage here. |
| 16 | **Copilot guardrail contract** (extends competitors.md §6) | The copilot runs as the invoking user's RBAC. Actions tagged `sensitive` always need explicit approval. Each answer shows a **plan view** (interpreted question → steps → tools → JSON artifacts). Every agent action goes into `nimbus.agent_audit`, which can be queried with SQL. | Cortex AgentiX | The most complete guardrail spec published in the cluster. It is cheap to adopt and makes AI features acceptable to security buyers. |
| 17 | **Smart re-evaluation on CVE feed updates** | When the vuln DB (OSV, NVD, KEV, EPSS) updates, nimbus re-matches stored SBOMs by image or AMI digest without re-snapshotting. New findings get the tag "first seen via feed update". | Aqua | Agentless snapshots are expensive. This gives near-real-time CVE exposure at almost no cost. |
| 18 | **Identifier-paste search without an LLM** | Pasting an ARN, resource ID, CVE, IP, CIDR or port into the search box auto-detects the type and jumps to a pre-built query. Keyword phrases ("exposed mongodb", "aws critical vulns") map to query templates, with the inferred filters shown before running. | FortiCNAPP | Gives most of NL search's value offline and deterministically. It matches nimbus's "useful without an LLM" principle. |
| 19 | **Exposure verification probes (opt-in)** | For graph-flagged public endpoints (open `.git/`, public bucket listing, unauthenticated admin/K8s API, open DB port), nimbus runs a safe, read-only, rate-limited probe. The request and response are attached as **Exploit Evidence**, and the Issue is promoted to `verified`. | SentinelOne (Verified Exploit Paths) | Turns "possible" into "proven" for the riskiest Issues, which is the strongest argument against alert fatigue. It must be opt-in with a scope allowlist. |
| 20 | **ATT&CK technique + threat-group tags** | Each rule maps to MITRE ATT&CK (Cloud) techniques. Using the open ATT&CK groups dataset, findings show "technique used by N known groups" and can be filtered by group or industry. | CrowdStrike (adversary-informed risk) | Adds threat context from open data. It also helps SOC teams that think in ATT&CK. |
| 21 | **Three-bucket finding verdicts** | Detections and posture alerts carry `verdict: malicious \| suspicious \| bad_practice`. Routing rules send `bad_practice` to the owning DevOps team (from CODEOWNERS or tags) and keep it out of the SOC queue. | Sweet | A simple taxonomy that cuts SOC noise. It slots straight into the YAML routing rules (competitors.md §9). |
| 22 | **FAIR-style $ risk per business unit** (extends competitors.md §7) | Optional `business_units:` config with an asset value and loss estimate per tag. A dashboard shows ALE per BU and the residual ALE after enforced controls. Every input is visible, and only *enforced* controls (not audit-only) reduce risk. | Aqua | Answers the cluster-wide "weak exec reporting" complaint with defensible, editable math. |
| 23 | **Supply-chain threat center** | A feed of compromised packages, actions and images (e.g. the 2026-03 trivy-action tag hijack) with an automatic "am I affected?" query over stored SBOMs and CI workflow files. Also base-image allow/deny lists. | Cortex 2.2; Sysdig (Base Image Allow/Deny) | High-attention events drive adoption, and nimbus already holds the SBOM and IaC data to answer them. |
| 24 | **Config-as-code for nimbus itself** | A Terraform provider (or a fully declarative `nimbus.yaml`) for rules, mutes, frameworks, routing, business units, dashboards and RBAC, checked into git and reviewed via PR. | Orca, Upwind (Terraform providers) | Platform teams expect every tool to be GitOps-managed. It also yields an audit trail for free. |

**A lesson, not a feature**

nimbus's own release pipeline should use immutable releases, SHA-pinned GitHub Actions, and credential rotation done all at once, not in stages. The 2026-03 Trivy compromise came from staged rotation, and the attacker force-pushed 76 of 77 `trivy-action` tags. An OSS security tool that ships through GitHub Actions is the same kind of target ([sourced: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23]).
