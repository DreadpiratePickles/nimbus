# Competitor Research — Hyperscaler-native & Security-platform CSPMs

_Research date: 2026-10-09. Extends (does not repeat) [`../competitors.md`](../competitors.md), which already covers Defender's attack-path UX, the SCC Risk Engine formula, Datadog Inbox ordering/suppressions/Jira sync, Tenable's "toxic cloud trilogy", and the general nimbus design decisions. Each vendor section uses the same 19 subsections. Every claim is tagged `[sourced: URL]` or `[inferred]`; numbers appear only if a source states them._

_Method & limits: research fanned out to five parallel research agents using WebSearch/WebFetch on official docs, release notes, pricing pages and press. G2, Gartner Peer Insights, TrustRadius, Capterra and Reddit returned HTTP 403 or were not fetchable during this session, so complaint quotes come mostly from **PeerSpot**, plus documented limits and deprecations. The shared web-search budget ran out partway through, so some later sections rely on direct doc fetches. A few items are marked "via search snippet" where the page itself could not be loaded._

## Market state at a glance (Oct 2026)

| Vendor | Status / trajectory | Public price meter |
|---|---|---|
| Microsoft Defender CSPM + Exposure Mgmt | Cloud posture became part of Exposure Management in the Defender portal (GA 2026-05-05). There are now two Secure Score models (the risk-based score only in the Defender portal) | $0.007 per billable resource-hour (≈$5.11/resource/mo, derived); Foundational CSPM free |
| Google SCC | Retreating to GCP-only: the multicloud Enterprise tier was deprecated 2026-05-21 (shutdown 2027-05-21) and SCC DSPM was deprecated 2026-09-14. Wiz (acquisition closed 2026-03-11) is now Google's multicloud CNAPP | Premium 5% of annual GCP spend (min $15k/yr) or $0.0071 per vCPU-hour |
| AWS Security Hub | New "Security Hub" (GA 2025-12-02) handles exposures and correlation; the old product was renamed "Security Hub CSPM". Azure is GA for a limited scope; no GCP | $3.75 per resource unit per month plus per-check CSPM, across about 8 meters |
| Datadog Cloud Security | Agent-plus-observability-led; Security Graph is AWS-only Preview | CSM Pro $10 / Enterprise $25 per host per month (annual) |
| Tenable Cloud Security | Identity-led (CIEM/JIT) inside Tenable One; Hexa AI agent fleet | Private offer only |
| Rapid7 Exposure Command | InsightCloudSec now ships as the cloud layer of Exposure Command; DSPM and runtime come from partners | Older page via search snippet: $7 / $23 / $49 per asset (unverified) |
| Qualys TotalCloud | VM-heritage CNAPP inside ETM; named AI-agent workforce | Qualys Units (QLU) per resource type; non-compute resources free; $/QLU not public |
| Zscaler Posture Control | **End-of-Sale 2025-03-15, End-of-Life 2026-03-15**; customers moved to Zscaler DSPM and UVM/Risk360 | n/a |
| Sonrai Security | Narrowed to CIEM *enforcement* (Cloud Permissions Firewall) plus the WALLy agent | $150 per account per month, $15k/yr minimum |
| JupiterOne | Graph CAASM; rebranded "AI Risk Management Platform" (May 2026) | $25k / $50k / $100k tiers by ingested datapoints |
| Check Point CloudGuard | CNAPP customers being moved to **Wiz** (partnership Feb 2025, combined offer GA 2025-10-15); API still live | Unknown publicly |

**Takeaway for nimbus [inferred]:** this cluster is consolidating fast. Two products are gone, one hyperscaler has pulled back to its own cloud, and AWS and Microsoft are only partly multicloud. Customers left on discontinued or single-cloud CSPMs are an opening for an open-source, multicloud, explainable tool. The recurring complaints are cost, dense or dated UIs, hard-to-use reporting, and opaque scores. Each of these is something nimbus can address.

---

## Microsoft Defender for Cloud (Defender CSPM) + Microsoft Security Exposure Management

### Positioning & pricing model
- There are two CSPM tiers. **Foundational CSPM is free** (asset inventory, MCSB recommendations, Secure Score, workflow automation, export, Workbooks). **Defender CSPM is paid** and adds attack paths, cloud security explorer, risk prioritization, governance, DSPM, AI-SPM, API posture, EASM, regulatory compliance packs, custom recommendations, and agentless VM vuln/secrets scanning. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management]
- **List price.** The Azure Retail Prices API lists the "Microsoft Defender CSPM / Standard Node" meter at **$0.007 per billable resource per hour** (US Gov: $0.00875/hr). At 730 h/month that works out to about **$5.11 per billable resource per month**. The marketing pricing page renders prices client-side ("$-"), so its numbers couldn't be read directly. [sourced: https://prices.azure.com/api/retail/prices?$filter=contains(productName,'CSPM') ; https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/] [inferred: monthly conversion]
- **Billable meter.** Only these resource types are billed:
  - Azure: VMs/VMSS (deallocated and Databricks VMs excluded), storage accounts that have blob containers or file shares, SQL/PG-flex/MySQL-flex/Synapse.
  - AWS: EC2, S3, RDS.
  - GCP: Compute and instance groups, buckets (Nearline/Coldline/Archive excluded), Cloud SQL.
  - Add-ons: **Serverless protection** (Functions/Web Apps/Lambda) has been billed since 2026-04-01, with **1 billable unit = 8 Lambda functions**. **Serverless containers** (ACA/ACI/ECS-Fargate) have been billed since 2026-07-01, with **1 unit = 2 Fargate workloads**.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management]
- **Other meters** (retail API, eastus): Defender for Servers P1 $0.00672/hr and P2 $0.02/hr per node; Containers $0.00941 per vCore-hr; AI Services $0.0008 per 1K tokens; EASM $0.011 per asset. There is a 30-day free trial and 1-year pre-purchase commit units at a 10–22% discount. [sourced: https://prices.azure.com/api/retail/prices ; https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/]
- **Exposure Management (MSEM)** has no separate SKU. It comes with M365 E5, E3 plus add-ons, or the "Microsoft Defender suite". Non-Microsoft **data connectors are free in preview and will be consumption-priced per asset retrieved at GA**. It runs in the public cloud only, with no GovCloud. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/prerequisites]
- **Strategic shift.** CSPM was folded into MSEM in the Defender portal (preview Nov 2025, **GA 2026-05-05**). The new risk-based Cloud Secure Score is available **only in the Defender portal**, while the classic score stays in the Azure portal. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]

### Deployment
- **Agentless connectors** cover Azure subscriptions, AWS accounts/orgs (CloudFormation), and GCP projects/orgs (onboarding script). Hybrid machines come in via Azure Arc. DevOps connectors cover GitHub Enterprise Cloud (not data-residency instances), Azure DevOps, and GitLab SaaS. External registries supported are Docker Hub and JFrog Artifactory Cloud (GA 2025-11-03). [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/devops-support]
- **Agentless VM scanning** snapshots root and data disks and analyzes them out-of-band in the same region. Snapshots are kept for "typically a few minutes". It uses a scoped role per cloud: Azure "VM scanner operator", AWS `VmScanner` with snapshot actions tag-conditioned on `CreatedBy=Microsoft Defender for Cloud`, and GCP `roles/MDCAgentlessScanningRole`. CMK/CMEK disks are supported. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection]
- **Agent/sensor options:** the MDE agent (Defender for Servers), the Defender for Containers sensor via Helm (outbound to `*.cloud.defender.microsoft.com:443`), and admission control for gated deployment on AKS/EKS/GKE. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **MSEM data freshness.** Microsoft data lands in the exposure graph **within 72 h**. It is retained **for at least 14 days, latest snapshot only, no history**. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/prerequisites]

### Inventory & graph
- **Two graphs.**
  - (1) The **cloud security graph** in Defender for Cloud. It covers assets, connections, lateral movement, internet exposure, permissions, network, and vulnerabilities. It is queried via the **Cloud Security Explorer**, a no-code query builder with dropdown entity/sub-filter chains, **query templates ("Open query")**, **Share query link**, and **Download CSV report**. Snapshots refresh **daily**. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/how-to-manage-cloud-security-explorer]
  - (2) The **enterprise exposure graph** in MSEM. It spans endpoints, identities, cloud, OT, and 3rd-party connectors, and is exposed in Advanced Hunting as the `ExposureGraphNodes` (`NodeId, NodeLabel, NodeName, Categories, NodeProperties, EntityIds`) and `ExposureGraphEdges` tables. [sourced: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-exposuregraphnodes-table]
- **Query language: KQL with graph operators** (`make-graph`, `graph-match`, variable-length `*1..3`). Documented example [sourced: https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph]:
  ```kusto
  ExposureGraphEdges
  | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
  | graph-match (IP)-[anyEdge*1..3]->(VM)
      where set_has_element(IP.Categories,"ip_address") and set_has_element(VM.Categories,"virtual_machine")
      project IpIds=IP.EntityIds, VmProps=VM.NodeProperties.rawData
  ```
  - Node labels are cloud-native type strings (e.g. `microsoft.compute/virtualmachines`, `aws.*`, `gcp.*`). Edge labels include `Can Authenticate As` and `CanRemoteInteractiveLogonTo`. Property flags include `exposedToInternet`, `vulnerableToRCE`, `IsInternetFacing`, and `criticalityLevel`.
  - The docs give an indexing tip: use `has` plus `set_has_element`, because `isnotnull()` on dynamic columns skips the index. [same source]
- **ARG/KQL for posture data.** The `SecurityResources | where type == 'microsoft.security/securescores'` query is documented. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls]
- **Attack Surface Map / Exposure map.** Has a **Layers** toggle, including a "Discovery Sources" layer showing which product reported each asset. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new]
- **Coverage numbers.** The June 2026 GA added **~90 AWS/GCP resource types and 200+ recommendations** (e.g. EMR, Neptune, DMS, FSx, Kinesis, Cognito). In the Defender portal, all discovered resources are listed even when they have no findings; the Azure portal lists only assets with issues. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]

### Attack paths & toxic combinations
- **Path model.** A path starts **only at an external entry point**, then follows lateral movement via attached identities and permissions, plain-text keys, and network reachability to a critical target. The algorithm is proprietary. Paths cover storage, containers, serverless, unprotected repos, unmanaged APIs, and AI agents. Exposure is validated with "**active reachability scans**". [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path]
- **2025 refinements:**
  - Sep 2025 "refined attack paths": external-driven only.
  - **Exposure width (GA Sep 2025)**: tags VMs as **wide vs narrow** exposure and puts it in the path title (e.g. "Widely internet exposed virtual machines has high permissions to storage account").
  - **Trusted IPs (preview)** are defined via Azure Policy IP groups and suppress paths from trusted-only exposure.
  - Nov 2025: **Entra OAuth app compromise** paths.
  - Paths through plain-text keys are generated only if **both ends have Defender CSPM**.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/internet-exposure-analysis ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **MSEM cross-workload paths.** Paths cover cloud, on-prem, and **hybrid** (cloud VM → identity → on-prem DC), with a **Type** column and DACL-aware AD paths. On-prem paths stop at "End Game" assets (Domain/Enterprise Admins, DCs).
  - The dashboard shows attack paths over time, top choke points, top scenarios, top targets, and top entry points.
  - You can group by name, entry point, entry point type, target type, risk level, status, target criticality, or target.
  - **Choke points tab → "View blast radius"** shows the highest-risk paths fanning out from a choke point.
  - [sourced: https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview]
- **Incident-time blast radius** (Sep 2025). Built on the Sentinel data lake graph, it draws an interactive graph of possible propagation from the selected node to predefined critical targets, scoped to the user's permissions. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new]
- **UX caveat.** Microsoft warns that "You may see an empty Attack Path page", because the focus is imminent rather than exploratory paths. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview]

### Risk prioritization
- **Engine inputs.** Risk levels are Critical/High/Medium/Low (the "Not evaluated" state was removed on **2026-03-11** in favor of severity-derived risk). Without Defender CSPM, the risk columns appear **blurred** in the UI (an upsell). [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/risk-prioritization ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Risk-based Cloud Secure Score** (Defender portal). It runs 0–100 and aggregates per-asset scores. Each asset score is a weighted average of open recommendations by risk level (Low/Med/High/Critical), factoring in asset risk factors (internet exposure, data sensitivity) and **asset criticality**. Daily values are **end-of-day snapshots**, not averages (since 2026-05-05). [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls]
- **Classic score** (Azure portal). Each MCSB control has a fixed max (MFA 10, management ports 8, system updates 6, vulnerabilities 6, …) and is recalculated **every 8 h**. Control score = max/(healthy+unhealthy) × healthy. Preview recommendations are excluded. [same source]
- **Critical assets.** There are predefined classification rules plus custom query-builder rules. 2025–26 additions include "Executive-Sponsored AI Agent", "Widespread Local Admin", 15 SaaS apps (Entra, Azure, Exchange…), "APIs with Sensitive Data", and **dynamic reclassification from Purview eDLP**: an endpoint touching sensitive docs becomes high criticality and reverts after **5 days** of inactivity. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new]

### CIEM/identity
- **Native CIEM** across Azure/AWS/GCP (GA logic Feb 2026), replacing the retired Entra Permissions Management.
  - Inactivity is measured by **unused role assignments** over a **90-day lookback** (previously 45). New identities under 90 days old are skipped.
  - The **Permissions Creep Index was removed**.
  - AWS SAML/SSO identities need **CloudTrail ingestion (preview, Dec 2025)**. GCP needs **Cloud Logging via Pub/Sub (preview, Oct 2025)**.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Breaking change (2026-08-06).** The "Unused actions" list was dropped for AWS/GCP over-provisioned identity findings; Microsoft tells users to fall back to native IAM last-accessed data. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Identity edges in MSEM** include `Can Authenticate As` and `CanRemoteInteractiveLogonTo`, with AD DACL edges. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph]

### DSPM
- **Sensitive data discovery** (Defender CSPM or Defender for Storage) uses the **Purview classification engine and SITs**. It supports importing custom SITs and labels and a confidence threshold. **Smart sampling** samples up to **20 MB per file** in object stores and **300–1,024 rows** from selected DB tables via nonblocking queries. GCP supports Cloud Storage only. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-data-security-posture]
- **How sensitivity is used.** It feeds the "data sensitivity" risk factor, attack path targets, and explorer templates (e.g. publicly accessible plus sensitive data). Hosted DBs and data flows are discoverable without the extension. [same source]

### Vulnerability & secrets
- **Agentless scanning** covers VMs (MDVM engine), containers (registries, AKS runtime GA Nov 2025, and EKS/GKE runtime images in preview Jun 2026), and Docker Hub/JFrog.
  - Registry images are **rescanned daily if pushed or pulled in the last 30 days**.
  - Supported image sources include Chainguard/Wolfi, Minimus, Photon, and Docker Hardened Images.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Agentless VM secrets scanning** finds plain-text keys on disk, and these feed lateral-movement edges. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection]
- **Code scanning.** Repo secrets need GHAS/GitLab Ultimate. **Endor Labs reachability SCA** went GA in Dec 2025. **Cloud software inventory** in MSEM vuln management is in preview (Jan 2026). [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/devops-support ; https://learn.microsoft.com/en-us/security-exposure-management/whats-new]

### Code-to-cloud / IaC
- **Agentless code scanning (preview)** works on the default branch of ADO and GitHub repos.
  - Repos are discovered **every 8 h**, scans run **daily**, and repos must be **under 1 GB**.
  - It bundles managed OSS scanners: **Template Analyzer** (ARM/Bicep), **Checkov** (TF, TF plan, CFN, K8s, Helm, Dockerfile, SAM, Kustomize, Serverless, OpenAPI), **Bandit**, **ESLint**, **Trivy**, and **Syft** (queryable SBOM).
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/devops-support]
- **Defender CSPM-only features:** PR annotations, code-to-cloud mapping for containers and IaC templates, and DevOps nodes in attack paths/explorer. **"Code to runtime enrichment"** (preview Mar 2026) traces runtime recommendations back to source, showing SDLC chain visibility and a code-change "blast radius". [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Defender for Cloud CLI** does in-pipeline container image scanning (preview Nov 2025). The GitHub connector requests `artifact_metadata:write` for build-provenance attestations. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **Agentic code scanner "Codename MDASH"** (MSEM, private preview Jul 2026):
  - It is a multi-model scanner with a MAI-Cyber-1-Flash "MAI-Augmented" profile.
  - It can be run from the Defender CLI or GitHub/ADO connectors.
  - It shows scan progress states (waiting/processing/validating/publishing) and supports cancel.
  - It uses keyless Foundry auth.
  - [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new]

### Remediation
- **Recommendation actions** include **Fix** (one-click on multiple resources), **Enforce** (deploy a policy for new resources), **Deny**, and remediation scripts. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls]
- **Attack path remediation** separates "Recommendations", which break the path, from "Additional recommendations". *(Already in competitors.md.)*
- **GHAS integration (GA 2026-05-03).** It requires DCSPM plus GHAS.
  - Runtime risk factors (internet exposure, sensitive data, lateral movement) appear on GHAS alerts.
  - Security admins can **launch GitHub Security Campaigns from Defender**.
  - **Copilot Autofix** offers multi-fix bundling into one PR.
  - Issue status and ownership sync back to Defender within minutes.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Containers:** gated deployment, with Audit/Deny admission rules driven by vulnerability results (GA Nov 2025), and K8s misconfiguration enforcement (GA Jul 2026). **Storage:** automated malware soft-delete (GA Mar 2026). [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]

### Compliance
- **Default standard:** MCSB, with **MCSB v2 in preview** since Nov 2025 (adds AI workload controls). Many frameworks reached GA on 2025-11-03 across Azure/AWS/GCP, including NIS2, PCI DSS 4.0.1, NIST CSF 2.0, NIST 800-53 R5.1.1, ISO 27001:2022, CIS AWS 3.0, CIS GKE/EKS/AKS, CMMC L2/L3, HITRUST 11.3, SOC 2, **NIST AI RMF**, and EO 14028. **DORA, EU AI Act, k-ISMS-P, and CIS Azure 3.0** arrived in preview in Jul 2025. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **Guardrails for score jumps:** a **"New" tag** for 30 days, a "View updates" change log on the score card, and a portal banner when coverage expansions shift the score. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]

### Detection & response / real-time
- **CWPP plans:** Servers, Containers, Storage, SQL/OSS DBs, Key Vault, ARM, APIs, AI Services. Recent additions:
  - **Threat protection for Foundry AI agents** (preview Feb 2026).
  - Container anti-malware detect/block and binary-drift blocking (GA Apr 2026).
  - Kubernetes DNS detection.
  - **Restrict Pod Access** response action in Defender XDR.
  - The `CloudStorageAggregatedEvents` hunting table.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **Posture is not real-time.** The explorer refreshes daily, classic score every 8 h, and the MSEM graph has up to 72 h latency. A resolved attack path can take up to 24 h to clear. [sourced: links above] [inferred: overall freshness characterization]

### Integrations & workflow
- **Governance rules:**
  - Fields: scope (management scopes apply before single scopes), priority **1–1000**, and conditions by severity, risk level, **category**, or specific recommendation.
  - Owner comes from a **resource tag key** or an email address.
  - SLAs are **7/14/30/90 days**, with an optional **grace period** that keeps the item out of Secure Score until overdue.
  - **Weekly emails** go to owners, and to managers (from Entra) for overdue items.
  - Exclusions are **API-only**.
  - A **Governance report** workbook shows on-time, overdue, and unassigned items by rule and owner.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/governance-rules]
- **Other integrations:**
  - ServiceNow ticketing (preview), with OAuth 2.0 support on the MSEM connector.
  - Continuous export to SIEM, Logic Apps workflow automation, and Sentinel/XDR.
  - MSEM ingests **Wiz, Prisma Cloud, Tenable, ServiceNow CMDB, and OT (Armis, Dragos, Forescout)** data connectors.
  - [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management]

### Dashboards & reporting UX
- **Cloud Overview dashboard** (Defender portal): posture, coverage, assets, health, top improvement actions, and workload views. **Cloud initiative page:** current score, score over time, **score by environment (Azure/AWS/GCP)**, **score by workload**, a recommendations summary, and most common recommendations by criticality. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls]
- **MSEM Initiatives:**
  - Each initiative shows a **14-day change trend**, a settable **target score**, metrics with high/med/low weight or "risk accepted", and a **0→100% progress bar**.
  - The History tab shows the **top 100 changed assets** per score change.
  - An **Events** page lists initiative and metric score-drop events, and content versioning notices preview upcoming metric changes.
  - A new Overview dashboard (preview Jun 2026) is organized around "**Resolve Now**" and "**Monitor Exposure**".
  - [sourced: https://learn.microsoft.com/en-us/security-exposure-management/initiatives ; https://learn.microsoft.com/en-us/security-exposure-management/whats-new]
- **Cloud security reporting (GA 2026-06-30):**
  - Built-in **CNAPP Executive Summary** (threats, score trends, vulns, recommendations, IR activity, compliance) and **Cloud Posture** reports.
  - Custom reports are built from sections and cards, with **PDF export** and Private/Tenant/Public visibility.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]

### AI assistant
- **Security Copilot in Defender for Cloud** can summarize, remediate (step-by-step guidance plus scripts), and **delegate recommendations** in natural language. "Help me remediate" can open an ADO PR. It requires provisioned **Security Compute Units**, which are a separate cost. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/remediate-with-copilot ; https://learn.microsoft.com/en-ie/azure/defender-for-cloud/delegate-with-copilot]
- **AI-SPM:**
  - Discovers AI BOM across Azure OpenAI, Foundry, AML, **Bedrock**, and **Vertex** (GA Nov 2025).
  - IaC AI checks cover private endpoints and managed identity.
  - AI model security scans AML models for malware and unsafe operators, including via CLI (preview Mar 2026).
  - **Since 2026-07-01, agent-level discovery and posture moved to a separate Microsoft Agent 365 license.**
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-security-posture ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- **APIs:** REST APIs for Secure Scores and Secure Score Controls, plus Azure Resource Graph KQL. Governance exclusions are API-only. Plans are enabled through the Azure Policy and plan-enablement API, which blocks 5 deprecated plans as of Jul 2026. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **RBAC:**
  - Azure roles: Security Reader/Admin, Reader/Contributor/Owner.
  - In the Defender portal, **Unified RBAC** has "Exposure Management (read/manage)" and "Core security settings (manage)".
  - **Cloud scopes** (preview) group subscriptions, accounts, and projects into logical units for RBAC and persistent filtering.
  - Device-group scoping applies to endpoint data only.
  - [sourced: https://learn.microsoft.com/en-us/security-exposure-management/prerequisites ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **SSO/tenancy.** SSO is through Entra ID. Multi-tenant management via Azure Lighthouse is not covered in the fetched docs. [inferred]

### Unique "wow" features released 2025–2026
- **Hybrid attack paths** (cloud VM → identity → on-prem DC) and Entra OAuth-app compromise paths. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive]
- **Exposure width (wide/narrow)** and **Trusted IPs** to kill false-positive exposure. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/internet-exposure-analysis]
- **Incident blast-radius graph** in the SOC flow, and choke point → "View blast radius". [sourced: https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview]
- **Defender → GitHub Security Campaigns** with runtime context and bidirectional sync. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Dynamic criticality from DLP activity**, with auto-revert after 5 days. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new]
- **CNAPP Executive Summary PDF report**, and a score change-log with "New" tags. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes]
- **Ingesting competitor findings** (Wiz/Prisma connectors) into its own graph. [sourced: https://learn.microsoft.com/en-us/security-exposure-management/whats-new]

### Documented weaknesses/complaints
- **Cost:** "Defender for Cloud is pretty costly for a single line. It's incredibly high to pay monthly". Also: "license price is a little bit higher from an ingestion cost perspective" (VP Sales, Mar 24 2026). [sourced: https://www.peerspot.com/products/microsoft-defender-for-cloud-reviews]
- **Multicloud:** "has not helped me manage and secure multi-cloud environments" (Head of IT, Cirrus Response, Mar 24 2026). [sourced: https://www.peerspot.com/products/microsoft-defender-for-cloud-reviews]
- **UX and docs:** "developed from an engineer's perspective rather than the end user perspective", and documentation "can be outdated due to the legacy support" (Sr. Sysadmin, Nov 19 2025). [sourced: https://www.peerspot.com/product_reviews/microsoft-defender-for-cloud-review-8530956-by-syed-abid]
- **Configuration and accuracy:** TrustRadius cons say configuration is "very complex and requires experts", with "Increased false positives" and "delayed detection". [sourced: https://tr-web.dev.trustradius.com/products/azure-security-center/reviews]
- **Structural issues** (from the docs):
  - Two portals with **two incompatible Secure Score models**.
  - The explorer still isn't in the Defender portal for serverless.
  - Frequent breaking changes: PCI removed, AWS/GCP unused actions removed, agent posture moved behind the Agent 365 license.
  - The MSEM 72 h latency and 14-day, no-history retention.
  - Attack paths depend on CSPM being enabled on both ends.
  - [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes ; https://learn.microsoft.com/en-us/security-exposure-management/prerequisites]
- **Review sources:** G2 and Gartner Peer Insights returned HTTP 403, and Reddit-specific threads weren't surfaced by search. No quotes come from those sites. [inferred]

### Sources
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes-archive
- https://learn.microsoft.com/en-us/security-exposure-management/whats-new
- https://prices.azure.com/api/retail/prices (Defender CSPM meters)
- https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-attack-path
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/how-to-manage-cloud-security-explorer
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/secure-score-security-controls
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/governance-rules
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-data-security-posture
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-security-posture
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/internet-exposure-analysis
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-agentless-data-collection
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/devops-support
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/risk-prioritization
- https://learn.microsoft.com/en-us/azure/defender-for-cloud/remediate-with-copilot
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-exposuregraphnodes-table
- https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph
- https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview
- https://learn.microsoft.com/en-us/security-exposure-management/initiatives
- https://learn.microsoft.com/en-us/security-exposure-management/prerequisites
- https://www.peerspot.com/products/microsoft-defender-for-cloud-reviews
- https://tr-web.dev.trustradius.com/products/azure-security-center/reviews


---

## Google Security Command Center (SCC)

### Positioning & pricing model
- **The big 2026 change: SCC is becoming GCP-native again.** The multicloud **Enterprise tier was deprecated on 2026-05-21** and shuts down on or after **2027-05-21**. Enterprise orgs move to Premium by default. [sourced: https://docs.cloud.google.com/security-command-center/docs/deprecations]
- Google **completed the $32B Wiz acquisition on 2026-03-11**. Wiz "will maintain its brand" and covers all clouds. [sourced: https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz]
- At Next '26, Google pitched **"Agentic Defense"** as "Google's Threat Intelligence and Security Operations with Wiz's Cloud and AI Security Platform". [sourced: https://cloud.google.com/blog/topics/google-cloud-next/google-cloud-next-2026-wrap-up]
- Reading of the above: multicloud CNAPP moves to Wiz, and SCC Premium stays the GCP-native posture, threat and AI-protection layer. [inferred]
- Tiers now in effect:
  - **Standard**: free. It received "a new set of capabilities" and auto-activates for some orgs (2026-02-11). Enhanced Standard is auto-on for new org-level activations (2026-05-11). [sourced: RN]
  - **Premium**: paid. Adds attack paths, threat detection and compliance monitoring, at org or project level. [sourced: https://docs.cloud.google.com/security-command-center/docs/service-tiers]
  - **Enterprise**: deprecated.
- **Premium subscription pricing:**
  - Cost is **5% of projected annualized GCP spend**, or 5% of the committed spend if that is larger.
  - Term is 1 year minimum, with a **$15,000/yr minimum**.
  - If annual spend is above $15M, pricing is by contacting sales. [sourced: SP]
- **Premium pay-as-you-go**, metered on the consumption of the protected services:

  | Meter | Project-level | Org-level |
  |---|---|---|
  | Compute Engine (per vCPU-hour) | $0.0071 | $0.0057 |
  | Cloud SQL (per hour) | $0.0071 | $0.0057 |
  | App Engine Standard (per hour) | $0.001781 | $0.001425 |
  | GCS Class A ops (per 1,000) | $0.002 | $0.0016 |
  | Artifact Registry scan (per count) | $0.20 | $0.20 |
  | BigQuery on-demand (per TiB) | $1.00 | $0.80 |

  [sourced: SP]
  - Since 2026-01-01, **Cloud Run and AlloyDB** are also billed per vCPU-hour, at $0.0071 (project-level) or $0.0057 (org-level). [sourced: SP]
  - Google's own example bill: 50k vCPU-hours + 100 BigQuery slots + 5M Class A ops = **$765/mo** at project level or **$613/mo** at org level. [sourced: SP]
- **Enterprise "other clouds" add-on** (legacy): priced by AWS/Azure footprint relative to GCP.
  - Small (≤10%) = no fee. Medium (≤50%) = 10% of the GCP component. Large = 50%. XL = 100%.
  - $15k minimum. [sourced: SP]
- **Model Armor pricing:**
  - Subscriptions include **3B tokens/month**. PAYG and standalone include 2M tokens/month.
  - Beyond that, **$0.10 per 1M tokens**. [sourced: SP]

### Deployment
- Agentless for posture: Security Health Analytics, Risk Engine and Compliance Manager. [sourced: https://docs.cloud.google.com/security-command-center/docs/service-tiers]
- **Vulnerability Assessment for Google Cloud** does agentless disk scanning of Compute Engine VMs.
  - Preview 2025-04-29, **GA 2026-08-10**.
  - Added XFS/NTFS partitions (2026-05) and GKE Image streaming support. [sourced: RN]
- Threat detection is service-native, with no customer agents:
  - Event Threat Detection (logs).
  - Container Threat Detection (GKE kernel-level).
  - VM Threat Detection (hypervisor memory scanning).
  - Cloud Run Threat Detection (GA 2025-09-10; worker pools added 2026-04-14).
  - Agent Platform Threat Detection.

  [sourced: RN]
- Since 2025-11-20, activation has needed fewer IAM roles. Since 2026-04-15, it auto-provisions per-service agents with their roles. [sourced: RN]
- AWS/Azure support existed only in Enterprise and is now deprecated with that tier:
  - Azure toxic combinations, CIEM and Blob DSP arrived in Preview on 2025-04-28.
  - EC2 disk scanning by VM Threat Detection arrived in Preview on 2025-03-03.

  [sourced: RN]
- Data residency: EU, US and KSA. Settings can be changed after activation (2026-07-09). CMEK for SCC data went GA on 2025-08-14. [sourced: RN]

### Inventory & graph
- **Security graph** is described as a "relationship-aware database". It maps resources, configs, vulnerabilities, permissions, data sensitivity and network exposure. [sourced: https://docs.cloud.google.com/security-command-center/docs/graph-search]
- **Graph search** (Preview from 2025-09-22; Premium/Enterprise; org-level only):
  - A query has three parts:
    - **Nodes**, e.g. CVE Vulnerability, Virtual Machine, IAM Service Account, BigQuery Dataset.
    - **Where** filters, e.g. `Severity = Critical`, `Has Full API Access = True`, `Exploitation Activity = Confirmed`.
    - **Connections**: verb phrases such as `that affects` and `that uses`.
  - Example query: CVE `that affects` VM `that uses` service account with full API access.
  - CSV export is **capped at 1,000 rows**.

  [sourced: https://docs.cloud.google.com/security-command-center/docs/graph-search]
- The legacy asset API is replaced by **Cloud Asset Inventory**, whose SQL interface is already described in competitors.md. [sourced: https://docs.cloud.google.com/security-command-center/docs/deprecations]
- **App Hub application filter** for findings, issues and compliance (2026-02-26): you can scope risk to an "application", not only to a project. [sourced: RN]

### Attack paths & toxic combinations
- Base Risk Engine model: see competitors.md. New 2025–26 facts:
  - **Issues + security graph + chokepoints**:
    - Preview 2025-03-20.
    - Toxic combinations GA for Premium 2025-06-04.
    - Issues, GCP chokepoints and predefined graph rules GA 2025-08-20.
    - Chokepoints for AWS/Azure: Preview 2025-07-01.

    [sourced: RN]
  - **CVEs without known exploitation are excluded** from attack paths (2025-06-19). **Muted findings are excluded** from the Risk Engine (2025-05-19). [sourced: RN]
  - **Coverage added over time** [sourced: RN]:

    | Date | What was added |
    |---|---|
    | 2025-01 | Spanner |
    | 2025-02-14 | Vertex AI datasets, auto-valued from data sensitivity |
    | 2025-11-06 | Cloud Run jobs/services |
    | 2025-12-05 | `storage.restrictAuthTypes` used for signed-URL reachability |
    | 2026-03-31 | Vertex AI Reasoning Engine |
    | 2026-05-21 | Cloud Build |
    | 2026-05-28 | Managed Spark / Lightning Engine |
    | 2026-09-28 | Reasoning engines that modify IAM policies or move laterally, as toxic combinations |

- **Issue** = the unit of risk. Sources are virtual red teaming, toxic combinations, chokepoints, predefined graph rules, Correlated Threats, and design-time findings from Application Design Center. [sourced: https://docs.cloud.google.com/security-command-center/docs/issues-overview]
  - Severity is Medium, High or Critical.
  - Issues are grouped by severity and detection type.
  - An issue auto-resolves when its findings are fixed or its resources deleted.
  - Inactive issues are kept for 90 days (Correlated Threats: 14 days).
- Issue filter categories: **CVE Vulnerabilities, Identity, Data, AI Security** (2025-05-29). [sourced: RN]

### Risk prioritization
- The **new risk-scoring algorithm (2025-07-25)** warned that exposure scores may shift. [sourced: RN]
- Heuristics now auto-select high-value resources and identify non-production resources (2025-09-12, further enhanced 2026-03-27). [sourced: RN]
- **Lesson:** Google changed scores silently twice. A published, versioned formula with a changelog beats that. [inferred]
- **Design-time risk:** the Application Design Center integration (GA 2026-04-17/08-10) scores architectures before they are deployed. [sourced: RN]

### CIEM/identity
- CIEM covers AWS Managed Microsoft AD and on-prem AD identities, with AWS account-level findings (2025-02-12). [sourced: RN]
- Ingestion: SQS-based log ingestion, plus a cheaper **"CIEM only" feed** (2025-03-18). Azure management-group logs since 2025-07-25. [sourced: RN]
- IAM recommender findings (unused permissions) are available on project-level activations (2025-04-09). [sourced: RN]
- AI Protection flags **over-privileged agents** (Premium). [sourced: https://docs.cloud.google.com/security-command-center/docs/ai-protection-overview]

### DSPM
- DSPM went **GA for Enterprise on 2025-11-10** and became available for Premium at org level on 2025-11-14. [sourced: RN]
- Advanced data-governance controls for GCS entered Preview on 2026-04-17. [sourced: RN]
- **DSPM was deprecated on 2026-09-14, with shutdown on or after 2027-02-01.** Google points users to "alternative detection capabilities". [sourced: https://docs.cloud.google.com/security-command-center/docs/deprecations]
- What remains is Sensitive Data Protection discovery. Premium orgs got a complimentary org-level SDP discovery subscription (2025-10-17). SDP data sensitivity auto-promotes high-value resources. [sourced: RN]
- On 2026-09-29, Event Threat Detection began enriching sensitive-resource findings with SDP. [sourced: RN]

### Vulnerability & secrets
- **Coverage:**
  - Artifact Registry image scanning across GKE, Cloud Run and App Engine: Preview 2025-03-13, container-image findings GA 2025-10-20.
  - GKE node/container scanning: Preview 2025-05-19.
  - Notebook Security Scanner for Colab Enterprise Python packages: Preview 2025-07-11.

  [sourced: RN]
- **Agent Platform Vulnerability Assessment:**
  - Finds CVEs in custom agent dependencies (2026-04-16).
  - Scans for **plaintext secrets in agent containers** (2026-07-31).

  [sourced: RN]
- Snyk integration in Preview (2025-02-13). [sourced: RN]
- **Artifact guard** (supply-chain gating):
  - Entered Preview 2026-05-21.
  - The **CI/CD integration was deprecated 2026-10-06** and shuts down 2026-10-30.

  [sourced: RN]

### Code-to-cloud / IaC
- IaC validation against org policy / security posture already existed and is not new. [inferred]
- New items:
  - Application Design Center design-time assessments.
  - Terraform support for Model Armor resources (2025-07-29).
  - Org Policy custom constraints over SCC resources (GA 2025-02-25).

  [sourced: RN]
- With Artifact guard CI/CD deprecated, Google's code-security story is now Wiz Code: Lovable integration, IDE hooks and "Wiz Skills" for coding agents. [sourced: https://cloud.google.com/blog/topics/google-cloud-next/google-cloud-next-2026-wrap-up]

### Remediation
- Findings and issues carry step-by-step guidance. Each chokepoint issue says that fixing one node fixes several toxic combinations. [sourced: https://docs.cloud.google.com/security-command-center/docs/issues-overview]
- Enterprise had SecOps **cases and playbooks**. They are deprecated with that tier. [sourced: https://docs.cloud.google.com/security-command-center/docs/service-tiers]
- Ticketing:
  - **Jira integration** to review findings in Jira projects (2026-07-13).
  - ServiceNow ITSM 1.2.0 / SIR 1.3.0, with mute sync and CI lookup rules (2026-07-28).

  [sourced: RN]
- No auto-fix PRs are documented in SCC itself. [inferred]

### Compliance
- **Compliance Manager:** Preview 2025-08-01, GA 2025-08-07. Custom frameworks/controls, APIs and audit logging went GA 2025-10-15. Premium org-level since 2025-11-03; single projects since 2026-05-11. [sourced: RN]
- Model: **frameworks → cloud controls → rules**.
  - Rules can be org policies, IAM policies, or **CEL detection logic**.
  - Modes: **Detective**, and **Audit** (Premium), which collects evidence and generates reports.

  [sourced: https://docs.cloud.google.com/security-command-center/docs/compliance-manager-overview]
- Scan cadence: **batch every 16h (Premium) / 38h (Standard)**, plus **near-real-time scans** on config change (Premium). [sourced: same]
- Frameworks:
  - **Security Essentials** is free on all tiers.
  - Premium adds CIS Controls 8, ISO 27001:2022, NIST 800-53 r5, PCI DSS 4.0, FedRAMP Low, CIS GKE 1.7, CSA CCM, Qatar NIAS and more (updated 2026-03-25 and 2026-05-21).

  [sourced: RN]

### Detection & response / real-time
- Event Threat Detection now covers:
  - Backup & DR detectors.
  - 13 GKE rules GA (2025-03-14).
  - Vertex AI detectors (Preview 2025-06-13).
  - Cloud SQL exfiltration (GA 2025-06-27).

  [sourced: RN]
- Container Threat Detection added the Ingress Nightmare detector, file-monitoring detectors, and piped/encoded execution. [sourced: RN]
- **Correlated Threats** (Preview 2025-10-10):
  - Graph rules run **hourly** and fold related threat findings into one issue.
  - Three rules: crypto mining, malware patterns, **account lateral movement**.

  [sourced: https://docs.cloud.google.com/security-command-center/docs/correlated-threats-overview]
- **"Malicious Skill" runtime detectors** for AI agents on GKE, Cloud Run and Agent Platform (2026-08-04). [sourced: RN]
- **External Exposure** (Preview 2026-06-18, Premium): automated asset discovery plus **exploitability testing**, a DAST/ASM-style feature. [sourced: RN]

### Integrations & workflow
- Exports:
  - Pub/Sub and BigQuery continuous export.
  - **Bulk export to BigQuery** (GA 2025-09-23).
  - Since 2026-10-09, notifications also fire **when findings are deleted** by the retention policy.

  [sourced: RN]
- Finding retention dropped from **13 months to 90 days** for new activations from 2025-05-26. That is why the BigQuery export matters. [sourced: RN]
- Other integrations: Jira, ServiceNow, Snyk, and Cloud Hub "Security & compliance" insights (GA 2026-07-17). [sourced: RN]

### Dashboards & reporting UX
- **Risk Overview** page:
  - Separate tabs for misconfiguration, vulnerability and identity (2025-12-12).
  - **Findings** has predefined views (All, Vulnerabilities, Identity, Threats, plus Data and Code on Enterprise), a cloud-provider selector, and **Quick Filters** (renamed from Aggregations).

  [sourced: RN]
- **Risk reports as downloadable PDF** (2025-06-30), now including a "system attack exposure" page. [sourced: RN]
- Service-specific dashboards [sourced: RN]:
  - Compute Engine Security Risk Overview: top findings plus a top-CVE table (GA 2025-06-05).
  - GKE security posture dashboard.
  - **AI Security dashboard** with an agent overview (2025-11-17).
  - Model Armor monitoring dashboard (GA 2025-09/12).
- No published SLA/MTTR dashboard was found. [inferred]

### AI assistant
- **Gemini attack-path summaries were discontinued on 2024-12-13.** [sourced: RN]
- The remaining Gemini features are Enterprise/SecOps-only: case summaries in the "AI Investigation widget", and NL → UDM Search. [sourced: https://docs.cloud.google.com/security-command-center/docs/gemini-overview]
- **MCP server** (Preview 2026-09-16): endpoint `https://securitycenter.googleapis.com/mcp/investigate`. LLM agents use it to "perform investigative and management tasks" in SCC and SCC Management. [sourced: https://docs.cloud.google.com/security-command-center/docs/reference/mcp, RN]
- SecOps agents announced at Next '26: Threat Hunting, Detection Engineering, Third-Party Context. These belong to SecOps, not SCC. [sourced: https://cloud.google.com/blog/topics/google-cloud-next/google-cloud-next-2026-wrap-up]
- **Model Armor** (launched 2025-02-03), an inline guardrail for prompts and responses:
  - Detects prompt injection/jailbreak, Responsible AI issues, SDP data, and malicious URLs.
  - Handles **10k tokens** for prompt injection and a **4 MB** input cap.
  - Supports 9+ languages and DOCX/PPTX/XLSX.
  - Floor settings for **Google-managed MCP servers**.
  - Integrations: Agent Gateway / Agent Runtime / LangChain (Preview) and Firebase (GA).

  [sourced: RN; Next '26 wrap-up]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Interfaces: REST `securitycenter` API, `gcloud scc`, client libraries, and Terraform. Mute configs, security marks, notification configs and BigQuery exports are all API resources. [sourced: https://docs.cloud.google.com/security-command-center/docs/reference/mcp]
- Compliance Manager has REST APIs and client libraries (GA 2025-10-15). [sourced: RN]
- RBAC uses Google Cloud IAM roles at org/folder/project scope, and SSO comes from Cloud Identity. There is no MSSP multi-tenant console. [inferred]
- Org Policy custom constraints can lock SCC settings. [sourced: RN]

### Unique "wow" features released 2025–2026
- **Chokepoint issues** that state "fix one → closes many toxic combos", including for AWS/Azure. [sourced: RN]
- **AI agents as first-class attack-path nodes:** Reasoning Engine high-value resources, and toxic combos for agents that modify IAM or move laterally. [sourced: RN]
- **Correlated Threats:** a graph-rule fusion of runtime alerts into one issue. [sourced: correlated-threats-overview]
- **External Exposure** with exploitability testing. [sourced: RN]
- **Malicious Skill detectors** for agent capability supply chain. [sourced: RN]
- **Design-time (pre-deploy) risk** via Application Design Center. [sourced: RN]
- **Deletion notifications** for retention-expired findings. [sourced: RN]

### Documented weaknesses/complaints
- **Product churn:** Enterprise tier, DSPM, Artifact guard CI/CD and Gemini attack-path summaries were all deprecated within about 2 years. Multicloud customers are being pushed toward Wiz. [sourced: https://docs.cloud.google.com/security-command-center/docs/deprecations]
- **Findings retention cut to 90 days** (from 13 months) for new activations. [sourced: RN]
- **Scores moved without warning:** risk scoring changed on 2025-07-25 and 2026-03-27, and customers "may observe exposure score changes". [sourced: RN]
- **Feature gating:** graph search needs Premium plus org-level activation, has 1,000-row CSV export, and is still Preview. Compliance Standard scans run every 38h. [sourced: graph-search doc; compliance-manager-overview]
- **Cost anxiety:** a user asked: "If We end up paying more than I expected, can we revert to the standard plan even after only a few days of use?" Staff did not answer directly (2024-08-27). [sourced: https://security.googlecloudcommunity.com/security-command-center-4/security-command-centre-premium-tier-s-price-4087]
- **Indirect charges:** vulnerability scans can raise the cost of the scan targets. [sourced: SP]
- G2 and Gartner review text was not retrievable (403). [inferred]

### Sources
- https://docs.cloud.google.com/security-command-center/docs/release-notes
- https://docs.cloud.google.com/security-command-center/docs/deprecations
- https://docs.cloud.google.com/security-command-center/docs/service-tiers
- https://cloud.google.com/security-command-center/pricing
- https://docs.cloud.google.com/security-command-center/docs/graph-search
- https://docs.cloud.google.com/security-command-center/docs/issues-overview
- https://docs.cloud.google.com/security-command-center/docs/correlated-threats-overview
- https://docs.cloud.google.com/security-command-center/docs/ai-protection-overview
- https://docs.cloud.google.com/security-command-center/docs/compliance-manager-overview
- https://docs.cloud.google.com/security-command-center/docs/gemini-overview
- https://docs.cloud.google.com/security-command-center/docs/reference/mcp
- https://cloud.google.com/blog/topics/google-cloud-next/google-cloud-next-2026-wrap-up
- https://www.googlecloudpresscorner.com/2026-03-11-Google-Completes-Acquisition-of-Wiz
- https://security.googlecloudcommunity.com/security-command-center-4/security-command-centre-premium-tier-s-price-4087

## Datadog Cloud Security (formerly Cloud Security Management, CSM)

### Positioning & pricing model
- Positioning: security built on the observability agent. One product covers misconfigurations, identity risks, vulnerabilities and Workload Protection, with a single **Security Inbox** across Cloud Security, Code Security, App & API Protection and Workload Protection. [sourced: https://docs.datadoghq.com/security/cloud_security_management/]
- **List prices (DDP)**, shown as annual / monthly / on-demand. [sourced: https://www.datadoghq.com/pricing/list/]

  | Product | Meter | Annual / monthly / on-demand |
  |---|---|---|
  | **CSM Pro** | per CSM host/month | **$10 / $12 / $12** |
  | CSM Pro containers | per container/month (or per container-hour) | $0.50 ($0.001) |
  | **CSM Enterprise** | per CSM host/month | **$25 / $30 / $30** |
  | CSM Enterprise containers | per container/month (or per container-hour) | $1 ($0.002) |
  | **Workload Protection** | per host/month | **$15 / $18 / $18** |
  | Workload Protection containers | per container/month | $1 |
  | Fargate (Workload Protection) | per task/month | $2.60 / $3.10 / $3.70 |

- **Bundles** [sourced: https://www.datadoghq.com/pricing/?product=cloud-security]:
  - **DevSecOps Pro: $22/host/month** (annual; $27 on-demand). Infra Pro + CSM Pro: CSPM, KSPM, compliance mapping, vulnerability management for containers and hosts, CIEM, inventory.
  - **DevSecOps Enterprise: $34/host/month** ($41 on-demand). Adds FIM, Workload Protection, and 10 containers per host.
  - Volume discounts start at 500+ hosts.
- **Code Security** (per committer/month, annual) [sourced: DDP]:
  - SAST $25.
  - Static SCA $25.
  - **IaC Security $15**.
  - Secret Scanning $15.
  - **Code Security Bundle $40**.
  - Runtime SCA $10/host. IAST $20/host.
- **Meter caveat:** the meter is per host. Agentless-only and serverless resources are priced in ways that are not clear publicly. [inferred]

### Deployment
- **Agentless Scanning** covers AWS, Azure and GCP. [sourced: https://docs.datadoghq.com/security/cloud_security_management/agentless_scanning/]
  - It snapshots VM volumes, fetches Lambda code, and scans storage.
  - **Scans every 12h.** AWS also supports on-demand scans via API.
  - The scanner runs **in the customer's account** (you pay the compute) and scales to zero. Datadog recommends one scanner per region above 150 hosts.
  - Only SBOM metadata leaves the account.
- **Datadog Agent** adds real-time updates. Identity risks and host benchmarks work agentless. [sourced: https://docs.datadoghq.com/security/cloud_security_management/setup/]
- Supported clouds: AWS, Azure, GCP, and **OCI**. DASH 2026 added 45 OCI rules mapped to CIS OCI 3.0.0. [sourced: setup doc; https://www.datadoghq.com/blog/dash-2026-new-feature-roundup-secure/]
- **Azure secretless auth** via workload identity federation (DASH 2026). [sourced: DASH 2026 blog]
- CI: the Datadog Security CLI scans container images in pipelines. [sourced: setup doc]

### Inventory & graph
- Inventory surfaces: **Resource Catalog**, plus the **Cloudcraft Security Map** and a security overlay on Cloudcraft diagrams (NIST/SOC 2/HIPAA). [sourced: https://docs.datadoghq.com/security/cloud_security_management/; https://www.datadoghq.com/blog/dash-2025-new-feature-roundup-secure/]
- **Security Graph** (Preview at DASH 2025): [sourced: https://docs.datadoghq.com/security/cloud_security_management/security_graph/]
  - Query builder: **Search for** (resource type) → **Where** (tag = value) → **That** (relationship) → more resources, with multiple conditions.
  - Data comes from agentless and agent scans.
  - **AWS resources only.** Not available on the gov sites.
- **SQL over findings via the MCP server:** "Analyze misconfigurations, vulnerabilities, and identity risks using SQL queries". [sourced: https://docs.datadoghq.com/security/mcp_server/]
- Infrastructure Packages Catalog: a real-time package inventory across hosts, host images and container images. [sourced: https://docs.datadoghq.com/security/cloud_security_management/vulnerabilities/]

### Attack paths & toxic combinations
- Security Inbox includes "attack paths". Its **security context map** shows vulnerabilities and misconfigurations linked as breach chains, with service-ownership context. [sourced: https://docs.datadoghq.com/security/security_inbox/]
- Security Graph supports "trace trust paths" for privilege escalation. [sourced: DASH 2025 blog]
- No published path-scoring formula or simulation model was found. Path logic is rule-based (Datadog Security Research inbox rules). [inferred]

### Risk prioritization
- The Inbox checks five risk factors: **public accessibility, privileged access, active attacks, available exploits, production environment**. [sourced: https://docs.datadoghq.com/security/security_inbox/]
- **Custom inbox rules** via Automation Pipelines:
  - First match wins, evaluated top-down.
  - They can set severity-based **due dates**.
  - Results group by up to 2 fields.

  [sourced: same]
- The **Datadog Severity Score** is CVSS base adjusted by CISA KEV, EPSS, public exploits, production exposure, sensitive-data processing, and privileged access. [sourced: vulnerabilities doc]

### CIEM/identity
- Covers AWS, Azure and GCP. Risk types: lingering admin, privilege escalation, permission gaps, large blast radius, cross-account access. Entities covered: users, roles, groups, policies, EC2, Lambda. [sourced: https://docs.datadoghq.com/security/cloud_security_management/identity_risks/]
- **"View Suggested Policy"** gives a right-sized policy based on observed usage over **90 days**. AWS IAM Access Analyzer extends past that window. [sourced: same]
- **Access Insights** shows which principals reach a resource directly or indirectly, filtered by entity type, account and access path. [sourced: same]
- Fix options: **"Fix in <cloud provider>"** button, Workflow Automation, **Terraform PR to GitHub**, and Jira. [sourced: same]

### DSPM
- No standalone DSPM product. Agentless scanning covers "cloud storage". Sensitive Data Scanner is mainly log/telemetry-focused. [sourced: agentless doc; https://www.datadoghq.com/blog/dash-2025-new-feature-roundup-secure/]
- DASH 2026 added the **SDS Findings Explorer**: leaks grouped by pattern, with trends. Bits Code finds where sensitive data is logged in source. [sourced: https://www.datadoghq.com/blog/dash-2026-new-feature-roundup-secure/]
- Datadog's DSPM is weaker than Wiz/Orca for data-store classification. [inferred]

### Vulnerability & secrets
- Scans hosts, container images, Lambda / Azure Container Apps / Cloud Run, and registries: **ECR, Docker Hub, GHCR**. [sourced: vulnerabilities doc]
- **SBOM export**. CVEs are traced to an **image layer** and back to source via Dockerfile annotations. Includes SLAs and out-of-the-box dashboards. [sourced: same]
- Agentless vs agent: agentless deploys in minutes and scans every 12h. The agent takes "hours to weeks" to roll out but scans in real time with runtime context. [sourced: same]
- **Secret Scanning** (Preview at DASH 2025): detects and **validates** secrets in code. [sourced: DASH 2025 blog]

### Code-to-cloud / IaC
- **IaC Security** scans GitHub, GitLab and Azure DevOps across all commits and branches. [sourced: https://docs.datadoghq.com/security/code_security/iac_security/]
  - Inline PR comments with suggested fixes.
  - You can open a fix PR from Datadog.
  - Fixes can be handed off "to an AI coding agent such as Cursor" with a tailored prompt.
- Format coverage (pricing page): Terraform, CloudFormation, Kubernetes. "One-click remediations for over 180 different findings" (DASH 2025). [sourced: pricing page; DASH 2025 blog]
- **Bits Code for SCA/IaC** generates PRs that fix vulnerable dependencies and IaC misconfigurations (DASH 2026). **AI-native SAST** claims "true positive rates up to three times higher". [sourced: DASH 2026 blog]
- Custom IaC rules are written in **Rego** and can be generated and published through the MCP server. [sourced: MCP doc]

### Remediation
- Identity fix buttons and Terraform PRs; IaC one-click fixes; Workflow Automation; Jira with **bidirectional automated ticket creation** (DASH 2026). [sourced: identity doc; DASH 2026 blog]
- **Dynamic Notification Routing** sends findings to Datadog Teams based on ownership (DASH 2026). [sourced: DASH 2026 blog]

### Compliance
- **1,300+ out-of-the-box compliance rules.** [sourced: https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/frameworks_and_benchmarks/]
  - **Posture score** per framework, with time tracking (1-month default).
  - Breakdowns by severity, resource type and control.
  - **PDF/CSV reports**, filterable by account/team/service/env.
  - **Custom frameworks** are supported.
- **Custom rules in Rego:** mark each resource pass/fail/skip (unmarked = skip). The UI has a **Test Rule** step against selected resources. Severity has 5 levels, Critical through Info. [sourced: https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/custom_rules/]
- **Resource Policies** (Preview, DASH 2025): custom policies such as "Lambda Functions should not run deprecated runtimes", plus reliability/cost templates. [sourced: DASH 2025 blog]
- AI workloads: **Bedrock misconfigurations** (DASH 2025). Datadog for Government reached **FedRAMP High** (DASH 2026). [sourced: DASH blogs]

### Detection & response / real-time
- **Workload Protection** [sourced: https://docs.datadoghq.com/security/workload_protection/]:
  - Collection: eBPF on Linux, ptrace on Fargate, a Windows driver.
  - 40+ event types; **350+ agent rules + 200 detection rules**.
  - Active response: kill the process, stop the container, or **eBPF network filtering**.
- Cloud SIEM additions [sourced: DASH 2025 blog]:
  - Content anomaly detection.
  - **Sequence detection** for multi-stage attacks.
  - Scheduled rules.
  - Editing default rules without cloning them.

### Integrations & workflow
- Integrations: Jira (bidirectional), ServiceNow, Case Management, Slack, Workflow Automation (SOAR). DASH 2026 added 30+ security integrations (Jamf, Box, Zscaler, Recorded Future). [sourced: MCP doc; DASH 2026 blog]
- Datadog's main advantage is correlation with APM, logs and service ownership (Teams/Software Catalog). [inferred]

### Dashboards & reporting UX
- **Cloud Security Summary page** (DASH 2025): key metrics, coverage insights, and "team performance". [sourced: DASH 2025 blog]
- Redesigned Misconfigurations and Identity Risks explorers support **group by team** and chained groupings. [sourced: DASH 2025 blog]
- Vulnerability SLAs and out-of-the-box dashboards; compliance posture-score trend. [sourced: vulnerabilities doc; frameworks doc]

### AI assistant
- **Bits AI Security Analyst** is for Cloud SIEM. [sourced: https://docs.datadoghq.com/bits_ai/bits_ai_security_analyst/]
  - Investigates signals autonomously and gives a **Benign/Suspicious** verdict with evidence, remediation and embedded queries.
  - Updates Slack/Jira.
  - Covers 30+ sources.
- DASH 2026 [sourced: DASH 2026 blog]:
  - The analyst became **standalone** and runs on Splunk and Microsoft Sentinel.
  - **Bits Threat Hunting**: autonomous, hypothesis-driven hunts.
  - **Bits Assessments**: TP/FP confidence scores on SAST findings.
- **Security MCP server toolset** (`?toolsets=core,security`), for Cursor, Claude Code and Codex [sourced: https://docs.datadoghq.com/security/mcp_server/]:
  - Search signals and IoCs.
  - SQL over findings.
  - Manage rules and suppressions.
  - Manage WAF.
  - Generate Rego IaC rules.

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Datadog Security CLI; MCP server; new **PATs, service access tokens and workload identity federation** replacing app keys (DASH 2026). [sourced: setup doc; DASH 2026 blog]
- Rules and suppressions are managed by API. Datadog's Terraform provider covers security monitoring rules. [inferred]
- **Data Access Controls** (tag-based) and **role-based unmasking** (DASH 2025). [sourced: DASH 2025 blog]
- Multi-org, SAML SSO and custom roles are standard Datadog platform features. [inferred]
- The **FIPS Agent** is available. [sourced: DASH 2025 blog]

### Unique "wow" features released 2025–2026
- **IaC fix handoff to coding agents** (Cursor) plus Bits Code PRs for SCA/IaC. [sourced: iac doc; DASH 2026]
- **Security MCP server with SQL over findings and Rego rule generation.** [sourced: MCP doc]
- **"View Suggested Policy"** right-sizing plus Terraform PR. [sourced: identity doc]
- **Bits Analyst running on third-party SIEMs.** [sourced: DASH 2026]
- **Dynamic ownership-based routing** to Teams. [sourced: DASH 2026]
- **Claude activity compliance monitoring** in Cloud SIEM. [sourced: DASH 2026]

### Documented weaknesses/complaints
- **Security Graph is AWS-only** and in Preview. No graph or Security Graph on the gov sites. [sourced: security_graph doc]
- **12h agentless cadence.** Real-time requires the agent, which takes "hours to weeks" to deploy. [sourced: vulnerabilities doc]
- **Scanner compute runs on the customer's cloud bill.** [sourced: agentless doc]
- **Per-host plus per-container metering** adds up when combined with Workload Protection ($15/host) and Code Security per committer. [sourced: DDP]
- Bits Security Analyst and the MCP security tools are **unavailable on the gov sites**. [sourced: bits doc; MCP doc]
- No standalone DSPM. No published attack-path scoring. [inferred]
- G2 and Gartner review text was not retrievable (403). [inferred]

### Sources
- https://docs.datadoghq.com/security/cloud_security_management/
- https://docs.datadoghq.com/security/cloud_security_management/setup/
- https://docs.datadoghq.com/security/cloud_security_management/agentless_scanning/
- https://docs.datadoghq.com/security/cloud_security_management/security_graph/
- https://docs.datadoghq.com/security/cloud_security_management/identity_risks/
- https://docs.datadoghq.com/security/cloud_security_management/vulnerabilities/
- https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/frameworks_and_benchmarks/
- https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/custom_rules/
- https://docs.datadoghq.com/security/security_inbox/
- https://docs.datadoghq.com/security/code_security/iac_security/
- https://docs.datadoghq.com/security/workload_protection/
- https://docs.datadoghq.com/security/mcp_server/
- https://docs.datadoghq.com/bits_ai/bits_ai_security_analyst/
- https://www.datadoghq.com/pricing/list/
- https://www.datadoghq.com/pricing/?product=cloud-security
- https://www.datadoghq.com/blog/dash-2025-new-feature-roundup-secure/
- https://www.datadoghq.com/blog/dash-2026-new-feature-roundup-secure/


---

## AWS Security Hub (+ Inspector, GuardDuty, Config, Macie, IAM Access Analyzer)

> Note: the web-search budget ran out partway through, so the review-site quotes come from PeerSpot only (G2 returned 403). Facts about Config, Macie and Security Lake beyond pricing are lighter than the rest.

### Positioning & pricing model
- AWS split the product into two. "Security Hub" (preview June 17 2025, re:Inforce; GA Dec 2 2025) is a correlation, exposure and response layer. The old product was renamed **Security Hub CSPM** and still runs the control checks [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html].
- By 2026 AWS was pitching it as a "unified control plane for cloud and AI security" that covers Azure too. Michael Fuller (AWS) said: "Don't make me buy a different tool when I already have Security Hub" [sourced: https://siliconangle.com/2026/07/22/aws-turns-security-hub-ai-multicloud-security-control-plane/].
- **Essentials plan** is billed per resource unit at **$3.75/unit/month**:
  - 1 EC2 instance or Azure VM = 1 unit; 12 Lambda functions = 1 unit; 18 ECR images = 1 unit; 125 IAM users/roles = 1 unit.
  - Pro-rated by time monitored. 30-day trial per account per Region [sourced: https://aws.amazon.com/security-hub/pricing/].
  - It bills only four resource types (VMs, container images, functions, identities) across AWS and Azure [sourced: https://siliconangle.com/2026/07/22/aws-turns-security-hub-ai-multicloud-security-control-plane/].
- **Threat Analytics add-on**:
  - $4.00 per million CloudTrail management events.
  - $0.55/GB for data events, network activity and logs (first 1,000 GB).
  - Runtime activity is metered per vCPU.
  - **Extended plan partners** are billed on the AWS bill, for example "$5.00 per user per month" (Proofpoint) and "$52.75 per container per month" (SentinelOne) [sourced: https://aws.amazon.com/security-hub/pricing/].
- Worked example from a third party: 200 VMs, 600 Function Apps, 900 images and 500 identities come to about 304 units, roughly **$1,140/month** [sourced: https://ecorpit.com/aws-security-hub-azure-multicloud-cspm-decision-guide-2026/].
- **Security Hub CSPM**:
  - Checks: $0.0010/check for the first 100k per month, $0.0008 for the next 400k. Azure checks are $0.0012.
  - Finding ingestion: 10k events/month free, then $0.00003 per event.
  - Automation rules: 1M evaluations/month free, then $0.10 per million.
  - AWS Config configuration items are billed separately [sourced: https://aws.amazon.com/security-hub/cspm/pricing/].
- **Inspector**:
  - EC2: $1.258 per instance/month with the agent, $1.75 agentless.
  - ECR: $0.09 per image for the first scan, $0.01 per rescan.
  - Lambda: $0.30 standard, plus $0.60 for code scanning.
  - Code repositories: **$0.15 per scan** (SAST, SCA or IaC).
  - CIS assessments: $0.03 per instance.
  - Azure VMs, ACR images and Function Apps are priced the same as their AWS equivalents [sourced: https://aws.amazon.com/inspector/pricing/].
- **GuardDuty**:
  - $4/M CloudTrail management events; $1.00/GB for flow and DNS logs (first 500 GB).
  - Runtime: $1.50/vCPU/month.
  - Malware Protection for S3: $0.09/GB plus $0.215 per 1k objects.
  - EBS malware scan: $0.03/GB.
  - AI Protection: $1.00/GB of AI data events [sourced: https://aws.amazon.com/guardduty/pricing/].
- **Macie**: $0.10 per bucket/month; $0.01 per 100k objects monitored; $1/GB inspected [sourced: https://aws.amazon.com/macie/pricing/].
- **IAM Access Analyzer**:
  - External access analysis is free.
  - **Internal access: $9.00 per resource per Region per month** (S3 buckets and DynamoDB tables).
  - Unused access: $0.20 per role or user per month.
  - Custom policy checks: $0.002 per call [sourced: https://aws.amazon.com/iam/access-analyzer/pricing].
- **Security Lake**: $0.75/GB for CloudTrail, $0.25/GB for other sources, plus $0.035/GB normalization [sourced: https://aws.amazon.com/security-lake/pricing/].

### Deployment
- Everything is native, delegated-admin, and org-wide via configuration policies. Exposures need CSPM, Inspector, GuardDuty and Macie switched on as signal sources [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html].
- Inspector EC2 scanning can run with the SSM agent or agentless [sourced: https://aws.amazon.com/inspector/pricing/]. It also covers ECR, Lambda and code repositories.
- **Azure is GA (July 2026)**:
  - Setup is an app registration, federated identity, role assignments and an Event Hub. A Security Hub connector then takes the tenant ID, client ID, scope and Event Hub Region.
  - **AWS Config runs internally to collect Azure configuration, and you are not billed for Config separately.**
  - Inspector scans Azure VMs (which needs SSM), Function Apps and ACR images.
  - Defender for Cloud alerts are ingested via Event Hub and mapped to OCSF [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-azure.html].
- No GCP. AWS has said only "more clouds following quickly" [sourced: https://ecorpit.com/aws-security-hub-azure-multicloud-cspm-decision-guide-2026/].
- **Network Scanning (July 8 2026)** probes from the internet to confirm real reachability (public IPs, VMs, load balancers on AWS and Azure; open ports; services). It is included in Essentials and on by default for new customers [sourced: https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/].

### Inventory & graph
- There is a resource inventory for AWS and Azure. Each exposure shows the resource configuration both "at the time the finding was created" and now [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html].
- **AI inventory (July 14 2026)** finds AI assets three ways:
  - Config resources from Bedrock, AgentCore and SageMaker.
  - Inspector SBOM detection of self-hosted Ollama, vLLM and HF TGI on EC2 and ECR.
  - GuardDuty DNS telemetry showing calls to external AI APIs.
  - Included free [sourced: https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-ai/].
- **Query language**: AWS Config advanced query is a SQL `SELECT` subset. Example: `SELECT * WHERE resourceType = 'AWS::EC2::SecurityGroup' AND configuration.ipPermissions.ipRanges BETWEEN '10.0.0.0' AND '10.0.0.255'`. Aggregators extend it across accounts and Regions [sourced: https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html].
  - Limits: no `FROM`, `JOIN`, `DISTINCT`, `HAVING` or `UNION`; no NULL queries; suffix wildcards only, at least 3 characters; deleted and third-party resources can't be queried [sourced: same].
  - So there is **no graph query language** over the exposure graph. The graph is visible only in the console [inferred].
- Findings use the OCSF schema with an AWS extension. They are read through the `GetFindingsV2` API [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html].

### Attack paths & toxic combinations
- An **exposure finding** correlates *traits*, and a resource can be the primary resource in at most one exposure. The trait types are:
  - **Assumability**: from Config.
  - **Impact**: from effective-permissions analysis.
  - **Misconfiguration**: from CSPM, GuardDuty and Config.
  - **Reachability**: EC2, EKS, Lambda and S3, from CSPM, GuardDuty and Inspector network reachability.
  - **Sensitive Data**: S3, from Macie.
  - **Vulnerability**: EC2, ECS, EKS and Lambda, from Inspector and GuardDuty malware findings.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html]
- **Impact trait (June 2026)**: "effective permissions" combine identity policies, resource policies, **SCPs and RCPs**. Security Hub traces privilege-escalation chains to downstream resources, and each hop is labelled with the permission that enables it [sourced: same].
- Exposures recalculate in near real time as contributing findings change. Example title: "Potential Data Destruction: S3 bucket with versioning, Object Lock, and MFA delete disabled" [sourced: https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/].
- The **Potential attack path and Blast radius** graph in the Overview tab offers:
  - Draggable nodes, zoom and fullscreen.
  - A legend colouring primary, involved and blast-radius resources, with trait counts.
  - A collapsed network-path node next to a "public internet" node.
  - An **Impact assessment** tab that lists each escalation chain with the permission used at each step.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/potential-attack-path-graph.html]
- Exposures with **Contextual traits** are signals that were found but did not cause the exposure. For example: "47 unused permissions across 5 services" from Access Analyzer [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html].
- **Remediation guides now exist for Azure exposures**: VMs, blob containers, SQL, Cosmos DB, Function and Container apps, AKS, and Graph users [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/toc-contents.json].

### Risk prioritization
- Severity comes from a **Likelihood × Impact risk matrix** (June 2026):
  - Likelihood sets the base level. High impact raises it one level, low impact lowers it one level.
  - Low likelihood with low impact gives INFORMATIONAL, and those findings are **not published**.
  - Likelihood factors are Awareness, Ease of discovery, Ease of exploit, and Likelihood of exploit (**EPSS**, 30-day).
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html]
- OCSF filter fields include `vulnerabilities.is_exploit_available`, `vulnerabilities.cve.epss.score` and `finding_info.related_events_count` [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-automation-rules.html].

### CIEM/identity
- **IAM Access Analyzer** has three analyzers:
  - External access (free).
  - **Internal access**: which principals in the org can reach critical S3 or DynamoDB resources; $9 per resource.
  - Unused access: unused roles, keys, passwords and permissions within a usage window.
  - [sourced: https://aws.amazon.com/iam/access-analyzer/pricing], [sourced: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html]
- As of May 19 2026, Security Hub generates unused-access findings from Access Analyzer itself [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html].
- There is no general cross-account "who can reach what" identity graph. What exists is the effective-permission analysis inside exposures [inferred].

### DSPM
- **Macie** offers automated sensitive data discovery by sampling, plus targeted jobs (5 TB default quota). It covers S3 only [sourced: https://aws.amazon.com/macie/pricing/].
- Macie findings feed the **Sensitive Data trait**, but only for S3 buckets [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html].
- RDS, DynamoDB and Azure data stores are not classified [inferred].

### Vulnerability & secrets
- Inspector:
  - Agent or agentless EC2 scanning.
  - ECR images on push and rescan.
  - Lambda packages and Lambda **code** scanning.
  - CIS OS benchmarks.
  - Azure VMs, ACR and Functions [sourced: https://aws.amazon.com/inspector/pricing/].
- **Inspector code security (GA June 17 2025)** does SAST, SCA and IaC scanning for **GitHub and GitLab**, triggered on push or PR, in CI/CD, or on a schedule. It is available in 10 Regions [sourced: https://aws.amazon.com/about-aws/whats-new/2025/06/amazon-inspector-code-security-shift-security-development].
- Lambda code scanning detects hard-coded secrets [inferred]. There is no dedicated cloud-wide secrets scanner [inferred].

### Code-to-cloud / IaC
- IaC scanning in GitHub and GitLab comes through Inspector code security.
- An ASFF `CodeRepository` resource object was added on Aug 1 2025 [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html].
- No documented mapping from a cloud resource back to the line of IaC that created it, in the way Wiz or Prisma do it [inferred].

### Remediation
- **Remediation plans (Sept 30 2026)** group exposures by root cause, with one target resource per plan.
  - Plan fields: Priority, Status (New, Updated or Resolved), Impact (how many exposures each plan resolves, reduces or merely addresses), and Rollout ("Immediate" or "Requires deployment").
  - They also show reversibility, automation level and whether human review is needed.
  - Guidance is split into phases (**Prerequisite → Snapshot → Fix → Verify → Done**), with **rollback for each step**. Snippets are given in CLI, Azure CLI, Python, Terraform, CDK, CloudFormation, Bicep and ARM.
  - Security Hub "doesn't change your resources for you".
  - Resolved plans stay listed for about 14 days.
  - The filter bar accepts only two equality filters, and the list **can't be sorted**.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html]
- AI agents can read plans through the API [sourced: https://builder.aws.com/content/3KD2iUC05Ls0WOQrggBDU4o9XmN/security-hub-remediation-plans-root-cause-remediation-dissected].
- Fixes otherwise run through EventBridge to Lambda or SSM Automation [sourced: https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/].

### Compliance
- **Security Hub CSPM** standards include:
  - AWS FSBP (frequent additions, for example 11 controls in March 2026).
  - CIS AWS v5.0.0 (40 controls).
  - NIST 800-53 and 800-171 r2.
  - PCI DSS v4.0.1.
  - Resource Tagging.
  - **AI Security Best Practices (June 30 2026)**: Bedrock.1, BedrockAgentCore.7 and SageMaker.20-25.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html]
- Azure: **CIS Azure v4.0** and **Azure Foundational Best Practices** [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-azure.html].
- Recent CSPM changes:
  - July 2025: findings are updated in place instead of new ones being created.
  - June 2025: archived findings are kept for 30 days instead of 90.
  - May 2026: a service-linked Config recorder.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html]
- Config conformance packs and Audit Manager provide the evidence layer (Audit Manager is already covered in competitors.md) [inferred].

### Detection & response / real-time
- **GuardDuty Extended Threat Detection** is on by default at no extra cost. It correlates API, runtime, malware and EKS audit signals into critical **attack-sequence** findings.
  - EKS was added in June 2025.
  - EC2 and ECS were added in Dec 2025: `AttackSequence:EC2/CompromisedInstanceGroup` and `AttackSequence:ECS/CompromisedCluster`.
  - [sourced: https://aws.amazon.com/about-aws/whats-new/2025/12/guardduty-extended-threat-detection-ec2-ecs/]
- **GuardDuty AI Protection (GA July 14 2026)** covers Bedrock and SageMaker. It detects unusual invocation patterns, **cost harvesting**, and prompt injection via Bedrock Guardrails [sourced: https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-guardduty-ai-protection-aws/].
- Malware Protection for S3 and EBS, Runtime Monitoring, and RDS Protection are all available [sourced: https://aws.amazon.com/guardduty/pricing/].
- GuardDuty threats feed exposure correlation [sourced: https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/].

### Integrations & workflow
- **Jira Cloud** uses an OAuth 3LO connector (a dedicated system account is recommended). **ServiceNow ITSM** uses OAuth client credentials stored in Secrets Manager under a customer-managed KMS key.
- Connectors are created with `CreateConnectorV2`. AWS documents that Jira rate limits can mean "some findings may not be processed into Jira tickets at all" [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/jiracloud.html], [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/servicenow.html].
- **Automation rules (v2)**:
  - Criteria use OCSF fields, the same filters as `GetFindingsV2`.
  - Actions can update only Comment, SeverityId and StatusId, or create a ticket.
  - Rules apply in `RuleOrder`, and a rule created in the home Region applies to linked Regions.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-automation-rules.html]
- OCSF partners include Splunk, CrowdStrike, Datadog, Cribl, Zscaler, Sumo Logic and Dynatrace. Security Lake stores data as OCSF in Parquet/Iceberg [sourced: https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/], [sourced: https://aws.amazon.com/security-lake/pricing/].

### Dashboards & reporting UX
- The **Summary** dashboard has **Executive** and **Triage** tabs.
  - Widgets: Trends overview (month-, week- and day-over-day), Exposure and Threat finding trends (5d, 30d, 90d, 6mo, 1yr), and **Security Coverage** by account and Region.
  - Filter sets are saved, delegated-admin layouts are kept separate, and up to **1 year** of history is retained.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/dashboard-v2.html]
- A **Remediation plans** widget shows the top 5 New or Updated plans [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html].
- There is no documented SLA or MTTR widget and no scheduled exec PDF [inferred].

### AI assistant
- **Security Hub MCP App (preview, July 27 2026)** is a local, read-only MCP server for Claude Desktop.
  - It returns the top exposures, the attack path and expanded network path, correlated findings and fixes.
  - Each tool returns **text plus an interactive visualization**. It is free.
  - [sourced: https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-mcp-app/]
- **GuardDuty AI-powered investigations (preview, June 2026)** look at 90 days of activity. Output is a disposition with a confidence score, MITRE ATT&CK mapping, evidence, and suppress, contain or remediate recommendations. It is in 10 Regions [sourced: https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-guardduty/].
- The GA blog called exposure findings "AI-powered" [sourced: https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/]. Nothing confirms an in-console natural-language chat [inferred].

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- V2 APIs include `GetFindingsV2`, `BatchUpdateFindingsV2`, `CreateAutomationRuleV2` and `CreateConnectorV2`.
  - CLI, CloudFormation and Terraform coverage follows the usual AWS pattern [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-automation-rules.html] [inferred for IaC].
- Multi-account works through Organizations delegated admin, configuration policies, and Region aggregation with a home Region.
- RBAC is IAM (managed policies such as `AWSSecurityHubFullAccess`). SSO is IAM Identity Center [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html] [inferred for SSO].
- There is no MSSP-style multi-tenant console [inferred].

### Unique "wow" features released 2025–2026
- Remediation plans: root-cause grouping, phased steps with rollback, and multi-format IaC snippets (Sept 2026).
- Likelihood × Impact matrix built on effective permissions (SCP- and RCP-aware) plus EPSS (June 2026).
- Network Scanning, which checks reachability from outside instead of reading configuration (July 2026).
- AI inventory, including shadow AI found through DNS (July 2026).
- GuardDuty AI Protection with cost-harvesting detection (July 2026).
- MCP App with visual tool results (July 2026).
- Azure VMs, functions, ACR images and identities monitored natively, with no Azure security services required (2026).

### Documented weaknesses/complaints
- The graph and plan list are thin:
  - Plans can't be sorted and take at most 2 equality filters.
  - The attack graph is console-only.
  - Config SQL has no JOIN.
  - [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html], [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/potential-attack-path-graph.html]
- Ticket loss under Jira rate limits [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/jiracloud.html].
- Spending is split across many meters: Security Hub units, CSPM checks, Config CIs, Inspector, GuardDuty, Macie, the $9 internal-access charge, and Security Lake. A PeerSpot reviewer at Cisco (May 2026): "the cost factor is something that is the main concern" [sourced: https://www.peerspot.com/products/aws-security-hub-reviews].
- Noise. Carbon MFB (Aug 2024): "Many findings are too generic or irrelevant" [sourced: same].
- Multicloud is still limited:
  - Scybers (Oct 2025): "cannot scale up to multiple different cloud environments; it only works for AWS."
  - Azure is limited to 4 resource types plus benchmark checks, and there is no GCP [sourced: same], [sourced: https://ecorpit.com/aws-security-hub-azure-multicloud-cspm-decision-guide-2026/].
- Setup effort. M2P Fintech: "requires more configurations and integration" [sourced: https://www.peerspot.com/products/aws-security-hub-reviews].
- DSPM covers S3 only. Exposure trait coverage is limited to a handful of resource types [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html].

### Sources
- https://aws.amazon.com/security-hub/pricing/
- https://aws.amazon.com/security-hub/cspm/pricing/
- https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/
- https://docs.aws.amazon.com/securityhub/latest/userguide/doc-history.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/potential-attack-path-graph.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-automation-rules.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/dashboard-v2.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-azure.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/jiracloud.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/servicenow.html
- https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/
- https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-ai/
- https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-mcp-app/
- https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-guardduty/
- https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-guardduty-ai-protection-aws/
- https://aws.amazon.com/about-aws/whats-new/2025/12/guardduty-extended-threat-detection-ec2-ecs/
- https://aws.amazon.com/about-aws/whats-new/2025/06/amazon-inspector-code-security-shift-security-development
- https://aws.amazon.com/inspector/pricing/
- https://aws.amazon.com/guardduty/pricing/
- https://aws.amazon.com/macie/pricing/
- https://aws.amazon.com/iam/access-analyzer/pricing
- https://aws.amazon.com/security-lake/pricing/
- https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html
- https://siliconangle.com/2026/07/22/aws-turns-security-hub-ai-multicloud-security-control-plane/
- https://ecorpit.com/aws-security-hub-azure-multicloud-cspm-decision-guide-2026/
- https://www.peerspot.com/products/aws-security-hub-reviews
- https://builder.aws.com/content/3KD2iUC05Ls0WOQrggBDU4o9XmN/security-hub-remediation-plans-root-cause-remediation-dissected


---

## Tenable Cloud Security (Tenable One Cloud Exposure; ex-Ermetic)

### Positioning & pricing model
- Rebranded inside the platform as "Tenable One Cloud Exposure". Positioned as an "identity-first" CNAPP, a heritage it inherits from Ermetic. Tenable bought Ermetic for about $265M ($240M cash plus $25M stock); the deal closed in Q4 2023. [sourced: https://www.sdxcentral.com/news/tenable-looks-to-strengthen-cloud-security-portfolio-with-240m-ermetic-buy/] [sourced: https://es-la.tenable.com/press-releases/tenable-unveils-ai-powered-cloud-detection-and-response-capabilities]
- Pricing: the AWS Marketplace listing is "[Private Offer Only]" with "custom pricing only", billed as monthly SaaS usage through AWS. No public unit price exists. [sourced: https://aws.amazon.com/marketplace/pp/prodview-vpqhy4y3w77zg] A third-party summary says the meter is "billable resources running in your cloud" and that Tenable One starts around $50K/yr. Neither figure is verified by Tenable. [sourced: https://beaglesecurity.com/blog/article/tenable-pricing.html]
- Licensing tiers seen in the console: **Standard** covers vuln scanning, compliance, AI-SPM, CI/CD, KSPM, workload protection, and data protection. **Enterprise** adds an admission controller, on-site workload scanning, and K8s agent-based scanning. JIT and CIEM are separate SKU options. [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]

### Deployment
- Agentless and API-based. Azure onboarding needs a Global Admin to add the Entra tenant, then a choice of features: Monitoring, Data Scanning, Workload Protection, Remediation, and JIT Access. Required roles include Reader, Key Vault Reader, AKS Cluster User, AKS RBAC Reader, Disk Snapshot Contributor, and User Access Administrator, so scanning is snapshot-based. [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]
- Workload scan cadence: "generally speaking, scanning occurs once every 2-7 days". [sourced: same]
- Clouds and IdPs: AWS, Azure, GCP, Microsoft Entra ID, and Google Workspace for entitlements. [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments]
- Runtime: agentless Tenable-authored detections plus an **optional eBPF runtime sensor** (June 2026). [sourced: https://es-la.tenable.com/press-releases/tenable-unveils-ai-powered-cloud-detection-and-response-capabilities]

### Inventory & graph
- Console menu: Dashboard / **Explore** (Inventory, Compute, Permissions Query, Identity Intelligence) / Risks (Cloud Findings, Vulnerabilities, Container CI/CD Scans) / Policies (547 built-in, 210 of them Azure) / Operations (Automation Rules) / Reports / Settings. [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]
- **Explorer** (Feb 2026): a "unified data model" across clouds, with an advanced query builder that supports granular filters, logical operators, and "relationship-based joins". Queries can be saved. A **Graph view** shows blast radius. The query language is GUI-only; no textual syntax is published. [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments]
- The CIEM Inventory view lists all roles and identity-based policies, whether active or not, to find "ghost" identities and stale permissions. [sourced: same]
- API: a **GraphQL** endpoint (`/graphql`) with cursor pagination (`first`/`after`, `pageInfo.hasNextPage`). Inventory and findings pages are limited to 100 items; vulnerabilities to 10,000. Tenable recommends polling at most daily, with a 12-hour cooldown on on-demand requests. [sourced: https://developer.tenable.com/docs/cloud-security-integrations]

### Attack paths & toxic combinations
- Uses the "toxic cloud trilogy/triad" framing: public exposure, critical vulnerability, and high privilege. Tenable says 38% of orgs have one (Oct 2024 DSPM launch); see competitors.md for the 2025 figure. [sourced: https://itwire.com/business-it-news/security/tenable-cloud-security-integrates-dspm-to-%E2%80%98expose-and-close-toxic-cloud-triads%E2%80%99-that-cause-data-breaches]
- The Nov 2025 release "enhanced toxic-combination analysis for identity-driven risk prioritization". [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation]
- Tenable One **Attack Path Analysis** spans IT, identity, and cloud. ExposureAI writes an "Attack Path Summary" for each path, and users can ask questions about each node. The GenAI runs on Google Vertex AI / Gemini. [sourced: https://www.tenable.com/press-releases/tenable-expands-generative-ai-capabilities-for-faster-attack-path-analysis-and-mitigation-guidance]
- Hexa AI "exposure path insights" (May 2026) let users query paths by service account, privileged user, or AD group. [sourced: https://itbrief.co.uk/story/tenable-launches-hexa-ai-to-automate-exposure-fixes]

### Risk prioritization
- **VPR** (Vulnerability Priority Rating) is AI-assisted. Tenable claims the Nov 2025 version is "twice as efficient" and focuses teams on "1.6% of vulnerabilities". [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation]
- An external network scanner actively probes the cloud attack surface to validate reachability, filterable by resource type, port, and IP (Feb 2026). [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments]
- "Trusted vendor" configuration cuts non-critical cross-account alerts. [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation]
- **Exposure Signals** (Tenable One) explain why an asset is included in an exposure insight. [sourced: https://docs.tenable.com/pdfs/how-tenable-uses-ai-and-machine-learning.pdf]

### CIEM/identity
- This is the strongest area. It computes effective permissions across AWS, Azure, GCP, Entra ID, and Google Workspace, supports custom policies per role category, and detects ghost and stale identities. [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments]
- **JIT access**: a self-service portal with justification-based approvals. Requests can come from Slack or Microsoft Teams. The Nov 2025 Slack app added self-revoking of active sessions and recurring access requests. The audit trail records who, when, and what. [sourced: https://kr.tenable.com/cloud-security/products/just-in-time] [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation]
- One-click automated remediation for **unused SSO permissions**. [sourced: same Nov 2025 blog]

### DSPM
- Agentless discovery and classification of sensitive data, with sensitivity levels feeding finding priority. Launched Oct 2024 alongside **AI-SPM**, which covers AI entitlements, exposed AI resources, and training data. [sourced: https://itwire.com/business-it-news/security/tenable-cloud-security-integrates-dspm-to-%E2%80%98expose-and-close-toxic-cloud-triads%E2%80%99-that-cause-data-breaches]
- The product page also flags "exposed training bucket identification" and "overprivileged AI identity detection". [sourced: https://www.tenable.com/cloud-security]
- **Tenable AI Exposure** (private preview Aug 2025, GA early 2026) discovers shadow AI, agents, and browser plug-ins such as ChatGPT Enterprise and Copilot. [sourced: https://siliconangle.com/2025/08/06/tenable-launches-ai-exposure-address-enterprise-generative-ai-risk/]

### Vulnerability & secrets
- Workload scanning covers VMs, containers, and serverless, plus public AMI scanning. Nov 2025 added scoped npm packages and K8s mapping of image findings to workloads. False positives on unused Linux kernels were removed. [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation] [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments]
- The product page mentions malware detection. Secrets scanning was not confirmed in the sources found. [sourced: https://www.tenable.com/cloud-security] [inferred]

### Code-to-cloud / IaC
- "IaC security" and Container CI/CD Scans are listed in the console; the Settings menu has a "Code" section for repo integration. [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]
- PR auto-fix depth is not documented in the sources found. [inferred]

### Remediation
- Onboarding has a "Remediation" feature toggle, which grants write permissions, and the console has "Automation Rules". [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]
- Hexa AI (GA May 21, 2026, for Tenable One Foundation/Advanced) adds automated remediation workflows. In Aug 2026 it added a Jamf integration that pushes patch policies. [sourced: https://itbrief.co.uk/story/tenable-launches-hexa-ai-to-automate-exposure-fixes] [sourced: https://connect.tenable.com/discussions/product-announcements/tenable-product-update-newsletter-%E2%80%94-august-2026/112325 (via search snippet; page 403)]

### Compliance
- Frameworks include CIS, NIST, ISO 27001, PCI DSS, and GDPR reports, with 547 built-in policies. [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]
- Hexa AI routines produce weekly "Executive and Compliance Reporting" briefings. [sourced: https://www.tenablecloud.cn/press-releases/tenable-delivers-the-industrys-first-always-on-agentic-fleet-for-exposure-management]

### Detection & response / real-time
- CDR (June 9, 2026) produces **AI-powered "threat stories"** that correlate detections across time, identity, and resources into one attack narrative. Hexa AI provides guided response with a plain-language response plan. Active scanning confirms internet reachability. [sourced: https://es-la.tenable.com/press-releases/tenable-unveils-ai-powered-cloud-detection-and-response-capabilities]
- CDR behavioral analysis uses 30 to 90 days of activity logs. [sourced: https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html]

### Integrations & workflow
- Slack and Teams (JIT), Jamf (Hexa), and an MCP server for custom agents. Ticketing and SIEM integrations live under Settings > Integrations. [sourced: https://itbrief.co.uk/story/tenable-launches-hexa-ai-to-automate-exposure-fixes] [inferred for the ticketing specifics]

### Dashboards & reporting UX
- Nov 2025: a redesigned navigation menu, a **"TV mode"** full-screen dashboard for SOC walls, and customizable inventory reports with column selection. [sourced: https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation]

### AI assistant
- **ExposureAI**: GenAI search and chat, attack path summaries, mitigation guidance, and asset summaries. [sourced: https://www.tenable.com/press-releases/tenable-expands-generative-ai-capabilities-for-faster-attack-path-analysis-and-mitigation-guidance]
- **Tenable Hexa AI**:
  - Announced at RSAC on Mar 25, 2026, and GA on May 21, 2026.
  - It is an agentic orchestration engine on the "Exposure Data Fabric".
  - Out-of-box agents cover asset management/tagging, dashboard creation, and health checks.
  - Custom agents get human-in-the-loop controls, and an MCP server lets customers build their own agents.
  - One customer claims it saved 2 days a month on asset tagging.
  - [sourced: https://securityboulevard.com/2026/03/tenable-launches-hexa-ai-an-agentic-orchestration-engine-inside-tenable-one/] [sourced: https://itbrief.co.uk/story/tenable-launches-hexa-ai-to-automate-exposure-fixes]
- **Always-on agentic fleet** (Aug 2026):
  - Agents keep context memory between sessions.
  - Scheduled routines: daily Autonomous Exposure Remediation (scan, analyze, remediate, verify the patch), weekly drift "guardrails", and weekly exec/compliance briefings.
  - The **Agent Center** shows routines as running, completed, queued, or awaiting input.
  - [sourced: https://www.tenablecloud.cn/press-releases/tenable-delivers-the-industrys-first-always-on-agentic-fleet-for-exposure-management] [sourced: Aug 2026 newsletter via search snippet]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- GraphQL API (above). pyTenable has a Tenable One inventory module. [sourced: https://developer.tenable.com/docs/cloud-security-integrations] [sourced: https://pytenable.readthedocs.io/en/1.9.0/api/tenableone/inventory/index.html]
- Details on RBAC, SSO, and an MSSP edition for the cloud module were not found. [inferred: Tenable MSSP portal exists per the docs nav]

### Unique "wow" features released 2025–2026
- Explorer with relationship joins plus Graph view and saved queries (Feb 2026). [sourced: Feb 2026 blog]
- AI "threat stories" CDR with an optional eBPF sensor (Jun 2026). [sourced: CDR press release]
- Hexa AI always-on agent fleet with scheduled routines, Agent Center, and MCP (May–Aug 2026). [sourced: above]
- TV mode dashboards, plus Slack self-revoke of JIT sessions. [sourced: Nov 2025 blog]

### Documented weaknesses/complaints
- G2 rates it 4.6/5 across 37 reviews. Recurring complaints are complex setup and a dense UI: "it takes time to learn where everything lives and how to tune policies". [sourced: https://www.g2.com/products/tenable-tenable-cloud-security/reviews (via search snippet; page 403)]
- PeerSpot: "I have faced several bug incidents with the solution" (Senior System Engineer). "In my experience, Tenable Cloud Security is not very stable" (Cloud Security Engineer). "there might be room for more integrations" (BDM). [sourced: https://www.peerspot.com/products/ermetic-pros-and-cons]
- The PeerSpot aggregate cites "slow operations, and poor graphing". [sourced: https://www.peerspot.com/products/tenable-cloud-security/questions (via search snippet)]
- Workload scan cadence of 2–7 days is slow compared with event-driven competitors. [sourced: 51sec blog] [inferred as weakness]

### Sources
- https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation
- https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments
- https://es-la.tenable.com/press-releases/tenable-unveils-ai-powered-cloud-detection-and-response-capabilities
- https://securityboulevard.com/2026/03/tenable-launches-hexa-ai-an-agentic-orchestration-engine-inside-tenable-one/
- https://itbrief.co.uk/story/tenable-launches-hexa-ai-to-automate-exposure-fixes
- https://www.tenablecloud.cn/press-releases/tenable-delivers-the-industrys-first-always-on-agentic-fleet-for-exposure-management
- https://developer.tenable.com/docs/cloud-security-integrations
- https://blog.51sec.org/2025/10/tenable-cloud-security-step-by-step.html
- https://kr.tenable.com/cloud-security/products/just-in-time
- https://www.tenable.com/press-releases/tenable-expands-generative-ai-capabilities-for-faster-attack-path-analysis-and-mitigation-guidance
- https://itwire.com/business-it-news/security/tenable-cloud-security-integrates-dspm-to-%E2%80%98expose-and-close-toxic-cloud-triads%E2%80%99-that-cause-data-breaches
- https://siliconangle.com/2025/08/06/tenable-launches-ai-exposure-address-enterprise-generative-ai-risk/
- https://aws.amazon.com/marketplace/pp/prodview-vpqhy4y3w77zg
- https://www.peerspot.com/products/ermetic-pros-and-cons

## Rapid7 InsightCloudSec / Exposure Command (ex-DivvyCloud)

### Positioning & pricing model
- Rapid7 now sells InsightCloudSec mainly as the cloud layer of **Exposure Command** on the Command Platform. The Command Platform combines EASM, CAASM, VM, and CNAPP. [sourced: https://www.rapid7.com/compare/exposure-management-providers/]
- Package tiers:
  - **Surface Command**: CAASM, EASM, asset graph, blast radius, Exposure Management dashboard, and Remediation Hub.
  - **Exposure Command Essentials**: adds VM, risk-based prioritization, and policy assessment.
  - **Exposure Command Ultimate**: adds multi-cloud/K8s, cloud posture and compliance, attack path analysis, identity risk, IaC, and app/API testing.
  - Pricing is "Pay for what you use" / "Grow without re-buying". Prices are not shown on the current page.
  - [sourced: https://www.rapid7.com/products/command/pricing/]
- Indexed list prices: Surface Command "begins at $7/asset", Exposure Command at $23/asset, and Exposure Command Advanced at $49/asset. Billable assets are the "daily max resource count averaged over 90 days". This comes from a search-engine snapshot of the older pricing page and could not be re-verified. [sourced: https://old.rapid7.com/products/command/pricing (via search snippet; now redirects)]

### Deployment
- Agentless API "harvesting" runs on a polling schedule that can be customized per service, region, account, or badge. **Event-Driven Harvesting (EDH)** uses AWS CloudWatch Events/CloudTrail, Azure EventGrid, and GCP Cloud Asset Inventory. EDH events are kept for 5 days. [sourced: https://docs.rapid7.com/insightcloudsec/harvesting-overview/]
- Rapid7 markets "identify change in real time and assess risk in 60 seconds". [sourced: https://rapid7.com/globalassets/_pdfs/product-and-service-briefs/insightcloudsec-product-brief.pdf (via search snippet)]
- Clouds: AWS (including GovCloud and China), Azure (Gov and China), GCP, **OCI, and Alibaba Cloud**. It also covers K8s guardrails with remote or local scanners, plus cluster sensors and node scanning. [sourced: https://docs.rapid7.com/insightcloudsec/welcome-to-insightcloudsec]
- Runtime (GA Mar 19, 2026): ARMO-powered CADR with **eBPF sensors**, included in Exposure Command Ultimate. [sourced: https://www.rapid7.com/blog/post/em-preemptive-proactive-enhanced-cnapp-available-exposure-command/] [sourced: https://www.rapid7.com/blog/post/pt-whats-new-rapid7-products-services-q1-2026/]

### Inventory & graph
- The core model is **Query Filters**, **Insights**, and **Bots**:
  - Query Filters are server-side Python classes registered with `@QueryRegistry.register()`. Each has `query_id`, `supported_clouds`, `supported_resources`, `settings_config`, and `version`, and its logic uses SQLAlchemy (`.filter()`, `or_()`, `and_()`, `.like()`). Users pick filters by name, for example "Access List Contains Public IPs", and custom filters show an Owner.
  - Insights are filters plus scope plus reporting.
  - Bots act on filter and Insight output.
  - [sourced: https://docs.rapid7.com/insightcloudsec/filters/]
- Since Jan 2026 there is no longer a hard cap of 1,000 Insights per custom pack. An "Insight Finding Severity" advanced filter was also added. [sourced: https://docs.rapid7.com/insight/release-notes-2026-january/]
- Surface Command's asset graph is queried with **Cypher**. In Q2 2026, Rapid7 added filter-based dashboard widgets "without writing Cypher queries". [sourced: https://www.rapid7.com/blog/post/pt-new-products-services-q2-2026-mdr/]
- Layered Context Resources tab: a Source Data pane shows raw CSP JSON. CSV or JSON export runs in the background with a 10-minute timeout. Tag filters refresh every 12 hours. [sourced: https://docs.rapid7.com/insightcloudsec/layered-context-user-guide/]

### Attack paths & toxic combinations
- Attack paths are predefined path types: AWS 5, Azure 4 (more with Defender for Cloud), GCP 4. Examples are "Publicly Exposed Compute Instance with access to a Bucket Containing PII Data" and "Publicly Exposed Container with High/Critical vulnerabilities".
- Only Critical and High paths are shown, and stopped instances are not tracked. The graph has draggable nodes and network/K8s filters, and exports to PDF, JPG, PNG, or SVG.
- [sourced: https://docs.rapid7.com/insightcloudsec/attack-paths/]
- Aug 2025 expansion: AWS EKS paths, container risk weighted by public vs internal exposure, and VM Scan Engine confirmation of internet reachability. [sourced: https://rapid7.com/blog/post/whats-new-in-exposure-management-at-rapid7-q3-2025]
- The Exposure Command Cloud Posture page flags "toxic combinations". [sourced: https://documentation.rapid7.com/exposure-command/evaluate-your-cloud-posture.htm]

### Risk prioritization
- **Layered Context** risk score runs 0–1000: Low 0–399, Medium 400–699, High 700–899, Critical 900+.
- Factors:
  - Vulnerabilities, via Active Risk; findings above 700 weigh most.
  - Sensitive data.
  - Insights (misconfigurations).
  - Public accessibility (a multiplier).
  - Business criticality (a multiplier).
  - Attack paths (more paths mean a higher score).
  - Critical IAM Insights.
  - Threat Findings.
- The view has Cloud, Applications, and Resources tabs. Clicking a severity bar auto-filters the list.
- [sourced: https://docs.rapid7.com/insightcloudsec/layered-context-risk-score-preview/] [sourced: https://documentation.rapid7.com/exposure-command/evaluate-your-cloud-posture.htm] [sourced: https://docs.rapid7.com/insightcloudsec/layered-context-user-guide/]

### CIEM/identity
- Access Explorer, Principal Explorer, and Identity Analysis compute effective permissions, defined as "net actions a principal may perform on a resource". Least-Privileged Access (LPA) uses **90 days** of executed actions on AWS, Azure, and GCP. [sourced: https://docs.rapid7.com/insightcloudsec/cloud-iam-governance/]

### DSPM
- **Partner-based** through Symmetry Systems DataGuard (Q1 2026). It covers PII, PHI, and financial data across cloud and SaaS, and users can pivot into the Symmetry UI. Results feed Layered Context and attack paths. [sourced: https://www.rapid7.com/blog/post/em-protect-breaches-align-sensitive-data-with-exposure-risk/] [sourced: https://www.helpnetsecurity.com/2026/03/20/rapid7-exposure-command-cloud-security-capabilities/]

### Vulnerability & secrets
- Vulnerabilities come from InsightVM Active Risk, using CVSS plus threat intel. It separates "actively exploited in the wild" CVEs from those with a PoC or exploit. [sourced: https://documentation.rapid7.com/exposure-command/evaluate-your-cloud-posture.htm]
- It is vendor-agnostic: it normalizes Tenable and Qualys findings into one prioritized list. [sourced: https://rapid7.com/blog/post/whats-new-in-exposure-management-at-rapid7-q3-2025]
- Secrets scanning was not found. [inferred]

### Code-to-cloud / IaC
- A CLI IaC scanning tool handles Terraform 0.12+ plans (AWS, Azure, GCP) and CloudFormation, scored against the same Insight packs with Pass, Warn, or Fail. CI integrations: Jenkins, CircleCI, TFC/TFE, GitHub Actions, Azure DevOps, and GitLab. Exceptions can be created from scan results.
- No PR comments or auto-fix are documented.
- [sourced: https://docs.rapid7.com/insightcloudsec/getting-started-with-iac-security/]

### Remediation
- **Bots** (Bot Factory):
  - A bot combines Scope (badges, accounts, clusters, resource groups), Query Filters, and Actions.
  - Actions run per resource, can run in parallel, and support delays.
  - Triggers are resource-creation events, vuln or package changes, or schedules such as nightly.
  - Bots can be created from an Insight via Security > Insights > Library > Action > Create Bot Automation.
  - Bots can't be deleted, only archived, and they auto-pause if their Insight is deleted.
  - No approval workflow is documented.
  - [sourced: https://docs.rapid7.com/insightcloudsec/botfactory/] [sourced: https://docs.rapid7.com/insightcloudsec/filters/]
- **Remediation Hub** (Surface and Exposure Command):
  - Fixes can be assigned, tracked, and validated, then pushed to ServiceNow, Jira, or Automox (Aug 2025).
  - **AI-generated risk intelligence** summaries cover the why, where, and how, with KEV/EPSS signals and compensating controls. They group findings into the fixes with the biggest risk reduction (from late Nov 2025).
  - The **Top Remediations Report** has asset-level OS, IP, cloud, tags, EDR/patch coverage, and reboot status. It exports CSV, HTML, or PDF and can be emailed on a schedule (Apr 2026).
  - A Remediation Bulk Export API feeds Tableau and Power BI.
  - [sourced: https://rapid7.com/blog/post/whats-new-in-exposure-management-at-rapid7-q3-2025] [sourced: https://www.rapid7.com/blog/post/pt-remediate-vulnerabilities-faster-with-ai-generated-risk-intelligence/] [sourced: https://www.rapid7.com/blog/post/em-path-from-prioritized-exposures-to-remediation-progress/] [sourced: https://www.rapid7.com/blog/post/pt-whats-new-rapid7-products-services-q1-2026/]
- Runtime auto-response can terminate a process, pause a container, or isolate a namespace. [sourced: https://www.rapid7.com/blog/post/em-preemptive-proactive-enhanced-cnapp-available-exposure-command/]

### Compliance
- **Compliance Packs** span security, cost, and governance, with 20+ standards including NIST 800-53, ISO 27001, HIPAA, PCI, SOC 2, and CIS. [sourced: https://docs.rapid7.com/insightcloudsec/welcome-to-insightcloudsec] [sourced: https://docs.rapid7.com/insightcloudsec/glossary (via search snippet)]
- Jan 2026 brought CIS AWS 6.0, Azure 4.0, and GCP 4.0, plus a CIS AWS End User Compute v1.2.0 pack. HITRUST packs came in 26.7.28. [sourced: https://docs.rapid7.com/insight/release-notes-2026-january/] [sourced: release notes feed via search snippet]
- **Cyber GRC** module: early access Q2 2026, broadly available late July 2026. It handles control-to-telemetry mapping and evidence automation. [sourced: https://www.rapid7.com/blog/post/pt-new-products-services-q2-2026-mdr/]

### Detection & response / real-time
- Threat Findings has a unified view. The ARMO CADR adds AI-baselined anomaly detection and L7 visibility. Rapid7 also announced monitoring of "AI agents for deviations" (Mar 2026). [sourced: https://www.helpnetsecurity.com/2026/03/20/rapid7-exposure-command-cloud-security-capabilities/]
- EDH provides near-real-time posture. [sourced: harvesting doc]

### Integrations & workflow
- ServiceNow, Jira, Automox, Tableau/Power BI (bulk export), Defender for Cloud attack paths, and Symmetry (DSPM). It also ingests Tenable and Qualys VM data. [sourced: Q3 2025 blog; attack-paths doc; Q1 2026 blog]

### Dashboards & reporting UX
- **Exposure Management Dashboard** (rolled out from Aug 2025): a real-time risk summary, trends in risk and assessed assets over time, vulns by age and severity, and discovered vs remediated counts. [sourced: https://rapid7.com/blog/post/whats-new-in-exposure-management-at-rapid7-q3-2025]
- A Cloud Summary page (more flexible as of Jan 2026), plus saved-filter dashboard widgets. [sourced: Jan 2026 release notes; Q2 2026 blog]

### AI assistant
- There is no named conversational cloud copilot in the sources found. AI shows up as:
  - Remediation Hub summaries.
  - Runtime "remediation narrative".
  - AI baselining.
  - Incident Command log summaries.
  - Agentic MDR from the Kenzo Security acquisition.
  - [sourced: https://www.rapid7.com/blog/post/pt-whats-new-rapid7-products-services-q1-2026/]
- Open-source **Rapid7 Bulk Export MCP Server** plus an "Agent Skill" (Apr 21, 2026, `github.com/rapid7/rapid7-bulk-export-mcp`). It bulk-exports vuln, asset, and policy data into a local offline store so an LLM can query it. [sourced: https://www.rapid7.com/blog/post/em-bulk-export-ai-ready-security-workflows-open-source-mcp-server-agent-skill/]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- REST API (docs at /insightcloudsec/api-documentation/), plus Detail Resource and Export Source Data endpoints. [sourced: welcome doc; layered-context doc]
- SSO: AD, Entra ID, SAML, Okta, PingOne, LDAP. Bot creation needs Editor or Admin entitlements. Badges give tag-like scoping across accounts. [sourced: https://docs.rapid7.com/insightcloudsec/welcome-to-insightcloudsec] [sourced: botfactory doc]

### Unique "wow" features released 2025–2026
- Remediation Hub "Top Remediations" grouping, with AI risk intelligence (Nov 2025 – Apr 2026). [sourced: above]
- Vendor-agnostic VM ingestion of Tenable and Qualys data (Aug 2025). [sourced: Q3 2025 blog]
- Runtime validation with eBPF auto-containment (Mar 2026). [sourced: helpnetsecurity]
- An open-source MCP server and agent skill for bulk data (Apr 2026). [sourced: MCP blog]

### Documented weaknesses/complaints
- PeerSpot:
  - "somewhat complicated to navigate through the UI" (SRE).
  - "wish the UI and UX for reporting could be more straightforward" (Platform Engineer).
  - "better human-readable report formats with thorough explanations" (Sr Platform Eng Lead).
  - "generates numerous false positives" (SOC Analyst).
  - "lot of other solutions...providing features of CSPM, but also CNAPP" (Security Architect).
  - [sourced: https://www.peerspot.com/products/divvycloud-pros-and-cons]
- Gartner and PeerSpot snippets: "The web GUI is clunky and confusing", "Enabling Kubernetes Vulnerability scanning is quite difficult (role binding part)", and it needs "the ability to search back the last three months". [sourced: https://www.gartner.com/reviews/market/cloud-security-posture-management-tools/vendor/rapid7/product/insightcloudsec (via search snippet; page 403)]
- Structural gaps:
  - DSPM depends on the Symmetry partner and runtime on the ARMO partner.
  - Attack paths are a fixed catalog (4–5 per cloud) limited to Critical/High.
  - Query filters can only be extended in server-side Python.
  - [inferred from docs above]

### Sources
- https://docs.rapid7.com/insightcloudsec/filters/
- https://docs.rapid7.com/insightcloudsec/botfactory/
- https://docs.rapid7.com/insightcloudsec/harvesting-overview/
- https://docs.rapid7.com/insightcloudsec/attack-paths/
- https://docs.rapid7.com/insightcloudsec/layered-context-risk-score-preview/
- https://docs.rapid7.com/insightcloudsec/layered-context-user-guide/
- https://docs.rapid7.com/insightcloudsec/cloud-iam-governance/
- https://docs.rapid7.com/insightcloudsec/getting-started-with-iac-security/
- https://docs.rapid7.com/insightcloudsec/welcome-to-insightcloudsec
- https://docs.rapid7.com/insight/release-notes-2026-january/
- https://documentation.rapid7.com/exposure-command/evaluate-your-cloud-posture.htm
- https://www.rapid7.com/products/command/pricing/
- https://rapid7.com/blog/post/whats-new-in-exposure-management-at-rapid7-q3-2025
- https://www.rapid7.com/blog/post/pt-remediate-vulnerabilities-faster-with-ai-generated-risk-intelligence/
- https://www.rapid7.com/blog/post/em-path-from-prioritized-exposures-to-remediation-progress/
- https://www.rapid7.com/blog/post/pt-whats-new-rapid7-products-services-q1-2026/
- https://www.rapid7.com/blog/post/pt-new-products-services-q2-2026-mdr/
- https://www.rapid7.com/blog/post/em-bulk-export-ai-ready-security-workflows-open-source-mcp-server-agent-skill/
- https://www.rapid7.com/blog/post/em-preemptive-proactive-enhanced-cnapp-available-exposure-command/
- https://www.rapid7.com/blog/post/em-protect-breaches-align-sensitive-data-with-exposure-risk/
- https://www.helpnetsecurity.com/2026/03/20/rapid7-exposure-command-cloud-security-capabilities/
- https://www.peerspot.com/products/divvycloud-pros-and-cons

## Qualys TotalCloud

### Positioning & pricing model
- TotalCloud is the CNAPP module of the Enterprise TruRisk Platform. Its "Now with TruRisk Insights" messaging describes CSPM, CWP, CIEM, KSPM, CDR, SSPM, and code-to-cloud. Qualys claims Forrester Wave CNAPP Leader, KuppingerCole 2025 CNAPP Leader, GigaOm Leader, and FedRAMP High. It offers a 30-day free trial. [sourced: https://www.qualys.com/apps/totalcloud/ (page data via curl)]
- **Public meter: Qualys Units (QLU)**, which can be reallocated across modules (CSPM, CWPP, CDR, KCS, SSPM). Published ratios:
  - 1 VM under CSPM = 8 QLU.
  - 1 VM under CDR = 8 QLU.
  - 1 VM with Cloud Agent = 1 QLU.
  - 1 VM with FlexScan = 2 QLU.
  - 1 VM with containers (including CI/CD build nodes) = 30 QLU.
  - 100 registry images = 8 QLU.
  - 100 serverless functions (CSPM or CDR) = 8 QLU.
  - 15 serverless containers = 30 QLU.
  - "Only Virtual Machines and Serverless Functions count toward your CSPM QLU", so S3, DBs, LBs, VPCs and the like are free.
  - The dollar price per QLU is not public.
  - [sourced: https://www.qualys.com/qlu-pricing/ (via curl)]

### Deployment
- **FlexScan** combines agent, agentless snapshot, "zero-touch" network, and API-based scanning under one risk view. [sourced: https://www.qualys.com/apps/totalcloud/]
- GCP agentless snapshot scanning (TotalCloud 2.24, Apr 29, 2026):
  - Ephemeral scan VMs with no public IP, with snapshots attached read-only.
  - A Python "Flexscan scanning server" runs the scans.
  - A Cloud Function bridge allows execution inside private VPCs.
  - Dual IAM roles: a Target role and a Service role.
  - [sourced: https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_24.htm]
- Clouds: AWS, Azure, GCP, and OCI, plus hybrid and on-prem K8s. Also serverless and SaaS (SSPM). [sourced: https://www.qualys.com/apps/totalcloud/]
- Event-driven connectors use AWS EventBridge and, from 2.26/2.27 (Jul–Aug 2026), Azure EventGrid. Only changed resources are processed, with periodic full scans. [sourced: https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_27.htm]

### Inventory & graph
- **QQL (Qualys Query Language)** uses dotted tokens with colon values. Documented examples:
  - `aws.account.tag.key` and `cloud.resource.isDeleted:true`.
  - `aws.ouName: Production`, `aws.rootId: r-a1b2`, `azure.managementGroupName: Finance Production`, `gcp.folderId: 123456789012`, and `oci.subnet.cidrBlock`.
  - Wildcard tag search: `tags:"prod_*"`, `tags:"*_legacy"`, `tags:"*finance*"`. Tag search is case-sensitive.
  - [sourced: https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_25.htm] [sourced: https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_27.htm]
- The **Function Catalog** tab (2.27) under Policy and Investigate lists 23 functions in 9 categories used in custom controls: Date & Time, IP Address, Port, Set Algebra, AWS Cloud Account, AWS SNS, AWS VPC, AWS Policy, and AWS S3. Each shows Info and Logic tabs with a JSON usage example. [sourced: release_2_27]
- **Multi-Cloud Inventory Overview** (2.26): one card per provider showing connectors, resources, and failed controls, with clickable drill-downs. Version 2.27 added 40 new resource types. [sourced: https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_26.htm] [sourced: release_2_27]
- **Dynamic tags** driven by QQL rules, validated against live inventory before save (2.28, Sep 30, 2026). [sourced: https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_28.htm]

### Attack paths & toxic combinations
- **TruRisk Insights** are numbered toxic-combination detections. Examples (Azure coverage added in 2.24):
  - 5003 "Successful SSH brute-forcing on a public VM with critical/high vulnerabilities".
  - 5004 "Malware detection on a public VM with misconfigurations and vulnerabilities".
  - 5008 "DNS exfiltration or tunneling on public VM".
  - 5010 "C2 DNS detected on VM with a critical exploitable vulnerability".
  - These mix runtime threat signals into posture combinations.
  - [sourced: release_2_24]
- Graph-based attack path mapping "from code to crown jewels" with blast radius. [sourced: https://www.qualys.com/apps/totalcloud/]
- Since 2.27, the Instances listing shows an Insights count for each VM, with one-click drill-down to that asset's attack paths. Before that, paths were only visible on the Insights tab. [sourced: release_2_27]

### Risk prioritization
- **TruRisk** scoring combines severity, exploitability, exposure, asset criticality, threat intel, and business importance. [sourced: https://www.qualys.com/apps/totalcloud/]
- ETM add-ons:
  - **TruLens**: dynamic re-ranking from live threat intel.
  - **TruConfirm**: safe exploit validation. It was in preview at ROCon in Oct 2025.
  - [sourced: https://nhimg.org/nhi-news/qualys-enhances-etm-with-agentic-ai-for-identity-security-and-threats]

### CIEM/identity
- CIEM claims to detect "toxic permission chains" and to automate revocation of risky roles. 2.25 added 8 more Azure CIEM resource types. [sourced: https://www.qualys.com/apps/totalcloud/] [sourced: release_2_25]
- **ETM Identity**: an Identity TruRisk score across AD, Entra ID, Okta, and cloud IdPs. It finds AD-to-cloud lateral paths and can auto-remediate (MFA enforcement, de-privileging). It is driven by **Agent Grant**, which is "coming soon". [sourced: https://www.qualys.com/apps/agentic-ai (via curl)]

### DSPM
- "Discover, Classify and Correlate Data at Cloud" is listed as a TotalCloud module. 2.26 added sensitive-data and secret detection on GCP Linux instances (credentials, API keys, tokens) under Inventory > Instance > Security > Sensitive Data. Windows is not supported. [sourced: https://www.qualys.com/apps/totalcloud/] [sourced: release_2_26]

### Vulnerability & secrets
- Qualys's main strength is VMDR heritage: agent and agentless VM, container, and registry scanning, plus secrets via FlexScan snapshots ("filesystem, configuration, secrets, and vulnerability assessments"). [sourced: release_2_24]

### Code-to-cloud / IaC
- IaC build-time controls are published as numbered CIDs in the "AWS Infrastructure as Code Security Best Practices Policy", for example CID 672 ECS Exec logging and 723 Kendra CMK. Build-time policies don't support Tags/Connectors. Container image scanning is gated in Jenkins and GitHub Actions. [sourced: release_2_25] [sourced: release_2_26] [sourced: https://www.qualys.com/apps/totalcloud/]
- Code-to-cloud correlation with TotalAppSec. [sourced: same]

### Remediation
- **AI-Powered Remediation** (2.28, Sep 30, 2026):
  - On any failed system-defined control, the evidence panel offers "AI Powered" or "Manual Remediation".
  - The AI option generates resource-scoped code as Terraform, CLI, Python, or CloudFormation/Bicep/GCP Deployment Manager.
  - Each plan has numbered steps and a **verification step**.
  - It carries an explicit "might not always be perfect" caveat.
  - [sourced: release_2_28]
- **QFlow**: no-code drag-and-drop workflows with "300+ prebuilt playbooks" for patching, policy enforcement, and drift correction, plus ServiceNow and Jira ticketing. Qualys claims MTTR drops "30% or more". [sourced: https://www.qualys.com/apps/totalcloud/]
- **Agent Sara** (ETM):
  - Patches in "confidence-gated waves" driven by AI patch-reliability scoring: zero-touch for high-confidence patches, ring-staged for medium, manual CAB for low. The tiers map to BOD 26-04.
  - Falls back to patchless fixes (mitigate, uninstall, script, isolate) and rolls back automatically.
  - Verifies closure.
  - [sourced: https://www.qualys.com/apps/agentic-ai (via curl)]

### Compliance
- Frameworks include PCI DSS 4.0, HIPAA 2023, NIST 800-53/171, GDPR, DORA, and ISO 27001, for both deployed resources and IaC. Qualys claims "one-click evidence for auditors". SSPM covers 2,000+ SaaS resource types against 40+ standards. TotalCloud and CDR (AWS) are FedRAMP High as of 2.24. [sourced: https://www.qualys.com/apps/totalcloud/] [sourced: release_2_24]
- 2.27 added granular RBAC on Policies, Controls, and Exceptions (view / create-clone / edit / delete). There are new roles "TotalCloud Policy Admin/Reader" and a `GLB_POLICY_READ` scoping tag. Policies can be copied with one click. [sourced: release_2_27]

### Detection & response / real-time
- **CDR** uses eBPF runtime monitoring plus ML to catch zero-days, fileless malware, drift, and privilege escalation, with QFlow response playbooks. A customer quote: Centrica "detects malware at least four hours faster". [sourced: https://www.qualys.com/apps/totalcloud/]

### Integrations & workflow
- ServiceNow, Jira, GitHub Actions, Jenkins, and SIEMs. ETM also ingests third-party findings ("Consolidate & translate security & vulnerability findings from 3rd party tools"). [sourced: https://www.qualys.com/apps/totalcloud/] [sourced: https://www.qualys.com/apps/agentic-ai]

### Dashboards & reporting UX
- A default TruRisk Insights dashboard drills down to impacted inventory and then to a remediation workflow. [sourced: https://www.qualys.com/apps/totalcloud/]
- 2.28 brought interactive posture health charts and CSPM reports with a "Report Display" step. That step toggles 5 sections (Overall Compliance Score, Account-, Control-, and Resource-level stats, Details) and individual CSV columns. [sourced: release_2_28]
- The inventory CSV now includes Lambda runtime (2.25). [sourced: release_2_25]

### AI assistant
- **ROCky**: a conversational AI in the Risk Operations Center that answers questions about exposure data and navigates remediation in plain language. [sourced: https://www.qualys.com/apps/agentic-ai]
- **Agentic AI marketplace** in ETM:
  - **Agent Val**: exploit validation via TruConfirm. It covers 1,600+ CVEs without a new sensor and runs post-mitigation validation. Qualys claims a 90%+ cut in remediation noise and 70% faster remediation. GA Mar 26, 2026, at no extra cost in ETM.
  - **Agent Insta**: "scanless detection" that correlates new advisories with existing telemetry "within minutes of disclosure".
  - **Agent Nyra**: tracks threat actor campaigns and re-ranks the backlog.
  - **Agent Sid**: blast radius and IT-ops technical plans.
  - **Agent Sara**: patching.
  - **Agent Grant**: identity, coming soon.
  - [sourced: https://securitymea.com/2026/03/26/qualys-unveils-industrys-first-ai-agent-for-safe-exploit-validation-and-autonomous-remediation/] [sourced: https://www.qualys.com/apps/agentic-ai]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Separate API release notes ship with each TotalCloud version (for example release_2_28_api). QQL works in both the UI and the APIs. There is tag-based and connector-based scope for sub-users and Manager-only preferences. The FedRAMP High platform runs at qualysguard.gov1.qualys.us. [sourced: https://www.qualys.com/documentation/release-notes/] [sourced: release_2_27] [sourced: release_2_24]

### Unique "wow" features released 2025–2026
- AI remediation code in 4 formats with a verification step (Sep 2026). [sourced: release_2_28]
- QQL-driven dynamic tags and a Function Catalog that documents query functions in-product (Aug–Sep 2026). [sourced: release_2_27/2_28]
- A named agent workforce (Val, Insta, Nyra, Sid, Sara, Grant) plus ROCky (2025–2026). [sourced: agentic-ai page]
- A transparent per-resource-type QLU pricing calculator where non-compute resources are free. [sourced: qlu-pricing]

### Documented weaknesses/complaints
- PeerSpot:
  - "the UI is not user-friendly and feels dated compared to other tools like Prisma Cloud" (Systems Engineer).
  - "there is a complex interface that sometimes overwhelms new engineers" (DNS Architect).
  - "Sometimes we need to wait weeks" for support (IT Security Expert).
  - "one challenge that most leaders face involves alert fatigue".
  - "remediation still belongs to the cloud team".
  - [sourced: https://www.peerspot.com/products/qualys-totalcloud-pros-and-cons]
- Release notes show gaps that were only recently closed: attack paths were not searchable outside the Insights tab until Aug 2026, Azure was event-driven only from mid-2026, and GCP secrets work on Linux only. [sourced: release_2_26/2_27] [inferred as weakness]
- Most cloud functions in the Function Catalog are AWS-only (SNS, VPC, S3, Policy). [sourced: release_2_27] [inferred as weakness]

### Sources
- https://www.qualys.com/apps/totalcloud/ (content extracted from page data via curl)
- https://www.qualys.com/qlu-pricing/
- https://www.qualys.com/apps/agentic-ai
- https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_24.htm
- https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_25.htm
- https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_26.htm
- https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_27.htm
- https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_28.htm
- https://www.qualys.com/documentation/release-notes/
- https://securitymea.com/2026/03/26/qualys-unveils-industrys-first-ai-agent-for-safe-exploit-validation-and-autonomous-remediation/
- https://nhimg.org/nhi-news/qualys-enhances-etm-with-agentic-ai-for-identity-security-and-threats
- https://www.peerspot.com/products/qualys-totalcloud-pros-and-cons


---

## Zscaler Posture Control (ZPC) → Zscaler DSPM + UVM/Risk360 (Avalor Data Fabric)

### Positioning & pricing model
- **Status: discontinued.** ZPC End-of-Sale **2025-03-15**, End-of-Life **2026-03-15**. New ZPC licences stopped on the EOS date. [sourced: https://help.zscaler.com/product-usage-terms/end-sale-end-life-notice-zscaler-posture-control-zpc (via search snippet; the page renders with JS)]
- Migration path: **Zscaler Data Security Posture Management (DSPM)**. Customers get a 2-month overlap with both products running, then the rest of the ZPC term becomes a DSPM subscription "at no extra charge". [sourced: same URL]
- This is the second time Zscaler has sunset a cloud-posture product. Its earlier ZCSPM went EOS 2022-10-18 and EOL 2024-03-31, and customers were moved to ZPC at that point. [sourced: https://help.zscaler.com/product-usage-terms/end-sale-and-end-life-notice-zscaler-cloud-security-posture-management]
- **Correction to the brief's premise:** ZPC was not built from Canonic or Smokescreen. Zscaler said the ZPC team came from the **Cloudneeti** and **Trustdome** acquisitions. [sourced: https://www.zscaler.com/blogs/product-insights/introducing-posture-control-by-zscaler] Smokescreen is deception technology (now Zscaler Deception) and Canonic is SaaS/SSPM supply-chain security. [inferred]
- Zscaler's cloud-risk story is now three products: DSPM (data), **Unified Vulnerability Management (UVM)** and **Risk360** (exposure management), both built on the **Data Fabric for Security** that came with Avalor (acquired 2024). [sourced: https://www.zscaler.com/blogs/company-news/start-spreading-news-zscaler-rocks-exposure-management]
- List pricing: unknown publicly for DSPM, UVM and Risk360. [inferred: no public price page found]
- Related acquisitions in fiscal 2026: **Red Canary** (MDR, closed 2025-08-01, $651.4M cash) and **SPLX** (AI red-teaming and AI asset discovery). Aggregate purchase price was $692.0M. [sourced: https://www.sec.gov/Archives/edgar/data/1713683/000171368326000047/zs-01312026_991.htm (via search summary)]

### Deployment
- ZPC was "100% agentless" and covered VMs, containers and serverless. [sourced: https://www.zscaler.com/press/zscaler-extends-cnapp-capabilities-integrated-data-loss-prevention-and-threat-intelligence]
- DSPM is agentless and covers "IaaS, SaaS, on-premises, endpoint". On-prem data visibility was announced at Zenith Live (2025-07-10). [sourced: https://www.zscaler.com/products-and-solutions/data-security-posture-management-dspm ; https://www.zscaler.com/blogs/product-insights/cutting-edge-data-security-innovations-zenith-live-25]
- DSPM covers AWS, Azure and GCP, and added Snowflake support in 2025. [sourced: https://www.zscaler.com/jp/blogs/product-insights/level-your-data-security-zscaler-dspm-and-snowflake]

### Inventory & graph
- ZPC had a "graph-based correlation and prioritization engine". [sourced: ZPC enhancements press release above]
- DSPM builds a "data inventory graph" of buckets, Cloud SQL instances and disks. [sourced: https://www.zscaler.com/jp/blogs/product-insights/zscaler-dspm-ultimate-data-security-google-cloud]
- **Data Fabric for Security** ingests from **150+ prebuilt connectors**. The **AnySource Connector** takes flat files or webhooks, and new connectors are "built in a matter of a few weeks". The **AnyTarget Connector** pushes data out to other tools. [sourced: https://www.zscaler.com/products-and-solutions/vulnerability-management]
- Asset Exposure Management (CAASM) builds inventory "integrating data across hundreds of sources" and finds coverage gaps, such as assets missing an EDR agent. [sourced: exposure-management blog above]
- No public query language. [inferred]

### Attack paths & toxic combinations
- DSPM uses an "AI correlation engine" to "uncover hidden attack paths" and "toxic combinations". [sourced: DSPM product page]
- Under ZPC, sensitive-data discovery via DLP was correlated with other signals to find attack paths. Zscaler's pitch was that other CNAPPs "do not help organizations understand sensitive data exposure". [sourced: ZPC enhancements press release]

### Risk prioritization
- UVM uses multi-factor scoring that includes **mitigating controls** (for example, a compensating Zscaler policy). Customers can change factor **weights**, and any ingested source can feed the score. [sourced: https://www.zscaler.com/products-and-solutions/vulnerability-management]
- Risk360 produces "financial loss estimates" from industry-standard and custom risk factors, and scores risk by attack stage. [sourced: exposure-management blog]

### CIEM/identity
- ZPC flagged "excessive entitlements". [sourced: https://www.zscaler.com/blogs/product-insights/prioritizing-and-remediating-cloud-risk-cnapp]
- DSPM's **Adaptive Access Intelligence** gives "a granular, risk-based, user-centric view over all access paths" to sensitive data. [sourced: DSPM product page]
- There is no standalone CIEM product after the ZPC sunset. [inferred]

### DSPM
- This is Zscaler's main posture product now. It does "LLM classification" for unusual sensitive data (financial, medical, manufacturing) alongside regex. [sourced: Zenith Live 25 blog]
- Compliance mapping covers GDPR, HIPAA, PCI DSS and NIST AI RMF. [sourced: DSPM product page]
- Data security is unified with the Zscaler DLP/SSE policy: "both DSPM and DLP capabilities come together… unified around a single policy". [sourced: Zenith Live 25 blog]

### Vulnerability & secrets
- ZPC scanned VMs and containers agentlessly. [sourced: ZPC press]
- UVM does not scan. It aggregates and deduplicates findings from third-party scanners. [sourced: UVM page]
- Secrets scanning: unknown publicly after ZPC. [inferred]

### Code-to-cloud / IaC
- ZPC had IDE, SCM and CI/CD integrations, for example feedback on a Terraform file in VS Code. [sourced: prioritizing-and-remediating blog]
- No code-to-cloud product exists after the sunset. [inferred]

### Remediation
- DSPM offers "guided, step-by-step risk remediation" and automated workflows. [sourced: DSPM product page]
- UVM offers **two-way ticketing** that closes and reopens tickets automatically, custom routing workflows, and **exception management** with SLA-extension requests and approvals. [sourced: UVM page]

### Compliance
- Through DSPM: GDPR, HIPAA, PCI DSS, NIST and NIST AI RMF, with "automated reporting". [sourced: DSPM product page]

### Detection & response / real-time
- ThreatLabz intelligence fed ZPC. [sourced: ZPC press]
- Red Canary MDR joined in 2025, pitched as "exposure management with agentic AI-driven threat management". [sourced: SEC 8-K via search summary]

### Integrations & workflow
- 150+ data-fabric connectors, AnySource/AnyTarget, and ITSM integrations. [sourced: UVM page]

### Dashboards & reporting UX
- UVM ships prebuilt reports (risk posture, remediation history, asset coverage) and custom dashboards for **SLA performance and KPIs**. [sourced: UVM page]
- DSPM has an **Enhanced GenAI dashboard** with prompt categorisation and an interactive prompt explorer. [sourced: Zenith Live 25 blog]

### AI assistant
- **Data Security AI Agent**: a conversational investigation copilot inside DSPM. [sourced: Zenith Live 25 blog]
- Zenith Live 2025 themes were "Agentic Operations" and agentic CTEM. [sourced: https://www.wwt.com/blog/zenith-live-2025-unveils-zscaler-agentic-ai-your-digital-kingdoms-new-guardians]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Public detail is thin. Zscaler products use the ZIdentity/OneAPI framework. [inferred]

### Unique "wow" features released 2025–2026
- **Microsoft Copilot Deployment Wizard**: shows the "blast radius of Microsoft Copilot sharing" and bulk-fixes missing Purview labels. [sourced: Zenith Live 25 blog]
- **AI-SPM**: discovers models, services and agents, and scans against the OWASP LLM Top 10. [sourced: DSPM product page]
- **Mitigating-control-aware vulnerability scoring**: UVM lowers a score when a Zscaler control already blocks the path. [sourced: UVM page]

### Documented weaknesses/complaints
- **Product churn.** Two cloud-posture products have been sunset in four years (ZCSPM, then ZPC), so customers re-platformed twice. [sourced: both EOS notices]
- ZPC had a 4.4 rating on Gartner Peer Insights from only **13 ratings**, which suggests low adoption. [sourced: https://www.gartner.com/reviews/product/zscaler-posture-control (via search snippet)]
- PeerSpot now redirects ZPC reviews to the ZTE platform. One reviewer there says "Scanning takes a lot of time…unable to identify the source" (Dayforce, 2026-02-04). [sourced: https://www.peerspot.com/products/zscaler-posture-control-reviews]

### Sources
- https://help.zscaler.com/product-usage-terms/end-sale-end-life-notice-zscaler-posture-control-zpc
- https://help.zscaler.com/product-usage-terms/end-sale-and-end-life-notice-zscaler-cloud-security-posture-management
- https://www.zscaler.com/blogs/product-insights/introducing-posture-control-by-zscaler
- https://www.zscaler.com/press/zscaler-extends-cnapp-capabilities-integrated-data-loss-prevention-and-threat-intelligence
- https://www.zscaler.com/blogs/product-insights/prioritizing-and-remediating-cloud-risk-cnapp
- https://www.zscaler.com/products-and-solutions/vulnerability-management
- https://www.zscaler.com/products-and-solutions/data-security-posture-management-dspm
- https://www.zscaler.com/blogs/product-insights/cutting-edge-data-security-innovations-zenith-live-25
- https://www.zscaler.com/blogs/company-news/start-spreading-news-zscaler-rocks-exposure-management
- https://www.sec.gov/Archives/edgar/data/1713683/000171368326000047/zs-01312026_991.htm
- https://www.peerspot.com/products/zscaler-posture-control-reviews

---

## Sonrai Security (Cloud Permissions Firewall + WALLy)

### Positioning & pricing model
- Sonrai has pivoted from a broad CNAPP/CIEM product (the Sonrai Dig identity graph) to a single enforcement product: the **Cloud Permissions Firewall (CPF)**, plus **WALLy**, a "Cloud PAM AI Agent". The current homepage does not mention Dig or the identity graph. [sourced: https://sonraisecurity.com/ ; inferred re: Dig legacy]
- **List price (sonraisecurity.com/pricing):**
  - Startup: minimum **$15k/year**.
  - Standard: **$150/account/month** for 10–50 accounts across AWS, Azure and GCP.
  - Enterprise: 50+ accounts, "Contact us".
  - All tiers include JIT, third-party restrictions, region/service disablement, identity quarantine, unused-permission removal, enterprise SSO and ChatOps.
  - **14-day free trial**, "results in two hours". [sourced: https://sonraisecurity.com/pricing/]
- **AWS Marketplace:** reported as **$200/account/month, minimum 5 accounts**, metered per account where controls are deployed. [sourced: https://aws.amazon.com/marketplace/pp/prodview-3x3c4b5dnslwk (via search snippet; the listing did not render)] Older direct prices ($99 Starter, $125 Enterprise) appear in stale search caches and look superseded. [inferred]
- 2025 results: **4x ARR**, **220%** customer growth, and **60%** of customers expanded. New logos include Sandisk, Fiserv, ISO New England and PG&E. [sourced: https://sonraisecurity.com/newsroom/sonrai-closes-2025-with-4x-arr-growth/]

### Deployment
- Agentless. Onboarding is at the organisation level with a **read-only role at the top cloud level**, and only metadata is collected. [sourced: pricing page]
- Supports AWS, Azure and GCP. [sourced: https://sonraisecurity.com/cloud-security-platform/cloud-permissions-firewall/]
- Enforcement uses **native org guardrails**: AWS **SCPs** (customers can also "bring your own… SCPs and RCPs into CPF and manage them from a single control plane") and GCP/Azure org policies. [sourced: https://docs.sonraisecurity.com/cpf-public/overview/permissions-firewall-intro/ ; https://siliconangle.com/2025/10/07/sonrai-security-introduces-wally-ai-agent-fix-cloud-privilege-risks-automatically/]
- Limit: about **~50 CPF protections** per SCP budget. Docs note "most customers use approximately 30 AWS services per account", and org-wide exemptions use up SCP space. [sourced: permissions-firewall-intro]
- A JIT tech note covers EKS with Kyverno. [sourced: https://docs.sonraisecurity.com/cpf-public/tech-notes/jit-eks-kyverno/]

### Inventory & graph
- The CPF UI has **Controls**, **Workflow**, **Utilities (Reporting, WALLy, Explorer)** and **Manage**. [sourced: https://docs.sonraisecurity.com/cpf-public/cpf-interface/utilities/wally/wally-intro/]
- The data model is exposed via a **GraphQL API** (below). The legacy Dig "identity graph"/"Cloud Privilege Graph" is no longer marketed. [inferred]

### Attack paths & toxic combinations
- The **Threat Vector dashboard** (2025) translates "cloud identity risk into prioritized threat vectors such as data exposure and cryptomining, with one-click remediation". [sourced: 4x ARR newsroom]
- Sonrai claims CPF "preventatively blocked 16 of 16 real AWS privilege-escalation attack paths". [sourced: same]

### Risk prioritization
- Privilege is prioritised by **sensitive or privileged permissions that are unused or sparsely used**. [sourced: permissions-firewall-intro]
- WALLy "ranks findings by impact priority" and "distinguishes critical privilege risk from expected use". [sourced: https://sonraisecurity.com/wally/ ; SiliconANGLE]

### CIEM/identity
This is the core product. The four CPF primitives are:
- **Protect** privileged permissions.
- **Quarantine** unused IAM users and roles (zombies). Identities stay dormant rather than deleted and can be reactivated "in minutes".
- **Disable** unused services and regions (Region/Service lock).
- **Exempt** identities such as break-glass and deployment roles.

[sourced: https://docs.sonraisecurity.com/cpf-public/ ; CPF product page]

Additional controls:
- **Third-party access controls** block external access granted through roles or resource policies. They were expanded in 2025. [sourced: CPF product page; 4x ARR newsroom]
- **Permissions on Demand (PoD) / JIT** works like this: a protected action is denied, then a ChatOps message asks a human identity for a justification (machine identities skip this step), then the request goes to approvers. Escalation moves to the next approver after **1 hour**, requests expire after **24 hours**, and duplicate requests within **15 minutes** are suppressed. Grants can be permanent or time-limited. [sourced: https://docs.sonraisecurity.com/cpf-public/permissions-on-demand/permissions-on-demand-intro/]
- 2025: **JIT for all enrolled identities**, which "eliminate[s] standing privileges". [sourced: 4x ARR newsroom]
- 2026 content push: JIT for Azure "without new infrastructure", and Azure RBAC/PIM guides. [sourced: https://sonraisecurity.com/blog/]
- AI agents are treated as identities: WALLy can "eliminate unused privileges for every AI agent across all accounts". [sourced: SiliconANGLE]

### DSPM
- None. The Threat Vector dashboard shows "data exposure" only as an identity-risk vector. [sourced: 4x ARR newsroom; inferred]

### Vulnerability & secrets
- Not offered. [inferred]

### Code-to-cloud / IaC
- Not offered. Enforcement is runtime SCPs and org policies, not IaC PRs. [inferred]

### Remediation
- Remediation is **preventive enforcement**: SCPs and org policies are generated automatically from observed usage, and exemptions are reviewed before enforcement. Self-service unblock runs through Slack, Teams or email. [sourced: homepage; CPF page]
- Sonrai claims a "92% reduction in privilege risk", "97% time savings" and "100% protection of new identities". [sourced: CPF page]
- WALLy cannot deploy on its own. Every change lands on a **Pending Changes** screen for human approval. [sourced: wally-intro doc]

### Compliance
- Messaging is "compliance-aligned actions" for least privilege. No framework pack was found. [sourced: SiliconANGLE; inferred]

### Detection & response / real-time
- Denied privileged calls trigger PoD flows in near real time. Sonrai blog posts cover live incidents (Amazon Q Developer extension, Trivy key theft, a Cursor prod-deletion case) as the reason for blocking delete permissions. [sourced: homepage; blog]

### Integrations & workflow
- ChatOps via Slack, Teams and email. [sourced: pricing]
- Integrations with CNAPP, CIEM, ticketing and SIEM. [sourced: WALLy page]

### Dashboards & reporting UX
- Threat Vector dashboard, Reporting and Explorer utilities, and AI-generated **session summaries for privileged access activity**. [sourced: 4x ARR newsroom; wally-intro]

### AI assistant
- **WALLy** was announced 2025-10-07, in beta then, with GA planned for Q4 2025. [sourced: SiliconANGLE]
- It covers five areas: service management, identity and permission governance, administration (review changes, audit history), visibility, and JIT/PoD access control.
- It is available on a chat page, as a contextual "Ask WALLy" pop-up, and in Slack and Teams.
- Conversations auto-delete after **90 days** unless starred. [sourced: wally-intro doc]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- **GraphQL API** at `https://<orgId>.sonraisecurity.com/graphql`. It uses `Authorization: Bearer` plus a `sonraisecurity-com-org` header. Tokens are minted with the `GenerateSonraiUserToken` mutation, last between 2 hours and 30 days, and are audit-logged. Clients must handle 429 with backoff.
- Documented example queries include "unused identities (90+ days dormant)", third-party access, and JIT sessions.

[sourced: https://docs.sonraisecurity.com/cpf-public/developer/graphql-reference/sonrai-graphql-api/]
- Enterprise SSO is in every tier, and there is RBAC with change history. [sourced: pricing; WALLy page]

### Unique "wow" features released 2025–2026
- **JIT for all identities** through org-level guardrails, with no agent or broker in the data path. [sourced: newsroom]
- **WALLy** stages fixes through human approval. Example asks: "remove ransomware privilege risk in production", "quarantine all unused identities in staging". [sourced: SiliconANGLE]
- **Threat Vector dashboard** with one-click remediation. [sourced: newsroom]
- **Bring-your-own SCP/RCP management** from one control plane. [sourced: permissions-firewall-intro]

### Documented weaknesses/complaints
- Almost no public reviews. PeerSpot has **0 reviews** and gives Sonrai 4.8% CIEM mindshare, against 14.3% each for CrowdStrike and Tenable. [sourced: https://www.peerspot.com/products/sonrai-security-reviews]
- Structural limit: SCP-size ceiling of about ~50 protections, and org-wide exemptions eat into it. [sourced: permissions-firewall-intro]
- PoD docs describe AWS only. Azure and GCP JIT details are thin. [sourced: PoD intro]
- Narrow scope: no vulnerabilities, DSPM or IaC, so it is a bolt-on to a CNAPP. [inferred]

### Sources
- https://sonraisecurity.com/pricing/
- https://aws.amazon.com/marketplace/pp/prodview-3x3c4b5dnslwk
- https://sonraisecurity.com/cloud-security-platform/cloud-permissions-firewall/
- https://sonraisecurity.com/wally/
- https://sonraisecurity.com/newsroom/sonrai-closes-2025-with-4x-arr-growth/
- https://siliconangle.com/2025/10/07/sonrai-security-introduces-wally-ai-agent-fix-cloud-privilege-risks-automatically/
- https://docs.sonraisecurity.com/cpf-public/
- https://docs.sonraisecurity.com/cpf-public/overview/permissions-firewall-intro/
- https://docs.sonraisecurity.com/cpf-public/permissions-on-demand/permissions-on-demand-intro/
- https://docs.sonraisecurity.com/cpf-public/cpf-interface/utilities/wally/wally-intro/
- https://docs.sonraisecurity.com/cpf-public/developer/graphql-reference/sonrai-graphql-api/
- https://sonraisecurity.com/blog/
- https://www.peerspot.com/products/sonrai-security-reviews

---

## JupiterOne

### Positioning & pricing model
- Rebranded on **2026-05-13** as the "**JupiterOne AI Risk Management Platform**", the "security data layer for AI". It launched **AI Attack Surface Management (AI ASM)** and **Unified Vulnerability Management (UVM)**, and claims 200+ sources. [sourced: https://www.jupiterone.com/blog/say-hi-to-the-new-jupiterone-and-our-new-products ; https://securitybrief.co.nz/story/jupiterone-launches-tools-for-ai-attack-surface-risk]
- CEO is Paul Forte; CPO is Kevin Tonkin. [sourced: securitybrief]
- **Public pricing, metered on "datapoints"** (the total volume of ingested asset data):
  - Small-Market: **$25k/12 months**.
  - Mid-Market: up to 200k datapoints, **$50k**.
  - Enterprise: up to 400k datapoints, **$100k**.
  - Custom: 1M+.
- **UVM is priced separately on vulnerability findings.** **CCM is priced on existing datapoints** at no extra input. [sourced: https://www.jupiterone.com/pricing]

### Deployment
- Agentless, API-based integrations. Docs say "over 180 integrations" and marketing says "200+". [sourced: https://docs.jupiterone.io/integrations ; https://www.jupiterone.com/blog/the-best-caasm-tools]
- Clouds: AWS, Azure, GCP, Oracle and Alibaba. Kubernetes is included. On-prem **Collectors** handle behind-firewall sources. Custom sources come in through the **Ingest API** and an **Integration SDK**. [sourced: integrations doc]

### Inventory & graph
- It is a native graph. Each entity has a `_type` (source-specific, e.g. `aws_instance`) and a `_class` (abstract, e.g. `Host`, `DataStore`), with **100+ entity classes**.
- Relationship verbs include HAS, CONTAINS, USES, EXPLOITS, IMPACTS, IMPLEMENTS, MITIGATES, MANAGES, ASSIGNED and DEPLOYED TO.
- There are three singleton entities: `Everyone`, `Internet` (`0.0.0.0/0`) and `Root`.

[sourced: https://docs.jupiterone.io/data-model/jupiterone-data-model]
- **J1QL** draws on SQL and Cypher. Verbatim examples from the docs:
  - `FIND DataStore WITH encrypted = false`
  - `FIND Firewall AS f THAT PROTECTS Host WITH public = true AS h RETURN f, h` (and `RETURN tree` for the traversed subgraph)
  - `FIND Person THAT HAS Device THAT !PROTECTS HostAgent` (negated relationship)
  - `FIND User THAT HAS >> Device` (directional)
  - `FIND Firewall AS fw THAT ALLOWS AS rule * AS n WHERE rule.ingress=true AND rule.fromPort=22` (relationship-property filter)
  - `FIND User AS u THAT IS Person AS p RETURN u.username, COUNT(p.email) AS emailCount HAVING emailCount > 1`
  - Full text: `FIND "127.0.0.1" WITH _class='Host'`

  [sourced: https://docs.jupiterone.io/j1ql/basic-queries ; https://docs.jupiterone.io/j1ql/basic-keywords]
- The **Question Library** of prebuilt "starter questions" lives at ask.us.jupiterone.io. Its contents did not render. [sourced: https://docs.jupiterone.io/j1ql]
- June 2026 search update: **⌘K "search anywhere"** with instant results, AI returns **multiple query candidates**, the inspector is available app-wide, and graph-canvas performance improved. [sourced: https://docs.jupiterone.io/features/admin/whats-new-in-search]

### Attack paths & toxic combinations
- Attack paths are built by the user as multi-hop J1QL traversals rather than precomputed. For example, the CSPM intro's canonical case is "public-facing instances that have access to non-public S3 buckets". [sourced: https://docs.jupiterone.io/platform-overview/cspm-intro]
- AI ASM "reveals previously hidden attack paths" across AI agents, identities and cloud. [sourced: say-hi blog]

### Risk prioritization
UVM scores on a **0–10** scale. [sourced: https://docs.jupiterone.io/features/vulnerability-management] The score is built from:
- a threat blend (impact and likelihood);
- a **KEV floor**;
- **context multipliers** for asset criticality and internet exposure;
- an optional MITRE ATT&CK controls layer.

The default prioritisation threshold is **9.0** (the top 10%). [sourced: same]

### CIEM/identity
- Identity unification across IdPs (Okta, Entra/AD and others) and cloud IAM is modelled in the graph. An example is the SSO-to-AWS-account mapping query in the docs. There is no permission-effective analysis engine. [sourced: basic-queries; inferred]

### DSPM
- No native classification. Data stores are graph entities with tags. [inferred]

### Vulnerability & secrets
UVM (2026) does not scan. [sourced: vuln-mgmt doc] It:
- deduplicates "one row per CVE per asset" across CrowdStrike, Qualys, SentinelOne, Tenable and **Wiz**;
- routes cases to an **Owner team** (organisational unit);
- tracks remediation plans.
- **Emerging Threats** (2026-10-05) does the following. [sourced: https://www.jupiterone.com/blog/announcing-emerging-threats]
  - Shows up to 10 trending CVEs, ranked by *escalation transitions*: public PoC, then weaponised, then exploited in the wild, then added to CISA/VulnCheck KEV.
  - Assigns one of four tiers: **Act Now / Elevated / Monitor / Low**.
  - Includes a **scanner-gap flag** for CVEs that no commercial scanner checks yet ("a clean scan isn't evidence of absence").

### Code-to-cloud / IaC
- GitHub/GitLab/CI entities (CodeRepo, Deployment) sit in the graph. Reviewers want "deeper Terraform and IaC integration". [sourced: data-model doc; https://www.peerspot.com/products/jupiterone-reviews]

### Remediation
**Alert rules** are J1QL queries that run on a poll, and their actions handle remediation. [sourced: https://docs.jupiterone.io/features/insights-and-alerts/alerts]
- Poll intervals: 15m, 30m, 1h, 4h, 8h, 12h, 1d or 1w. The shortest intervals depend on plan.
- Trigger modes:
  - all results when changed;
  - newly discovered results only;
  - every evaluation.
- Actions: tag entities, email, Slack, **Jira (update-on-change, auto-resolve)**, ServiceNow, SNS, SQS, S3, webhook, Tines, BigQuery, and a nested "For each" action.
- Rules that have not run for 30+ days auto-disable. `ORDER BY` is discouraged in rules.
- Importable **rule packs** and an **Evaluation history** tab are available.

### Compliance
- **Continuous Controls Monitoring (CCM)** is versioned 1.2/1.3 in release notes and pitched as "control tests are really detections". [sourced: whats-new; https://www.jupiterone.com/blog/what-is-continuous-controls-monitoring]
- A reviewer says the "compliance module underperforms; manual tracking still necessary". [sourced: PeerSpot]

### Detection & response / real-time
- This is an investigation and incident-response context graph, not a CDR. Detection is poll-based through alert rules. [sourced: platform intro https://docs.jupiterone.io/platform-overview/j1-platform-introduction ; alerts doc]

### Integrations & workflow
- 180–200+ sources, Ingest API, SDK, Collectors, and outbound "Data Out" integrations. [sourced: integrations doc; whats-new]

### Dashboards & reporting UX
**Insights** dashboards are made of J1QL-backed widgets. [sourced: https://docs.jupiterone.io/features/insights-and-alerts/insights]
- Widget types: Number (with thresholds), Pie, Line, Bar (stacked), Matrix, Table, Graph and Status, plus a Markdown widget.
- **Trend widgets** snapshot data daily over 1 week to 1 year and show sparklines with % change.
- Dashboards are either team (scoped by resource group and RBAC) or personal. Managed dashboards must be cloned before editing.
- The UVM executive dashboard shows **time-to-remediate baseline**, **reopens by fix confidence** and **accepted risk over time**. [sourced: vuln-mgmt doc]

### AI assistant
- **JupiterOne AI** turns natural language into J1QL, and since June 2026 offers multiple candidate queries. [sourced: j1ql doc; whats-new]
- **MCP Server** GA was 2025-07-28. It exposes Tools (query vulnerable assets, ownership, trigger remediation tasks), Resources and Prompts. [sourced: https://www.jupiterone.com/blog/launching-the-jupiterone-mcp-server-supercharging-agentic-ai-for-cybersecurity-first-enterprises]
- JupiterOne joined **Anthropic's MCP directory** on 2026-08-10. The documented access is read-only: exposure, blast radius and change detection. [sourced: https://www.jupiterone.com/blog/jupiterone-joins-anthropic-mcp-directory]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- Public API reference at `/reference`. Resource groups plus RBAC scope dashboards. [sourced: docs home https://docs.jupiterone.io/ ; insights doc]
- There is a J1 CLI and Terraform provider on GitHub. [inferred]

### Unique "wow" features released 2025–2026
- **Emerging Threats** with escalation-transition ranking and the scanner-gap flag. [sourced]
- **MCP server plus Claude directory listing**. [sourced]
- **Exec UVM metric "reopens by fix confidence"**. [sourced]
- **Datapoint-metered public pricing** that bundles CCM. [sourced]

### Documented weaknesses/complaints
All from PeerSpot (overall **4.2/5** across 6 reviews). [sourced: https://www.peerspot.com/products/jupiterone-reviews]
- "Steep learning curve; J1QL requires significant time to master"
- "Queries sometimes take too long with large datasets or complex graph relationships"
- "Alert noise; better filtering needed for critical issues"
- "Entity naming needs improvement; AI struggles with recognition"
- "Governance data sometimes outdated"
- "Remediation workflows need tighter DevOps pipeline integration"

### Sources
- https://www.jupiterone.com/pricing
- https://www.jupiterone.com/blog/say-hi-to-the-new-jupiterone-and-our-new-products
- https://securitybrief.co.nz/story/jupiterone-launches-tools-for-ai-attack-surface-risk
- https://docs.jupiterone.io/j1ql ; https://docs.jupiterone.io/j1ql/basic-queries ; https://docs.jupiterone.io/j1ql/basic-keywords
- https://docs.jupiterone.io/data-model/jupiterone-data-model
- https://docs.jupiterone.io/integrations
- https://docs.jupiterone.io/features/insights-and-alerts/alerts
- https://docs.jupiterone.io/features/insights-and-alerts/insights
- https://docs.jupiterone.io/features/vulnerability-management
- https://docs.jupiterone.io/features/admin/whats-new-in-search
- https://www.jupiterone.com/blog/announcing-emerging-threats
- https://www.jupiterone.com/blog/launching-the-jupiterone-mcp-server-supercharging-agentic-ai-for-cybersecurity-first-enterprises
- https://www.jupiterone.com/blog/jupiterone-joins-anthropic-mcp-directory
- https://www.jupiterone.com/blog/the-best-caasm-tools
- https://www.peerspot.com/products/jupiterone-reviews

---

## Check Point CloudGuard CNAPP (ex-Dome9)

### Positioning & pricing model
- **The CNAPP is being handed to Wiz.** The Feb 2025 Check Point–Wiz partnership includes "support in the transition of Check Point's CNAPP customers to Wiz". Check Point is reinvesting in cloud network security, WAF and GenAI. [sourced: https://en.globes.co.il/en/article-1001501891 (2025-02-11)] Wikipedia also says the deal was "to replace CloudGuard CNAPP with Wiz's offering". [sourced: https://en.wikipedia.org/wiki/Check_Point]
- The integrated Wiz CNAPP plus Check Point Cloud Network Security went **GA on 2025-10-15**. [sourced: https://www.channelinsider.com/security/check-point-wiz-cnapp-cloud-security/]
- `checkpoint.com/cloudguard/cnapp/` now resolves to a page titled "**Wiz – Check Point Software**". [sourced: https://www.checkpoint.com/cloudguard/cnapp/]
- The CloudGuard product menu lists Cloud Firewalls, Cloud Virtual WAN, WAF and DDoS. [sourced: https://www.checkpoint.com/cloudguard/]
- Google closed its Wiz acquisition on **2026-03-11** ($32B). [sourced: https://en.wikipedia.org/wiki/Wiz,_Inc.]
- **Veriti** (2025) became part of Infinity External Risk Management / exposure management with "70+ vendor integrations". **Lakera** (2025, $300M) brought AI security. [sourced: Wikipedia Check Point]
- The legacy CNAPP API is still live and was updated in Sept 2025. [sourced: https://docs.cgn.portal.checkpoint.com/reference/querycontroller_executetoxiccombinationquery_post_v2security-graphquery.md]
- Pricing: "Licensing based on assets/workloads with annual or pay-as-you-go options… blade-based model… can become expensive". No public list price. [sourced: https://www.peerspot.com/products/check-point-cloudguard-cnapp-reviews]

### Deployment
- Agentless posture covers AWS, Azure, GCP, **OCI** and **Alibaba**, with AWS and Azure organisation onboarding. [sourced: CloudGuard API index https://docs.cgn.portal.checkpoint.com/llms.txt]
- **AWP** (agentless workload protection) uses snapshot scanning with tenant-level scanner settings. [sourced: llms.txt; https://github.com/dome9/terraform-dome9-awp-aws]
- K8s agents via Helm handle Image Assurance and **Admission Control**. [sourced: llms.txt; https://github.com/CheckPointSW/charts]
- API regions: `api.dome9.com` (US) plus `eu1`, `ap1`, `ap2`, `ap3` and `cace1`. [sourced: toxic-combination API doc]

### Inventory & graph
- The inventory API is broken out by AWS service family, GCP, Azure and OCI. [sourced: llms.txt]
- A **Security Graph** has an entity/relationship **schema endpoint** (`/v2/security-graph/entity-schema`) and a query model named `SgqlQueryRunRequestModel` (Security Graph Query Language). [sourced: llms.txt; toxic-combination doc]

### Attack paths & toxic combinations
- These are first-class objects: `/v2/security-graph/query` runs a "toxic combination query", and there are separate **evidence-path** queries plus a per-finding "evidence path" GET. [sourced: llms.txt; toxic-combination doc]
- Issue enrichment endpoints return the asset's vulnerabilities, **IAM sensitivity**, **data sensitivity**, security events, container images and malware. [sourced: llms.txt]

### Risk prioritization
**Effective Risk Management (ERM)** API features: [sourced: llms.txt]
- **Business Priority rules** (`/v2/erm/business-priority/*`).
- One **custom ERM ruleset per platform**.
- **Group risk data**, giving a risk score, risk level and per-group distribution, sorted descending.
- **Top remediation actions** per asset.
- Risk-modifier asset types.
- **WAF coverage stats** for publicly exposed assets.

### CIEM/identity
- There is a CIEM findings API. **IAM Safe** offers **access leases** (JIT) for AWS IAM users and roles, plus lease invitations. [sourced: llms.txt]

### DSPM
- Not native. ERM ingests DSPM from **Sentra** and **Cyera** accounts (`/v2/erm/dspm/sentra-account`, `/cyera-account`). [sourced: llms.txt]

### Vulnerability & secrets
- Agentless and K8s vulnerability scan results, with CSV export, ignored-CVE lists and malware ignore lists. [sourced: llms.txt]
- Code security came from **Spectral**. Its `CheckPointSW/spectral-github-action` is now **archived**. [sourced: `gh api repos/CheckPointSW/spectral-github-action` (archived=true)]

### Code-to-cloud / IaC
- The Spectral scanner covered IaC, secrets and OSS. With the action archived, this area looks deprioritised. [sourced: repo README; inferred]

### Remediation
- **CloudBots** is open-source auto-remediation, deployed as a Lambda behind an SNS topic via CloudFormation, in single- or multi-account (cross-account role) mode. Azure and GCP have their own repos. [sourced: https://github.com/dome9/cloud-bots]
- It is triggered from a compliance rule with `AUTO: <bot> [params]`, for example `AUTO: cloudtrail_encrypt_log_files_using_existing_key <key_id>`. [sourced: https://github.com/dome9/cloud-bots/blob/master/bots/Bots.md]
- About ~80 AWS bot entries, including `ec2_quarantine_instance`, `iam_quarantine_role`, `s3_block_all_public_access` and `iam_entity_create_and_attach_permissions_boundary`. The last commit was 2025-07-10. [sourced: Bots.md; GitHub API]
- A portal "Remediation" API (`/v2/ComplianceRemediation`) and Intelligence "trigger remediation" also exist. [sourced: llms.txt]

### Compliance
**GSL (Governance Specification Language)** has the form `<Entity> [where …] should [not] have <expr>`. Real rules: [sourced: `gh search code` hits in dome9/cloud-bots, dome9/cloud-bots-gcp, dome9/cloud-bots-azure]
- `AMI should have isPublic=false`
- `VMInstance should not have isPublic=true`
- `NetworkSecurityGroup should have inboundRules contain [ destinationPort=22 and source='0.0.0.0/0' ]`
- `SecurityGroup where (name like 'default' and networkAssetsStats contain-all [ count = 0 ]) should have inboundRules isEmpty() and outboundRules isEmpty()`

GSL can also traverse the network graph in a single rule, for example `nics contain [subnet.nacl contain [inbound with [...]]]`, and query scanner output, for example `Instance should not have scanners.findings contain-any [ ruleSeverity='High' ... ]`. [sourced: https://github.com/tamnoon-io/Tamnoon-Public-Playbooks (CloudGuard custom policies)]

Rulesets can be managed as code with the `dome9_ruleset` Terraform resource, which has fields `logic`, `severity`, `remediation`, `compliance_tag`, `domain`, `priority` and `control_title`. [sourced: https://raw.githubusercontent.com/dome9/terraform-provider-dome9/master/website/docs/r/ruleset.html.markdown]

### Detection & response / real-time
- **Intelligence (CDR, ex-Magellan)** onboards account activity (CloudTrail and Azure activity logs) and network traffic (VPC/NSG flow logs) for AWS, Azure, GCP and Alibaba.
- It has a **usage quota** with notification emails at **80/90/100%**.
- Findings are tagged "originated in Magellan".

[sourced: llms.txt]

### Integrations & workflow
- Generic Integrations API, SNS and email notifications with filters, and external findings ingest. [sourced: llms.txt]
- With Wiz, the integration runs both ways: Check Point firewall policies feed into Wiz risk analysis, and Check Point can apply "IPS-based prevention in seconds" to vulnerable workloads. [sourced: checkpoint.com/cloudguard/cnapp]

### Dashboards & reporting UX
- Intelligence reports API (create/update/delete). ERM group-risk views. [sourced: llms.txt]
- A reviewer asks for "better AWS-specific dashboards". [sourced: PeerSpot]

### AI assistant
- **Infinity AI Copilot** spans the Infinity platform. Its CloudGuard CNAPP coverage could not be verified because the page did not render. [inferred]

### API/CLI/IaC-as-config/multi-tenant/RBAC/SSO
- REST API v2 with basic auth (API key ID/secret). [sourced: toxic-combination doc]
- Roles, users and assumable roles (cross-account) are available, as are **user lockout/unlock** and org-wide **usage notifications to parent accounts**, which implies MSP hierarchies. [sourced: llms.txt]
- Terraform provider `dome9/dome9`. [sourced: provider doc]

### Unique "wow" features released 2025–2026
- **Network-enforced remediation of CNAPP findings**: Wiz risk triggers a Check Point gateway/IPS virtual patch (GA Oct 2025). [sourced: channelinsider]
- **Third-party DSPM ingest into risk scoring** (Sentra and Cyera). [sourced: llms.txt]
- **WAF coverage of exposed assets** as an ERM metric. [sourced: llms.txt]

### Documented weaknesses/complaints
- **Product sunset or transition to Wiz.** It is a strategic dead end for new buyers. [sourced: Globes]
- PeerSpot (it merges CloudGuard network reviews; 4.2/5, 245 reviews) says: "expensive compared to other vendors", "Initial configuration is somewhat difficult", "very manual process that should be more automated", and "Blade-based model… can become expensive". [sourced: https://www.peerspot.com/products/check-point-cloudguard-cnapp-reviews]
- API churn shows in deprecated image-assurance endpoints ("move to use /v2/vulnerability/policy") and duplicated "old" remediation APIs. [sourced: llms.txt]

### Sources
- https://en.globes.co.il/en/article-1001501891
- https://www.channelinsider.com/security/check-point-wiz-cnapp-cloud-security/
- https://www.nasdaq.com/press-release/check-point-and-wiz-enter-strategic-partnership-deliver-end-end-cloud-security-2025
- https://www.checkpoint.com/cloudguard/cnapp/ ; https://www.checkpoint.com/cloudguard/
- https://en.wikipedia.org/wiki/Check_Point ; https://en.wikipedia.org/wiki/Wiz,_Inc.
- https://docs.cgn.portal.checkpoint.com/llms.txt
- https://docs.cgn.portal.checkpoint.com/reference/querycontroller_executetoxiccombinationquery_post_v2security-graphquery.md
- https://github.com/dome9/cloud-bots ; https://github.com/dome9/cloud-bots/blob/master/bots/Bots.md
- https://github.com/dome9/cloud-bots-gcp ; https://github.com/dome9/cloud-bots-azure
- https://github.com/tamnoon-io/Tamnoon-Public-Playbooks
- https://raw.githubusercontent.com/dome9/terraform-provider-dome9/master/website/docs/r/ruleset.html.markdown
- https://github.com/CheckPointSW/spectral-github-action
- https://www.peerspot.com/products/check-point-cloudguard-cnapp-reviews

---


---

## Best-in-class per capability (this cluster)

| Capability | Vendor | What makes it best | Source |
|---|---|---|---|
| Inventory query language (readability) | JupiterOne | J1QL reads like English, supports negated edges (`FIND Person THAT HAS Device THAT !PROTECTS HostAgent`), and can return results as a `tree` | https://docs.jupiterone.io/j1ql/basic-queries |
| Graph query power | Microsoft Exposure Mgmt | KQL `make-graph`/`graph-match` over `ExposureGraphNodes`/`ExposureGraphEdges` supports multi-hop pattern matching in a language SOC teams already use | https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph |
| No-code graph search | Google SCC | Verb-phrase builder (`CVE that affects VM that uses ServiceAccount where …`), with CSV export | https://docs.cloud.google.com/security-command-center/docs/graph-search |
| Attack-path scoring transparency | Google SCC (formula) / AWS Security Hub (matrix) | SCC publishes its simulation score (see competitors.md). AWS publishes a Likelihood × Impact matrix in which EPSS/exploitability set the base and an SCP/RCP-aware blast radius moves it ±1 level | https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html |
| Exposure accuracy | Microsoft Defender CSPM | Internet exposure split into wide vs narrow, plus Trusted IP ranges that suppress paths reachable only from those IPs | https://learn.microsoft.com/en-us/azure/defender-for-cloud/internet-exposure-analysis |
| Reachability validation | AWS Security Hub | Network Scanning probes from outside to confirm reachability instead of inferring it from config (Jul 2026) | https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-network-scanning/ |
| Choke points → action | Microsoft Exposure Mgmt / Google SCC | MS: a choke point opens "View blast radius" showing every path through the node. SCC: chokepoint issues say "fix one → closes many", including on AWS/Azure | https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview |
| Root-cause remediation | AWS Security Hub | Remediation plans: one plan per target resource with "resolves N / reduces M" counts, phases Prerequisite→Snapshot→Fix→Verify→Done, rollback per step, and CLI/TF/CFN/CDK/Bicep/ARM snippets | https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html |
| Remediation grouping & reporting | Rapid7 Remediation Hub | "Top Remediations" groups findings into the fixes that remove the most risk, adds AI why/where/how summaries, and sends scheduled CSV/HTML/PDF reports | https://www.rapid7.com/blog/post/em-path-from-prioritized-exposures-to-remediation-progress/ |
| Policy-driven auto-remediation | Check Point CloudGuard (CloudBots) / Rapid7 (Bots) | CloudGuard binds a fix declaratively to a rule (`AUTO: <bot> <params>`, about 80 AWS bots). Rapid7 Bots combine scope + filter + action + trigger (event, schedule or vuln change) | https://github.com/dome9/cloud-bots/blob/master/bots/Bots.md ; https://docs.rapid7.com/insightcloudsec/botfactory/ |
| Policy-as-code DSL | Check Point GSL / Datadog Rego | GSL is a one-line `Entity where … should …` rule. Datadog adds a Rego **Test Rule** preview that runs against live resources before saving | https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/custom_rules/ |
| CIEM right-sizing | Datadog | "View Suggested Policy" builds a least-privilege policy from 90 days of observed usage and delivers it as a Terraform PR | https://docs.datadoghq.com/security/cloud_security_management/identity_risks/ |
| CIEM enforcement | Sonrai | Org-level SCP/RCP "permissions firewall": protects privileged permissions, quarantines zombie identities, locks regions/services, and grants JIT access (escalates at 1h, expires at 24h) | https://docs.sonraisecurity.com/cpf-public/overview/permissions-firewall-intro/ |
| JIT access UX | Tenable Cloud Security | JIT requests and approvals in Slack/Teams, with self-revoke and recurring requests | https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation |
| Governance / ownership / SLA | Microsoft Defender CSPM | Governance rules: owner taken from a tag, 7/14/30/90-day due dates, a grace period, weekly owner email, and on-time/overdue tracking | https://learn.microsoft.com/en-us/azure/defender-for-cloud/governance-rules |
| Runtime + posture fusion | Google SCC (Correlated Threats) / Qualys (TruRisk Insights) | SCC runs hourly graph rules that fold runtime alerts into one issue. Qualys publishes numbered toxic combinations that mix threat and posture signals (e.g. 5003 SSH brute-force on a public VM with critical CVEs) | https://docs.cloud.google.com/security-command-center/docs/correlated-threats-overview ; https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_24.htm |
| Threat detection sequences | AWS GuardDuty | Extended Threat Detection "attack sequences" chain signals across services. AI Protection (2026) adds cost-harvesting detection | https://aws.amazon.com/about-aws/whats-new/2025/12/guardduty-extended-threat-detection-ec2-ecs/ ; https://aws.amazon.com/about-aws/whats-new/2026/07/amazon-guardduty-ai-protection-aws/ |
| AI-asset security (AI-SPM) | Google SCC / AWS Security Hub | SCC treats AI agents as attack-path nodes ("agent modifies IAM" toxic combination). AWS builds an AI inventory from managed services, SBOM-detected self-hosted inference, and DNS-detected shadow AI | https://docs.cloud.google.com/security-command-center/docs/ai-protection-overview ; https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-ai/ |
| AI remediation code | Qualys TotalCloud 2.28 | For any failed control: Terraform/CLI/Python/native template, numbered steps, and a **verification step** | https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_28.htm |
| Agentic copilot (governed) | Sonrai WALLy / Tenable Hexa AI | WALLy stages fixes into a Pending Changes approval queue. Hexa runs scheduled agent routines with an Agent Center status board | https://docs.sonraisecurity.com/cpf-public/cpf-interface/utilities/wally/wally-intro/ |
| MCP / agent-native access | Datadog / AWS / JupiterOne / Rapid7 | Datadog: MCP tools for SQL over findings and Rego rule generation. AWS: an MCP app returning text plus an interactive graph. J1: GA MCP server. Rapid7: open-source bulk-export MCP server into a local store | https://docs.datadoghq.com/security/mcp_server/ ; https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-mcp-app/ |
| Dev handoff | Datadog / Microsoft | Datadog: "send to coding agent" (Cursor) with a tailored prompt. MS: Defender launches GitHub Security Campaigns with Copilot Autofix bundling | https://docs.datadoghq.com/security/code_security/iac_security/ ; https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes |
| Trend dashboards | JupiterOne | Any saved query can become a daily-snapshot trend widget (sparkline + % change). Alert rules have a "new results only" mode and Jira auto-resolve | https://docs.jupiterone.io/features/insights-and-alerts/insights |
| Executive reporting | Microsoft (CNAPP Executive Summary PDF) / Qualys (report builder) | MS: a card-based PDF. Qualys: report display step that toggles sections and CSV columns | https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes ; release_2_28 |
| Compensating-control-aware risk | Zscaler UVM / Check Point ERM | The score drops when a control (proxy, WAF, IPS) already blocks the path. Check Point measures WAF coverage of exposed assets | https://www.zscaler.com/products-and-solutions/vulnerability-management |
| Pricing transparency | Qualys (QLU calculator) / JupiterOne (public tiers) | Published per-resource-type units, with non-compute resources free. J1 publishes tier prices by datapoints | https://www.qualys.com/qlu-pricing/ |

## Features nimbus should steal (ranked)

Ranked by (user-visible impact × fit with nimbus's graph/SQL/IaC-PR core) ÷ build cost [inferred]. Items already committed in `competitors.md` are not repeated; where an item extends one, the extension is stated.

1. **Root-cause remediation plans** (AWS Security Hub). `nimbus plan` / UI "Plans" tab: exposures are grouped by the *one resource change* that fixes them. Each plan shows "resolves N / reduces M issues", ordered phases (Prerequisite → Snapshot → Fix → Verify → Done), a rollback per step, and TF/CFN/CLI snippets. *Why:* it turns a list of findings into the fewest actions that remove the most risk, and it feeds the existing fix-PR pipeline directly.
2. **Exposure width + trusted CIDRs** (Microsoft). Every internet exposure is labelled `wide` (0.0.0.0/0, large ranges) or `narrow`. A `nimbus.yaml` `trusted_cidrs:` list suppresses paths reachable only from those ranges, and the UI shows the reason. *Why:* the biggest source of false-positive "public" findings, fixed cheaply.
3. **Governance rules as YAML with SLAs and owner digests** (Microsoft, Datadog inbox rules). `governance:` rules use first-match ordering: owner from a tag key or CODEOWNERS, due date by severity (7/14/30/90d), and a grace period. Outputs: a weekly owner email/Slack digest, on-time/overdue columns, and an MTTR/SLA tile on the home screen. *Why:* turns findings into accountable work, which buyers ask for in every RFP.
4. **"View suggested policy" least-privilege generator** (Datadog) **+ org-guardrail generator** (Sonrai). From 90 days of CloudTrail/activity logs, emit (a) a right-sized IAM policy per role and (b) SCP/RCP deny statements for unused privileged actions, regions and services, with exemptions. Both are delivered as an IaC PR, with an "SCP budget" meter showing how much of the policy-size limit is used. *Why:* the highest-value CIEM fix, built on data nimbus already ingests.
5. **Choke point → blast-radius drill-in** (Microsoft, Google). Clicking a choke node renders only the sub-graph of paths through it. A chokepoint *issue* states "fixing this closes N toxic combos". *Why:* one-click justification for fixing that node first. It complements nimbus's planned min-cut, which computes the fix set; this view shows why.
6. **Published likelihood × impact matrix** (AWS), extending the committed nimbus score. Ship a documented 5×5 matrix as a second, coarser lens on the 0–10 score: likelihood from KEV/EPSS/reachability, impact from effective-permission blast radius (SCP/RCP/boundary-aware). Never publish low/low. *Why:* executives understand a matrix, and engineers get the chips.
7. **Per-hop "why" labels on paths** (AWS impact tab, Check Point evidence path). Every edge shows the exact permission or rule that enables it (`iam:PassRole via policy X`, `SG sg-1 allows 22 from 0.0.0.0/0`). The full path is available as JSON via the API. *Why:* a path users can audit is a path they trust.
8. **Score/version changelog** (Microsoft "New" tags, Google's silent score shifts). Scores carry `score_version`. After an upgrade a banner explains "score moved −4: 12 new rules (New badge for 30d), formula v2→v3". *Why:* coverage expansions otherwise look like regressions. Google has shifted its scores without notice twice.
9. **Readable graph query syntax with negation and tree output** (JupiterOne, Google). A `FIND … THAT … [!]EDGE …` mini-language that compiles to nimbus SQL/paths(), shows the generated SQL, and returns table or tree. A no-code builder (Tenable Explorer, Datadog Search for/Where/That) produces the same AST. *Why:* the SQL engine reaches users who don't write SQL.
10. **Saved query → trend widget → alert rule** (JupiterOne). Any saved query can be pinned as a daily-snapshot sparkline with % change, and promoted to a scheduled rule with a "new results only" mode, routes, and ticket auto-resolve. *Why:* a home screen users can customize, and alerting that reuses the SQL layer.
11. **Policy-bound auto-remediation bots with approval** (Check Point `AUTO:`, Rapid7 Bots, Sonrai WALLy queue). An opt-in `remediate:` block per rule sets scope, action and trigger (event, schedule or vuln change). Default is dry-run. Actions go to a **Pending Changes** queue for human approval; reversible actions such as quarantine-by-deny are preferred over deletes. *Why:* safe automation is the step past PRs, and approval-first keeps nimbus's guardrails intact.
12. **Zombie-identity quarantine** (Sonrai). A one-click, reversible deny-all on identities unused for more than N days, with a "ghost identities" list showing last-used dates (Tenable). *Why:* cheap to build from last-accessed data, high impact, and low-risk because it can be undone.
13. **Verify step on every fix** (Qualys, AWS). Each fix (PR, CLI or plan) ships with `nimbus verify <finding>`, which re-runs the exact check against live state and closes the ticket when it passes. *Why:* "fixed" becomes evidence rather than a claim, which matches the "implemented ≠ verified" stance in nimbus's rulebook.
14. **Read-only MCP server with SQL + graph tools** (Datadog, AWS, JupiterOne, Rapid7). `nimbus mcp` exposes `sql`, `paths`, `explain_finding` and `draft_fix` over a local DuckDB snapshot and returns optional graph JSON for rendering. *Why:* nimbus's copilot then works inside Claude Code/Cursor at no UI cost.
15. **"Hand off to coding agent"** (Datadog). On an IaC finding, generate a self-contained prompt (finding, file/line, fix strategy, validation commands) and a "copy for Claude Code/Cursor" button. *Why:* almost free to build and meets developers in the tool they already use.
16. **Correlated threat issues** (Google Correlated Threats, Qualys TruRisk Insights). Hourly rules join runtime/log detections with posture paths into one issue that has a stable published ID (e.g. `NIM-TC-0003 public VM + critical CVE + SSH brute-force success`). *Why:* fewer, higher-fidelity issues, and stable IDs that users can track.
17. **AI assets as graph nodes + shadow-AI inventory** (Google, AWS). Model endpoints, agents and MCP servers become node types. Toxic combos include "agent role can modify IAM". Inventory combines managed AI services, SBOM-detected self-hosted inference (Ollama/vLLM), and DNS/egress evidence. *Why:* the fastest-rising crown-jewel class in 2026 RFPs.
18. **Compensating-control-aware scoring** (Zscaler UVM, Check Point ERM). Add a score multiplier below 1 when a WAF, SCP deny, NetworkPolicy or private endpoint already blocks the path step, shown as a chip (`WAF ×0.6`). *Why:* buyers can see the noise drop, and it is honest risk math.
19. **Report builder + executive PDF** (Microsoft, Qualys, Rapid7). Users toggle sections (score trend, top risks, compliance %, account/control/resource stats) and CSV columns, then export PDF/HTML/CSV on a schedule by email. *Why:* the "dated reporting" complaints against Rapid7 and Qualys show demand.
20. **Source-data pane** (Rapid7). Every resource drawer shows the raw provider JSON next to the normalized view, with the API call and timestamp that produced it. *Why:* builds trust, speeds up rule debugging, and supports auditor evidence.
21. **Event-driven targeted harvest** (Rapid7 EDH, Qualys EventBridge/EventGrid). Extends competitors.md §9: re-collect only the resource named in the event, with a visible "last full sync" per account. *Why:* makes the sub-2-minute posture claim real without full rescans.
22. **Query-driven dynamic tags** (Qualys 2.28). Save a SQL query as a tag rule, validate it against live inventory before saving, and auto-apply the tag so policies, reports and routing can scope by it. Wildcard tag filters and OU/management-group/folder dimensions come with it. *Why:* scoping without touching cloud tags.
23. **In-editor schema & function catalog** (Qualys Function Catalog). The query editor gets a searchable side panel listing tables, columns and helper functions, each with an example. *Why:* lowers the SQL learning curve directly.
24. **JIT access broker via Slack** (Tenable, Sonrai). Optional module: time-boxed role assignment requested and approved in Slack, auto-expiring, with self-revoke. *Why:* turns read-only CIEM into risk reduction. Lower rank because it means nimbus writes to IAM.
25. **TV mode** (Tenable). A full-screen, auto-refreshing kiosk view of the home panels. *Why:* trivial to build and demos well in SOCs.

---

## Appendix — raw steal candidates per vendor (from section research)

#### Steal candidates (Microsoft Defender for Cloud + Exposure Management)
1. **Exposure width + trusted CIDRs.** Tag each exposed resource `wide`/`narrow` from SG/NSG source ranges, let users declare trusted CIDRs in `nimbus.yaml`, and suppress paths that come only from trusted IPs. This kills the top source of false-positive "public" findings cheaply. https://learn.microsoft.com/en-us/azure/defender-for-cloud/internet-exposure-analysis
2. **Choke point → "blast radius" view.** Clicking a node renders every path that flows through it toward crown jewels, giving one-click justification for fixing that node first. https://learn.microsoft.com/en-us/security-exposure-management/work-attack-paths-overview
3. **Governance rules as config.** Map owner from a tag key, set SLAs of 7/14/30/90 days, add a grace period that keeps items out of the score until overdue, and send a weekly owner digest plus an overdue/on-time report. This turns findings into accountable work, and nimbus can ship it as YAML plus email/Slack. https://learn.microsoft.com/en-us/azure/defender-for-cloud/governance-rules
4. **Score change-log with "New" rule tags.** When a nimbus upgrade adds rules, show "score moved because N new rules" with a 30-day New badge, so trust survives coverage expansions. https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes
5. **Graph-match query examples over our edges table.** Ship documented `paths()` / Cypher-style recipes mirroring MS's `make-graph`/`graph-match` examples (internet IP →1..3 hops→ VM with RCE). Power users get the KQL-graph experience in DuckDB/SQL. https://learn.microsoft.com/en-us/security-exposure-management/query-enterprise-exposure-graph
6. **CNAPP executive summary PDF.** A built-in, card-based report (score trend, top risks, vulns, compliance) exported to PDF with private/public visibility, which buyers expect for leadership. https://learn.microsoft.com/en-us/azure/defender-for-cloud/release-notes

#### Steal candidates (Google SCC)
1. **Graph search with a verb-phrase builder**, e.g. `CVE that affects VM that uses ServiceAccount where HasFullApiAccess=true`. It gives non-SQL users a readable graph query, which nimbus can compile to SQL or Cypher. https://docs.cloud.google.com/security-command-center/docs/graph-search
2. **Correlated Threats:** hourly graph rules that fold runtime alerts and posture into one issue (crypto mining, lateral movement). It is a cheap rule-based fusion that cuts alert count. https://docs.cloud.google.com/security-command-center/docs/correlated-threats-overview
3. **Downloadable PDF risk report** with a "system attack exposure" page. Execs want one artifact, and nimbus already plans static HTML, so add PDF. https://docs.cloud.google.com/security-command-center/docs/release-notes
4. **Exclude non-exploited CVEs and muted findings from path scoring**, and say so in the UI. It keeps paths credible and is a simple rule to document. https://docs.cloud.google.com/security-command-center/docs/release-notes
5. **Score-algorithm changelog banner.** Google silently shifted scores twice. nimbus should version its formula (`score_v2`) and show "scores changed because…". https://docs.cloud.google.com/security-command-center/docs/release-notes
6. **AI agents and MCP servers as graph nodes**, with toxic combos such as "agent can modify IAM". This is a fast-rising class of crown jewel and attack path. https://docs.cloud.google.com/security-command-center/docs/ai-protection-overview

#### Steal candidates (Datadog)
1. **"View Suggested Policy"**: a least-privilege policy derived from the last 90 days of CloudTrail usage, emitted as a Terraform PR. It is the highest-value CIEM fix, and nimbus already ingests the logs. https://docs.datadoghq.com/security/cloud_security_management/identity_risks/
2. **Rego custom-rule "Test Rule" step**: pick live resources, preview pass/fail before saving. It removes fear of noisy custom rules. https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/custom_rules/
3. **"Hand off to coding agent"** button: generates a tailored prompt and context for Claude Code or Cursor from an IaC finding. It costs little to build and fits nimbus's copilot story. https://docs.datadoghq.com/security/code_security/iac_security/
4. **MCP security toolset with SQL over findings** plus Rego rule generation. nimbus already has SQL, so exposing it as MCP tools makes it agent-native. https://docs.datadoghq.com/security/mcp_server/
5. **Inbox rules with due dates** (first-match, ordered, severity → SLA) and **group by team**. This adds SLA/MTTR tracking to the nimbus home screen. https://docs.datadoghq.com/security/security_inbox/
6. **Framework posture score with a time selector and PDF/CSV export** filtered by team/env tags. This is the audit-ready compliance report users expect. https://docs.datadoghq.com/security/cloud_security_management/misconfigurations/frameworks_and_benchmarks/

#### Steal candidates (AWS Security Hub)
1. **Root-cause remediation plans**: one fix per target resource, showing "resolves N / reduces M exposures", with phases Prerequisite→Snapshot→Fix→Verify→Done, a rollback for each step, and Terraform/CFN/CLI snippets. It turns a list of findings into the fewest actions that cut the most risk. https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-remediation-plans.html
2. **Published Likelihood × Impact matrix**: EPSS and exploitability set the baseline, and the effective-permission blast radius moves it up or down one level. It is simple and explainable, and drops low/low combinations. https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-severity.html
3. **Effective-permission blast radius aware of SCPs and RCPs**, with each hop labelled by the permission used (an "Impact assessment" tab). nimbus's graph can show why a hop is possible, not just that it is. https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings-supported-traits.html
4. **Contextual traits**: show signals that did not trigger the exposure, such as "47 unused permissions across 5 services", next to it. This adds blast-radius context cheaply without creating extra findings. https://docs.aws.amazon.com/securityhub/latest/userguide/exposure-findings.html
5. **AI inventory from three sources**: managed AI services, SBOM-detected self-hosted inference (Ollama, vLLM), and external AI API calls from DNS. Shadow-AI discovery is a 2026 buying criterion. https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-ai/
6. **MCP server that returns text plus an interactive graph per tool call** (read-only, local creds). It lets nimbus's copilot run inside the user's existing AI client. https://aws.amazon.com/about-aws/whats-new/2026/07/aws-security-hub-mcp-app/

#### Steal candidates (Tenable)
1. **JIT access via Slack/Teams with self-revoke and recurring requests.** Nimbus already maps identities. A small JIT broker that issues time-boxed role assignments, with a ChatOps approval flow, turns read-only CIEM into risk reduction. https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation
2. **Explorer: a visual query builder with relationship joins that saves to a Graph view.** Nimbus has SQL. Add a no-code builder that compiles to SQL, plus a graph toggle for blast radius, so non-SQL users can use it. https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-multi-cloud-risk-analysis-attack-surface-assessments
3. **Ghost/stale identity inventory.** List every role and policy, including inactive ones, with last-used dates. This is cheap to build from IAM last-accessed data and gets high engagement. Same URL.
4. **AI "threat stories".** Cluster related detections by identity, resource, and time window into one narrative card for each incident. https://es-la.tenable.com/press-releases/tenable-unveils-ai-powered-cloud-detection-and-response-capabilities
5. **Scheduled agent routines plus an "Agent Center" status board.** Run daily or weekly copilot jobs (drift review, exec brief) and show their state: running, queued, or awaiting approval. https://www.tenablecloud.cn/press-releases/tenable-delivers-the-industrys-first-always-on-agentic-fleet-for-exposure-management
6. **TV mode.** A full-screen, auto-refreshing kiosk dashboard is trivial to build and demos well. https://www.tenable.com/blog/whats-new-in-tenable-cloud-security-enhanced-visibility-prioritization-and-navigation

#### Steal candidates (Rapid7)
1. **Bots: scope, query, action, trigger.** Event, schedule, or vuln-change triggers drive actions such as tag, notify, or fix. Nimbus can offer this as YAML "automations" on its existing queries, with dry-run and approval, which the Rapid7 docs show it lacks. https://docs.rapid7.com/insightcloudsec/botfactory/
2. **Transparent 0–1000 risk score with documented factors and multipliers.** Publish the formula (public exposure multiplier, business-criticality multiplier, attack path count) so the score is explainable. This is a natural advantage for open source. https://docs.rapid7.com/insightcloudsec/layered-context-risk-score-preview/
3. **"Top Remediations" view.** Group findings by the single fix (patch, SG rule, IAM change) that removes the most risk, then schedule CSV, HTML, or PDF emails. https://www.rapid7.com/blog/post/em-path-from-prioritized-exposures-to-remediation-progress/
4. **Event-driven harvesting.** Re-collect only the resource named in a CloudTrail, EventGrid, or Asset Inventory event, with periodic full syncs. This is key for "60-second" posture claims. https://docs.rapid7.com/insightcloudsec/harvesting-overview/
5. **Source Data pane.** Show the raw cloud-provider JSON for any resource next to the normalized view. It builds trust and helps debug rules. https://docs.rapid7.com/insightcloudsec/layered-context-user-guide/
6. **Bulk-export MCP server and agent skill.** Ship an MCP server that loads a local snapshot (for example DuckDB or SQLite) for LLM querying, which fits nimbus's SQL plus copilot design. https://www.rapid7.com/blog/post/em-bulk-export-ai-ready-security-workflows-open-source-mcp-server-agent-skill/

#### Steal candidates (Qualys)
1. **AI remediation with format choice and a verification step.** For any failed check, generate resource-scoped Terraform, CLI, or native IaC, plus a "verify" command that re-runs the check. This maps directly onto nimbus's IaC PRs. https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_28.htm
2. **Query-driven dynamic tags.** Save a nimbus SQL query as a tag rule, validate it against live inventory, and auto-apply the tag. Policies and reports can then scope by tag. Same URL.
3. **In-product Function or Schema Catalog.** Make the SQL tables, columns, and helper functions searchable with usage examples inside the query editor. This directly lowers the SQL learning curve. https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_27.htm
4. **Numbered, documented toxic-combination insights that blend runtime and posture.** For example, "public VM + critical CVE + SSH brute-force success". Publish a stable ID for each insight so users can track them. https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_24.htm
5. **Report builder with section and column toggles.** Before export, let users switch on overall score, account, control, resource, and details sections, and pick CSV columns. https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_28.htm
6. **Wildcard and org-hierarchy filters.** Support `tags:"prod_*"` plus AWS OU, Azure management group, and GCP folder as first-class filter dimensions. https://docs.qualys.com/en/tc/release-notes/totalcloud/release_2_27.htm

#### Steal candidates (Zscaler)
- **Mitigating-control-aware risk score**: lower a finding's score when a compensating control (WAF, SCP, NetworkPolicy) already blocks the path. This cuts noise in a way buyers can see. https://www.zscaler.com/products-and-solutions/vulnerability-management
- **User-tunable risk-factor weights**: let teams change factor weights per org in config. https://www.zscaler.com/products-and-solutions/vulnerability-management
- **SLA exception workflow**: request and approve a remediation-deadline extension against a finding, keeping an audit trail. https://www.zscaler.com/products-and-solutions/vulnerability-management
- **AnySource-style generic ingest** (CSV/webhook to findings) so nimbus can absorb third-party scanner output. https://www.zscaler.com/products-and-solutions/vulnerability-management

#### Steal candidates (Sonrai)
- **"Unused privileged permission → org guardrail" generator**: emit SCP/RCP or GCP org-policy deny statements (with exemptions) from observed CloudTrail usage, delivered as an IaC PR. https://docs.sonraisecurity.com/cpf-public/overview/permissions-firewall-intro/
- **Zombie-identity quarantine** (deny-all policy rather than delete, reversible in minutes) as a one-click remediation. https://sonraisecurity.com/cloud-security-platform/cloud-permissions-firewall/
- **Region/service lock recommendations** built from actual usage. https://docs.sonraisecurity.com/cpf-public/
- **SCP budget meter**: show how much of the ≈50-protection SCP capacity a proposed policy uses. https://docs.sonraisecurity.com/cpf-public/overview/permissions-firewall-intro/
- **AI-agent-staged fixes with a Pending Changes approval queue**, so the copilot proposes and a human approves. https://docs.sonraisecurity.com/cpf-public/cpf-interface/utilities/wally/wally-intro/

#### Steal candidates (JupiterOne)
- **Readable graph query language with `!` negated edges and `RETURN tree`**. `FIND Person THAT HAS Device THAT !PROTECTS HostAgent` is a strong UX benchmark for nimbus SQL/graph queries. https://docs.jupiterone.io/j1ql/basic-queries
- **Saved query → scheduled rule → actions**, with "newly discovered results only" mode and Jira auto-resolve. https://docs.jupiterone.io/features/insights-and-alerts/alerts
- **Trend widgets**: daily snapshots of any query count, shown as sparkline plus % change. https://docs.jupiterone.io/features/insights-and-alerts/insights
- **Emerging Threats panel**: CVEs ranked by escalation (PoC → weaponised → KEV), mapped to affected assets, with a "no scanner coverage" flag. https://www.jupiterone.com/blog/announcing-emerging-threats
- **Read-only MCP server** over the nimbus graph, plus a Claude directory listing. https://www.jupiterone.com/blog/launching-the-jupiterone-mcp-server-supercharging-agentic-ai-for-cybersecurity-first-enterprises

#### Steal candidates (Check Point)
- **GSL-style one-line policy DSL** (`Entity where … should [not] have …`) that compiles to nimbus graph/SQL, with policies managed in Terraform. https://github.com/dome9/cloud-bots-azure
- **`AUTO: <bot> <params>` remediation binding on a rule**: a declarative auto-fix hook, opt-in per rule. https://github.com/dome9/cloud-bots/blob/master/bots/Bots.md
- **Evidence path per finding** (an API plus UI showing the exact graph path that made a toxic combination true). https://docs.cgn.portal.checkpoint.com/llms.txt
- **Business Priority rules** that tag crown-jewel assets by rule and feed the risk score. https://docs.cgn.portal.checkpoint.com/llms.txt
- **Pluggable DSPM ingest** (Cyera/Sentra-style connectors) instead of building classification first. https://docs.cgn.portal.checkpoint.com/llms.txt

