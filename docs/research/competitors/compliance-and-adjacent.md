# Competitor Research: Compliance Automation and Adjacent Categories (DSPM, CIEM, CDR, CTEM, Analysts)

_Research date: 2026-10-09. Extends `docs/research/competitors.md` (2026-10-08). That file already covers: Vanta hourly tests and the 400+ integrations claim, Drata Audit Hub at headline level, the AWS Audit Manager report ZIP layout, Prowler/Powerpipe compliance mapping, and the nimbus evidence-bundle design. None of that is repeated here. This file covers what CSPM buyers compare nimbus **against** or **alongside**: GRC/compliance automation, DSPM, CIEM/identity, CDR, CTEM, and analyst/RFP criteria._

**Tagging rules.** `[sourced: URL]` means a fetched page or search-result page said it. `[inferred]` means it is my reasoning and not a vendor statement. Numbers appear only when a source gave them. Many sources are third-party review or comparison blogs, and several are written by competing vendors (ComplyJet, 6clicks, SmartSuite, Sprinto, Sentra). Where that matters, the bias is flagged.

**Research limits (be honest).** The web-search budget for this session ran out partway through. So: (1) the Forrester Wave for Cloud Workload Security and the GigaOm CSPM/CNAPP radar criteria are paywalled and could not be quoted directly; (2) public complaints for most identity, CDR, and CTEM vendors were not collected; (3) Latio's full CNAPP report sits behind a login. These gaps are marked `[gap]` where they apply.

---

## Part A — Compliance automation / GRC

### A1. Vanta

**Positioning & pricing model**
- Calls itself an "Agentic Trust Platform". AI Agent 2.0 (January 2026) drafts policies, answers security questionnaires from an evidence library, auto-scores vendor risk, and shows control relationships in a **Risk Graph**. [sourced: https://cipherssecurity.com/vanta-vs-drata/] (third-party blog)
- Pricing is not public. Third-party estimates: entry about $10k–12k/yr, mid-market (50–200 staff) about $25k–55k/yr, about $5k/yr per added framework. [sourced: https://cipherssecurity.com/vanta-vs-drata/] Price scales by headcount, framework add-ons, questionnaire volume caps, and vendor-count thresholds. Audits and pentests are billed separately. [sourced: https://www.complyjet.com/blog/vanta-reviews] (ComplyJet competes with Vanta)

**What it does that a CSPM typically does not**
- Covers people and process controls: policy acceptance, personnel task completion, device compliance, DPIAs, and data-processor records, all through the Vanta Agent. [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]
- Third-party risk management (TPRM): parallel AI assessments across security, privacy, legal, financial, AI, and ESG domains within one vendor lifecycle. [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]
- **Customer Commitments Automation** ingests contracts and tracks the obligations they create. [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]
- A Trust Center (sold as an add-on). [sourced: https://cipherssecurity.com/vanta-vs-drata/]

**How it integrates with CSPMs**
- **Wiz → Vanta**: Wiz vulnerabilities come in as Vanta vulnerabilities, filterable by severity and mapped to controls. Wiz Issues that are OPEN with severity Critical, High, or Medium come in as security alerts. Configuration findings sync as security alerts mapped to standards. Setup needs a Wiz service account with `create:reports` and `read:reports`. Setup takes under 10 minutes. [sourced: https://help.vanta.com/en/articles/11345611-connecting-wiz-with-vanta]
- **Private integrations / custom resources API**: push resources to `/v1/resources/custom_resource`. Sync is **full-state**: "Every PUT must contain the complete set of resources… Any resource omitted from a sync is treated as no longer existing and will be marked as deleted." Properties must be flat (`boolean`, `int32`, `string`, `timestamp`), plus `displayName`, `uniqueId`, and `externalUrl`. Custom resources have no built-in tests, so you write a Custom Test, and Vanta re-runs it on each fresh push. [sourced: https://developer.vanta.com/docs/concepts/resources.md]
- **Outbound webhooks** fire on events such as vendor created, Trust Center access request, and questionnaire status change. [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]
- **Remote MCP server** (public preview, April 2026). A Claude plugin offers `/vanta:list-tests` and `/vanta:fix-test`, which does IaC remediation across "500+ cloud tests on AWS, GCP, and Azure". [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]

**Compliance specifics**
- "35+ frameworks", 1,200+ automated tests per hour. [sourced: https://cipherssecurity.com/vanta-vs-drata/]
- Custom Tests: a 4-step wizard (Test data → Match data sources → Evaluation logic → Test details). It joins **at most 2 data sources** (one primary plus one secondary, for example `User.email == GitHubMembership.user_email`). [sourced: https://developer.vanta.com/docs/concepts/tests]
- Vendor risk: continuous vendor monitoring with threshold alerts, powered by the Riskey acquisition. [sourced: https://getcoai.com/news/vantas-ai-agent-cuts-compliance-work-from-8-hours-to-1-hour-weekly/] (search summary)

**Dashboards & reporting UX**: Not deeply documented in the sources fetched. [gap] The Risk Graph shows control relationships. [sourced: https://cipherssecurity.com/vanta-vs-drata/]

**AI features**: The Vanta Agent covers policies, privacy, personnel, and questionnaires. AI assessments run in parallel across vendor-risk domains. There is an MCP server. [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]

**Unique "wow" 2025–2026**: `/vanta:fix-test` turns a failing compliance test into an IaC fix from inside Claude or Cursor. [sourced: https://www.vanta.com/resources/new-in-vanta-april-2026]

**Documented weaknesses/complaints**
- "Evidence workflows are less customizable than Drata's". [sourced: https://cipherssecurity.com/vanta-vs-drata/]
- G2/Capterra themes reported as "difficulty of set up", "limitations in Vanta's integrations", "renewal and price jumps", "limitations of Vanta's risk management feature". [sourced: https://www.complyjet.com/blog/vanta-reviews]
- Some integrations "result in false positives, requiring manual intervention to override". [sourced: https://www.6clicks.com/resources/blog/understanding-vantas-limitations-insights-from-real-user-experiences] (6clicks competes with Vanta)

**Sources**: links inline above.

### A2. Drata

**Positioning & pricing model**
- "Agentic Trust Management Platform". Acquired SafeBase (Trust Center) in February 2025. [sourced: https://cipherssecurity.com/vanta-vs-drata/]
- Plans are Foundation, Advanced, and Enterprise, with no public prices. User Access Review is an add-on on Foundation and Advanced. Custom connections start at Advanced. [sourced: https://soc2auditors.org/insights/drata-review/] Third-party estimate: entry about $7.5k/yr, about $1.5k/yr per added framework. [sourced: https://cipherssecurity.com/vanta-vs-drata/]

**What it does that a CSPM typically does not**
- **AI Agent Governance** (June 2026, early access). Inline sensors discover AI agents, including "shadow AI agents no one knew existed", and map each to its owner, identity, permissions, and scope. Agent actions are checked against policy in real time, with "violations blocked before execution". Decisions go into a "tamper-evident record". [sourced: https://drata.com/about/news/drata-expands-trust-management-platform-to-support-governance-of-enterprise-ai-agents]
- Native support for the AIUC-1 AI-agent standard. [sourced: https://drata.com/blog/cybersecurity-roles-among-most-in-demand] (search-result title)
- Trust Center via SafeBase; user access reviews. [sourced: https://soc2auditors.org/insights/drata-review/]

**How it integrates with CSPMs**: Connector-based nightly syncs (AWS, GitHub, Google Workspace…). [sourced: https://soc2auditors.org/insights/drata-review/] "170+ integrations". [sourced: https://cipherssecurity.com/vanta-vs-drata/] Whether Drata ingests findings from a third-party CSPM was not confirmed in this pass. [gap]

**Compliance specifics**
- "20+ frameworks", including CMMC and NIS2. [sourced: https://cipherssecurity.com/vanta-vs-drata/]
- Tests run daily at 19:00 Pacific, and can be re-run by hand. [sourced: https://soc2auditors.org/insights/drata-review/]
- **Custom Test Builder** has a visual builder plus an **Advanced editor using JSON-based rules**. It handles nested objects and arrays, AND/OR logic, and tag key–value matching, with real-time syntax and logic validation that points to the exact line. [sourced: https://help.drata.com/en/articles/13403932-advanced-editor-in-the-test-builder]
- **Audit Hub/Portal**: CPAs see scoped audit data, requests, linked controls, and downloadable evidence packages. The customer sets framework, audit period, and auditor. [sourced: https://soc2auditors.org/insights/drata-review/]
- Access reviews refresh nightly, and "review dates don't freeze access data". In other words, they are not point-in-time snapshots. [sourced: https://soc2auditors.org/insights/drata-review/]

**Dashboards & reporting UX**: New UI shipped March 2026. [sourced: https://drata.com/blog/announcing-new-drata-look] (title only) [gap]

**AI features**: AI questionnaire answers and AI control mapping. [sourced: https://soc2auditors.org/insights/drata-review/] AI agent governance (see above).

**Unique "wow" 2025–2026**: Governing AI agents as a compliance object, with discovery, policy, and a tamper-evident log. [sourced: https://drata.com/about/news/drata-expands-trust-management-platform-to-support-governance-of-enterprise-ai-agents]

**Documented weaknesses/complaints**
- "When a test fails, figuring out exactly which cloud resource Drata is complaining about can still be more painful than it should be". [sourced: https://soc2auditors.org/insights/drata-review/]
- "Too many false positives, intermittent integrations and workflow quirks". [sourced: same]
- "Drata can make compliance look deceptively simple during a demo". [sourced: same]
- Daily rather than hourly cadence gives "wider drift-detection window". [sourced: https://cipherssecurity.com/vanta-vs-drata/]

**Sources**: inline.

### A3. Secureframe

**Positioning & pricing model**: GRC automation with "Comply AI". Pricing is not public in the sources fetched. [gap]

**What it does that a CSPM typically does not**: Comply AI for Risk takes a risk description and produces an inherent risk score, a treatment plan, and a residual risk score. AI vendor-risk extracts answers from vendor documents such as SOC 2 reports. Generative policy drafting. [sourced: https://secureframe.com/newsroom/secureframe-new-suite-of-ai-capabilities]

**How it integrates with CSPMs**: Runs its own cloud tests on AWS, Azure, and GCP. Integrations with external CSPMs were not confirmed. [gap]

**Compliance specifics**: Comply AI for Control Mapping maps controls for **custom frameworks**. Added NIST AI RMF and ISO 42001. [sourced: https://secureframe.com/newsroom/secureframe-new-suite-of-ai-capabilities] (May 2024, older than the 2025–2026 window)

**Dashboards & reporting UX**: [gap]

**AI features**: **Comply AI for Remediation** generates "fixes for infrastructure as code so you can easily copy, paste, and deploy". It supports Terraform, AWS CLI, and CloudFormation across AWS, Azure, and GCP. [sourced: https://secureframe.com/features/ai] (search summary)

**Unique "wow"**: It was the first GRC tool to emit IaC fixes for failing cloud controls (launched 2023). [sourced: https://secureframe.com/features/ai] That makes it the GRC tool closest to nimbus's fix-PR story. [inferred]

**Documented weaknesses/complaints**: None collected. [gap]

### A4. Sprinto

**Positioning & pricing model**: "Autonomous Trust Platform". In 2025 the platform was modularized and "Sprinto AI" agents were added across workflows. [sourced: https://sprinto.com/blog/sprinto-review/] (vendor-authored) Third-party tier estimates: Starter about $7k–9k/yr, Professional about $9k–10k, Advanced about $10k–15k, Enterprise $15k+. Pricing scales with company size and frameworks, not seats. [sourced: https://complyjet.com/blog/sprinto-review]

**What it does that a CSPM typically does not**: "Zones" for multi-entity compliance (separate products or regions), employee training tracking, a Trust Centre, and vendor risk. [sourced: https://complyjet.com/blog/sprinto-review]

**How it integrates with CSPMs**: 200+ integrations, including AWS, Azure, and GCP. [sourced: https://complyjet.com/blog/sprinto-review] CSPM finding import: [gap]

**Compliance specifics**: Claims "200+ global security standards natively" (vendor). [sourced: https://sprinto.com/blog/sprinto-review/] A third party counts "over 30 frameworks". [sourced: https://complyjet.com/blog/sprinto-review] The two numbers conflict. Custom controls (Professional tier and up), an auditor portal with independent evidence access, access reviews, and vendor risk. [sourced: https://complyjet.com/blog/sprinto-review]

**Dashboards & reporting UX**: Real-time dashboard with readiness percentage per control and framework. [sourced: https://complyjet.com/blog/sprinto-review]

**AI features**: Agents that "identify issues, predict risk, validate readiness, and take action". [sourced: https://sprinto.com/blog/sprinto-review/]

**Unique "wow"**: The Zones multi-entity model. [sourced: https://complyjet.com/blog/sprinto-review]

**Documented weaknesses/complaints**: "Steep learning curve, limited UI customisation". "Expensive if you're a 5-person team just starting SOC 2". Integration bugs. [sourced: https://complyjet.com/blog/sprinto-review]

### A5. Thoropass

**Positioning & pricing model**: Bundles the platform with **in-house auditors**, so a single vendor handles both readiness and the audit. No public price list. Third parties cite SOC 2 implementation at $20k–37k. [sourced: https://www.complyjet.com/blog/thoropass-review]

**What it does that a CSPM typically does not**: Performs the audit itself, plus pentesting services and questionnaire automation. [sourced: https://www.complyjet.com/blog/thoropass-review]

**How it integrates with CSPMs**: 100+ integrations, with AI pre-screening of evidence. [sourced: https://www.complyjet.com/blog/thoropass-review] CSPM import: [gap]

**Compliance specifics**: 30+ frameworks, including HITRUST and ISO 42001. Multi-framework control reuse. The auditor works inside the platform. [sourced: https://www.complyjet.com/blog/thoropass-review]

**AI features**: **"First Pass" AI** checks evidence before the auditor sees it. [sourced: https://www.complyjet.com/blog/thoropass-review]

**Unique "wow"**: Evidence is pre-validated by AI and then reviewed by the same company's auditor, which shortens the request-and-response loop. [sourced: same]

**Documented weaknesses/complaints**: "The UI can sometimes feel a bit cluttered… this can slow down workflows." "There's nothing in the audit module that shows you 'hey, we've looked / we're looking at this ER-XX'." Users also report duplicate document uploads between the compliance and audit phases. [sourced: https://www.complyjet.com/blog/thoropass-review]

### A6. AWS Audit Manager

**Positioning & pricing model**: **No longer open to new customers as of April 30, 2026**. "Existing customers can continue to use the service as normal." [sourced: https://docs.aws.amazon.com/audit-manager/latest/userguide/doc-history.html] Usage-based pricing (not re-verified). [inferred]

**What it does that a CSPM typically does not**: Collects evidence (it "does not assess compliance", per the existing competitors.md), lets you delegate control sets to reviewers, and accepts manual evidence (file upload or text) for risk-assessment questions. [sourced: https://docs.aws.amazon.com/audit-manager/latest/userguide/doc-history.html]

**How it integrates with CSPMs**: Uses **Security Hub CSPM consolidated control findings** and AWS Config managed and custom rules as data sources. Exports evidence to MetricStream. Emits EventBridge events. [sourced: https://docs.aws.amazon.com/audit-manager/latest/userguide/doc-history.html]

**Compliance specifics**: Prebuilt frameworks were last updated in 2025 (SOC 2, PCI DSS v4.0, ISO 27001:2013, NIST 800-53r5, FedRAMP r4, 800-171r2, CSF 1.1, CIS v8 IG1, Essential Eight, ACSC ISM). Custom frameworks can be shared across accounts and Regions. "Common controls" are managed groupings of data sources usable as evidence sources. Custom controls can use a list of supported AWS API calls, including paginated calls. [sourced: https://docs.aws.amazon.com/audit-manager/latest/userguide/doc-history.html] Evidence finder offers up to 12 query filters and CSV export. [sourced: https://docs.aws.eu/audit-manager/latest/userguide/evidence-finder-settings-enable.html] (search summary)

**Dashboards & reporting UX**: Dashboard of active assessments and non-compliant evidence (2021). [sourced: doc-history above]

**AI features**: None. [inferred from doc history]

**Unique "wow"**: Its departure is the news. New AWS customers have **no first-party evidence collector**, which leaves an opening for nimbus's evidence bundles. [inferred]

**Documented weaknesses**: AWS-only. Closed to new customers. Framework versions lag (ISO 27001:2013 rather than :2022; CSF 1.1 rather than 2.0). [sourced: doc-history above, version names] [inferred: lag]

### A7. Hyperproof

**Positioning & pricing model**: Enterprise GRC with compliance, risk, audit, third-party risk, and policy modules. Pricing: [gap]

**What it does that a CSPM typically does not**: A crosswalked control library ("link once, map everywhere"), risk register, audit management, and TPRM. [sourced: https://hyperproof.io/resource/hyperproof-delivers-the-ai-guided-experiences-that-get-work-done/]

**How it integrates with CSPMs**: The Evidence Collection experience "recommend[s] source systems like AWS and Okta" and drafts IT credential requests. [sourced: https://securityboulevard.com/2026/03/hyperproof-launches-ai-guided-experiences-for-compliance-operations-at-rsac-2026/]

**Compliance specifics**: "160+ compliance frameworks", including DORA, NIS2, FedRAMP, and CMMC. [sourced: https://hyperproof.io/resource/hyperproof-delivers-the-ai-guided-experiences-that-get-work-done/]

**AI features**: "AI Guided Experiences" (RSAC 2026). **Suggested Links** finds missing control↔policy↔risk↔evidence links, "hundreds of audit artifacts in minutes". **Evidence Collection and Validation** applies "validation tests to catch potential audit issues". Its stance: "not a chatbot", "The AI does the heavy lifting. You do the deciding.", and no training on customer data. [sourced: both Hyperproof URLs above]

**Unique "wow"**: AI that finds missing links in a control graph, which is a graph-completion problem. [sourced: same]

**Documented weaknesses**: [gap]

---

## Part B — DSPM

### B1. Cyera

**Positioning & pricing model**: An AI-native data security platform. Reported $12B valuation (June 2026) and more than $2.3B raised. Acquisitions: Otterize (June 2025, NHI and cloud-native access), Ryft (April 2026), Genie (May 2026, endpoint DLP), and Oasis Security (closed September 1, 2026, NHI management). [sourced: https://yespress.io/cyera] (aggregator; treat as unverified) Licensing "based on storage and user count". [sourced: https://www.peerspot.com/products/cyera-pros-and-cons] (search summary)

**What it does that a CSPM typically does not**: AI classification of structured and unstructured data without regex tuning. "30+ automated actions including access revocation, data masking". Covers on-prem stores (82M+ NetApp files scanned "in under 40 days", per an IDC study). [sourced: https://www.cyera.com/pt-br/platform/dspm] Named a Leader in Forrester Wave Sensitive Data Discovery & Classification, Q2 2026 (vendor claim). [sourced: same]

**How it integrates with CSPMs**: Two-way enrichment with Wiz. Cyera data context feeds Wiz risk, and Cyera uses a "Data Security Graph" for blast radius. [sourced: https://www.cyera.com/press-releases/cyera-and-wiz-partner-to-strengthen-cloud-security-with-data-security-posture-management] Cohesity OEMs Cyera's DSPM. [sourced: https://www.cohesity.com/newsroom/press/cohesity-expands-data-security-portfolio-with-cyera-dspm/]

**Risk/identity/data specifics**: Correlates "data sensitivity, business context, identities, access activity, and exposure factors". [sourced: https://www.cyera.com/pt-br/platform/dspm] Classification precision of "up to 95%" (Cohesity's figure). [sourced: Cohesity URL above]

**AI features**: AI classification. Agent Guardian, for AI-agent data access. [sourced: https://yespress.io/cyera] (aggregator)

**Unique "wow"**: Joins data context with NHI identity (Otterize, Oasis) to answer "which machine identity can reach this PII". [sourced: https://yespress.io/cyera] [inferred: the significance]

**Documented weaknesses**: "Recurring complaints about limited self-serve reporting and custom export flexibility". "Very large data estates report scalability and performance concerns". [sourced: https://www.rfp.wiki/vendors/cyera] "filters and reporting are not super intuitive". "a need to collaborate on API and alert integrations into SIEM systems". [sourced: https://www.peerspot.com/products/cyera-pros-and-cons] (search summary)

### B2. Sentra

**Positioning & pricing model**: DSPM plus Data Access Governance plus Data Detection & Response. Pricing: [gap] [sourced: https://aimultiple.com/dspm-vendors] (search summary)

**What it does that a CSPM typically does not**: **In-environment, ephemeral scanning**: "no data ever leaves your perimeter". This removes egress cost and third-party data retention. It uses metadata clustering plus sampling and claims cloud-cost reductions of "three orders of magnitude". [sourced: https://sentra.io/learn/wiz-dspm-alternatives] (vendor, search summary)

**How it integrates with CSPMs**: The Wiz integration adds Sentra classification to the Wiz Security Graph, so attack paths that touch regulated data are highlighted. [sourced: https://itbrief.com.au/story/sentra-wiz-add-data-classification-to-cloud-risks]

**Risk/data specifics**: Covers IaaS, PaaS, DBaaS, SaaS, and on-prem. ML classification "learns your data patterns". M365 Copilot readiness. [sourced: https://sentra.io/sentra-vs-wiz-dspm]

**Critique of CSPM-embedded DSPM (useful for nimbus positioning)**: CSPMs are "focused primarily on cloud infrastructure", with "rule-based and static classification logic". [sourced: https://sentra.io/sentra-vs-wiz-dspm]

**Unique "wow"**: The data-custody model: the scanner runs in the customer account. [sourced: above] This is the model nimbus should copy. [inferred]

**Documented weaknesses**: Sentra does "not publicly share information about its automated remediation capabilities". [sourced: https://aimultiple.com/dspm-vendors] (search summary)

### B3. Varonis

**Positioning & pricing model**: Moving to SaaS: 86% of ARR was SaaS by year-end 2025. [sourced: https://yespress.io/varonis] (aggregator, citing Q4 2025 results: https://s203.q4cdn.com/582009126/files/doc_news/Varonis-Announces-Fourth-Quarter-2025-and-Full-Year-2025-Financial-Results-2026.pdf) Multi-module licensing. [sourced: https://www.peerspot.com/products/varonis-platform-pros-and-cons]

**What it does that a CSPM typically does not**: Data activity monitoring, MDDR (managed data detection and response), Database Activity Monitoring (2025), Atlas (2026) for AI tools and agents, and Interceptor email. [sourced: https://yespress.io/varonis]

**How it integrates with CSPMs**: Covers AWS, Azure, GCP, Salesforce, ServiceNow, and databases. CSPM integration: [gap]

**Unique "wow"**: It has deep file and activity history to back its data-access answers. [inferred]

**Documented weaknesses**: "The product is very complicated". It needs "multiple servers… called collectors". Pricing is "expensive and hard to forecast". "Initial scanning, indexing, and tuning can be slow or resource-heavy". [sourced: https://www.peerspot.com/products/varonis-platform-pros-and-cons] (search summary)

### B4. BigID

**Positioning & pricing model**: Discovery, privacy, and DSPM. Launched DSPM Express for MSPs/MSSPs (June 2025), deployable "in hours". [sourced: https://www.bigdatawire.com/this-just-in/bigid-launches-1st-managed-dpsm-offering-for-global-mssps-and-msps]

**What it does that a CSPM typically does not**: DSAR automation, data lifecycle (retention, minimization, deletion), and privacy automation. "Agentic Risk Remediation". [sourced: https://bigid.com/dspm] (search summary)

**How it integrates with CSPMs**: ServiceNow ecosystem integration. [sourced: https://cloudwars.com/cloud-wars-minute/bigid-bolsters-servicenow-ecosystem-with-data-security-posture-management-features] CSPM: [gap]

**Documented weaknesses**: "good for technical reporting but not for business or management reporting". "UI bugs, non-intuitive navigation, and occasional scan reliability issues in very large environments". [sourced: https://www.gartner.com/reviews/market/data-security-posture-management/vendor/bigid] (via search summary; the page itself returned 403)

### B5. Normalyze (Proofpoint DSPM)

**Positioning & pricing model**: Acquired by Proofpoint (deal announced 2024) and folded into its "human-centric" platform. [sourced: https://itpro.com/business/acquisition/proofpoint-acquires-data-security-posture-management-firm-normalyze]

**What it does that a CSPM typically does not**: "in-place scanning and quantified risk analysis", on-prem through cloud. [sourced: https://securitybuzz.com/industry-news/proofpoint-expands-human-centric-security-with-normalyze-dspm-acquisition/]

**How it integrates with CSPMs (the most concrete spec in this cluster)**: **Bidirectional Wiz integration**. Inbound, it pulls Wiz Issues "daily (24-hour) schedule" and shows Status, Severity, Resource Name, Provider, Issue Name, and Description in an "External Issues" tab. Outbound, it pushes data-classification findings to Wiz "to update severity and risk". It covers AWS, Azure, and GCP data stores. [sourced: https://docs.public.analyze.proofpoint.com/dspm/guide/getting-started/integrations-setup/wiz.htm]

**Unique "wow"**: Shows a CSPM's issues next to data context in an "External Issues" tab. [sourced: above]

**Documented weaknesses**: [gap]

---

## Part C — CIEM / identity

### C1. Permiso (now Okta)

**Positioning & pricing model**: ITDR for human, non-human, and agentic identities. **Okta announced the acquisition on July 30, 2026, and it closed on August 26, 2026.** It has "over 2,500 research-driven signals" and "70+ identity partners". [sourced: https://www.okta.com/newsroom/press-releases/okta-signs-definitive-agreement-to-acquire-permiso-security/] Pricing: [gap]

**What it does that a CSPM typically does not**: A **Universal Identity Graph** stitches sessions across the IdP, IaaS, PaaS, and SaaS (AWS, Azure, GCP, GitHub, Slack, Salesforce). Behavioral detection uses "1500+ detection rules" from P0 Labs. [sourced: https://permiso.io/identity-threat-detection-and-response-solution] (search summary; the rule count differs from Okta's 2,500 signals) SandyClaw, a sandbox for AI supply-chain attacks. [sourced: Okta URL above]

**How it integrates with CSPMs**: Reads cloud audit logs (CloudTrail and similar) and IdP logs. [inferred] Open-source tool CloudGrappler. [sourced: https://permiso.io/blog/permiso-launches-cloudgrappler-to-help-security-teams-better-detect-threat-actors-in-their-cloud-environments] (title)

**Unique "wow"**: Following a single human across Okta → AWS role → GitHub token as one session. [sourced: Permiso ITDR page] [inferred: how it works]

**Documented weaknesses**: [gap]

### C2. Veza (being acquired by ServiceNow)

**Positioning & pricing model**: An "Access Graph" for permission-level visibility. ServiceNow signed a definitive agreement on December 1, 2025 (terms undisclosed). Veza had "nearly 150 global enterprise customers". [sourced: https://www.businesswire.com/news/home/20251201652471/en]

**What it does that a CSPM typically does not**: Effective permissions across apps such as Snowflake, Salesforce, SAP, and Oracle EBS. **Access Reviews** with "Automatic Access Remediation Validation", which confirms a revoked grant is actually gone from the graph. Access Hub self-service. [sourced: https://veza.com/blog/veza-product-updates-june-2025/]

**How it integrates with CSPMs**: **Open Authorization API (OAA)** pushes custom app permissions into the graph. Integrations: "325+". Bidirectional CrowdStrike risk scoring. ServiceNow "Veza Actions" for remediation tickets. [sourced: Veza June 2025 URL above; https://www.plushcap.com/companies/veza/blog/summaries/2026/05]

**Risk/identity specifics**: Risk Score 2.0 with drillable factors ("exact factors driving high-risk identities"). NHI governance: GitHub secrets discovery, GCP cross-org impersonation. [sourced: Veza June 2025 URL]

**AI features**: Access AI explanations for dashboard tiles and queries. AI-suggested query improvements. Role mining for Entra ID (2026.4). [sourced: https://www.plushcap.com/companies/veza/blog/summaries/2026/05]

**Unique "wow"**: Remediation is validated by re-reading the graph rather than trusting a closed ticket. [sourced: above]

**Documented weaknesses**: [gap]

### C3. Saviynt (Identity Cloud, cloud PAM/CIEM)

**Positioning & pricing model**: A converged IGA, application access governance, external identity, and PAM platform. Gartner named it a Challenger in the 2025 PAM MQ. [sourced: https://www.businesswire.com/news/home/20250109818956/en/Saviynt-Recognized-as-an-Identity-Security-Leader-by-the-Industrys-Leading-Analyst-Firms] (search summary)

**What it does that a CSPM typically does not**: Certification campaigns and joiner/mover/leaver lifecycle. **Copilot for certifications** "improving the access revokes of sensitive and critical access up to 75%". [sourced: https://www.businesswire.com/news/home/20240910046728/en/Saviynt-Unveils-Its-Cutting-Edge-Intelligence-Suite-to-Revolutionize-Identity-Security] (2024)

**How it integrates with CSPMs, dashboards, wow, weaknesses**: [gap]

### C4. Britive

**Positioning & pricing model**: "Runtime Privileged Access Management". Zero Standing Privileges through ephemeral JIT access. Pricing: [gap] [sourced: https://www.britive.com/]

**What it does that a CSPM typically does not**: Creates permissions at request time and deletes them after use. **Britive ARC** (Agentic Runtime Control) for task-scoped AI agent privileges. An **MCP Gateway** enforces AI-agent tool access at runtime. No proxy sits in the data path. Every decision is recorded. Covers AWS, Azure, GCP, OCI, K8s, Snowflake, and Salesforce. [sourced: https://www.britive.com/]

**How it integrates with CSPMs**: API-first. [sourced: https://www.britive.com/] A CSPM finding such as "standing admin" can be fixed by moving that access to Britive JIT. [inferred]

**Unique "wow"**: An MCP gateway for agent privilege. [sourced: above]

**Documented weaknesses**: [gap]

### C5. Entitle (BeyondTrust Pathfinder)

**Positioning & pricing model**: JIT cloud permissions within BeyondTrust Pathfinder, with a single login across PAM, ITDR, and CIEM. Rated a **Leader and Outperformer in the 2026 GigaOm Radar for CIEM**. [sourced: https://www.securitysolutionsmedia.com/2026/03/03/beyondtrust-recognised-as-a-leader-and-outperformer-in-the-2026-gigaom-radar-for-cloud-infrastructure-entitlement-management-ciem/]

**What it does that a CSPM typically does not**: Self-service access requests, permission bundling, auto-expiring JIT grants, "100+ integrations". [sourced: https://beyondtrust.com/products/entitle] (search summary)

**Risk/identity specifics**: GigaOm cites "AI-driven anomaly detection, automated least-privilege recommendations, continuous multicloud discovery". [sourced: securitysolutionsmedia URL above]

**Unique "wow"**: GigaOm calls it "industry-first AI agent governance" and notes "architectural unification of CIEM with ITDR and PAM". [sourced: same]

**Documented weaknesses**: [gap]

---

## Part D — CDR / cloud incident response

### D1. Gem Security → Wiz Defend

**Positioning & pricing model**: Wiz acquired Gem in April 2024. Forrester estimated the price at $300–400M. [sourced: https://www.forrester.com/blogs/wiz-acquires-cloud-detection-and-response-specialist-gem-security-to-round-out-cloud-security-portfolio/] Gem was rebuilt as **Wiz Defend** on the Wiz Security Graph. [sourced: https://www.wiz.io/blog/introducing-wiz-defend]

**What it does that a CSPM typically does not**: Detection across the control plane, data and network, identity, SaaS, and an eBPF runtime **Sensor** that can block. "One-click containment playbooks". A unified "visual storyline". [sourced: https://www.wiz.io/blog/introducing-wiz-defend]

**How it integrates**: WIN, with 100+ integrations (SIEM, SOAR, MDR, Cribl, Exabeam, Expel, Panther). [sourced: same]

**AI features**: AskAI generates "Incident Stories that explain the progression of an attack and potential impact in natural human language". [sourced: same]

**Unique "wow"**: Detections inherit posture context, such as exposure and attack path, from the same graph. [sourced: same] [inferred: significance]

**Documented weaknesses**: [gap] The agentless CSPM buyer must deploy a sensor to get runtime blocking. [inferred]

### D2. Mitiga

**Positioning & pricing model**: "Zero-impact" CDR, with AI detection and response (Helios AIDR). Pricing not disclosed. [sourced: https://www.mitiga.io/platform]

**What it does that a CSPM typically does not**: A **Cloud Security Data Lake**: "unlimited, normalized log storage across 1,000+ days", about 100 platforms (cloud, SaaS, identity, AI). Investigation Workbench timelines. CIRA response automation. [sourced: https://www.mitiga.io/platform] A third-party source says "more than 50 platforms", which conflicts. [sourced: https://yespress.io/mitiga.md]

**How it integrates with CSPMs**: "Runs alongside existing CNAPP and endpoint stacks without requiring replacement." [sourced: https://www.mitiga.io/platform]

**Unique "wow"**: Long-retention forensic readiness. The breach-impact question ("what did this identity touch in the last 2 years") is answerable. [sourced: same] [inferred: example]

**Documented weaknesses**: [gap]

### D3. Skyhawk Security

**Positioning & pricing model**: Synthesis Security Platform: CDR plus an AI "Autonomous Purple Team". [sourced: https://www.msspalert.com/news/skyhawk-security-offers-ai-based-purple-teaming]

**What it does that a CSPM typically does not**: A cycle that discovers crown jewels → analyzes "least-resistance paths" → simulates attacks → evaluates defenses → adapts detections. In December 2025, agentic AI Red Team "validates third-party security controls" and checks "whether detection tools would generate appropriate alerts". [sourced: https://www.nasdaq.com/press-release/skyhawk-security-strengthens-autonomous-red-team-agentic-ai-enabling-continuous] (search summary)

**Unique "wow"**: Uses attack-path simulation to produce verified detections. [sourced: above]

**Documented weaknesses**: [gap]

---

## Part E — CTEM / exposure management and validation

### E1. XM Cyber

**Positioning & pricing model**: CTEM built on an attack graph spanning on-prem, AD, and multi-cloud. Pricing: [gap]

**What it does that a CSPM typically does not**: **Cross Graph** (paths from multi-cloud to AD). **XM EASM** connects external exposures to internal entities. AD unused permissions (dormant 90+ days). AI exposure (shadow AI, agent infrastructure). [sourced: https://xmcyber.com/blog/xm-cybers-2025-milestones-and-what-they-mean-for-you/; https://itbrief.com.au/story/xm-cyber-adds-ai-exposure-mapping-across-hybrid-cloud]

**Risk specifics**: "74% of identified exposures are 'dead ends'". **Choke Points** are where "multiple attack scenarios converge". [sourced: XM 2025 milestones]

**Dashboards & reporting UX**: **Entity Cards** (compromise scenarios, breach points, critical-asset relations). An **Executive Summary Report** with scoring "calculated every four hours". [sourced: same]

**How it integrates**: ServiceNow, Google SecOps, and SentinelOne enriched with attack-graph context. [sourced: same]

**Unique "wow"**: **Remediation Confirmation** tracks whether a fix actually blocked the path, giving "defensible proof" rather than relying on closed-ticket counts. [sourced: same]

**Documented weaknesses**: [gap]

### E2. Pentera (Pentera Cloud)

**Positioning & pricing model**: Automated security validation (Core, Surface, Cloud). Pricing: [gap]

**What it does that a CSPM typically does not**: Actually emulates cloud-native attacks on AWS and Azure (identity compromise, role privilege escalation, lateral movement to PaaS, RCE), mapped to MITRE ATT&CK. Tests cloud↔on-prem paths. [sourced: https://www.helpnetsecurity.com/2024/03/06/pentera-cloud/] (2024 launch)

**How it integrates with CSPMs**: Positioned to complement CSPM/CNAPP "by validating whether detected risks are actually exploitable, reducing false positives". [sourced: same]

**Documented weaknesses**: [gap]

### E3. Cymulate

**Positioning & pricing model**: CTEM centered on exposure validation (BAS). Gartner Peer Insights "Customers' Choice" 2026 for Adversarial Exposure Validation (vendor claim). [sourced: https://www.cymulate.com/ctem/]

**What it does that a CSPM typically does not**: Aggregates scanner exposures, simulates attacks to prove exploitability, and pushes mitigations (IoCs and behavioral rules) into controls. [sourced: same] For cloud: business context on resources and validation of cloud controls. [sourced: https://cymulate.com/report/] (search summary)

**AI features**: **Vero AI** for "agentic cyber defense engineering". "Cowork" agentic workflows. [sourced: https://www.cymulate.com/ctem/]

**Documented weaknesses**: [gap]

---

## Part F — Analyst view and RFP criteria

### F1. Gartner — Market Guide for CNAPP (2025)
- The 2025 edition is dated **August 5, 2025** (authors Dale Koeppen and Esraa ElTahawy). [sourced: https://start.paloaltonetworks.com/gartner-report-cloud-native-application-protection.html] (Wiz's landing page shows an older 22 July 2024 attribution line: https://www.wiz.io/lp/2025-gartner-market-guide-for-cnapp.)
- Definition: "a unified and tightly integrated set of security and compliance capabilities, designed to protect cloud-native infrastructure and applications". The listed components are **artifact scanning, security guardrails, configuration and compliance management, risk detection and prioritization, and behavioral analytics**. [sourced: https://www.wiz.io/lp/2025-gartner-market-guide-for-cnapp] (search summary)
- Now a common feature: "Integration with other common tools, such as server endpoint protection tools and on-premises cloud and orchestration platforms, as well as integration with SIEM/SOAR/TDIR/SOC platforms". Deep SOC integration separates mature CNAPPs from first-generation ones. [sourced: PANW landing page above]
- "Security teams must understand and acknowledge that a perfect, risk-free application is not possible", so the focus is the "highest severity, highest confidence risks". GenAI is entering CNAPP "to reduce management overhead". By 2029, 40% of enterprises that implement zero trust in CSP environments "will rely on" CNAPP. [sourced: https://www.upwind.io/?p=11263]
- Evaluate "agentless visibility and runtime protection". [sourced: https://www.wiz.io/lp/2025-gartner-market-guide-for-cnapp] (search summary)
- A 2026 CNAPP Market Guide was not found in this pass. [gap]

### F2. Forrester — Cloud Workload Security Wave
- The last edition located is "The Forrester Wave™ Cloud Workload Security Q1 2024". Its criteria are paywalled. [sourced: https://www.forrester.com/blogs/wiz-acquires-cloud-detection-and-response-specialist-gem-security-to-round-out-cloud-security-portfolio/] [gap: criteria not quoted]
- Forrester's CDR buyer advice (Gem note): seamless detection integration; "centralized policy management and reporting"; business-user data-access mapping with response; unified IAM across products; GenAI-based reporting and auditing. [sourced: same]
- Related: Forrester Wave Sensitive Data Discovery & Classification Q2 2026 (Cyera claims Leader). [sourced: https://www.cyera.com/pt-br/platform/dspm]

### F3. GigaOm
- **2026 Radar for CIEM**: 22 vendors rated on "key features, emerging capabilities, and business criteria". Named criteria: cloud identity threat detection and response; just-in-time access; lifecycle entitlements governance; compliance automation; AI-enabled anomaly detection; platform interoperability. [sourced: https://www.securitysolutionsmedia.com/2026/03/03/beyondtrust-recognised-as-a-leader-and-outperformer-in-the-2026-gigaom-radar-for-cloud-infrastructure-entitlement-management-ciem/]
- GigaOm CSPM/CNAPP radar criteria: paywalled and not retrieved. [gap] GigaOm's usual structure is "key features / emerging features / business criteria (e.g., flexibility, scalability, ease of use, cost, ecosystem)". [inferred]

### F4. Latio
- **2025 Latio Cloud Security Report** (October 13, 2025): "CNAPP is defined in the present by code-to-cloud and runtime capabilities, and that the future will be defined by broader vulnerability management and incident response programs." [sourced: https://www.latio.com/reports/2025-latio-cloud-security-report]
- Other 2025–2026 reports: 2026 AI Security (September 15, 2026), 2026 Security Operations (June 4, 2026), 2026 AppSec (February 15, 2026), and the 2025 AI AutoFixing Tools Guide (March 3, 2025). Latio claims "the only analysts who implement products before reviewing them". [sourced: https://www.latio.com/reports; https://www.latio.com/]
- The full CNAPP/ADR market map is behind a login. [gap]

### F5. Public RFP scoring templates
- **rfp.wiki CNAPP/CSPM template** has 21 criteria. Product & Technology carries **43%**: Multi-Cloud Asset Coverage; Misconfiguration Detection Depth; Identity Posture Analysis; Remediation Workflow Automation; Alert Noise Control; IaC And Pipeline Shift-Left; Runtime-to-Posture Correlation; Reporting And Executive Dashboards; Data Residency And Tenant Controls. **Security & Compliance (14%)**: Risk Prioritization Context; Compliance Framework Mapping; Policy Customization And Governance. **Business & Strategy (5%)**: Integration Ecosystem. Commercials 24% (pricing, TCO, ROI, flexibility). Customer Experience 9%. Vendor Health 5% (uptime). [sourced: https://www.rfp.wiki/vendors/wiz]
- **rfp.wiki DSPM template**: Sensitive Data Discovery Coverage; Classification Accuracy and Context; Identity and Access Context; Exposure Prioritization; Remediation Workflow Depth; Cloud and SaaS Connector Breadth; Data Movement and Sharing Visibility; Compliance and Policy Mapping; Governance and Ownership Model; Hybrid Estate Support. [sourced: https://www.rfp.wiki/vendors/cyera]

### F6. The analyst capability checklist (synthesized)
The quoted criteria above reduce to this checklist analysts and RFPs use to rank CSPM/CNAPP vendors. Each line is tied to F1–F5. The checklist itself is [inferred].
1. Multi-cloud asset inventory and agentless visibility (F1, F5)
2. Misconfiguration detection depth plus policy customization (F5)
3. Compliance framework mapping and reporting (F1 "configuration and compliance management", F5)
4. Risk detection and prioritization with context, and alert-noise control (F1, F5)
5. Identity posture / CIEM: effective permissions, JIT, lifecycle (F3, F5)
6. Artifact/IaC/pipeline scanning (shift-left) (F1, F5)
7. Runtime protection and runtime-to-posture correlation, behavioral analytics (F1, F5)
8. SOC integration (SIEM/SOAR/TDIR) and an integration ecosystem (F1, F5)
9. Remediation workflow automation (F5)
10. Executive dashboards and reporting (F5)
11. Data residency and tenant controls (F5)
12. GenAI assistance to reduce overhead (F1, F2)
13. Data context (DSPM) (F2, F5-DSPM)
14. Commercials and TCO (F5)

---

## Best-in-class per capability (this cluster)

| Capability | Vendor | What makes it best | Source |
|---|---|---|---|
| Continuous control-test cadence | Vanta | Hourly, 1,200+ tests/hour, against daily for Drata | https://cipherssecurity.com/vanta-vs-drata/ |
| Custom control logic | Drata | Visual builder ↔ JSON rules with nested and array logic, AND/OR, tag key–value matching, line-level validation | https://help.drata.com/en/articles/13403932-advanced-editor-in-the-test-builder |
| Ingesting third-party resources | Vanta | Full-state PUT of flat custom resources plus custom tests that re-run on push | https://developer.vanta.com/docs/concepts/resources.md |
| CSPM → GRC finding import | Vanta (Wiz connector) | Vulns, Issues (Crit/High/Med), and config findings mapped to controls, with remediation SLAs | https://help.vanta.com/en/articles/11345611-connecting-wiz-with-vanta |
| Compliance fix from the AI tool | Vanta MCP | `/vanta:fix-test` produces IaC remediation for 500+ cloud tests | https://www.vanta.com/resources/new-in-vanta-april-2026 |
| GRC-native IaC remediation | Secureframe | Comply AI emits Terraform, CloudFormation, and CLI fixes for failing controls | https://secureframe.com/features/ai |
| Auditor workflow | Drata Audit Hub / Thoropass | Scoped audit period with downloadable evidence packages (Drata); in-platform auditor plus AI First Pass (Thoropass) | https://soc2auditors.org/insights/drata-review/ ; https://www.complyjet.com/blog/thoropass-review |
| Control↔evidence crosswalk | Hyperproof | 160+ frameworks; AI "Suggested Links", link once, map everywhere; humans approve | https://hyperproof.io/resource/hyperproof-delivers-the-ai-guided-experiences-that-get-work-done/ |
| Multi-entity compliance | Sprinto | "Zones" per product or region | https://complyjet.com/blog/sprinto-review |
| AI-agent governance | Drata | Discover shadow agents, policy-block before execution, tamper-evident log | https://drata.com/about/news/drata-expands-trust-management-platform-to-support-governance-of-enterprise-ai-agents |
| Data-custody-safe scanning | Sentra | In-environment ephemeral scanners; sampling and clustering for cost | https://sentra.io/learn/wiz-dspm-alternatives |
| DSPM↔CSPM interop spec | Proofpoint DSPM | Daily Wiz Issue pull plus push of data context to raise Wiz severity | https://docs.public.analyze.proofpoint.com/dspm/guide/getting-started/integrations-setup/wiz.htm |
| Data classification + remediation | Cyera | AI classification (up to 95% precision cited) plus 30+ remediation actions | https://www.cyera.com/pt-br/platform/dspm |
| Effective-permission graph + extensibility | Veza | 325+ integrations; OAA for custom apps; drillable Risk Score 2.0 | https://veza.com/blog/veza-product-updates-june-2025/ |
| Verified access remediation | Veza | "Automatic Access Remediation Validation" against the graph | https://veza.com/blog/veza-product-updates-june-2025/ |
| Zero standing privilege / agent privilege | Britive | Ephemeral JIT, no proxy, MCP Gateway, ARC for agents | https://www.britive.com/ |
| CIEM overall (analyst) | BeyondTrust (Entitle/Pathfinder) | GigaOm 2026 CIEM Leader and Outperformer | https://www.securitysolutionsmedia.com/2026/03/03/beyondtrust-recognised-as-a-leader-and-outperformer-in-the-2026-gigaom-radar-for-cloud-infrastructure-entitlement-management-ciem/ |
| Identity session stitching | Permiso (Okta) | Universal Identity Graph across IdP, IaaS, and SaaS; 2,500+ signals | https://www.okta.com/newsroom/press-releases/okta-signs-definitive-agreement-to-acquire-permiso-security/ |
| Graph-native CDR | Wiz Defend | Detections on the posture graph; AskAI Incident Stories; one-click containment | https://www.wiz.io/blog/introducing-wiz-defend |
| Forensic readiness | Mitiga | 1,000+ days normalized log lake; unified attack timeline | https://www.mitiga.io/platform |
| Detection validation | Skyhawk | Autonomous red team checks whether detections fire | https://www.nasdaq.com/press-release/skyhawk-security-strengthens-autonomous-red-team-agentic-ai-enabling-continuous |
| Choke points + fix proof | XM Cyber | 74% "dead ends" data; Remediation Confirmation; Entity Cards | https://xmcyber.com/blog/xm-cybers-2025-milestones-and-what-they-mean-for-you/ |
| Exploitability validation | Pentera Cloud / Cymulate | Real attack emulation on AWS/Azure (Pentera); validation plus control-update push (Cymulate) | https://www.helpnetsecurity.com/2024/03/06/pentera-cloud/ ; https://www.cymulate.com/ctem/ |

## Features nimbus should steal (ranked)

Ranking weighs buyer pull (how often the capability appears in RFPs and analyst criteria), fit with nimbus's agentless graph and SQL core, and whether an OSS team can build it. The ranking is [inferred]. Each item names the vendor it comes from.

1. **Vanta/Drata export connector (push nimbus as a "custom resource").** `nimbus export vanta` does a full-state PUT of flat resources (`uniqueId`, `displayName`, `externalUrl` deep-linking to the nimbus finding, plus flat boolean/int/string/timestamp properties). It ships matching Custom Test recipes. The user sees nimbus checks appear as passing or failing Vanta tests. *Source: Vanta resources API.* *Why:* most CSPM buyers already own a GRC tool, and becoming its evidence source turns a competitor into a channel. Mind the full-state rule: anything omitted is deleted.
2. **"Fill the Audit Manager gap" evidence mode.** A guided `nimbus evidence init --framework soc2|pci4|iso27001-2022` mirrors Audit Manager's control sets, common controls, and delegation. It is marketed to AWS shops that can no longer onboard Audit Manager. *Source: AWS Audit Manager closed to new customers 2026-04-30.* *Why:* a timely, concrete wedge.
3. **Two-mode custom control editor (builder ↔ rules-as-code).** The UI builder writes to the same YAML/SQL the CLI uses. It supports nested and array conditions, tag key=value matching, and multi-resource joins (more than Vanta's two-source cap). The editor validates live and points to the exact line. *Source: Drata Test Builder advanced editor; Vanta Test Builder limits.* *Why:* RFP criterion "Policy Customization And Governance".
4. **Finding → exact resource → fix, in one click.** Every failed control lists the failing resource IDs, the raw API evidence, and the IaC location. *Source: the Drata complaint "figuring out exactly which cloud resource… more painful than it should be".* *Why:* fixes the top GRC complaint.
5. **Remediation confirmation on the graph.** When a fix PR merges, nimbus re-scans and marks the finding "verified-fixed" only if the attack path or permission is actually gone. Closed tickets do not count. It shows "paths broken: N". *Source: XM Cyber Remediation Confirmation; Veza Automatic Access Remediation Validation.* *Why:* auditors and executives want proof, not ticket counts.
6. **"Dead-end" filter for exposures.** A toggle hides findings with no path to a crown jewel, with a header such as "X of Y exposures are dead ends". *Source: XM Cyber, 74% dead ends.* *Why:* "Alert Noise Control" is an RFP criterion.
7. **Entity Cards.** One panel per resource or identity: inbound and outbound paths, compromise scenarios, data class, permissions, recent changes, owner, linked controls. *Source: XM Cyber Entity Cards.* *Why:* stops analysts pivoting between dashboards.
8. **In-account DSPM sampler.** An ephemeral scanner (Lambda, Cloud Run job, or container) runs inside the customer account. It samples objects and rows, clusters by schema and prefix, and returns only labels and counts. No content leaves the account. The UI shows "data never left account" and an estimated scan cost before running. *Source: Sentra in-environment scanning; Cyera classification.* *Why:* data context is a CNAPP and RFP must-have, and custody is the main objection.
9. **DSPM/CSPM interop adapters.** Import Cyera, Sentra, or Proofpoint DSPM labels as resource attributes so they feed path scoring. Export nimbus issues in a format DSPMs can pull daily. *Source: Proofpoint DSPM ↔ Wiz spec.* *Why:* buyers with an existing DSPM still want nimbus attack paths to know where PII lives.
10. **Access review campaigns from the effective-permission graph.** `nimbus review start --scope prod-admins` builds a campaign with frozen point-in-time snapshots, approve/revoke decisions, and an evidence export. *Source: Veza Access Reviews; Drata access reviews (and their non-frozen-snapshot weakness).* *Why:* SOC 2 and ISO need it, and freezing the snapshot beats Drata.
11. **Standing-privilege → JIT recommendations.** Flag admin grants unused for 90 days or more. Emit a Terraform PR that removes the grant, or a policy to hand it to Britive or Entitle JIT. *Source: Britive ZSP; XM Cyber dormant permissions (90+ days); GigaOm CIEM "just-in-time access" criterion.* *Why:* a CIEM analyst criterion within OSS reach.
12. **Drillable risk score.** Every identity and resource score expands to the exact contributing factors. *Source: Veza Risk Score 2.0.* *Why:* fits nimbus's published-math promise.
13. **Identity session stitching (lite).** Link IdP sign-in (Okta/Entra logs) → AssumeRole chain → actions into one timeline per human or NHI. *Source: Permiso Universal Identity Graph.* *Why:* closes the posture→detection gap that Gartner flags.
14. **Incident Story generator.** For a detection or path, the copilot writes a plain-language narrative citing finding IDs and queries. *Source: Wiz Defend AskAI Incident Stories.* *Why:* SOC integration and GenAI both appear in Gartner's 2025 guide.
15. **Forensic snapshot retention + "what did X touch" query.** Keep normalized CloudTrail and activity in DuckDB/Parquet with configurable retention. A canned query answers "all actions by principal P on data class D in window W". *Source: Mitiga Cloud Security Data Lake.* *Why:* breach-impact scoping.
16. **Detection self-test.** `nimbus validate detections` replays benign simulated events (for example a test AssumeRole from a new ASN) in a sandbox account and confirms each nimbus or SIEM rule fired. *Source: Skyhawk autonomous red team; Cymulate validation.* *Why:* proves coverage. OSS prior art: Stratus Red Team. [inferred]
17. **Read-only exploitability check for top paths.** For the top N paths, run non-destructive API probes (for example simulate-principal-policy and reachability analyzer) and mark the path "validated exploitable" or "theoretical". *Source: Pentera Cloud.* *Why:* cuts false positives without running live attacks.
18. **AI evidence pre-check ("First Pass").** Before export, the copilot checks each evidence item for completeness (period covered, timestamp, account scope, screenshot dates) and flags gaps the way an auditor would. *Source: Thoropass First Pass; Hyperproof validation tests.* *Why:* fewer audit round-trips.
19. **Suggested control links.** The copilot proposes mappings from a nimbus rule to more framework requirements. Each one needs human approval and is stored in the mapping YAML. *Source: Hyperproof Suggested Links; Secureframe control mapping.* *Why:* scales framework coverage.
20. **MCP server with fix-test commands.** A read-only MCP server exposes `list_failing_controls`, `explain_finding`, and `propose_fix` (which returns a diff and never applies it). *Source: Vanta remote MCP plus `/vanta:fix-test`.* *Why:* AI-tool distribution. Matches nimbus's cite-everything copilot.
21. **Outbound webhooks for compliance events.** Events: control state changed, evidence bundle generated, access review completed, exception expiring. *Source: Vanta outbound webhooks.* *Why:* "Integration Ecosystem" RFP criterion.
22. **Executive summary with fixed recompute cadence.** A one-page leadership report shows score, trend, top choke points, and framework percentage, with "computed at" stamped. *Source: XM Cyber Executive Summary (every 4h); RFP criterion "Reporting And Executive Dashboards".* *Why:* the buyer persona has broadened (Gartner).
23. **AI-agent / NHI inventory as posture objects.** Discover Bedrock and Vertex agents, their execution roles, and MCP tool grants. Flag agents with standing admin. *Source: Drata AI Agent Governance; Britive ARC/MCP Gateway; XM Cyber AI exposure.* *Why:* every vendor in this cluster shipped agent governance in 2026.
24. **Multi-entity scopes.** Group accounts and projects into "entities" (product or region), each with its own framework scope and evidence bundle. *Source: Sprinto Zones.* *Why:* holding companies and multi-product SaaS.

## Analyst/RFP checklist

Legend for **OSS?**: **Yes** = realistically deliverable by an open-source tool. **Partial** = deliverable in a reduced form. **No** = needs a commercial organization or service. Requirement sources are F1–F5 above. OSS feasibility is [inferred].

| # | Capability required to be shortlisted | Where it comes from | OSS? | Note for nimbus |
|---|---|---|---|---|
| 1 | Agentless multi-cloud asset inventory (AWS/Azure/GCP + K8s) | Gartner 2025; rfp.wiki "Multi-Cloud Asset Coverage" | Yes | Prowler and CloudQuery prove it |
| 2 | Misconfiguration detection depth + custom policies | rfp.wiki "Misconfiguration Detection Depth", "Policy Customization And Governance" | Yes | Rules-as-code + builder (steal #3) |
| 3 | Compliance framework mapping + reports (CIS, SOC 2, PCI, ISO, NIST, HIPAA) | Gartner "configuration and compliance management"; rfp.wiki | Yes | Evidence bundles. The auditor *service* is No |
| 4 | Context-based risk prioritization + noise control | Gartner "risk detection and prioritization"; rfp.wiki "Alert Noise Control", "Risk Prioritization Context" | Yes | Graph + dead-end filter |
| 5 | Attack-path analysis | Implied by Gartner prioritization; XM Cyber and Wiz market bar | Yes | Core nimbus |
| 6 | Identity posture / CIEM (effective permissions, unused privileges) | rfp.wiki "Identity Posture Analysis"; GigaOm CIEM | Yes | Policy evaluation is hard but OSS-doable (e.g., PMapper prior art) |
| 7 | JIT access / lifecycle governance | GigaOm CIEM | Partial | Recommend and emit IaC. A JIT broker is out of scope |
| 8 | Identity threat detection (ITDR) | GigaOm CIEM "cloud identity threat detection and response" | Partial | Rule-based detections over CloudTrail. No 2,500-signal research team |
| 9 | IaC / pipeline / artifact scanning | Gartner "artifact scanning"; rfp.wiki "IaC And Pipeline Shift-Left" | Yes | Reuse Checkov/Trivy + plan-time path diff |
| 10 | Runtime protection / behavioral analytics | Gartner; Latio "runtime capabilities" | Partial | Agentless log-based detections yes. eBPF blocking means integrating Falco/Tetragon rather than building it |
| 11 | Runtime-to-posture correlation | rfp.wiki | Partial | Ingest Falco/GuardDuty into the graph |
| 12 | SIEM/SOAR/TDIR/SOC integration | Gartner 2025 (explicit quote) | Yes | OCSF/ASFF, webhooks, Splunk HEC |
| 13 | Remediation workflow automation (tickets, PRs, auto-fix) | rfp.wiki | Yes | Fix PRs + Jira + verified close |
| 14 | Executive dashboards & reporting | rfp.wiki | Yes | Static HTML/PDF reports |
| 15 | Data context (DSPM: discovery/classification) | Forrester CDR note; rfp.wiki DSPM; CNAPP market bar | Partial | Sampling classifier (regex + checksum + small model) in account. Not Cyera-grade accuracy |
| 16 | GenAI assistant | Gartner 2025 GenAI takeaway; Forrester | Yes | BYO-model, read-only, cited |
| 17 | Data residency & tenant controls | rfp.wiki | Yes | Self-hosted is a natural advantage |
| 18 | GRC integration (push to Vanta/Drata/ServiceNow) | Vanta/Drata ecosystem; ServiceNow–Veza deal | Yes | Steal #1 |
| 19 | Access reviews / certifications | GRC tools; Veza; SOC 2 practice | Partial | Campaign + evidence yes. Workflow/HR integrations limited |
| 20 | Vendor/third-party risk, questionnaires, trust center | GRC tools | No | Out of scope. Integrate rather than build |
| 21 | Attack/exploit validation (CTEM) | Gartner AEV Market Guide 2026 (cited by Cymulate); Pentera | Partial | Read-only validation + Stratus-style self-tests |
| 22 | Forensic log retention & investigation timeline | Mitiga; Wiz Defend | Partial | DuckDB/Parquet retention. Scale is limited by the user's storage |
| 23 | Enterprise vendor criteria (uptime SLA, support, NPS/CSAT, EBITDA, commercial flexibility) | rfp.wiki commercials/vendor health | No | Needs a commercial sponsor or support offering |
| 24 | Certifications of the vendor itself (SOC 2 Type II, FedRAMP) | Common RFP gating ([inferred]); Britive lists SOC 2 Type II | No | OSS can publish SBOM, signed releases, and a security policy instead |
