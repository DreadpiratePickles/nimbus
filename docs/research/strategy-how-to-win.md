# How an open-source CSPM actually wins in 2026: strategy research for nimbus

_Research date: 2026-10-09. Author: research agent for Bobby Meher. Scope: market, open-source precedents, practitioner demand, wedges, distribution, monetisation, recommendation._

**Evidence conventions.** Every factual claim carries `[sourced: URL]`. Anything that is my reasoning, not a published fact, is marked `[inferred]`. Numbers I computed from sourced inputs say so. GitHub/Homebrew/PyPI/Docker Hub figures were pulled live on 2026-10-09 from public APIs (`gh api repos/<owner>/<repo>`, `formulae.brew.sh/api/formula/<f>.json`, `pypistats.org/api/packages/<p>/recent`, `hub.docker.com/v2/repositories/<r>/`) and are cited as such.

**Research limits (read before trusting gaps).** The session's shared web-search budget ran out early, so most evidence comes from direct fetches of primary pages, public JSON APIs and Hacker News (via the Algolia API). Reddit could not be fetched (blocked), and G2 and Gartner Peer Insights returned 403, so buyer quotes come from Hacker News, PeerSpot and practitioner blogs instead. AWS Marketplace listings for the CNAPP vendors and Gartner Hype Cycle wording were **not found**. Where something was not found this document says so rather than guessing.

**nimbus current state (from `CLAUDE_CONTEXT.md`, `.planning/PROJECT.md`, `.planning/STATE.md`; code not read).**
- Go core: agentless collectors (AWS, Azure, GCP, Kubernetes, GitHub, Okta, M365), an in-memory security graph, attack-path rule chains with choke points, blast radius and break-the-path, SQLite SQL views, Neo4j push, cost (zombie/rightsizing), CloudTrail/Activity Log/audit-log monitor, Terraform/CFN/Bicep/K8s fix templates, a native HCL scanner and patcher, 11 alert sinks, and a live HTTP/WebSocket dashboard.
- Python: 7 compliance packs, AI copilot/LLM fixes, risk scoring, audit reports, FastAPI, Prowler-style boto3 checks and a plugin SDK. There is also a VS Code extension.
- Adapters already ingest **Prowler (OCSF + v3), ScoutSuite, Checkov, Trivy, Steampipe and native JSON** into one Finding contract with stable fingerprints.
- **Critical caveat:** "Nothing has run against a live cloud account yet; collectors/monitor/sinks are covered by fakes and httptest only." The dashboard was just rebuilt as an OpenBSD-cwm-style desktop and is not yet committed. In the rulebook's terms, nimbus is *implemented*, not *verified*. Most of the strategy below depends on closing that gap first.

---

## Executive summary

1. **The posture market has consolidated into suites, and the pure-play exits were mixed.** Google closed Wiz on 2026-03-11. Lacework sold to Fortinet for a small fraction of its $8.3B peak. Prisma Cloud became Cortex Cloud. Every hyperscaler now ships a cheap or free native CSPM. Latio's verdict was "the CSPM wars are over, and Wiz won." *Selling CSPM as a product is a losing game. Being the free, neutral, open layer that every team can run is not.* [inferred from §1]
2. **Prowler is the incumbent of open-source CSPM, and it is moving fast toward everything nimbus pitches.** It has 15k stars, about 2,400 commits in the last year, $99 per cloud account per month for the SaaS, attack paths built on Cartography, Lighthouse AI, an MCP server, a Claude Code plugin and an "autonomous fixer". nimbus cannot win by being "Prowler plus a graph". It has to win on things Prowler is structurally slow to do (§4).
3. **What practitioners actually reward:**
   - fewer, truer findings in context: "not just giving them a report full of false positives";
   - fixes that land on engineering's plate in a form engineers accept: "posture tools exist for developers, not security teams";
   - transparent price and docs: Wiz is criticised for "Closed docs" and "no public pricing";
   - multi-cloud neutrality after the Google/Wiz deal.
4. **Projects that grew had a distribution engine, not just features.** Checkov gets about 4M PyPI downloads a month and Trivy has 128M Docker pulls. Both live in CI. Cloud Custodian (c7n) gets about 1.4M PyPI downloads a month because it runs in automation. Prowler gets about 104k a month. Projects that stalled had **no maintainer business**: ScoutSuite has had 0 commits in 12 months, Fix Inventory has had 0 commits in 12 months, CloudMapper has had no push since 2024, and OpenCSPM is archived.
5. **Recommendation (§7):** position nimbus as **"the open, local-first security graph that turns every scanner's findings into the few attack paths that matter and the PR that closes them."** Commit to three wedges:
   - **(a)+(b)** unified ingestion feeding free attack paths and toxic combinations;
   - **(c)+(h)** fix-first, CI-native "this PR opens/closes a path" checks;
   - **(g)** local-first and private by default.

   Treat compliance evidence, SQL/NL and cost as features that support those wedges, not as positioning. Before any of this, **run nimbus end-to-end against a real open lab and publish the result.**

---

## 1. Market structure 2025–2026

### 1.1 Consolidation: posture got absorbed into suites

| Deal | Date | Price / terms | Source |
|---|---|---|---|
| Google ← Wiz | announced 2025-03-18, closed **2026-03-11** (DOJ cleared Nov 2025, EC unconditional 2026-02-11) | $32B all-cash | [sourced: https://www.securityweek.com/wiz-joins-google-cloud-as-landmark-acquisition-closes/] [sourced: https://www.clearygottlieb.com/news-and-insights/news-listing/google-completes-32-billion-acquisition-of-wiz] |
| Fortinet ← Lacework (now FortiCNAPP) | closed 2024-08-01 | reported $152.3M cash; Forrester estimated ~$200–230M vs Lacework's $8.3B peak valuation and >$1.3B raised | [sourced: https://sacra.com/chat/h/71b28bc1-a4d2-4739-806b-a100c43eee93/] [sourced: http://www.forrester.com/blogs/fortinet-acquires-lacework/] |
| SentinelOne ← PingSafe | announced Jan 2024, closed Feb 2024 | undisclosed (cash + stock) | [sourced: https://www.helpnetsecurity.com/2024/01/04/sentinelone-pingsafe-acqusition/] |
| Wiz ← Gem Security | 2024 | ~$350M reported, undisclosed | [sourced: https://www.privsource.com/acquisitions/deal/wySg9x] |
| Wiz ← Dazz (remediation/ASPM) | Nov 2024 | $450M cash + stock | [sourced: https://techcrunch.com/2024/11/21/wiz-acquires-dazz-for-450m-to-expand-its-cybersecurity-platform] |
| Palo Alto ← Dig Security (DSPM) | closed 2023-12-05 | ~$295.0M total per SEC 10-Q | [sourced: https://www.sec.gov/Archives/edgar/data/1327567/000132756724000005/panw-20240131.htm] |
| Palo Alto ← Talon | closed 2023-12-28 | ~$550.0M total | [sourced: same SEC filing] |
| Palo Alto Prisma Cloud → **Cortex Cloud** | 2025-02-13 | rebrand/merge of CNAPP into Cortex CDR | [sourced: https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-introduces-cortex-cloud--the-future-of-real-time-cloud-security] |
| Rubrik ← Laminar (DSPM) | Aug 2023 | $104.9M fair value per 10-K (press said ~$250M) | [sourced: https://www.sec.gov/Archives/edgar/data/1943896/000194389625000012/rbrk-20250131.htm] [sourced: https://en.globes.co.il/en/article-1001454562] |
| Tenable ← Ermetic (CIEM/CNAPP) | 2023 | ~$240M cash + $25M stock | [sourced: https://www.helpnetsecurity.com/2023/09/07/tenable-to-acquire-ermetic-for-240-million/] |
| CrowdStrike ← Bionic | Sep 2023 | ~$350M reported | [sourced: https://en.globes.co.il/en/article-1001458181] |
| Orca ← Opus (agentic remediation) | 2025-05-13 | undisclosed | [sourced: https://orca.security/resources/press-releases/orca-security-acquires-opus-ai-cloud-remediation/] |
| Check Point ← Veriti (exposure mgmt) | 2025-06-09 | ~$92.5M | [sourced: https://www.sec.gov/Archives/edgar/data/0001015922/000117891326001932/zk2634942.htm] |

Other signals:
- **Google is retiring its own multi-cloud CNAPP tier.** SCC Enterprise is "Deprecated (sunset May 21, 2027)", and customers move to Premium. [sourced: https://docs.cloud.google.com/security-command-center/docs/service-tiers] My reading is that Wiz becomes Google's multi-cloud CNAPP. [inferred]
- **Wiz says it stays multi-cloud:** "Wiz remains a multi-cloud platform... Our customers run on AWS, Azure, GCP, and OCI." [sourced: https://www.wiz.io/blog/google-closes-deal-to-acquire-wiz]
- **Independent challengers are still raising money.** Upwind raised **$300M at $3.8B (2026-09-02, Bessemer)**. Globes says it "benefited from market vacuum" after Google bought Wiz, with 2025 revenue under $20M and $50–60M so far in 2026. [sourced: https://en.globes.co.il/en/article-1001554301] Orca has raised more than $640M, with a last known valuation of about $1.8B. [sourced: https://pitchbook.com/profiles/company/268037-83]
- **Concentration:** Palo Alto, CrowdStrike and Wiz hold about 42% of a "$700 million CNAPP market". [sourced: https://www.govinfosecurity.com/blogs/upwind-eyeing-250m-funding-at-15b-valuation-p-4028] Treat the market-size figure with caution; it looks low against Wiz's reported ARR.
- **Analyst read:** "the fight for the 'posture' side of CNAPP... [is] over"; "the CSPM wars are over, and Wiz won"; "posture tools exist for developers, not security teams, because they reduce security teams to project managers." [sourced: https://pulse.latio.tech/p/the-great-cnapp-re-bundle]

**Implication for nimbus [inferred]:**
- Nobody is going to out-sell Wiz to the Fortune 500.
- Consolidation creates two kinds of orphans:
  1. teams who don't want to depend on Google's neutrality or Fortinet's roadmap;
  2. teams priced out of the suites.
- Both are open-source-shaped audiences.

### 1.2 Pricing: what is public

| Offering | Public price | Source |
|---|---|---|
| **AWS Security Hub** (2025 redesign, GA Dec 2025) Essentials | **$3.75 per resource unit/month**; EC2 = 1 unit, Lambda = 1/12, ECR image = 1/18, IAM user/role = 1/125; covers AWS **and Azure**; threat analytics $4.00/M CloudTrail events | [sourced: https://aws.amazon.com/security-hub/pricing/] [sourced: https://siliconangle.com/2025/12/02/aws-rolls-security-agent-strengthens-guardduty-security-hub-reinvent-2025/] |
| AWS Security Hub Extended (partner solutions billed via AWS) | "pay-as-you-go or flat-rate", partners not named | [sourced: https://aws.amazon.com/about-aws/whats-new/2026/02/sec-hub-extended] |
| **Microsoft Foundational CSPM** | **Free**; covers Azure, AWS, GCP (inventory, secure score, recommendations, MCSB) | [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management] |
| Microsoft Defender CSPM (paid) | $0.007 per billable resource-hour ≈ **$5.11/resource/month** (my calc at 730 h) | [sourced: https://prices.azure.com/api/retail/prices?$filter=contains(productName,'CSPM')] |
| Defender for Servers P1 / P2; Containers | $0.00672/h ≈ $4.91/mo; $0.02/h ≈ $14.60/mo; $0.00941 per vCore-hour | [sourced: https://prices.azure.com/api/retail/prices?$filter=serviceName eq 'Microsoft Defender for Cloud' and armRegionName eq 'eastus'] |
| **Google SCC** Standard | Free (Google Cloud only) | [sourced: https://docs.cloud.google.com/security-command-center/docs/service-tiers] |
| Google SCC Premium | PAYG $0.0071/vCPU-hour; subscription "5% of projected annualized run rate", min $15,000/yr (from search snippet; page did not render) | [sourced: https://cloud.google.com/security-command-center/pricing] |
| **Prowler Cloud** | **$99 per cloud account/month** (20% off annual); 15-day free trial; Private Cloud custom | [sourced: https://prowler.com/pricing] |
| Wiz | quote-only ("Wiz One", "Wiz Go", "À la Carte") | [sourced: https://www.wiz.io/pricing] |
| Wiz contracts (Vendr) | median **$154,381/yr** over 188 purchases; range $30,309–$536,300 | [sourced: https://www.vendr.com/marketplace/wiz] |
| Orca contracts (Vendr) | median **$95,625/yr** over 97 purchases; range $16,380–$210,125 | [sourced: https://www.vendr.com/marketplace/orca-security] |
| Sysdig | quote-only, per host | [sourced: https://sysdig.com/pricing/] |
| AWS Marketplace list prices for Wiz/Orca/Cortex/FortiCNAPP/Sysdig/Aqua/Upwind | **not found** (search budget exhausted) | — |

**Worked comparison [inferred, arithmetic only]:**
- Take a 50-account estate with 2,000 billable VMs/DBs/storage.
- Prowler Cloud ≈ 50 × $99 × 12 = $59,400/yr list.
- Defender CSPM ≈ 2,000 × $5.11 × 12 ≈ $122,640/yr.
- Security Hub Essentials ≈ 2,000 units × $3.75 × 12 = $90,000/yr, before IAM/Lambda fractions.
- Wiz's Vendr median is $154k.

nimbus at $0 is not the only "cheap" option. Prowler OSS is also $0, and the native tools are cheap per resource. **Price alone is not a wedge. Price plus neutrality plus depth is.**

### 1.3 Buyer complaints about incumbents

- **Cost:**
  - Wiz: "The pricing model is a little bit hefty on the pocket" (AVP, NatWest); "Wiz is expensive, but it offers good value." [sourced: https://www.peerspot.com/products/wiz-reviews]
  - Prisma Cloud: "The pricing for Prisma Cloud is high. Providing a pay-as-you-go model or pricing options tailored for medium and small enterprises could help." [sourced: https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-reviews]
  - FortiCNAPP/Lacework: "Licensing can become very expensive." [sourced: https://www.peerspot.com/products/lacework-reviews]
  - Orca: "Its license is a bit expensive." [sourced: https://www.peerspot.com/products/orca-security-reviews]
- **Closed, enterprise-only:** "it's basically enterprise-only and insanely expensive... will be a shame to see it die (or at least its non-GCP aspects wither and die) under Alphabet's ownership." (stego-tech, HN, 2025-03-18) [sourced: https://hn.algolia.com/api/v1/items/43400325]
- **Ticket noise, UX, closed docs:** Wiz "creates Jira tickets automatically with all the findings... tickets appear and disappear magically in hundreds each time Wiz scans, sometimes with no obvious explanations"; "UI/UX: Terrible"; "Closed docs. You can only check the docs if logged in"; Terraform provider "No source AFAIK, you just get a binary"; "no public pricing." (tecleandor, HN, 2025-03-18) [sourced: https://hn.algolia.com/api/v1/items/43402941]
- **Alert fatigue:** Prisma: "I notice multiple false positives." [sourced: https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-reviews] Wiz reviewers ask for "Reduced false positives in runtime threat detection." [sourced: https://www.peerspot.com/products/wiz-reviews] Mid-market orgs "get 50,000 alerts a week. Real attacks are happening inside the noise." [sourced: https://www.chrisfarris.com/post/security-poverty-cliff/]
- **Tool sprawl:** mid-market companies have "accumulated CrowdStrike, Splunk, Wiz, Snyk, Okta, KnowBe4, and a dozen others because each was the answer to a specific board question" (Chris Farris's "tool-debt cliff"). [sourced: https://www.chrisfarris.com/post/security-poverty-cliff/]
- **Agent friction:** Wiz's GTM story credits agentless onboarding: the "agentless approach removed this friction." [sourced: https://www.cybersecuritypulse.net/p/wizs-32b-gtm-playbook-unpacking-the] Orca reviewers note the trade-off: "Agentless provides great visibility, it does not offer real-time blocking." [sourced: https://www.peerspot.com/products/orca-security-reviews]
- **Lock-in and acquisition uncertainty:**
  - Forrester on Lacework: integration challenges moving "700+ employees... to Fortinet." [sourced: http://www.forrester.com/blogs/fortinet-acquires-lacework/]
  - Latio on Wiz/Google: it is unproven that "the industry really wants a Multi-Cloud security experience presented by your cloud vendor"; "cloud native solutions have often barely understood and supported their own clouds, never-mind other vendors." [sourced: https://pulse.latio.tech/p/wiz-acquisition-winners-losers-and]

### 1.4 The mid-market / SMB gap

- Vendr's lowest observed deals are about $30k/yr for Wiz and $16k/yr for Orca; medians are $154k and $96k. [sourced: https://www.vendr.com/marketplace/wiz] [sourced: https://www.vendr.com/marketplace/orca-security]
- Orca reviewers want "options for smaller businesses"; Prisma reviewers want pricing "tailored for medium and small enterprises." [sourced: PeerSpot URLs above]
- Google SCC Premium has a $15,000/yr subscription minimum. [sourced: https://cloud.google.com/security-command-center/pricing]
- Farris's "Security Valley of Death" covers companies with 50–2,500 employees that "appear secure on paper." "SOC 2 measures whether you can describe and document a security program. It does not measure whether that program works." This tier "[doesn't] have a coherent narrative" from vendors. [sourced: https://www.chrisfarris.com/post/security-poverty-cliff/]
- No dedicated Wiz SMB tier is documented publicly. [sourced: https://www.wiz.io/pricing]

**Read [inferred]:** the gap is real, but it is a *capacity* gap as much as a *price* gap. A free tool that produces 5,000 findings does not help a one-person security team. A free tool that produces "these 3 paths, these 3 PRs" does.

### 1.5 "CSPM is a feature now" vs the counter-argument

**For "CSPM is a feature":**
- All three hyperscalers bundle posture: Microsoft Foundational CSPM is free and multi-cloud; AWS Security Hub Essentials covers AWS + Azure at $3.75 per unit; Google SCC Standard is free. [sourced: MS Learn, AWS, Google URLs above]
- Microsoft: "CSPM is a core feature of Microsoft Defender for Cloud." [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management]
- Lacework's write-down shows pure-play CNAPP doesn't hold value alone; Forrester expects "further consolidation and formation of suites players." [sourced: http://www.forrester.com/blogs/fortinet-acquires-lacework/]
- A practitioner: "Conceptually, I don't think CSPMs are answering complicated questions, however there's quite a lot of complexity... in scaling the answers consistently, and keeping up to date with all of the tests." (raesene9, HN) [sourced: https://hn.algolia.com/api/v1/items/43678123]

**Against (where independent tools still win):**
- **Neutrality:** Google kept Wiz multi-cloud and is retiring its own multi-cloud tier. Upwind's valuation more than doubled in eight months on the "market vacuum". [sourced: SecurityWeek, Google tiers, Globes URLs above]
- **Native tools are uneven across clouds.** Defender reviewers describe themselves as "100 percent Microsoft... has not helped me manage and secure multi-cloud." [sourced: https://www.peerspot.com/products/microsoft-defender-for-cloud-reviews] Chris Farris on the new Security Hub: it still requires AWS Config recorders, and "I'm gonna wait a bit before I revisit this service to tell you how much I hate it." [sourced: https://www.chrisfarris.com/post/reinvent2025/]
- **The valuable part is context, not checks.** Attack paths, risk prioritisation and data-aware scanning are paid add-ons even at Microsoft. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management] Practitioners say Wiz earns its money "helping people understand when they actually have open S3 buckets and not just giving them a report full of false positives." (mdaniel, HN, 2025-02) [sourced: https://hn.algolia.com/api/v1/items/43161332]

**Synthesis [inferred]:** checks are a commodity, and so are rule counts. Context (the graph), neutrality (multi-cloud plus SaaS identity), and the last mile (a fix that merges) are not. nimbus should never market "N checks". It should market "N paths closed".

---

## 2. Open-source precedents: what grew, what stalled, and why

### 2.1 Scoreboard (pulled live 2026-10-09)

Stars, creation date, last push and licence come from `gh api repos/<repo>`. Commit counts are commits on the default branch since 2025-10-09, from `gh api repos/<repo>/commits?since=2025-10-09`. Homebrew = installs-on-request over 365 days (formulae.brew.sh). PyPI = downloads last month (pypistats.org). Docker = Docker Hub `pull_count`.

| Project | Stars | Created | Commits (12 mo) | Licence | Distribution signal | Steward / outcome |
|---|---|---|---|---|---|---|
| Trivy (incl. tfsec) | 38,313 | 2019 | — | Apache-2.0 | Docker 128.3M pulls; brew 134,685/yr | Aqua; tfsec folded in |
| Wazuh | 17,178 | 2015 | — | GPL-2 (NOASSERTION in API) | "30M+ downloads a year" (self-reported) | Wazuh Inc. (cloud + support) |
| Semgrep | 16,945 | 2019 | — | LGPL-2.1 | — | Semgrep Inc.; relicensed rules 2024 → Opengrep fork |
| CrowdSec | 15,121 | 2020 | — | MIT | "70,000+ active users sharing 40M+ signals a day" | CrowdSec (network-effect CTI) |
| **Prowler** | **14,992** | 2016 | **2,396** | Apache-2.0 | PyPI 103,669/mo; Docker 4.49M (toniblyx) + 0.23M; brew 7,250/yr; "46M+ downloads" (self-reported) | Prowler Inc. ($99/acct/mo SaaS) |
| Kubescape | 11,787 | 2021 | 1,793 | Apache-2.0 | brew 6,897/yr | ARMO; CNCF incubating 2025-01-13 |
| OpenCTI | 10,118 | 2018 | — | Apache-2.0 + EE (NOASSERTION) | 7,000+ Slack | Filigran (>$100M raised) |
| Falco | 9,465 | 2016 | — | Apache-2.0 | downloads +526% since incubation | Sysdig; CNCF graduated 2024-02-29 |
| Checkov | 9,061 | 2019 | 243 | Apache-2.0 | **PyPI 3,968,190/mo**; Docker 24.1M; brew 33,764/yr | Bridgecrew → Palo Alto ($156M, 2021) |
| Steampipe | 7,980 | 2021 | 177 | AGPL-3.0 | brew 3,264/yr; 158 plugins | Turbot (Pipes SaaS) |
| ScoutSuite | 7,839 | 2018 | **0** | GPL-2.0 | PyPI 22,062/mo; brew 703/yr | NCC Group; last release 2024-05-10 |
| tfsec | 7,048 | 2019 | — | MIT | brew 27,537/yr (legacy) | "Tfsec is now part of Trivy" |
| CloudQuery | 6,542 | 2020 | — | MPL-2.0 (core) | — | official cloud plugins moved to paid in 2024 |
| CloudMapper | 6,288 | 2018 | **0** | BSD-3 | — | Duo; last push 2024-07-15 |
| Cloud Custodian | 6,079 | 2016 | 338 | Apache-2.0 | **PyPI (c7n) 1,383,574/mo** | Capital One → CNCF incubating 2022 → Stacklet |
| Terrascan | 5,213 | 2017 | — | Apache-2.0 | — | Tenable; **archived** |
| Cartography | 4,128 | 2019 | 1,017 | Apache-2.0 | PyPI 13,810/mo | Lyft → CNCF sandbox 2024-08-23 → SubImage (YC W25) |
| CloudSploit | 3,777 | 2015 | 121 | GPL-3.0 | — | Aqua; README CTA → Aqua signup |
| Fix Inventory (Resoto) | 2,078 | 2020 | **0** | Apache-2.0 | — | Some Engineering; fix.security DNS gone |
| PMapper | 1,583 | 2018 | — | AGPL-3.0 | — | NCC; last push 2024-08 |
| Kexa | 351 | 2022 | — | — | Show HN 81 pts (2025-04-30) | small OSS CSPM launch |
| OpenCSPM | 347 | 2020 | 0 | MIT | — | **archived** |
| Magpie | 205 | 2021 | 0 | Apache-2.0 | — | Open Raven; domain does not resolve |

Sources:
- [sourced: gh api repos/* on 2026-10-09]
- [sourced: https://formulae.brew.sh/api/formula/{trivy,checkov,tfsec,prowler,kubescape,steampipe,scoutsuite}.json]
- [sourced: https://pypistats.org/api/packages/{checkov,c7n,prowler,scoutsuite,cartography}/recent]
- [sourced: https://hub.docker.com/v2/repositories/{aquasec/trivy,bridgecrew/checkov,toniblyx/prowler,prowlercloud/prowler}/]
- [sourced: https://prowler.com/] [sourced: https://wazuh.com/about-us/] [sourced: https://www.crowdsec.net/] [sourced: https://filigran.io/]
- [sourced: https://www.cncf.io/announcements/2024/02/29/cloud-native-computing-foundation-announces-falco-graduation/]
- [sourced: https://hub.steampipe.io/plugins] [sourced: https://hn.algolia.com/api/v1/search?query=Show%20HN%20cloud%20security%20open%20source&tags=story&numericFilters=created_at_i%3E1704067200,points%3E40]

**The most important number in this table [inferred]:**
- Checkov has fewer stars than Prowler (9.1k vs 15.0k) but about **38× the monthly PyPI downloads** (3.97M vs 0.10M). c7n has about 13×.
- Stars measure attention. Downloads measure *placement in automation*.
- For "100 companies", placement is the metric that matters, and placement comes from CI and scheduled jobs, not from dashboards.

### 2.2 How the winners grew

**Prowler: from a solo project to the open-source CSPM default.**
- **Origin and steward:** Toni de la Fuente started it in 2016. The About page calls him "a former top security practitioner at AWS". [sourced: https://prowler.com/about] It was a solo project until 2022, when "I've joined Verica and thanks to their support we have invested a lot on Prowler and we are announcing today the availability of Prowler Pro!" The team then had 4 full-time engineers. [sourced: https://blyx.com/2022/04/19/prowler-pro-and-verica-announcement/]
- **Lever 1, AWS endorsement:** a 2019-11-26 AWS Security Blog post by the Security Hub TPM showed Prowler on Fargate sending findings to Security Hub, and Security Hub later added native Prowler integration. [sourced: https://aws.amazon.com/blogs/security/use-aws-fargate-prowler-send-security-configuration-findings-about-aws-services-security-hub/]
- **Lever 2, CIS benchmark parity and CloudShell-friendliness.** [sourced: gh api repos/prowler-cloud/prowler/readme]
- **Lever 3, steady major versions.** v3 in Dec 2022 was a full Python rewrite adding Azure. v4 in Apr 2024 added Kubernetes and a dashboard. [sourced: https://blyx.com/2022/12/21/prowler-v3-piece-of-mind/] [sourced: https://blyx.com/2024/04/04/prowler-4-0-0-the-trooper/]
- **Lever 4, provider and framework breadth.** It now covers 15+ providers and claims "2,500+ checks and 70+ compliance frameworks". [sourced: https://prowler.com/]
- **Lever 5, community events and content.** It ran the "first-ever Open Cloud Security Conference" in 2025 [sourced: https://prowler.com/blog?6fde119e_page=4], had a Black Hat USA 2026 booth [sourced: https://prowler.com/blog/whats-new-in-prowler-july-2026], and has well-known practitioners such as Chris Farris writing for its blog [sourced: https://prowler.com/blog].
- **Licence:** Apache-2.0 throughout. It has never relicensed. [sourced: gh api repos/prowler-cloud/prowler]
- **Funding:** Prowler's Series A/B amounts were **not found** in this session.

**Checkov (Bridgecrew → Palo Alto).** Checkov was the open-source top of funnel for Bridgecrew, which Palo Alto acquired in Feb 2021 for $156M. [sourced: https://en.wikipedia.org/wiki/Palo_Alto_Networks] Its distribution is overwhelmingly in CI: 3.97M PyPI/month and 24.1M Docker pulls. [sourced: pypistats; Docker Hub] Post-acquisition it is still maintained but has slowed: 243 commits in 12 months. [sourced: gh api]

**Trivy (Aqua).**
- Aqua consolidated tfsec into Trivy: "our engineering attention will be directed at Trivy going forward." [sourced: https://github.com/aquasecurity/tfsec]
- One binary covering images, IaC, SBOM and K8s, shipped through every package manager, produced the biggest distribution numbers in the category (128M Docker pulls).
- That ubiquity made it a target: Trivy was compromised on 2026-03-19. [sourced: https://pulse.latio.tech/p/how-to-know-if-the-trivy-supply-chain]

**Cloud Custodian (Capital One → CNCF → Stacklet).**
- It was created inside Capital One by Kapil Thangavelu, who co-founded Stacklet. Investors include Addition, Foundation Capital and Capital One Ventures. [sourced: http://stacklet.ai/about]
- It joined the CNCF sandbox 2020-06-25 and moved to incubating 2022-09-14. [sourced: https://www.cncf.io/projects/cloud-custodian/]
- Lever: **it runs unattended, as policy-as-code in Lambda or CI**, hence 1.38M PyPI downloads a month.

**Cartography (Lyft → CNCF → SubImage).**
- Lyft open-sourced it in March 2019. CNCF sandbox acceptance on 2024-08-23 took about a year from application (opened 2023-08-28; 72.73% vote). [sourced: https://github.com/cncf/sandbox/issues/58]
- It has 876 contributors from 233 organisations. [sourced: https://www.cncf.io/projects/cartography/]
- The creators founded **SubImage** (YC W25, "The Open-Core Security Graph", $4.2M raised Oct 2025, "70+ companies use Cartography"). [sourced: https://www.ycombinator.com/companies/subimage]
- **Prowler now builds its attack paths on Cartography** [sourced: https://docs.prowler.com/developer-guide/attack-paths-queries]. A neutral foundation-hosted graph became shared infrastructure for competitors. [inferred]

**Steampipe / Turbot.**
- Steampipe moved to AGPLv3 on 2021-05-20. [sourced: https://github.com/turbot/steampipe/commit/13e644567f4e0d611986b77e4ec9c259776d8605]
- The plugin ecosystem grew to 158 plugins. [sourced: https://hub.steampipe.io/plugins]
- Turbot then **unbundled**: Flowpipe (v0.1 2023-12-13), Powerpipe (v0.1 2024-03-06; both v1.0 2024-10-22) and Tailpipe (v0.1 2025-01-30). The mods hub now redirects to hub.powerpipe.io. [sourced: https://github.com/turbot/powerpipe/releases/tag/v0.1.0] [sourced: https://github.com/turbot/tailpipe/releases/tag/v0.1.0] [sourced: https://hub.steampipe.io/mods]
- Turbot Pipes is still live and "Free for Developers!" [sourced: https://turbot.com/pipes]
- Steampipe's 12-month commit count (177) and Homebrew installs (3,264/yr) suggest Turbot's energy moved to the newer products and Guardrails. [inferred]

**Kubescape (ARMO)** went from CNCF sandbox (2022-12-13) to incubating (2025-01-13) in about 2 years. [sourced: https://www.cncf.io/projects/kubescape/] It had 1,793 commits in 12 months and 11.8k stars. [sourced: gh api]

**Falco (Sysdig)** went from sandbox (2018) to graduated (2024-02-29), with 30+ public adopters and "downloads up 526%" since incubation. [sourced: https://www.cncf.io/projects/falco/] [sourced: https://www.cncf.io/announcements/2024/02/29/cloud-native-computing-foundation-announces-falco-graduation/]

**CrowdSec** built a network-effect moat: "250,000+ active watchers", "70,000+ active users sharing 40M+ signals a day". [sourced: https://www.crowdsec.net/]

**Wazuh** sells cloud, support, consulting and training on top of free software: "100,000+ enterprise users", "30M+ downloads a year". [sourced: https://wazuh.com/about-us/]

**OpenCTI / Filigran** raised a $16M Series A (Feb 2024, Accel), a $35M Series B (Oct 2024, Insight) and a $58M Series C (Oct 2025, Eurazeo). It has a 7,000+ member Slack. [sourced: https://filigran.io/our-investors] [sourced: https://filigran.io/]

### 2.3 What stalled or died, and why

| Project | Evidence | Proximate cause |
|---|---|---|
| **ScoutSuite** (NCC Group) | 0 commits in 12 months; last release 2024-05-10; 246 open issues, 51 PRs | Consultancy side project with no product business behind it [inferred] [sourced: gh api; https://github.com/nccgroup/ScoutSuite] |
| **CloudSploit** (Aqua) | Still pushed (121 commits/12 mo) but README CTA points to Aqua's commercial signup; Aqua framed the purchase as extending into "service posture management" | Acquired content became lead-gen for the commercial CNAPP [inferred] [sourced: https://github.com/aquasecurity/cloudsploit] [sourced: https://www.aquasec.com/news/aqua-security-acquires-cloudsploit/] |
| **tfsec** | "Tfsec is now part of Trivy" | Folded into the parent's flagship [sourced: https://github.com/aquasecurity/tfsec] |
| **Terrascan** (Tenable) | Archived | Folded or abandoned after acquisition [sourced: gh api repos/tenable/terrascan on 2026-10-09] |
| **Fix Inventory / Resoto** (Some Engineering) | cloudkeeper → Resoto (2022) → AGPLv3 (Oct 2023) → Fix (Feb 2024) → Apache-2.0 (Feb 2025); last commit 2025-03-28; fix.security no longer resolves | Repeated renames and relicensing, then the company/SaaS disappeared [sourced: gh api repos/someengineering/fixinventory/commits?path=LICENSE] [inferred on cause] |
| **OpenCSPM** (Darkbit) | Archived; last commit 2021-05-28; darkbit.io parked | Company exit or abandonment; acquirer not confirmed [sourced: https://github.com/OpenCSPM/opencspm] |
| **Magpie** (Open Raven) | Last commit 2024-08-29; openraven.com does not resolve | Sponsor company gone [sourced: https://github.com/openraven/magpie] |
| **CloudMapper** (Duo) | "Network Visualization functionality... is no longer maintained"; last push 2024-07-15 | Corporate side project; sponsor moved on [sourced: https://github.com/duo-labs/cloudmapper] |
| **CloudQuery** | 2024-04 "Remove paid plugins"; AWS/GCP/Azure plugins moved to pay-per-row, old free versions "won't receive ongoing maintenance" | Took back the valuable part [sourced: https://github.com/cloudquery/cloudquery/pull/17779] [sourced: https://www.cloudquery.io/blog/cloudquery-official-free-plugins-moving-to-paid] |
| **Semgrep → Opengrep** | 2024-12-13 rules licence limited to "internal, non-competing, and non-SaaS"; Opengrep repo created the next day, backed by Aikido, Endor, Orca and others | Relicensing triggered a vendor-coalition fork [sourced: https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/] [sourced: https://www.opengrep.dev/] |
| **Terraform → OpenTofu** | BSL 2023-08-10; fork by 2023-08-25; GA 2024-01-10; CNCF sandbox 2025-04-23; about 30.4k stars | Same pattern at larger scale [sourced: https://www.hashicorp.com/blog/hashicorp-adopts-business-source-license] [sourced: https://opentofu.org/blog/opentofu-is-going-ga/] [sourced: https://www.cncf.io/projects/opentofu/] |

### 2.4 Which levers worked [inferred, from the evidence above]

| Lever | Worked for | Evidence strength |
|---|---|---|
| **Runs unattended in CI or automation** | Checkov, c7n, Trivy | Strongest: 10–40× download multiples |
| **Cloud-provider endorsement or native integration** | Prowler (AWS Security Hub blog + native integration) | Strong |
| **Founder-led, one permissive licence for years** | Prowler (Apache-2.0 since 2016), Falco, Kubescape | Strong (contrast: Fix, CloudQuery, Semgrep) |
| **Neutral foundation home (CNCF)** | Falco, Kubescape, Custodian, Cartography | Medium-strong (credibility plus multi-vendor contributors; Cartography has 233 orgs) |
| **Commercial company formed by the original authors** | Prowler, Stacklet, SubImage, ARMO, Filigran | Strong for sustainability |
| **Content breadth (checks/frameworks)** | Prowler | Strong but expensive; it is the treadmill |
| **Network effects from shared data** | CrowdSec | Strong but specific to its domain |
| **Conference presence and community events** | Prowler (own conference, Black Hat booth) | Medium (correlation only) |
| **Package-manager ubiquity** (brew/apt/docker/pip) | Trivy | Strong, *and* raises the supply-chain stakes |

**Stall causes, ranked by frequency in this sample:**
1. No business behind the project: ScoutSuite, CloudMapper, Magpie.
2. Absorbed by an acquirer's commercial product: tfsec, CloudSploit, Terrascan, OpenCSPM.
3. Licence or name churn, or taking back the valuable part: Fix, CloudQuery, Semgrep.

nimbus is currently a single-owner project with no business. That is the #1 stall pattern, and §6/§7 address it directly. [inferred]

---

## 3. What practitioners say they want

_Caveat: Reddit could not be fetched in this session. Quotes below come from Hacker News (Algolia API), PeerSpot, Latio, Chris Farris, Datadog, tl;dr sec and Metabase. Treat this section as directional, not a survey._

### 3.1 Unmet needs, by theme

**A. Context over volume ("tell me what's actually exploitable").**
- "Wiz makes their bread and butter on helping people understand when they actually have open S3 buckets and not just giving them a report full of false positives." (mdaniel, HN, 2025-02-24) [sourced: https://hn.algolia.com/api/v1/items/43161332]
- "There are many tools that let a security team pull in data from the cloud providers and detect misconfigurations, but this becomes soo much more useful when they're able to contextualize it against their internal data." (bavarianbob, HN) [sourced: same]
- "No security person says 'I don't have enough problems to look into.' Security spending is down, so navel gazing products are going to be a really hard sell." (mike_d, HN) [sourced: same]
- Datadog's 2025 data shows that raw misconfiguration *rates* are falling for the classic checks: only **1% of S3 buckets are effectively public** (down from 1.5%), and **83%** have Block Public Access. The persistent problems are identity and credentials:
  - **59% of AWS IAM users have access keys older than one year**;
  - **19.4% of EC2 instances are overprivileged**;
  - **39% of EKS clusters are internet-exposed**.

  [sourced: https://www.datadoghq.com/state-of-cloud-security/] **Read [inferred]:** the "public bucket" checklist era is ending, and value has moved to effective-permission and exposure *combinations*.

**B. Fixes that land with engineering, not more tickets.**
- "posture tools exist for developers, not security teams, because they reduce security teams to project managers"; "The solution to posture findings always ended up back on engineering's plate." (James Berthoty, Latio, 2025-03-13) [sourced: https://pulse.latio.tech/p/the-great-cnapp-re-bundle]
- Wiz auto-tickets: "We hate that because tickets appear and disappear magically in hundreds each time Wiz scans, sometimes with no obvious explanations." (tecleandor, HN, 2025-03-18) [sourced: https://hn.algolia.com/api/v1/items/43402941]
- Wiz buyers ask for "more flexible and automated remediation workflows." [sourced: https://www.peerspot.com/products/wiz-reviews]
- Incumbents have bought or built remediation: Wiz bought Dazz ($450M), Orca bought Opus, and Prowler shipped an "Autonomous Fixer" and a Claude Code plugin that can "open pull requests." [sourced: https://techcrunch.com/2024/11/21/wiz-acquires-dazz-for-450m-to-expand-its-cybersecurity-platform] [sourced: https://orca.security/resources/press-releases/orca-security-acquires-opus-ai-cloud-remediation/] [sourced: https://prowler.com/blog/whats-new-in-prowler-july-2026]

**C. Identity and attack-path depth (effective permissions, not policy text).**
- "I was watching a competitor of yours... trying to integrate IAMSpy with Cartography to have more insight into what, actually, the IAM Roles could do." (mdaniel, HN) [sourced: https://hn.algolia.com/api/v1/items/43161332]
- New open-source tools keep appearing in this space:
  - **AWSHound** (Aug 2026) does offline IAM evaluation across identity policies, permission boundaries, SCPs, RCPs and resource policies, with "156 edge types with 36 traversable paths". It processed "over 500 accounts producing approximately 160,000 nodes and 10.5 million edges in 15 minutes." [sourced: https://tldrsec.com/p/tldr-sec-343]
  - Datadog's **pathfinding.cloud** IAM privesc library was created 2025-10-09. [sourced: gh api repos/DataDog/pathfinding.cloud on 2026-10-09]
- TruffleHog's analysis of leaked AWS keys found "88% were still active with a median age of five years, 84% had full administrator access." [sourced: https://tldrsec.com/p/tldr-sec-343]

**D. Transparency: public docs, public pricing, inspectable code.**
- Wiz complaints: "Closed docs. You can only check the docs if logged in"; Terraform provider "No source AFAIK, you just get a binary"; "no public pricing." [sourced: https://hn.algolia.com/api/v1/items/43402941]
- Cartography's creator on open core: "I'm not a fan of doing things like premium modules because I don't want to ever get in the position where I'm declining a pull request in open source because it covers a premium feature." (SubImage launch, HN) [sourced: https://hn.algolia.com/api/v1/items/43161332]

**E. Multi-cloud neutrality and coverage of the identity plane.**
- "CSPM is most valuable for large enterprises that have many cloud tenants as they can provide visibility across the entire footprint in one place." (EE84M3i, HN, 2025-04-14) [sourced: https://hn.algolia.com/api/v1/items/43678123]
- Prowler's 2026 roadmap moved into Okta ("Your Identity Layer Is the New Perimeter"), M365, GitHub, Vercel, MongoDB Atlas and Cloudflare. [sourced: https://prowler.com/blog] [sourced: https://github.com/prowler-cloud/prowler]

**F. Capacity, not just budget (the mid-market).**
- "The upper middle (the 10%) and the Valley of Death sit in the middle and don't have a coherent narrative"; first security hires absorb pressure "that might otherwise have produced real investment." (Chris Farris, 2026-05-23) [sourced: https://www.chrisfarris.com/post/security-poverty-cliff/]

**G. Supply-chain trust in the security tool itself (new in 2026).**
- Trivy was compromised on **2026-03-19**. Latio calls it "a major step forward in attacker sophistication": "most organizations do not have adequate telemetry to assess the impact – and subsequently which secrets need to be rotated." [sourced: https://pulse.latio.tech/p/how-to-know-if-the-trivy-supply-chain]
- Rami McCarthy's 2026 writing is dominated by package security and GitHub Actions hardening ("How to Harden GitHub Actions: An Updated Guide", Apr 2026; TeamPCP and Shai-Hulud series). [sourced: https://ramimac.me/]
- LLM-driven bulk scanning means "Vulnerabilities are now being strip mined—If your code is available, and someone is willing to spend tokens, they can scan the code in bulk." (Metabase, 2026-05-14; HN 132 points) [sourced: https://www.metabase.com/blog/strip-mining-era-of-open-source-security] [sourced: https://hn.algolia.com/api/v1/search?query=Strip%20Mining%20Era%20of%20OSS%20Security&tags=story]
- **Read [inferred]:** a security tool that holds read access to every cloud account is now a top-tier supply-chain target. Signed releases, pinned actions, minimal dependencies and read-only roles are *buying criteria*, not nice-to-haves.

**H. AI agents as the new interface.**
- tl;dr sec in Sep–Oct 2026 is dominated by agentic security: an "AWS AI Security Analyst," "AI Agents Hacking Companies for $25," and an AWS threat-hunting agent at about $500/month. [sourced: https://tldrsec.com/]
- Prowler shipped a remote MCP server and a Claude Code plugin ("Ask Claude Code if you're CIS-compliant", Aug 2026). [sourced: https://prowler.com/blog]
- Farris: "Agents are wrong and then act on it." [sourced: https://www.chrisfarris.com/post/agent-accountability/]
- **Read [inferred]:** an MCP/agent interface is table stakes for 2027. "Read-only, cites its evidence" is the trust differentiator.

### 3.2 What makes people switch (from the evidence)

1. **Time-to-value and frictionless onboarding.** Wiz's GTM credits agentless onboarding and "easily onboard, prioritize the most important stuff, and gain a holistic view." It reached $100M ARR in 18 months. [sourced: https://www.cybersecuritypulse.net/p/wizs-32b-gtm-playbook-unpacking-the]
2. **Getting onto the questionnaire.** "Wiz got their offering included in the bingo sheet templates in approximately 18 months." (sublimefire, HN) [sourced: https://hn.algolia.com/api/v1/items/43678123] **Read [inferred]:** for an OSS tool, the equivalent of the "bingo sheet" is the CIS/SOC 2 auditor checklist plus "approved tools" lists in security programs, such as OSS starter stacks. One HN user describes an "OSS startup security program: Prowler as the CPSM, Trufflehog for secrets scanning". [sourced: https://hn.algolia.com/api/v1/search?query=open%20source%20CSPM&tags=comment&hitsPerPage=20]
3. **Fewer false positives and less noise.** Several Wiz reviewers report 80–90% less alert noise. [sourced: https://www.peerspot.com/products/wiz-reviews]
4. **Price shocks at renewal** (cost quotes in §1.3).

### 3.3 Complaints about the open-source options

- **ScoutSuite** has had **0 commits in the 12 months to 2026-10-09**. Its last release was 5.14.0 on 2024-05-10, and it has 246 open issues and 51 open PRs. [sourced: gh api repos/nccgroup/ScoutSuite/commits?since=2025-10-09, releases, on 2026-10-09] [sourced: https://github.com/nccgroup/ScoutSuite]
- **Prowler OSS** is broad (AWS 662 checks, Azure 191, GCP 110, K8s 92, 50+ frameworks). But the full attack-path graph, SSO, Jira/Slack integrations, scheduling and Lighthouse AI are paid. [sourced: https://github.com/prowler-cloud/prowler] [sourced: https://prowler.com/pricing] **Read [inferred]:** a team on Prowler OSS gets the list, not the prioritisation.
- **Steampipe** is excellent for ad-hoc SQL, but it is a query engine, not a prioritiser. It is AGPL-3.0 and had 177 commits in the last 12 months versus Prowler's 2,396. Homebrew installs are 3,264/yr versus Prowler's 7,250. [sourced: gh api repos/turbot/steampipe on 2026-10-09] [sourced: https://formulae.brew.sh/api/formula/steampipe.json]
- **The general OSS complaint** is that CSPM is a maintenance treadmill: "keeping up to date with all of the tests"; "maintaining the CIS Kubernetes benchmarks... each of the cloud distributions has its own CIS benchmark." (raesene9, HN) [sourced: https://hn.algolia.com/api/v1/items/43678123]

### 3.4 Most quotable lines (verbatim)

1. "the CSPM wars are over, and Wiz won." (Latio) [sourced: https://pulse.latio.tech/p/the-great-cnapp-re-bundle]
2. "posture tools exist for developers, not security teams, because they reduce security teams to project managers" (Latio) [sourced: same]
3. "not just giving them a report full of false positives" (HN) [sourced: https://hn.algolia.com/api/v1/items/43161332]
4. "No security person says 'I don't have enough problems to look into.'" (HN) [sourced: same]
5. "tickets appear and disappear magically in hundreds each time Wiz scans, sometimes with no obvious explanations." (HN) [sourced: https://hn.algolia.com/api/v1/items/43402941]
6. "it's basically enterprise-only and insanely expensive" (HN) [sourced: https://hn.algolia.com/api/v1/items/43400325]
7. "SOC 2 measures whether you can describe and document a security program. It does not measure whether that program works." (Farris) [sourced: https://www.chrisfarris.com/post/security-poverty-cliff/]
8. "I'm not a fan of doing things like premium modules because I don't want to ever get in the position where I'm declining a pull request in open source because it covers a premium feature." (SubImage/Cartography) [sourced: https://hn.algolia.com/api/v1/items/43161332]

---

## 4. Wedge options for nimbus

Each wedge is scored on the same template: **user**, **30-second demo**, **what incumbents cannot copy cheaply**, **what nimbus already has** (from `CLAUDE_CONTEXT.md` / `PROJECT.md` / `STATE.md`; code not read), and **risks**. A short verdict closes each one.

### Competitive baseline every wedge must clear (Prowler, 2026-10)

Prowler OSS has:
- 2,500+ checks (pricing page) or 1,379+ by provider table (README);
- 50+ frameworks;
- "Basic ThreatScore and attack paths (AWS only)";
- SARIF, OCSF, ASFF and a GitHub Action.

Prowler Cloud ($99/account/mo) adds:
- the "Full end-to-end attack path graph";
- Lighthouse AI, the "Autonomous Fixer" and an MCP server;
- SAML SSO, Jira/Slack, scheduling and SOC 2 Type 2.

[sourced: https://prowler.com/pricing] [sourced: https://github.com/prowler-cloud/prowler]

Prowler's attack paths are built on **Cartography** with read-only openCypher on Neo4j/Neptune. [sourced: https://docs.prowler.com/developer-guide/attack-paths-queries] Any nimbus wedge that reads as "Prowler's paid features, free" is credible but *temporary*: Prowler can move a line in its pricing table faster than nimbus can build community. [inferred]

### (a) Unified ingestion: one graph over Prowler, Checkov, Trivy and Steampipe outputs

- **User:** the cloud security engineer at a 200–2,000-person company who already runs two or three free scanners and drowns in their combined, duplicated output. This is the PROJECT.md persona: "drowning in 45 tools."
- **30-second demo:**
  1. `cloud-posture ingest prowler.ocsf.json checkov.sarif trivy.json`
  2. `cloud-posture paths --top 5`
  3. The output says 9,412 raw findings became 4,100 unique ones after dedup, which came down to **5 attack paths**. Each path shows which tool saw which hop.
- **Precedent:**
  - DefectDojo (4,989 stars, active since 2015) proves demand for aggregation, but it is AppSec- and ticket-oriented with no cloud graph. [sourced: gh api repos/DefectDojo/django-DefectDojo on 2026-10-09]
  - AWS Security Hub's core idea is aggregation; its 2025 redesign "correlates findings from GuardDuty, Inspector, Macie and Security Hub CSPM", but only for AWS-ecosystem sources. [sourced: https://siliconangle.com/2025/12/02/aws-rolls-security-agent-strengthens-guardduty-security-hub-reinvent-2025/]
  - Wiz grew partly as a vulnerability *ingestion* layer: "CSPM and the evolution of vulnerability ingestion it introduces will continue to be highly competitive." [sourced: https://pulse.latio.tech/p/wiz-acquisition-winners-losers-and]
- **Why incumbents cannot copy it cheaply [inferred]:**
  - Prowler's business is *its own* checks. Making Checkov, Trivy or a rival's findings first-class in its graph would commoditise its content moat.
  - Commercial CNAPPs ingest third-party findings only through paid connectors.
  - A neutral, vendor-agnostic normaliser is a natural open-source position, the way OpenTelemetry is for observability.
- **nimbus today:**
  - adapters for Prowler (OCSF + v3), ScoutSuite, Checkov, Trivy, Steampipe and native JSON;
  - a canonical `catalog.yaml` with per-tool aliases;
  - stable fingerprints;
  - findings-derived SQL views. [sourced: CLAUDE_CONTEXT.md]

  This is nimbus's most *distinctive existing* asset.
- **Risks:**
  - Upstream formats churn (Prowler v3 → OCSF already happened).
  - Users may not want a second tool on top of the first.
  - Dedup errors destroy trust.
  - "Aggregator" sounds boring unless it ends in paths. [inferred]
- **Verdict: commit.** Use it as the *on-ramp*, not the headline. "Keep your scanners, get a graph."

### (b) Free attack-path and toxic-combination analysis

- **User:** the same engineer, plus the head of security who needs "what do I fix first" for leadership.
- **30-second demo:** `cloud-posture paths --top 5 --explain` prints:

  ```
  Internet → sg-0ab:22 → i-123 (KEV CVE) → role/app → s3://pii
  score 8.7 = internet ×1.6 · KEV ×1.5 · PII ×1.5
  cheapest fix: remove 0.0.0.0/0 on sg-0ab (breaks 3/3 paths)
  ```

- **Market evidence:**
  - Toxic combinations are Wiz's core concept. A critical Issue is "a resource with a very high likelihood of being compromised **and** a significant business impact."
  - Google SCC publishes its scoring; Wiz does not. [sourced: docs/research/competitors.md §1, which cites https://wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk and https://docs.cloud.google.com/security-command-center/docs/attack-exposure-learn]
  - Microsoft makes attack paths a paid Defender CSPM feature. [sourced: https://learn.microsoft.com/en-us/azure/defender-for-cloud/concept-cloud-security-posture-management]
- **The open-source landscape is no longer empty. It is crowded and fragmented:**

  | Project | Stars | Status |
  |---|---|---|
  | Prowler | — | attack paths (AWS basic in OSS; full graph paid) |
  | Cartography | 4,128 | CNCF sandbox; 1,017 commits/yr |
  | SubImage | — | "open-core Wiz alternative" on Cartography, YC W25 |
  | BloodHound CE | 3,472 | — |
  | AWSHound | 80 | launched Aug 2026 |
  | PMapper | 1,583 | last push 2024-08 |
  | pathfinding.cloud | 156 | IAM privesc library |

  [sourced: https://prowler.com/pricing] [sourced: gh api repos/cartography-cncf/cartography, SpecterOps/BloodHound, AWSHound/AWSHound, nccgroup/PMapper, DataDog/pathfinding.cloud on 2026-10-09] [sourced: https://hn.algolia.com/api/v1/items/43161332]
- **Why incumbents cannot copy it cheaply [inferred]:**
  - Wiz and Orca keep their formulas closed, which is a deliberate moat.
  - Prowler gates the *full* graph because it is the upsell.
  - Cartography is a data layer that leaves scoring to SubImage.
  - None of them ships, in OSS, a **published, deterministic score plus a min-cut "cheapest fix set" plus cross-scanner hops**. Publishing the math is cheap for nimbus and expensive for a vendor whose pricing depends on the black box.
- **nimbus today:**
  - `internal/attackpath` with rule chains, multi-hop traversal, choke points, blast radius and break-the-path;
  - a typed graph with Cartography/BloodHound-style labels;
  - Neo4j push;
  - competitors.md design decisions for an AND/OR graph, published score and min-cut. [sourced: CLAUDE_CONTEXT.md; docs/research/competitors.md]
- **Risks:**
  - **Correctness is everything.** One false "critical path" in a public demo kills credibility. Effective-permission evaluation (SCPs, RCPs, boundaries, conditions) is genuinely hard; AWSHound and PMapper exist because of it.
  - nimbus has not run against a live account yet (STATE.md).
  - Prowler could open-source its full graph in a release.
- **Verdict: commit**, with a **reproducible benchmark** (§5) as the proof. Partner with rather than fight the IAM-path libraries: import pathfinding.cloud and BloodHound OpenGraph. [inferred]

### (c) Fix-first (PRs, IaC patches) vs report-first

- **User:** the platform or DevOps engineer who owns the Terraform. Latio's framing is "The solution to posture findings always ended up back on engineering's plate." [sourced: https://pulse.latio.tech/p/the-great-cnapp-re-bundle]
- **30-second demo:**
  1. `cloud-posture fix <path-id> --pr`
  2. A GitHub PR appears with a 3-line HCL diff on the exact module and line.
  3. The PR body says "closes 3 attack paths, blast radius: 1 SG, rollback: revert."
  4. CI re-scans, and the path count goes 5 → 2.
- **Market evidence:**
  - Remediation is where the 2024–25 M&A money went: Wiz bought Dazz for $450M and Orca bought Opus.
  - Prowler's "Autonomous Fixer" and Claude Code plugin "open pull requests."
  - Wiz buyers ask for "more flexible and automated remediation workflows."

  [sourced: https://techcrunch.com/2024/11/21/wiz-acquires-dazz-for-450m-to-expand-its-cybersecurity-platform] [sourced: https://orca.security/resources/press-releases/orca-security-acquires-opus-ai-cloud-remediation/] [sourced: https://prowler.com/blog/whats-new-in-prowler-july-2026] [sourced: https://www.peerspot.com/products/wiz-reviews]
- **Why incumbents cannot copy it cheaply [inferred]:**
  - They *can*, but they gate it: Prowler's fixer is Cloud-only.
  - An open, **deterministic** fix library (templates first, LLM second, every fix validated by re-scan) that anyone can audit and contribute to is a community asset, like Semgrep autofix rules.
  - Owning the cloud → code mapping locally (state file → module → line) without uploading state to a SaaS is a privacy advantage that SaaS vendors cannot match.
- **nimbus today:**
  - `internal/remediation` (Terraform, CFN, Bicep, K8s templates);
  - `internal/iac` (native HCL scanner and **patcher**);
  - the AI copilot with LLM fixes;
  - GitHub Issues integration;
  - the VS Code extension. [sourced: CLAUDE_CONTEXT.md]
- **Risks:**
  - A bad auto-PR is worse than no PR.
  - Monorepo and module complexity.
  - Teams may not grant write access.
  - Fixes without graph context are just Checkov.
- **Verdict: commit**, fused with (b) and (h): **"fix the path, not the finding."**

### (d) Compliance evidence that passes an audit ("Vanta-lite for engineers")

- **User:** a 20–300-person startup's first security or DevOps hire preparing SOC 2 or ISO 27001.
- **30-second demo:** `cloud-posture evidence --framework soc2 --period 2026-Q3` produces a ZIP organised by control, source and date, with a signed manifest and "control effective 88 of 92 days."
- **Market evidence:**
  - The Audit Manager evidence format and Vanta/Drata cadence are described in competitors.md §8.
  - Farris: "SOC 2 measures whether you can describe and document a security program. It does not measure whether that program works." [sourced: https://www.chrisfarris.com/post/security-poverty-cliff/]
  - Prowler already ships 50+ frameworks, DORA, and "Consolidated executive PDF reports." [sourced: https://prowler.com/blog/whats-new-in-prowler-july-2026]
- **Why incumbents cannot copy it cheaply [inferred]:**
  - Vanta and Drata sell the *auditor relationship and workflow*, which open source cannot replicate.
  - Framework mapping is exactly the content where Prowler is far ahead.
  - The defensible piece is narrow: **period coverage plus signed, reproducible evidence from raw API responses**.
- **nimbus today:** 7 framework packs, an audit-report builder, and per-framework SQL views. [sourced: CLAUDE_CONTEXT.md]
- **Risks:**
  - An auditor rejecting the output is reputational poison.
  - Most of SOC 2 is non-cloud (HR, policies).
  - It competes with well-funded GRC vendors and Prowler's framework breadth.
- **Verdict: support feature, not a wedge.** Ship evidence bundles as a *proof artefact* for (b)/(c): "here is evidence the path was closed on date X." Don't position nimbus against Vanta.

### (e) SQL and plain-English querying over everything

- **User:** the engineer who wants ad-hoc answers ("which internet-facing VMs run as an admin role in prod?").
- **30-second demo:**
  1. `cloud-posture ask "public VMs with admin roles in prod"`
  2. It shows the generated SQL and 4 rows, each a link into the graph.
- **Market evidence:**
  - Steampipe proved SQL-over-cloud appeal (7,980 stars) but is a query layer without prioritisation. Its Homebrew pull is modest (3,264 installs/yr). [sourced: gh api repos/turbot/steampipe; https://formulae.brew.sh/api/formula/steampipe.json]
  - Wiz AskAI and Orca NL search exist (competitors.md §4/§6).
  - Prowler Lighthouse and MCP are Cloud-only. [sourced: https://prowler.com/pricing]
- **Why incumbents cannot copy it cheaply [inferred]:** they can, and they have. The OSS angle is "local, BYO model, shows the query."
- **nimbus today:** SQLite views, the `graph_nodes`/`graph_edges` tables, and a rule-based offline copilot. [sourced: CLAUDE_CONTEXT.md]
- **Risks:**
  - NL→SQL hallucination.
  - Steampipe/Powerpipe already own "SQL for cloud".
- **Verdict: support feature.** Ship an **MCP server over the local graph**, which is cheap and catches the agent wave (§3.1H). Don't lead with SQL.

### (f) Cost + security

- **User:** a FinOps-aware platform lead, or a CISO who needs a budget story.
- **30-second demo:** "Close these 6 findings and save $1,240/mo." This covers unattached disks, idle public IPs and unused keys.
- **Market evidence:**
  - Infracost (12,558 stars, 9,866 Homebrew installs/yr) shows there is cost-in-PR demand. [sourced: gh api repos/infracost/infracost; https://formulae.brew.sh/api/formula/infracost.json]
  - OpenCost has 6,766 stars and Komiser 4,144. [sourced: gh api on 2026-10-09]
  - No evidence found that security buyers choose a CSPM because of cost features.
- **Why incumbents cannot copy it cheaply:** they can; it is not a moat. [inferred]
- **nimbus today:** `internal/cost` (zombie, rightsizing, security+cost wins, ROI). [sourced: CLAUDE_CONTEXT.md]
- **Risks:**
  - It dilutes the message.
  - ROI numbers invite scepticism.
- **Verdict: delight feature.** Use it as a single "security-driven savings" card. Never use it for positioning.

### (g) Local-first, offline and private (no SaaS)

- **User:**
  - regulated or data-residency-sensitive teams (EU/DORA, public sector, fintech);
  - anyone uneasy about sending their full cloud graph to a vendor that is now owned by a hyperscaler;
  - air-gapped or sovereign clouds.
- **30-second demo:**
  1. `brew install nimbus && cloud-posture scan --offline`
  2. The output is a single static HTML report and a local SQLite file.
  3. The dashboard works with no network. Show `tcpdump` with no egress.
- **Market evidence:**
  - The post-acquisition neutrality concern (§1.3) and the Wiz "Closed docs" and binary-only provider complaints. [sourced: https://hn.algolia.com/api/v1/items/43402941]
  - Prowler's "Private Cloud" tier exists for this demand but is "Custom tailored", i.e. sales-led. [sourced: https://prowler.com/pricing]
  - Prowler launched DORA audits in June 2026, which shows EU regulatory pull. [sourced: https://prowler.com/blog]
  - Farris writing about eu-central-1 being "about 2000km from Moscow" shows resilience and sovereignty are live concerns. [sourced: https://www.chrisfarris.com/]
- **Why incumbents cannot copy it cheaply [inferred]:**
  - SaaS CNAPPs are architected around central ingestion, and their pricing and AI features depend on it.
  - Local-first is a business-model conflict for them, not a feature gap.
- **nimbus today:**
  - "works offline (static dashboard, rule-based copilot)" is a stated constraint;
  - SQLite store;
  - no proprietary SaaS backend (non-goal);
  - embedded Cytoscape with no CDN. [sourced: .planning/PROJECT.md; STATE.md]
- **Risks:**
  - Local-first limits team collaboration and history. The answer is self-hosted server mode.
  - It is harder to monetise. Answer: §6.
- **Verdict: commit**, as the *trust frame* around (a)–(c).

### (h) CI-native / shift-left

- **User:** the developer or platform engineer in a PR.
- **30-second demo:** a PR comment from the nimbus GitHub Action: "This plan **opens 1 new attack path** to `s3://pii` (internet → alb → task-role:s3:*). Suggested fix: [commit suggestion]."
- **Market evidence:** CI placement is the single strongest distribution signal in this research.
  - **Checkov:** 3.97M PyPI downloads/month, 24.1M Docker pulls.
  - **Trivy:** 128.3M Docker pulls, 134,685 Homebrew installs/yr.
  - **Cloud Custodian (c7n):** 1.38M PyPI/month (automation-run).
  - **Prowler:** 104k PyPI/month, 4.5M Docker pulls.

  [sourced: pypistats.org/api/packages/{checkov,c7n,prowler}/recent; hub.docker.com/v2/repositories/{bridgecrew/checkov,aquasec/trivy,toniblyx/prowler}; formulae.brew.sh, all 2026-10-09]
  - Checkov was the open-source engine behind Bridgecrew, which Palo Alto acquired (see §2).
- **Why incumbents cannot copy it cheaply [inferred]:**
  - IaC scanners (Checkov, Trivy, KICS) see the *plan*.
  - CSPMs (Prowler) see the *cloud*.
  - Only a tool holding both the live graph and the plan can say "this PR opens a path."
  - Wiz Code does code-to-cloud via TF state, but it is paid and SaaS.
- **nimbus today:** the native HCL scanner, the VS Code extension and SARIF intent (competitors.md §10). No GitHub Action is listed as shipped. [sourced: CLAUDE_CONTEXT.md]
- **Risks:**
  - CI scanners are crowded.
  - The plan-time path diff needs a cached live graph, which raises credential questions in CI. Answer: OIDC plus a read-only role.
  - The 2026 Trivy compromise shows a widely used security Action is a prime supply-chain target. [sourced: https://pulse.latio.tech/p/how-to-know-if-the-trivy-supply-chain]
- **Verdict: commit**, as the *distribution engine* for (b)+(c).

### (i) A Prowler-compatible check ecosystem to inherit content

- **User:** contributors and existing Prowler users.
- **30-second demo:** `cloud-posture scan --checks prowler:aws` runs or imports Prowler's checks and metadata, and their findings land in the nimbus graph.
- **Market evidence:**
  - Prowler is Apache-2.0 with 2,396 commits in 12 months and 662 AWS checks. [sourced: gh api repos/prowler-cloud/prowler on 2026-10-09; https://github.com/prowler-cloud/prowler]
  - Content upkeep is the treadmill: "keeping up to date with all of the tests." [sourced: https://hn.algolia.com/api/v1/items/43678123]
  - Projects that tried to out-content incumbents stalled (§2).
- **Why incumbents cannot copy it cheaply:** not applicable, since this *is* copying. The point is to **not compete on content**. Prowler's licence allows reuse with attribution. [inferred]
- **nimbus today:**
  - a Prowler OCSF/v3 adapter;
  - Prowler-style boto3 checks in Python;
  - a catalog with per-tool aliases. [sourced: CLAUDE_CONTEXT.md]
- **Risks:**
  - It creates dependence on Prowler's release cadence and schema.
  - It looks like a fork-parasite unless nimbus contributes upstream. Mitigate by upstreaming fixes and crediting Prowler prominently.
  - Running Prowler as a subprocess doubles install weight.
- **Verdict: commit to *ingest*, not to *re-implement*.** Treat Prowler and Checkov as nimbus's content suppliers, and nimbus as their graph and fix layer. "Better together" beats "Prowler-killer" in a world where Prowler has 15k stars and a funded team.

### Wedge scorecard [inferred]

| Wedge | Distinctive vs Prowler OSS? | Already built? | Copy cost for incumbents | Role |
|---|---|---|---|---|
| (a) unified ingestion | High | High | High (conflicts with content moats) | **On-ramp (commit)** |
| (b) free attack paths/toxic combos | High (full graph is Prowler-paid) | Medium (unverified live) | Medium-high (closed formulas are their moat) | **Headline (commit)** |
| (c) fix-first PRs | Medium-high (Prowler fixer is paid) | Medium | Medium | **Payoff (commit, fused with b+h)** |
| (d) audit evidence | Low (Prowler breadth) | Medium | Low | Support |
| (e) SQL/NL/MCP | Low-medium | Medium | Low | Support (MCP) |
| (f) cost+security | Low | Medium | Low | Delight |
| (g) local-first/private | High | High | High (business-model conflict) | **Trust frame (commit)** |
| (h) CI-native | Medium (path-diff is unique) | Low-medium | Medium | **Distribution engine** |
| (i) Prowler-compatible content | n/a | Medium | n/a | **Strategy: ingest, don't rebuild** |

---

## 5. Distribution & credibility playbook

### 5.1 Evidence base: what distribution looks like for the winners

**CI placement dominates.**
- GitHub's dependency graph shows **trivy-action used by 55,417 repos** and **checkov-action by 7,654 repos**. Prowler shows 0, because the dependency graph doesn't track it. [sourced: https://github.com/aquasecurity/trivy-action/network/dependents] [sourced: https://github.com/bridgecrewio/checkov-action/network/dependents] [sourced: https://github.com/prowler-cloud/prowler/network/dependents]
- These line up with the download multiples in §2.1, where Checkov gets about 38× Prowler's PyPI downloads.

**A cloud provider's blessing.** Prowler's breakthrough channel was an AWS Security Blog post by the Security Hub team (2019), which led to native Security Hub integration (2021). [sourced: https://aws.amazon.com/blogs/security/use-aws-fargate-prowler-send-security-configuration-findings-about-aws-services-security-hub/]

**Interop formats.**
- **OCSF** is now Linux Foundation-governed (2024-11-19) and at v1.9.0 (2026-08-03). [sourced: https://ocsf.io/] [sourced: https://schema.ocsf.io/api/version]
- **AWS Security Hub** "currently supports findings in OCSF schema version 1.6". [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.html]
- **ASFF** survives under "Security Hub CSPM". [sourced: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html]
- **Security Lake** maps to OCSF 1.1.0. [sourced: https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html]
- **GitHub code scanning** takes SARIF 2.1.0 only: 10 MB gzipped, 25,000 results per run, top 5,000 kept. [sourced: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning]

**Supply-chain trust.**
- Trivy 2026: compromised credentials published malicious v0.69.4. The attacker **force-pushed 76/77 trivy-action tags**, and malicious Docker images followed. v0.69.3 and trivy-action 0.35.0 were *not* affected because **GitHub immutable releases** had been enabled days earlier. Images pinned by digest and the homebrew-core source build were safe, but the custom Homebrew tap was compromised. [sourced: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23]
- Aqua's lessons: pin to full SHAs, verify with cosign against the GitHub OIDC issuer, and check Rekor timestamps. [sourced: same]
- OpenSSF Scorecard as a visible trust number: Cloud Custodian 8.7, Cartography 8.4, Kubescape 7.3, Steampipe 6.8, Trivy 6.4. [sourced: https://api.securityscorecards.dev/projects/github.com/{repo}]

**Packaging gates.** homebrew-core requires "at least 30 forks, 30 watchers or 75 stars", and "at least 90 forks, 90 watchers or 225 stars for a self-submission by the repository owner". Projects under 30 days old are typically ineligible. [sourced: https://docs.brew.sh/Package-Acceptance-Policy]

**CNCF sandbox.**
- Requirements: Apache-2.0 required ("BSL... and GPL family licenses are not acceptable"), a MAINTAINERS file with companies, and a TOC vote. Reviews run about every two months, roughly 7–10 applications per session. [sourced: https://github.com/cncf/sandbox]
- Cartography took about 12 months from application (2023-08-28) to acceptance (2024-08-23). [sourced: https://github.com/cncf/sandbox/issues/58]
- nimbus is Apache-2.0, so it is eligible in principle. Steampipe (AGPL) is not. [inferred]

**Newsletters.**
- tl;dr sec reaches ">90,000 security professionals". [sourced: https://tldrsec.com/]
- CloudSecList has 12,000+ subscribers and 358 issues; a sponsored slot costs $1,950. [sourced: https://cloudseclist.com/] [sourced: https://cloudseclist.com/sponsor/]
- Both curate tools. tl;dr sec #343 featured AWSHound (80 stars) the month it launched. [sourced: https://tldrsec.com/p/tldr-sec-343]

**HN launches.**
- A Launch HN for a Cartography-based "open-core Wiz alternative" drew 135 points and 31 comments. [sourced: https://hn.algolia.com/api/v1/search?query=SubImage&tags=story]
- An open-source CSPM Show HN (Kexa) drew 81 points; the repo has 351 stars 18 months later. [sourced: https://hn.algolia.com/api/v1/search?query=Show%20HN%20cloud%20security%20open%20source&tags=story&numericFilters=created_at_i%3E1704067200,points%3E40] [sourced: gh api repos/kexa-io/Kexa]
- **Read [inferred]:** a launch spike without a placement engine doesn't compound.

**Open labs for a benchmark (gh api, 2026-10-09):**

| Lab | Stars | Last push / status |
|---|---|---|
| CloudGoat | 3,752 | 2026-10-06 |
| Kubernetes Goat | 5,906 | — |
| Stratus Red Team | 2,421 | — |
| TerraGoat | 1,306 (5,904 forks) | — |
| IAM Vulnerable | 590 | — |
| CNAPPgoat | 298 | dormant since 2024-09 |
| flaws.cloud | — | live |

[sourced: gh api repos/*; http://flaws.cloud/]

**Conferences and CFPs (as of 2026-10-09):**

| Event | Dates | CFP status | Source |
|---|---|---|---|
| **KubeCon + CloudNativeCon EU 2027** | 15–18 Mar 2027, Barcelona | **Closes 11 Oct 2026, 23:59 CEST** (2 days) | https://events.linuxfoundation.org/kubecon-cloudnativecon-europe/program/cfp/ |
| **RSAC 2027** | 5–8 Apr 2027, San Francisco | Archived page: "Submit by Oct. 9", i.e. **today, likely closing** (live page 403) | https://web.archive.org/web/20260922042941/https://www.rsaconference.com/usa |
| KubeCon NA 2026 | 9–12 Nov 2026, Salt Lake City | closed | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/ |
| KubeCon NA 2027 | 8–11 Nov 2027, New Orleans | not public | https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america-2027/ |
| fwd:cloudsec 2027 | not announced (2026: NA 1–2 Jun Bellevue; EU 7–8 Sep London) | not public; expect a spring CFP [inferred] | https://fwdcloudsec.org/ |
| Black Hat EU 2026 Arsenal / USA 2027 Arsenal | not obtained (403) | not obtained | https://www.blackhat.com/eu-26/ |
| DEF CON 35 Demo Labs | not public (DEF CON 34 demo labs included AWS tools: GnawLab, Senrigan x Suzaku) | not public | https://defcon.org/html/defcon-34/dc-34-demolabs.html |
| BSidesLV 2027 | not public (2026 CFP ran 1 Apr–8 May) | expect a similar window [inferred] | https://bsideslv.org/cfp |
| AWS re:Inforce 2027 | not public; re:Invent 2026 has a "Security Focus" track | n/a | https://aws.amazon.com/events/reinvent/sessions/security-focus/ |

### 5.2 The sequenced playbook

The order is deliberate: **credibility before reach, reach before community, community before foundation.** Each step has an exit criterion. Don't move on until it is met, because "implemented ≠ deployed ≠ verified" (the rulebook).

**Phase 0: Make it true (weeks 0–6).** Prerequisite for everything.
1. Run nimbus end-to-end against **CloudGoat + TerraGoat + Kubernetes Goat + a nimbus lab** (Terraform with labelled ground-truth paths). Fix what breaks.
   - Exit: all collectors pass on live AWS, Azure, GCP and K8s; the top-5 paths match ground truth.
   - Why: STATE.md says nothing has run live yet.
2. Cut the default surface to the three wedges: one Go binary, `scan` / `ingest` / `paths` / `fix` / `report`. Python stays optional.
   - Exit: `brew install` (own tap) or `curl | sh`, then the first path in under 10 minutes on a fresh laptop.
3. Ship the trust kit before the first public release:
   - signed releases (cosign keyless), SLSA L2+ provenance via GitHub's hosted build, and SBOM (CycloneDX or SPDX);
   - **GitHub immutable releases on**, all actions pinned by SHA;
   - SECURITY.md, `.well-known/security.txt`, an OpenSSF Scorecard target of 8 or higher, and the OpenSSF Best Practices "passing" badge (https://www.bestpractices.dev/en);
   - a generated least-privilege read-only IAM policy.
   - Why: Trivy 2026 shows this is a buying criterion.

**Phase 1: Prove it publicly (weeks 6–10).**
4. Publish **"nimbus-lab benchmark v1"**: the same lab scanned by Prowler OSS, Checkov, Trivy and nimbus. Report raw findings, deduped findings, *paths found vs ground truth*, fixes generated, and fixes that re-scan clean. Publish the methodology, lab Terraform and raw outputs.
   - Lead with "nimbus + Prowler + Checkov together", not "nimbus beats Prowler". That is honest, and it recruits the incumbents' users rather than their defenders. [inferred]
5. Write **comparison pages** (vs Prowler OSS / Prowler Cloud / Steampipe / Cartography / Wiz), factual and dated. Credit what each does better.
6. Make a **demo video** (90 s): ingest → 5 paths → PR → paths 5→2. Add an animated GIF in the README.

**Phase 2: Placement (weeks 8–16).**
7. Publish the **GitHub Action `nimbus/scan-action`**:
   - SARIF upload, plus a sticky PR comment with the plan-time path diff;
   - OIDC to a read-only role;
   - immutable releases, SHA-pinning guidance in the README, and verified-creator status on the Marketplace.
   - KPI: dependents count, compared with checkov-action's 7,654.
8. Add **output interop**:
   - OCSF 1.6 for Security Hub;
   - ASFF for Security Hub CSPM users;
   - SARIF 2.1.0 for code scanning;
   - Security Lake-compatible Parquet.
   - **Inbound:** accept OCSF from anything.
   - Being the bridge *into* AWS's own hub is how Prowler got AWS's blessing. [sourced: §5.1 AWS blog]
9. **Packaging:**
   - own Homebrew tap now; homebrew-core once at 225 stars (self-submit rule);
   - signed Docker images on GHCR + Docker Hub, referenced by digest;
   - Helm chart for in-cluster K8s scans;
   - scoop and winget, `.deb`/`.rpm` via goreleaser;
   - PyPI for the Python extras.
10. **MCP server over the local graph** ("ask your agent which paths reach prod data"). This is free in nimbus, while Prowler's MCP is Cloud-only. [sourced: https://prowler.com/pricing]

**Phase 3: Reach (weeks 12–26).**
11. **Launch sequence:**
    - Show HN (title: the benchmark result, not the product);
    - submit to tl;dr sec and CloudSecList as a *tool plus research* item;
    - pitch Latio/James Berthoty a briefing on the "posture belongs to developers" angle (his own thesis);
    - consider one CloudSecList sponsored slot ($1,950) only after organic coverage.
12. **CFPs:**
    - KubeCon EU 2027 closes **2026-10-11**. Submit a talk on "plan-time attack-path diffs for K8s + cloud IaC" only if Phase 0 can be done by March. Otherwise skip; don't present vapor.
    - Target **fwd:cloudsec 2027** (practitioner audience; CFP not yet announced; watch fwdcloudsec.org);
    - **Black Hat USA 2027 Arsenal** (open-source tool demos; dates not obtained);
    - **DEF CON 35 Demo Labs** (DEF CON 34 accepted AWS tools);
    - **BSidesLV 2027** (2026 CFP ran Apr–May).
13. **"State of cloud attack paths" report** from the open lab plus opt-in, anonymised design-partner aggregates. Datadog's State of Cloud Security shows the format earns press. [sourced: https://www.datadoghq.com/state-of-cloud-security/]
    - Don't fabricate population stats from a lab. Label lab findings as lab findings. [inferred]
14. **Pursue AWS endorsement.** Write an AWS Security Blog / APN post on "nimbus → Security Hub OCSF". Apply for Security Hub partner integration once the OCSF output is stable.

**Phase 4: Community and governance (months 4–12).**
15. Set up **Slack or Discord** with office hours. Filigran (7,000+ Slack) and Prowler show Slack is the norm in this niche. [sourced: https://filigran.io/] [sourced: https://github.com/prowler-cloud/prowler]
16. **Contribution flywheel:**
    - "good first adapter" and "good first fix template" issues;
    - a **bounty board** for fix templates and path rules, funded small, e.g. through GitHub Sponsors;
    - Prowler sells a custom check for $10,000, which shows what content is worth to buyers. [sourced: https://prowler.com/pricing]
17. **ADOPTERS.md**, MAINTAINERS.md (with companies), GOVERNANCE.md and a public roadmap.
18. **CNCF sandbox application** once there are at least 2 maintainers from at least 2 organisations and real adopters. Expect a 6–12-month review, as with Cartography. A foundation home is what kept Custodian, Falco, Kubescape and Cartography alive past their original sponsor (§2.4).

---

## 6. Monetisation that doesn't betray open source

### 6.1 What the comparables gate

| Feature | Prowler | Turbot Pipes | Stacklet | ARMO | Semgrep | GitLab |
|---|---|---|---|---|---|---|
| Core engine / checks | OSS Apache-2.0 | Steampipe AGPL; Developer tier $0 | Cloud Custodian OSS | Kubescape OSS | Engine LGPL; **rules restricted** for competing SaaS | individual-contributor features OSS |
| Basic SSO (Google/GitHub) | Cloud | Free | not found | not found | Free | buyer-based |
| SAML SSO | Cloud | Enterprise ($249/mo) | not found | not found | Teams ($30/contributor/mo) | paid |
| RBAC | not stated | Team+ | not found | not found | Enterprise | paid |
| Org-wide onboarding / multi-org | Cloud | Enterprise | platform | platform | n/a | paid |
| Jira/Slack integrations | Cloud | n/a | not found | platform | paid tiers | n/a |
| AI triage / fixer / MCP | Cloud (Lighthouse, Autonomous Fixer, MCP) | n/a | Jun0 (platform) | platform | AI credits | n/a |
| Attack-path graph | **full graph Cloud; basic AWS in OSS** | n/a | n/a | platform | n/a | n/a |
| Unit | per cloud account ($99/mo) | per user + compute + storage | not found | per vCPU/resources (quote) | per contributor | per seat |

[sourced: https://prowler.com/pricing] [sourced: https://turbot.com/pipes/pricing] [sourced: https://stacklet.io/] [sourced: https://www.armosec.io/pricing/] [sourced: https://semgrep.dev/pricing] [sourced: https://handbook.gitlab.com/handbook/company/stewardship/]

Other reference points:
- **Turbot Guardrails:** $0.05 per control per month (SaaS) with packs from $25,000; $0.10 self-hosted with packs from $50,000. [sourced: https://turbot.com/guardrails/pricing]
- **Wazuh Cloud:** from $571/month for up to 100 agents. [sourced: https://wazuh.com/cloud/]
- **CrowdSec:** blocklists from $1,900/month for SMB; IP reputation API $49/month. [sourced: https://www.crowdsec.net/pricing]
- **Infracost:** CI tier free for 1,000 runs/month, Starter $250/month, SSO on enterprise. [sourced: https://www.infracost.io/pricing/]
- **Grafana:** Pro from $19/month plus usage; Enterprise from a $25k/yr commit. [sourced: https://grafana.com/pricing/]
- **Prowler services:** training $5,000/day, custom check $10,000, TAM $50,000/yr. [sourced: https://prowler.com/pricing]

### 6.2 Principles drawn from the evidence

1. **GitLab's buyer-based rule.** "If the likely buyer is an individual contributor, the feature is open source." GitLab also promises that features already open sourced won't be moved to paid. [sourced: https://handbook.gitlab.com/handbook/company/stewardship/] Apply the same rule: anything an individual engineer needs to find and fix a path stays open source forever.
2. **Never take back content.**
   - CloudQuery moved its official AWS/GCP/Azure plugins to paid, and the free versions "won't receive ongoing maintenance". [sourced: https://www.cloudquery.io/blog/cloudquery-official-free-plugins-moving-to-paid]
   - Semgrep restricted its rules, and Opengrep forked the next day with vendor backing. [sourced: https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/] [sourced: https://www.opengrep.dev/]
   - HashiCorp's BSL produced OpenTofu (about 30k stars, CNCF). [sourced: https://opentofu.org/blog/opentofu-announces-fork-of-terraform/] [sourced: https://www.cncf.io/projects/opentofu/]
3. **Don't gate the thing that is the reason to adopt.** Prowler gates its full attack-path graph. That is a rational choice for Prowler and exactly the opening for nimbus (§4b). If nimbus later gates paths, it recreates the gap it was built to fill. [inferred]
4. **Cartography's founder on premium modules:** "I don't want to ever get in the position where I'm declining a pull request in open source because it covers a premium feature." [sourced: https://hn.algolia.com/api/v1/items/43161332]

### 6.3 Proposed line for nimbus [inferred]

**Free forever (Apache-2.0, including for commercial use):**
- all collectors, adapters, checks and fix templates;
- graph, attack paths, scoring, min-cut;
- CLI, GitHub Action, VS Code;
- local dashboard and static reports;
- SQL and MCP over the local graph;
- OCSF/SARIF/ASFF export;
- compliance mappings and evidence bundles;
- BYO-model AI;
- single-user self-hosted server.

**Paid, for the buyer who manages people or audits:**
- **nimbus Team / Enterprise (self-hosted licence key or source-available add-on):**
  - SAML/OIDC SSO, SCIM, RBAC and audit log;
  - multi-tenant / MSP mode;
  - long retention and period reports beyond N days;
  - approval workflows for fix PRs;
  - two-way Jira/ServiceNow sync with SLAs;
  - HA deployment.
- **Managed nimbus (optional, later):** hosted scheduled scanning and history, for teams that don't want to run it. Priced per cloud account so it can be compared with Prowler's $99/account/month: undercut it, or match it with more included. Data residency is a choice (EU/US), and a "bring your own bucket" storage mode keeps the local-first promise.
- **Services:**
  - support SLAs;
  - custom path rules and fix templates (anchor: Prowler charges $10k per custom check);
  - onboarding workshops;
  - benchmark or audit-readiness assessments.

**Write the promise into the repo** (`OPEN_SOURCE_PROMISE.md`), GitLab-stewardship style: no feature moves from open source to paid, core licence stays Apache-2.0, and no CLA that permits relicensing (DCO only). This is the credibility asset that Semgrep, CloudQuery and HashiCorp spent. [inferred]

**Sequencing:** do not build paid features before Phase 2 of §5 is met. The first revenue should be **services and support from design partners**, which also feeds the "100 companies" metric. Forming a company (or joining one) before seeking a foundation follows the pattern of Prowler, Stacklet, SubImage, ARMO and Filigran. [inferred from §2.4]

---

## 7. Recommendation

### 7.1 One-page positioning statement

> **For** cloud security and platform engineers at companies that run real multi-cloud estates but can't justify a $100k+ CNAPP (Vendr medians: Wiz about $154k, Orca about $96k), **and** for anyone who won't hand their full cloud graph to a vendor now owned by a hyperscaler,
>
> **nimbus is** the open, local-first security graph. It **takes the findings you already have** (Prowler, Checkov, Trivy, Steampipe and its own collectors), **turns them into the handful of attack paths that actually reach your crown jewels**, and **opens the pull request that closes them**. You can verify every step, because it is all published and runs on your own machine or CI.
>
> **Unlike** Prowler OSS, nimbus gives the full attack-path graph, cross-scanner correlation and fix PRs for free. Prowler gives you the list and charges for the graph and the fixer. **Unlike** Wiz, Orca and Cortex, nimbus publishes its scoring math, its docs and its price ($0), keeps your data local, and stays neutral across AWS, Azure, GCP, Kubernetes and SaaS identity.
>
> **Proof:** a public, reproducible benchmark on an open vulnerable-by-design lab. It shows raw findings in, paths out, PRs merged and paths closed, with Prowler, Checkov and Trivy run on the same lab.
>
> **Tagline candidates:** "Fix the path, not the finding." / "Bring your scanners. Get the paths. Merge the fix."

What nimbus is **not**:
- not "the best open-source CSPM by check count" (Prowler owns that);
- not a GRC platform (Vanta/Drata own that);
- not runtime or EDR (a stated non-goal);
- not a SaaS.

### 7.2 The three wedges to commit to

1. **Paths from everything: wedges (a)+(b)+(i).**
   - Ingest Prowler, Checkov, Trivy and Steampipe output plus nimbus collectors into one graph.
   - Compute attack paths and toxic combinations with a **published, deterministic score** and a **min-cut "cheapest fix set"**.
   - Treat Prowler and Checkov as content suppliers, not enemies.
   - Don't rebuild their check catalogues. Upstream fixes and credit them loudly.
2. **Fix the path, in the PR: wedges (c)+(h).**
   - A GitHub Action and CLI that comments "this PR opens or closes N paths" at plan time.
   - Deterministic template fixes as commit suggestions; LLM fixes only behind validate + re-scan + no-widening checks.
   - This is the distribution engine. CI placement is what turned Checkov and c7n into 1–4M-downloads-a-month tools.
3. **Local-first and verifiable: wedge (g)** as the trust frame.
   - Single binary, offline report, SQLite, BYO-model AI with cited evidence, read-only roles.
   - Signed, SBOM'd, SLSA-provenanced releases and pinned actions.
   - After the 2026 Trivy compromise, being the security tool you can *trust in CI* is a feature.

**Demote to supporting features:**
- compliance evidence bundles (d): reframe as "evidence the path was closed";
- SQL/NL (e): ship as an **MCP server over the local graph**;
- cost (f): one "security-driven savings" card.

**Deprioritise:** the bespoke cwm desktop UI as a primary surface. Keep it as a power-user mode, and make the default first-run experience a CLI path printout plus a single static HTML report. [inferred: mainstream users judge in the first 30 seconds, and the 30-second demos above are CLI/PR-native]

### 7.3 Five "unfair advantages" to build

1. **The open benchmark ("nimbus-lab").**
   - Use public vulnerable-by-design environments (CloudGoat 3,752 stars, active; Stratus Red Team 2,421; TerraGoat; CNAPPgoat) [sourced: gh api on 2026-10-09] plus a nimbus-authored Terraform lab with *labelled ground-truth attack paths*.
   - Publish precision and recall for path detection and fix success for nimbus vs Prowler, Checkov and Trivy, re-run in CI on every release.
   - Nobody in OSS publishes path-level ground truth; Wiz and Orca can't publish because their formulas are closed. [inferred]
2. **Published scoring + min-cut fix planner.**
   - A documented `path_score` (§competitors.md 1(c)) with `--explain` multiplier chips.
   - A weighted min-cut that returns "break 5/5 paths with 2 changes." No vendor publishes this, and SCC and Defender only list chokepoints. [sourced: docs/research/competitors.md §1]
3. **A cross-scanner normaliser as a public spec.**
   - Publish nimbus's Finding contract and `catalog.yaml` aliases as a small open spec layered on **OCSF**.
   - Ship adapters as the reference implementation, so other tools target it. Being the neutral "OpenTelemetry for cloud findings" is a position incumbents structurally won't take. [inferred]
4. **Plan-time path diff.** No tool today combines the IaC plan (Checkov/Trivy territory) with the live graph (CSPM territory) in a PR comment. This is the single most demo-able, shareable feature. [inferred from §4(h)]
5. **Supply-chain-grade trust posture.**
   - Signed releases (cosign), SLSA provenance, SBOMs, an OpenSSF Scorecard badge, SECURITY.md and security.txt.
   - Read-only IAM policy generated by `init`, zero network egress by default, and a reproducible build.
   - Turns the Trivy 2026 incident into nimbus's differentiator. [inferred; Trivy incident sourced in §3]

### 7.4 Metrics to track

**North star:** weekly *attack paths closed via merged nimbus PRs*, measured from opt-in telemetry or public GitHub search for the nimbus PR signature. [inferred]

| Layer | Metric | Why | Target to sanity-check against |
|---|---|---|---|
| Placement | GitHub Action runs per week; repos using the action (public code search); PyPI, brew and Docker pulls/month | Placement predicts adoption (Checkov 3.97M/mo vs Prowler 104k/mo) | Prowler PyPI ~104k/mo; brew 7,250/yr [sourced in §2.1] |
| Activation | % of first runs that print at least 1 path within 10 min; time-to-first-path | The 30-second demo must hold in the wild | — |
| Value | Paths closed per active install; PRs opened → merged ratio; regressions (paths reopened) | Fix-first only works if PRs merge | — |
| Trust | Benchmark precision/recall per release; false-positive reports per 100 paths; Scorecard score | One bad public path kills credibility | — |
| Community | Stars (lagging), external contributors per month, adapter/fix-template PRs, Slack/Discord WAU | Contributors, not stars, keep projects alive (§2.3) | Cartography: 876 contributors / 233 orgs [sourced] |
| Companies | Named adopters in ADOPTERS.md; inbound "support/hosted" requests | Measures the "100 companies" goal | Cartography YC page: "70+ companies" [sourced] |
| Content leverage | % of findings coming from ingested third-party tools vs native | Shows the "bring your scanners" thesis is working | — |

**Star target realism [inferred]:**
- 10k stars puts nimbus between Kubescape (11.8k, 5 years old, CNCF incubating, VC-backed) and Checkov (9.1k, Palo Alto).
- Prowler took about 10 years to reach 15k.
- Plan for 1k stars in the first 6 months after a credible launch, and treat 10k as a 3–4-year goal that needs a company or foundation behind it. "100 companies" is the better near-term goal.

### 7.5 Top 10 risks

| # | Risk | Likelihood / impact | Mitigation |
|---|---|---|---|
| 1 | **Unverified against live clouds.** STATE.md says nothing has run against a real account; a launch with broken collectors or false paths is unrecoverable | High / Critical | Gate launch on the open lab plus 3 design-partner accounts; publish the benchmark before marketing |
| 2 | **Prowler absorbs the wedges.** It already has AWS attack paths in OSS, a paid full graph, an autonomous fixer, MCP and a Claude Code plugin, with ~2,400 commits a year | High / High | Don't compete on checks; ingest Prowler; differentiate on cross-scanner graph, published math, plan-time diff, local-first. Prowler can't easily match these without undercutting its paid tier |
| 3 | **Single-maintainer bus factor.** The #1 stall pattern in §2.3 (ScoutSuite, CloudMapper, Magpie) | High / High | Recruit 2–3 committers; governance doc; CNCF sandbox application in year 1–2; define a business early (§6) |
| 4 | **Scope sprawl.** Go + Python, 7 collectors, 11 sinks, 7 frameworks, AI, cost, monitor, VS Code and a custom desktop UI is wider than Prowler's team ships | High / High | Cut the surface to the 3 wedges; mark the rest "experimental"; one install path |
| 5 | **Supply-chain compromise of nimbus itself** (cf. Trivy 2026-03-19) | Medium / Critical | Signing, SLSA, pinned deps and actions, minimal privileges, no telemetry by default, a 2FA-hardened release process |
| 6 | **IAM and attack-path correctness.** Effective-permission evaluation (SCP/RCP/boundaries/conditions) is hard | High / High | Reuse or borrow from proven OSS (PMapper, AWSHound, pathfinding.cloud, Cartography schema); publish ground truth; confidence labels on paths |
| 7 | **Bad auto-fix PRs** break production or widen access | Medium / High | Deterministic templates first; no auto-merge; mandatory re-scan and no-widening checks; rollback note in every PR |
| 8 | **"CSPM is a feature" squeeze.** Free/cheap native CSPM (MS Foundational free, AWS $3.75/unit, SCC Standard free) erodes the "free" pitch | Medium / Medium | Position on paths + fixes + neutrality, not on "free CSPM" |
| 9 | **Monetisation drift / licence regret.** CloudQuery, Semgrep and Fix show the backlash and fork risk | Medium / High | Commit publicly to Apache-2.0 for core, checks, adapters and fix templates; monetise hosting, team and support only (§6) |
| 10 | **Two-language install friction and a niche UI aesthetic** slow first-run success | Medium / Medium | Single static Go binary for the core path; Python optional; default to CLI + static HTML report; keep cwm UI as an opt-in mode |

---

_Method note: section-level research was split across three Opus research agents (market structure, OSS precedents, distribution/monetisation) plus direct fetches. All agent claims were carried over with their source URLs; where an agent flagged a source as weak (e.g. tech-insider.org on Wiz ARR), that claim was omitted or caveated._
