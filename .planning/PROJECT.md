# PROJECT — nimbus / cloud-posture

**One line:** the open-source CSPM that unifies every scanner into one security graph, shows attack paths, prioritizes by context, fixes with IaC and PRs, answers SQL and plain English, and proves compliance.

**Users:** cloud security engineers drowning in 45 tools; platform teams who want fixes not reports; CISOs who need audit evidence and a cost story.

**Success:** 10k stars / 100 companies; replaces Wiz-class spend; CLI-first, VS Code + CI native.

**Non-goals (v0.x):** agents on hosts; runtime/EDR; proprietary SaaS backend.

**Constraints:** agentless; secrets only from env; works offline (static dashboard, rule-based copilot); Go core + Python intelligence; Apache-2.0.

**Reference designs:** Prowler (checks/metadata), Cartography + BloodHound (graph), Steampipe (SQL), ScoutSuite (reports), Checkov (IaC), Google SCC + Defender (attack-path scoring/UX), Orca (risk bands), Semgrep/Snyk (fix PRs). Competitor bars: docs/research/competitors.md.
