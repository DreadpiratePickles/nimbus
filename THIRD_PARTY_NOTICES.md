# Third-party notices

nimbus (binary `cloud-posture`) is licensed under Apache-2.0 ([LICENSE](LICENSE)). This file lists
third-party content that is **vendored or embedded** in this repository or in the binary, with its
licence and provenance. It also lists content we deliberately do **not** copy. Rule for contributors:
any file imported from elsewhere must declare its licence and attribution, and must be added here in
the same pull request (plan v3 §5, "licence hygiene").

## 1. Embedded in the binary

### Cytoscape.js 3.30.2 (MIT)

- **Where:** [`internal/dashboard/cytoscape.min.js`](internal/dashboard/cytoscape.min.js), embedded
  into the Go binary and inlined into the generated HTML dashboard (no CDN; the dashboard makes no
  external requests).
- **Upstream:** <https://js.cytoscape.org/>, <https://github.com/cytoscape/cytoscape.js>
- **Licence:** MIT. The full notice is kept at the top of the file and reproduced here:

```text
Copyright (c) 2016-2024, The Cytoscape Consortium.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### CISA Known Exploited Vulnerabilities (KEV) catalog: offline snapshot

- **Where:** [`internal/intel/snapshot/kev.json`](internal/intel/snapshot/kev.json), embedded with `go:embed`
  (`internal/intel/intel.go`, `SnapshotDate = "2026-10-09"`).
- **Provenance:** a subset of the CISA KEV catalog, `catalogVersion` 2026.10.08 (released
  2026-10-08). It holds the most recent 196 entries plus calibration CVEs, 200 records in all (the
  file's `_snapshot_note` says so). Fetched from
  <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>. Fields are kept
  as published; the subset is a selection, not an edit.
- **Licence:** a U.S. Government work published by CISA. The KEV data is also published by CISA under
  CC0 1.0 in the `cisagov/kev-data` repository. **Check this again whenever the snapshot is
  refreshed** (the maintainer could not re-confirm it with the network off on 2026-10-09).
- **Live data:** at run time nimbus fetches the current catalog over HTTPS unless `--no-network` /
  `CLOUD_POSTURE_NO_NETWORK=1` is set. The snapshot is the fallback.

### FIRST EPSS scores: offline snapshot

- **Where:** [`internal/intel/snapshot/epss.csv`](internal/intel/snapshot/epss.csv), embedded with `go:embed`.
- **Provenance:** EPSS `model_version` v2026.06.15, `score_date` 2026-10-09T12:00:22Z (first line of
  the file). The file holds only the rows for the snapshot's KEV CVEs and the CVEs used in test data.
  Source: <https://epss.cyentia.com/epss_scores-current.csv.gz>. Model and data are by FIRST.org,
  <https://www.first.org/epss/>.
- **Licence / terms:** FIRST publishes EPSS scores for free use and asks for attribution. Attribution:
  *"EPSS scores: Forum of Incident Response and Security Teams (FIRST), https://www.first.org/epss/"*.
  Re-check FIRST's usage terms when the snapshot is refreshed.

### Compliance framework identifiers and control titles

- **Where:** [`internal/compliance/frameworks.yaml`](internal/compliance/frameworks.yaml),
  [`internal/compliance/extra.yaml`](internal/compliance/extra.yaml) and the bundled copy
  [`python/nimbus/frameworks/frameworks.yaml`](python/nimbus/frameworks/frameworks.yaml). They hold
  control **identifiers** and **short control titles** for CIS Benchmarks (AWS Foundations 3.0, Azure,
  GCP, Kubernetes, GitHub), NIST SP 800-53, PCI DSS, HIPAA, GDPR, ISO/IEC 27001 and SOC 2, plus
  nimbus's own mappings from checks to controls. The mappings are original work (Apache-2.0).
- **Licence status, which is an open question:**
  - CIS Benchmark text is © Center for Internet Security. CIS distributes the Benchmarks for
    non-commercial use (CC BY-NC-SA 4.0 under its terms of use; to be confirmed under O6). The
    recommendation titles copied here are CIS content.
  - PCI DSS (© PCI Security Standards Council), ISO/IEC 27001 (© ISO/IEC) and the SOC 2 Trust
    Services Criteria (© AICPA) are copyrighted standards.
  - NIST SP 800-53 is a U.S. Government work. HIPAA and GDPR are law.
  - **Plan:** redistribute identifiers and mappings, and link to the official text instead of copying
    titles. The owner decides this as action O6 (plan v3 §0.3). Until O6 is signed off, no further
    framework text is added.

## 2. Before importing Prowler's compliance framework JSON (Phase 1, P1-INTEROP)

Prowler's code and its framework JSON files are Apache-2.0. But several of those files reproduce
**CIS Benchmark text**, which keeps its own licence (see above). Before any import:

1. Record per file: source URL, upstream commit, licence and attribution (`licence` + `attribution`
   fields; the importer refuses a file without them).
2. For CIS-derived files, import identifiers and mappings only, and link to the CIS text, unless O6
   says otherwise.
3. Credit Prowler in this file and in the imported files' attribution fields.

### Imported: Prowler 5.44.0 compliance frameworks (2026-10-09)

- **Upstream:** Prowler release tag `5.44.0`, commit `499fd637f3393b485833b08cdaf4172917c5698e`,
  directory `prowler/compliance/` (<https://github.com/prowler-cloud/prowler/tree/499fd637f3393b485833b08cdaf4172917c5698e/prowler/compliance>).
  **Licence:** Apache-2.0 (upstream `LICENSE`: "Copyright @ 2024 Toni de la Fuente"; the repository has no
  `NOTICE` file at that commit).
- **Where:** [`internal/compliance/frameworks/`](internal/compliance/frameworks/), one `<key>.yaml` per
  upstream file (key = upstream file name without `.json`), 112 files with 17,294 requirements, plus
  `index.yaml` (key, upstream path, requirement count, SHA-256 of each upstream JSON). They are embedded
  in the binary and copied into the generated Python bundle
  [`python/nimbus/frameworks/frameworks.yaml`](python/nimbus/frameworks/frameworks.yaml).
- **Provenance per file:** every file declares `source` (`prowler@5.44.0 (<sha>)`), `upstream_path`,
  `upstream_url` (blob URL at the pinned commit), `license: Apache-2.0`, `attribution` (crediting Prowler)
  and `text_policy`. CIS-derived files also carry a `reference_url` to the CIS text. The loader refuses a
  file without licence, attribution or source; `TestFrameworkIntegrity` enforces it.
- **What was imported:** the framework name and version, requirement **identifiers** (verbatim), and
  the requirement-to-check **mappings**, translated to nimbus canonical ids (the catalog id when nimbus
  knows the Prowler check, otherwise `PROWLER:<check_id>`; the raw Prowler check ids are kept under
  `prowler_checks`). Requirement titles are nimbus's own catalog titles (empty when no mapped check is in
  the nimbus catalog).
- **What was not imported:** no upstream descriptive text: no requirement names or descriptions, no
  section names, no rationale or audit text, for CIS and non-CIS files alike (`text_policy` is
  `nimbus-titles`, or `ids-only` where no title applies). Until O6 is signed off, this is the default.
  The importer can copy text only on request: `--cis-text` (CIS Benchmarks and CIS Controls files) and
  `--upstream-text` (non-CIS files: requirement name, or description cut to 160 characters, plus
  section). Neither flag was used for the committed files.
- **Regenerate:** `go run ./tools/import-prowler-frameworks` (downloads at the pinned sha and refuses
  if the tag has moved, unless `--sha` is passed) or `--from-dir <prowler checkout>` offline; then
  `go generate ./internal/compliance/` to refresh the Python bundle.

## 3. Used but not copied

These are run as separate programs, or used only as references. None of their code or content is in
this repository or the binary, and the container image bundles none of them.

| Project | Licence | How nimbus uses it |
|---|---|---|
| Prowler | Apache-2.0 | Optional external scanner; nimbus ingests its output |
| ScoutSuite | GPL-2.0 | Optional external scanner; output ingested only, never linked or copied |
| Checkov | Apache-2.0 | Optional external scanner; output ingested |
| Trivy | Apache-2.0 | Optional external scanner; output ingested |
| Steampipe | AGPL-3.0 | Optional external process for `query --engine steampipe`; never linked or copied |
| PMapper | AGPL-3.0 | Behavioural reference for IAM evaluation only; no code or test content copied (plan v3 §9 item 9) |
| pathfinding.cloud (DataDog) | Apache-2.0 | Upstream credited by Prowler for the privesc techniques; verified from the repo (`DataDog/pathfinding.cloud`, `Apache-2.0`, `NOTICE`: "Datadog pathfinding.cloud, Copyright 2025-Present Datadog, Inc."). nimbus does **not** copy pathfinding.cloud text or files: the ported rules cite its technique id and URL only (as Prowler does). The technique facts (which AWS action sets escalate privilege) themselves came into nimbus through Prowler — see section 6. |

## 4. Dependencies

Go modules (`go.mod` / `go.sum`) and Python packages (`python/pyproject.toml`) are dependencies, not
vendored content. Each is under its own licence. The release workflow publishes an SPDX SBOM for every
archive, listing them ([SECURITY.md](SECURITY.md#how-releases-are-built-and-signed)). No `vendor/`
directory is committed.

## 5. Lab and test fixtures

`lab/` and `testdata/` hold synthetic estates and fixtures written for this repository. The account
ids are synthetic patterns (`111111111111`, `123456789012`, `999999999999`, `3100000000xx` and
similar), and the trusted CIDR is a documentation range (`203.0.113.0/24`). A fixture copied from an upstream project must say so in a header and be
listed here.

## 6. Ported: Prowler AWS attack-path privesc queries (2026-10-10, delta r3 #9)

- **Upstream:** Prowler, file
  `api/src/backend/api/attack_paths/queries/aws.py` at commit
  [`dd61c417b712856d87b84f5440b2480071991b52`](https://github.com/prowler-cloud/prowler/blob/dd61c417b712856d87b84f5440b2480071991b52/api/src/backend/api/attack_paths/queries/aws.py)
  (dated 2026-08-05). **Licence:** Apache-2.0, verified from the repo `LICENSE`
  (<https://raw.githubusercontent.com/prowler-cloud/prowler/master/LICENSE>); the repository has no
  `NOTICE` file. Prowler's own file attributes each privesc query to **pathfinding.cloud** (DataDog,
  Apache-2.0 — see section 3) with a technique id (e.g. `EC2-001`) and URL.
- **Where:** [`internal/attackpath/rules/aws/privesc/`](internal/attackpath/rules/aws/privesc/),
  one `<prowler-id>.yaml` per rule (21 rules), embedded in the binary. Each file carries a `credit`
  block: `source: Prowler`, `licence: Apache-2.0`, the Prowler blob `url` at the pinned commit, the
  Prowler query `upstream_id`, and the `upstream` / `upstream_url` crediting pathfinding.cloud as
  Prowler states it. The loader (`LibraryPathRules` / `ValidatePathRules`) refuses a ported rule
  without that credit.
- **What was ported:** the **technique facts** only — the Prowler/pathfinding.cloud **query id** (kept
  verbatim as the rule id and identifier) and the AWS **action set** that constitutes each escalation
  (e.g. `iam:PassRole` + `ec2:RunInstances`; `iam:CreatePolicyVersion`). Action names are facts about
  the AWS authorization model, not copyrightable expression.
- **What was NOT copied:** none of Prowler's openCypher query text, none of its Python, and no
  pathfinding.cloud text or files. Every rule's title, description and the YAML schema itself are
  nimbus's own; the queries were re-expressed as nimbus path rules evaluated by the internal IAM
  evaluator (`internal/graph`), not run as Cypher. The `modified` field in each credit block records
  this.
- **Covered techniques:** EC2-001 (PassRole+RunInstances), LAMBDA-001/002, CLOUDFORMATION-001,
  GLUE-001, SAGEMAKER-001, IAM-001/002/004/005/006/007/008/009/010/011/012/013, SSM-001/002,
  EC2INSTANCECONNECT-003.
