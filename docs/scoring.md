# nimbus risk score

**Current `score_version`: 2.4.0.** This page is the published contract for the number nimbus shows next to every
finding. There is one implementation, `internal/risk` (Go). The CLI, the dashboard and the API all show its output.
The Python package (`python/nimbus/risk.py`) only reads it.

`internal/risk/doc_test.go` fails when the weights table below differs from `risk.DefaultWeights`. It also fails when
the changelog has no entry for the current `ScoreVersion`. `TestCalibration` fails when any calibration example
changes score, band or order.

## Formula

```
raw   = base_severity × Π multiplier_i
score = raw                                          when raw ≤ 7.0 (the knee: the High threshold)
score = 7.0 + 3.0 × (1 − e^(−(raw − 7.0) / 4.5))     when raw > 7.0 (diminishing returns, bounded by 10)
score rounded to one decimal; an off-path finding is min(raw, 6.9) instead (see "Off-path cap")
```

**Bounded combination (2.2.0).** Up to 2.1.0 the product was clamped at 10, and on the labelled lab 41 of 62
findings tied at exactly 10.0 (raw products up to 38.22), so the top of `prioritize` was ordered by a hidden
tie-breaker. Since 2.2.0 everything above the knee is compressed: the function is continuous, strictly increasing
and never reaches 10, so findings keep the order of their raw products and a score of 10.0 (after rounding) needs
raw ≥ 7.0 + 4.5 × ln(3.0 / 0.05) ≈ 25.4. Critical (≥ 9.0) needs raw ≥ 7.0 + 4.5 × ln 3 ≈ 11.9. Below the knee the
score is the raw product, exactly as before. Every explanation carries `explanation.combination`, the rule with
this finding's numbers, e.g. `raw 23.92 > knee 7.0: score = 7.0 + 3.0 × (1 − e^(−(23.92 − 7.0) / 4.5)) = 9.93`.

- `base_severity` comes from the finding's severity.
- Each multiplier is one **factor**: exposure, identity, data sensitivity, criticality, exploitability, compliance
  scope, recent change, ownership, attack path, compensating controls and off path. Every factor appears exactly
  once in every explanation, in that order.
- **Not scored.** When a factor's input is unknown (no exposure data, no CVE or EPSS data, no classification, no
  criticality), its multiplier is ×1.0 and its status is `not scored`. It is also listed in `explanation.missing`,
  so you can see the score is incomplete. Missing data never silently counts as ×1.0, and it never counts as "safe".
- Synthetic factors make the product exact:
  - `combination` (= combined / raw) when the raw product exceeds the knee (7.0); its reason reads
    "diminishing returns above 7.0: raw R → S". It replaces the 2.x flat `cap` factor;
  - `off_path_cap` (= 6.9 / raw) instead when the finding is off path (see "Off-path cap") and the
    raw product exceeds 6.9;
  - `rounding` (= rounded / unrounded) for the one-decimal rounding.

  So `base × Π factors[].multiplier == score`; the test tolerance is 0.01.
- **Ordering.** Findings sort by score, then by the raw product (`explanation.raw`), then by finding ID. The
  combination is strictly increasing, so the score order is the raw order up to one-decimal rounding; two findings
  that round to the same score still rank by their raw products.

### Bands (Orca-style)

| Band | Score | SLA (days to fix) |
|---|---|---|
| Critical | ≥ 9.0 | 7 |
| High | 7.0 – 8.9 | 30 |
| Medium | 5.0 – 6.9 | 90 |
| Low | < 5.0 | 180 |

`due_at = first_seen + SLA`. The band always comes from the same score it is displayed with. Score 2.0.0 fixes the
old mismatch, where Python's score was shown with Go's band.

## Weights

These are the published multipliers. Each factor uses the first row that matches, in the order listed. For example,
an admin identity wins over a weak identity, and a KEV listing wins over EPSS.

<!-- weights:begin -->
| Key | Factor | Value | Evidence required |
|---|---|---|---|
| `severity.critical` | base | 7.0 | finding severity CRITICAL |
| `severity.high` | base | 5.5 | finding severity HIGH |
| `severity.medium` | base | 4.0 | finding severity MEDIUM |
| `severity.low` | base | 2.5 | finding severity LOW |
| `severity.info` | base | 1.0 | finding severity INFO |
| `exposure.wide` | exposure | ×1.4 | node/edge attr `exposure=wide`, or an internet edge / `PUBLIC_*` weakness with no width data (assumed wide; the evidence says so) |
| `exposure.narrow` | exposure | ×1.15 | attr `exposure=narrow` (specific, non-trusted source CIDRs) |
| `exposure.trusted` | exposure | ×0.8 | attr `exposure=trusted` (reachable only from config `trusted_cidrs`) |
| `exposure.none` | exposure | ×0.5 | attr `exposure=none` / `internal` / `private` |
| `identity.admin` | identity | ×1.25 | `OVERPRIVILEGED_IDENTITY` / `CLUSTER_ADMIN` / attr `admin=true` on the resource, or the resource runs as or assumes such an identity within 2 hops (`runs_as`, `attached_to`, `can_assume`, `bound_to`) |
| `identity.weak` | identity | ×1.2 | `NO_MFA` / `CROSS_ACCOUNT_TRUST` / `STALE_CREDENTIALS` |
| `identity.credential_vector` | identity | ×1.1 | `IMDSV1_ENABLED` / `SERVICE_ACCOUNT_TOKEN` with no admin identity behind it |
| `data.sensitive` | data_sensitivity | ×1.5 | DSPM/classification label (`dspm_labels`, `data_labels`, `classification`, `data_sensitivity`, or a `*classif*`/`*sensitiv*` tag) of pii, phi, pci, confidential, restricted, secret or sensitive; or graph node `sensitive=true` |
| `data.secrets` | data_sensitivity | ×1.3 | `SECRET_EXPOSURE` weakness |
| `data.non_sensitive` | data_sensitivity | ×0.9 | label public, internal or non-sensitive |
| `criticality.very_high` | criticality | ×2.0 | crown-jewel level very_high: config `crown_jewels` via `config.MatchCrownJewel`, else node attr `crown_jewel`, else node `criticality` |
| `criticality.high` | criticality | ×1.6 | crown-jewel level high |
| `criticality.medium` | criticality | ×1.2 | crown-jewel level medium |
| `criticality.low` | criticality | ×1.0 | crown-jewel level low |
| `criticality.production` | criticality | ×1.3 | node `criticality=production` (no crown-jewel level) |
| `criticality.staging` | criticality | ×1.0 | node `criticality=staging` |
| `criticality.dev` | criticality | ×0.8 | node `criticality=dev`/`test`/`sandbox` |
| `exploitability.kev` | exploitability | ×1.5 | a CVE on the finding is in CISA KEV |
| `exploitability.epss_top5` | exploitability | ×1.3 | highest EPSS percentile ≥ 0.95 |
| `exploitability.epss_top20` | exploitability | ×1.15 | highest EPSS percentile ≥ 0.80 |
| `exploitability.epss_mid` | exploitability | ×1.0 | highest EPSS percentile ≥ 0.50 |
| `exploitability.epss_low` | exploitability | ×0.85 | highest EPSS percentile < 0.50 |
| `compliance.regulated` | compliance_scope | ×1.0 | mapped to pci_dss or hipaa |
| `compliance.privacy` | compliance_scope | ×1.0 | mapped to soc2 or gdpr |
| `recent_change.modified_24h` | recent_change | ×1.1 | node `modified_at` within 24h |
| `recent_change.new_finding_24h` | recent_change | ×1.0 | finding `first_seen` within 24h |
| `ownership.orphaned` | ownership | ×1.0 | no owner on the node and no `owner`/`team` tag |
| `attack_path.per_point` | attack_path | 0.12 | multiplier = 1 + 0.12 × (max score of the attack paths the finding is on) |
| `attack_path.max` | attack_path | ×2.0 | upper bound of the attack-path multiplier |
| `compensating.scp_denied` | compensating_controls | ×0.5 | node attr `scp_denied=true` (hook for Track B: an SCP/RCP denies the path's key action) |
| `compensating.control` | compensating_controls | ×0.8 | node attr `compensating_controls` non-empty (WAF, private endpoint, NetworkPolicy; O49) |
| `off_path.multiplier` | off_path | ×0.5 | path analysis ran, the finding's resource is a step of no complete attack path, and it is not a crown jewel, sensitive data store or admin-level identity |
| `off_path.max_score` | off_path | 6.9 | score ceiling for such a finding (`off_path_cap`): its band is at most Medium |
| `combination.knee` | combination | 7.0 | raw product above which diminishing returns apply (the High threshold); below it score = raw |
| `combination.scale` | combination | 4.5 | above the knee, score = knee + (10 − knee) × (1 − e^(−(raw − knee) / scale)) |
<!-- weights:end -->

When nothing in a factor's rows matches, the factor scores ×1.0 *with a stated reason*, or it is `not scored`:

| Factor | ×1.0 scored (stated) | not scored → `missing` |
|---|---|---|
| exposure | — | no `exposure` attr, no internet edge, no `PUBLIC_*` weakness |
| identity | "no identity weakness or privileged identity found" | — |
| data_sensitivity | resource is not a data store | data store (class `datastore` or `DATABASE` weakness) with no label |
| criticality | — | no crown-jewel match and no environment criticality (`unknown`/empty) |
| exploitability | — | no CVE on the finding; or CVEs that are not in KEV and have no EPSS row |
| compliance_scope | no framework, or only non-regulated ones (cis, nist, iso) | — |
| recent_change | no change in 24h | no `modified_at` and no `first_seen` |
| ownership | owner known | — |
| attack_path | not on any attack path | — |
| compensating_controls | none recorded | — |
| off_path | on a complete path; or off path but an impact target (crown jewel / sensitive data store / admin-level identity) | no path analysis (findings-only input: `Options.NoAnalysis`, or no graph) — no cap |

## Off-path cap (2.1.0)

The finding score agrees with the path verdict (`docs/scoring.md` "Path score"). When path analysis ran and a
finding's resource is **on no complete attack path** and is **not an impact target**, the finding gets the
`off_path` factor ×0.5 with the reason "no attack path reaches an impact target from this resource", and its
score is capped at **6.9** (top of Medium) by an `off_path_cap` factor. Exposure-only resources
(`Analysis.Exposures`: a public website bucket, a host open on 443) are the main case; the factor's evidence
quotes the exposure record when `Options.Analysis` is given.

- **On a path** means: the finding is in a complete path's `finding_ids`, or its resource is a step
  (`resource` / `weakness_on`) of one of the complete paths, or `Analysis.ReachesCrownJewel[resource]` is true.
  A finding on a path never gets the factor, whatever its own weakness.
- **Impact targets are exempt** (off path, ×1.0, stated): a crown jewel (any level, from config `crown_jewels`,
  node attr `crown_jewel` or node criticality), a sensitive data store (the `data.sensitive` row matched), an
  admin-level identity (the resource itself carries `OVERPRIVILEGED_IDENTITY` / `CLUSTER_ADMIN` or attr
  `admin=true`; running as one does not count). Their weights decide their band: an admin role no path reaches
  scores HIGH 5.5 × 1.25 = 6.9, Medium.
- **Where the verdict comes from:** `risk.Options.Analysis` (`*attackpath.Analysis`: `Paths`,
  `ReachesCrownJewel`, `Exposures`) when the caller passes it. Otherwise a non-nil graph means the caller ran the
  analysis and passed its complete paths as the `paths` argument — what `scan`, `ingest`, `prioritize`,
  `serve` and MCP do. `Options.NoAnalysis` or a nil graph is findings-only: `off_path` is `not scored`
  (listed in `missing`) and nothing is capped.
- Issue severity (`internal/store`) is `max(min(risk band, scanner severity), best path band)`, so an off-path
  finding's Issue is at most Medium unless a path through its resource raises it.

## Exploitability data (KEV + EPSS)

`internal/intel` (`Enricher`) loads:

- the CISA KEV catalog, `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`;
- the FIRST EPSS scores, `https://epss.cyentia.com/epss_scores-current.csv.gz`.

It caches both in `.cloud-posture/intel/` with a 24h TTL. Downloads use HTTPS only, keep TLS verification on and
refuse redirects to plain HTTP. Every request has a timeout. Size caps are 32 MB for KEV, 64 MB for the EPSS gzip
and 256 MB once inflated. A download is validated before it replaces the cache.

When neither the network nor the cache is available, nimbus falls back to the embedded snapshot.
`Options.NoNetwork` is the `--no-network` mode: it uses the cache or the snapshot and makes no requests. The fallback
order is:

1. fresh cache
2. network
3. stale cache (with a warning)
4. embedded snapshot

**Embedded snapshot** (`internal/intel/snapshot/`, `intel.SnapshotDate = 2026-10-09`):

- **KEV:** `catalogVersion 2026.10.08`. It holds the 196 most recently added entries, plus four calibration CVEs:
  CVE-2021-44228, CVE-2023-4863, CVE-2022-22965 and CVE-2023-44487.
- **EPSS:** `score_date 2026-10-09T12:00:22Z`, model v2026.06.15. It holds 204 rows: one for each snapshot KEV CVE,
  the testdata CVEs (CVE-2024-6387, CVE-2024-1234), CVE-2024-3094, and CVE-2023-0002 (a low-percentile calibration
  example).

Offline, any CVE outside the snapshot is `not scored` for EPSS. That is honest, not a zero.

To refresh the snapshot, download both feeds and rebuild the two files with the same subset rule. Then run
`go test ./internal/intel ./internal/risk`. If a calibration score moves, bump `ScoreVersion` and add a changelog
entry.

`risk.Prioritize` uses the embedded snapshot. Callers that have a live `intel.Enricher` feed or config crown jewels
use `risk.PrioritizeWith(findings, graph, paths, risk.Options{Intel: feed, CrownJewel: risk.JewelFromConfig(cfg)})`.

## Crown-jewel levels (O62)

| Level | Multiplier |
|---|---|
| very_high | ×2.0 |
| high | ×1.6 |
| medium | ×1.2 |
| low | ×1.0 |

The level comes from the first source that has one:

1. config `crown_jewels` (`config.MatchCrownJewel`, adapted by `risk.JewelFromConfig`);
2. node attr `crown_jewel`;
3. node `criticality` when it names a level.

Otherwise the factor falls back to environment criticality (production ×1.3 / staging ×1.0 / dev ×0.8). If there is
no environment criticality either, the factor is `not scored`.

## Output fields

Every `risk.Ranked`, as returned by `cloud-posture prioritize --json`, `/api/risk/top` and the dashboard JSON, carries
these fields:

```json
{
  "finding": {"id": "…"},
  "risk_score": 7.1,
  "band": "High",
  "score_version": "2.4.0",
  "reasons": ["HIGH severity", "reachable only from trusted CIDRs", "workload runs as an administrative identity", "production workload"],
  "explanation": {
    "score": 7.1, "version": "2.4.0", "base": 5.5, "base_reason": "HIGH severity", "raw": 7.15,
    "combination": "raw 7.15 > knee 7.0: score = 7.0 + 3.0 × (1 − e^(−(7.15 − 7.0) / 4.5)) = 7.10 (diminishing returns, bounded by 10)",
    "factors": [
      {"name": "exposure", "multiplier": 0.8, "status": "scored", "reason": "reachable only from trusted CIDRs", "evidence": ["node attr exposure=trusted"]},
      {"name": "identity", "multiplier": 1.25, "status": "scored", "reason": "workload runs as an administrative identity", "evidence": ["runs as / assumes …-role"]},
      {"name": "data_sensitivity", "multiplier": 1, "status": "scored", "reason": "not a data store"},
      {"name": "criticality", "multiplier": 1.3, "status": "scored", "reason": "production workload"},
      {"name": "exploitability", "multiplier": 1, "status": "not scored", "reason": "not scored: no CVE data on this finding"},
      "… compliance_scope, recent_change, ownership, attack_path, compensating_controls",
      {"name": "off_path", "multiplier": 1, "status": "not scored", "reason": "not scored: no attack-path analysis (findings-only); no off-path cap applied"},
      {"name": "combination", "multiplier": 0.993, "status": "scored", "reason": "diminishing returns above 7.0: raw 7.15 → 7.10 (bounded combination, 2.2.0; replaces the flat cap at 10)"},
      {"name": "rounding", "multiplier": 1.0003, "status": "scored", "reason": "7.0984 rounded to one decimal"}
    ],
    "top_paths": [{"id": "…", "name": "…", "score": 9.0}],
    "missing": ["exploitability (no CVE data on this finding)", "off_path (no attack-path analysis (findings-only); no off-path cap applied)"]
  },
  "attack_paths": 0, "max_path_score": 0, "owner": "web-team", "sla_days": 14, "due_at": "…"
}
```

`risk.Explain(ranked)` returns the same `explanation` as a Go value. `top_paths` holds at most 3 paths, highest
score first.

`owner`, `sla_days` and `due_at` are **deprecated** (kept for one release): they are the governance assignment of the
Issue that carries the finding (`docs/governance.md`), filled by `prioritize`, `scan`/`ingest`, `/api/risk/top` and the
dashboard. The scorer itself no longer derives an SLA from the band; a finding no Issue carries has `sla_days: 0` and a
zero `due_at`. Read owner and due date from the Issue (`issues --json`, `/api/issues`).

**Python** (`nimbus.risk`) reads this JSON and never computes a score. It looks for the data in this order:

1. the `risk=` argument;
2. the `NIMBUS_RISK_JSON` environment variable;
3. `<db>.risk.json` next to the store's database (one per database file).

It passes `risk_score`, `band`, `reasons`, `score_version` and `explanation` through unchanged. Findings that Go has
not scored show `risk_score: null` and `band: "not scored"`.

## Calibration examples

All examples come from `internal/risk/testdata/calibration.yaml`, which has 53 scenarios. `TestCalibration` asserts
each one's exact score, its band and its order chains. Scenarios marked `analysis: none` are scored as
findings-only input (`off_path` not scored); the others as if path analysis ran, so a scenario without a path is
off path. The `noise_*` scenarios come from the noise estate classes (`lab/noise_truth.yaml`) and the `lab_*`
ones from the labelled lab (`lab/ground_truth.yaml`); the `tie_*` ones (2.2.0) all capped at 10.0 under the
flat cap and now keep distinct, raw-ordered scores. "→ c" below is the bounded combination (raw above 7.0).

| Scenario | Product | Score | Band |
|---|---|---|---|
| Public S3 with PII (HIGH, wide, PII, production, gdpr+pci; findings-only) | 5.5 × 1.4 × 1.5 × 1.3 = 15.0 → c | 9.5 | Critical |
| Private S3 with PII (same context, `exposure=none`) | 5.5 × 0.5 × 1.5 × 1.3 = 5.36 | 5.4 | Medium |
| Public S3, no classification | 5.5 × 1.4 = 7.7 → c (data `not scored`, criticality `not scored`) | 7.4 | High |
| IMDSv1 EC2 behind 0.0.0.0/0, admin instance profile, production | 5.5 × 1.4 × 1.25 × 1.3 = 12.5 → c | 9.1 | Critical |
| Same EC2 behind a trusted CIDR | 5.5 × 0.8 × 1.25 × 1.3 = 7.15 → c | 7.1 | High |
| Same open EC2 + attack path 9.0, but SCP-denied (Track B hook) | 5.5 × 1.4 × 1.25 × 2.0 × 0.5 = 9.63 → c | 8.3 | High |
| CRITICAL CVE in KEV (CVE-2021-44228; no exposure or path context) | 7.0 × 1.5 = 10.5 → c | 8.6 | High |
| CRITICAL CVE, EPSS top 5 % (CVE-2024-6387, not in KEV) | 7.0 × 1.3 = 9.1 → c | 8.1 | High |
| CRITICAL CVE, EPSS percentile 0.75 (CVE-2024-1234) | 7.0 × 1.0 | 7.0 | High |
| CRITICAL CVE, EPSS percentile 0.20 (CVE-2023-0002) | 7.0 × 0.85 = 5.95 | 6.0 | Medium |
| CRITICAL misconfiguration, no CVE | 7.0 (exploitability `not scored`) | 7.0 | High |
| MEDIUM on a confidential DB, crown jewel very_high / high / medium | 4.0 × 1.5 × 2.0 / 1.6 / 1.2 = 12.0 / 9.6 / 7.2 → c | 9.0 / 8.3 / 7.1 | Critical / High / High |
| Same DB, not a crown jewel, dev | 4.0 × 1.5 × 0.8 | 4.8 | Low |
| MEDIUM open SSH (narrow) on a 9.0 attack path vs findings-only | 4.0 × 1.15 × 2.0 = 9.2 → c vs 4.0 × 1.15 | 8.2 vs 4.6 | High vs Low |
| IAM user with an admin policy vs no-MFA user (findings-only) | 5.5 × 1.25 vs 5.5 × 1.2 | 6.9 vs 6.6 | Medium vs Medium |
| LOW, internal, non-sensitive, dev | 2.5 × 0.5 × 0.9 × 0.8 | 0.9 | Low |
| **Noise NZ01** public website bucket (CRITICAL, wide, `data_classification=public`, production, off path) | 7.0 × 1.4 × 0.9 × 1.3 × 0.5 = 5.73 | 5.7 | Medium |
| **Noise NZ90** `public-pii-redacted-reports` (graph marks it sensitive by name; classified public) | as NZ01: the explicit classification wins | 5.7 | Medium |
| **Noise NZ07** Lambda URL with `AuthType AWS_IAM` (HIGH, exposure private, production, off path) | 5.5 × 0.5 × 1.3 × 0.5 = 1.79 | 1.8 | Low |
| **Noise NZ07** org-conditioned bucket holding confidential data (CRITICAL, private, production; sensitive → not capped) | 7.0 × 0.5 × 1.5 × 1.3 = 6.83 | 6.8 | Medium |
| **Noise NZ15** sandbox public fixtures (HIGH, wide, classified `none`, sandbox, off path) | 5.5 × 1.4 × 0.9 × 0.8 × 0.5 = 2.77 | 2.8 | Low |
| **Noise NZ05** admin role no path reaches (HIGH, admin-level identity → not capped) | 5.5 × 1.25 = 6.875 | 6.9 | Medium |
| **Noise NZ06** org cross-account trust (HIGH, off path) | 5.5 × 1.2 × 0.5 | 3.3 | Low |
| **Noise** KEV host exposed but reaching no impact target (CRITICAL, wide, production, off path) | 7.0 × 1.4 × 1.3 × 1.5 × 0.5 = 9.56 → `off_path_cap` | 6.9 | Medium |
| **Lab P01** public PII bucket (CRITICAL, wide, PII, production, path 10.0) | 7.0 × 1.4 × 1.5 × 1.3 × 2.0 = 38.2 → c | 10.0 | Critical |
| **Lab P02** IMDSv1 instance, wide, admin profile (HIGH, production, path 7.6) | 5.5 × 1.4 × 1.25 × 1.3 × 1.91 = 23.9 → c | 9.9 | Critical |
| **Lab P19** KEV CVE on an exposed host (CRITICAL, wide, production, path 7.0) | 7.0 × 1.4 × 1.3 × 1.5 × 1.84 = 35.2 → c | 10.0 | Critical |
| **Lab P20** chained external trust into admin (HIGH, dev, path 5.99) | 5.5 × 1.25 × 0.8 × 1.72 = 9.45 → c | 8.3 | High |
| **Lab P12** OIDC deploy role with admin (HIGH, dev, path 3.8) | 5.5 × 1.25 × 0.8 × 1.46 = 8.01 → c | 7.6 | High |
| **Tie** public PII bucket on a 10.0 path / IMDSv1 admin host on a 7.6 path / IMDSv1 admin host, staging, findings-only (all 10.0, 10.0, 9.6 under 2.1.0) | 38.2 / 23.9 / 9.63 → c | 10.0 / 9.9 / 8.3 | Critical / Critical / High |

## How to reproduce a score by hand

1. Take the base for the finding's severity from the weights table: CRITICAL 7.0, HIGH 5.5, MEDIUM 4.0, LOW 2.5,
   INFO 1.0.
2. For each factor, in order (exposure, identity, data_sensitivity, criticality, exploitability, compliance_scope,
   recent_change, ownership, attack_path, compensating_controls):
   1. Find the first weights row whose evidence is present on the finding, its graph node or its paths.
   2. Multiply by that row's value. If no row matches, the factor is ×1.0, either scored with a stated reason or
      `not scored`.
3. For the attack-path factor, use `min(2.0, 1 + 0.12 × max_path_score)`.
4. Off path: if path analysis ran, the resource is a step of no complete path, and it is not a crown jewel,
   sensitive data store or admin-level identity, multiply by 0.5 and remember the 6.9 ceiling. Without path
   analysis this step is `not scored` (×1.0, no ceiling).
5. Off path: the score is min(product, 6.9). Otherwise, if the product is at most 7.0 it is the score; above 7.0
   the score is 7.0 + 3.0 × (1 − e^(−(product − 7.0) / 4.5)). Round to one decimal.
6. Read the band off the bands table.

Worked example 1, the IMDSv1 instance behind a trusted CIDR above (findings-only input):

1. Base for HIGH is 5.5.
2. Exposure is trusted: ×0.8.
3. Identity: the instance runs as a role with `OVERPRIVILEGED_IDENTITY`: ×1.25.
4. The instance is not a data store: ×1.0.
5. Criticality is production: ×1.3.
6. There is no CVE, so exploitability is `not scored` (×1.0).
7. Compliance, change, owner, path and controls are all ×1.0; off path is `not scored`.

The product is 5.5 × 0.8 × 1.25 × 1.3 = 7.15, just above the 7.0 knee: 7.0 + 3.0 × (1 − e^(−0.15 / 4.5)) = 7.098,
which rounds to **7.1, High** (7.2 under 2.1.0). The explanation's `factors` list exactly these multipliers, plus
`combination` = 7.098 / 7.15 and `rounding` = 7.1 / 7.098.

Worked example 2, the exposed KEV host that reaches no impact target: 7.0 (CRITICAL) × 1.4 (wide) × 1.0 (not a
data store) × 1.3 (production) × 1.5 (KEV) × 0.5 (off path) = 9.555, above the 6.9 ceiling, so the score is **6.9,
Medium**; the factors end with `off_path_cap` = 6.9 / 9.555.

## Changelog

### 2.4.0 (2026-10-10)

The exposure factor counts an internet route through a network control (W5-ENGINE; Verification 5 C11). No weight or
formula change. Outputs changed, so the version changed:

- **Exposed through a network control.** Some resources have no internet edge of their own and are reached only
  through an internet-exposed security group, NSG or firewall (`internet → nsg → vm`, the jump-01 shape). They were
  "not scored: no exposure data" (×1.00). They now take the route's width from `graph.Verdict`, or `wide-assumed`
  when no width is known, inferred. Example: the verify-5 jump-shape probe, a HIGH vulnerable production VM, moved
  from 3.6 Low to 5.0 Medium, the same as a VM with its own internet edge.
- **No network data is "unknown", not "".** `graph.Verdict` gives an internet route with no reachability data (edge,
  node, the control's edge or the control node) the status `unknown`. The exposure reason then carries ", inferred:
  reachability unknown — reachability not evaluated (no network verdict on this route)" even on graphs the
  reachability pass never ran on. Scores are unchanged by this. `python/tests/fixtures/go_risk.json` was regenerated
  and differs only in that reason text.
- `graph.Verdict` also consults the resource's own anonymous-access settings (`graph.AnonymousReachOf`) on internet
  routes before exposure annotation. An org-conditioned bucket reads `private (suppressed: org-conditioned …)` and
  its exposure factor is unchanged (annotation already labelled it private in the CLI pipeline).

### Governance due date (integration pass 4, 2026-10-09) — score unchanged

No score change (`score_version` stays 2.2.0). **Deprecated:** the band SLA in `internal/risk` (Critical 7, High 30,
Medium 90, Low 180 days from `first_seen`) is retired so users never see two due dates. `risk.Ranked.owner`,
`sla_days` and `due_at` keep their JSON keys for one release and are populated from the governance assignment of the
finding's Issue (rules → tags → CODEOWNERS → account owner → default; 7/14/30/90 days by default, fresh clock per
reopen). They will be removed from `risk.Ranked` in the next release; read `owner` / `due_at` / `overdue` from Issues.
`python/tests/fixtures/go_risk.json` regenerated (`sla_days: 0`, zero `due_at` from the scorer).

### 2.3.0 (2026-10-09)

Reachability verdict feeds the exposure factor (blocked ⇒ not exposed); ExternalId/SourceIdentity trusts 0.3; no
formula change otherwise (V4-ENGINE). Outputs changed, so the version changed. Details:

One verdict everywhere (competitive delta r2 #1). The `exposure` factor now reads the node's internet-reachability
verdict (`graph.Verdict`, the same verdict `paths --exposures` prints; docs/reachability.md):

- **blocked** → `not exposed (blocked: <reach_blocker>)`, multiplier `exposure.none`, whatever the exposure label or
  the `PUBLIC_*` weakness says (the label is quoted as overridden evidence). F04 (the ledger RDS, no IGW route) moves
  from `prioritize` #7 at 9.8 Critical out of the top 10, and its Issue from CRITICAL to MEDIUM (Issue severity is
  min(risk band, scanner severity), raised only by a complete path).
- **unknown** → the width multiplier stands, labelled `inferred: reachability unknown — <reason>`.
- **reachable** / no verdict → unchanged.

`risk.CriticalOnNonExposed` is the finding-level benchmark row: Critical findings on REACH-blocked (or benchmark-
benign) resources; the lab measures **0** (was 1: lab-W37 on the ledger).

Path entries (Path score below): a trust limited by `aws:PrincipalOrgID` / `aws:PrincipalOrgPaths` /
`aws:PrincipalAccount` (from `trust_conditions`, or the Condition of every cross-account Allow statement in
`trust_policy` / `assume_role_policy`) is **not an external entry**; one requiring `sts:ExternalId` or
`sts:SourceIdentity` is entry likelihood **0.3** (`ProtectedTrustEntry`, was 0.4 for ExternalId) and gets no
identity floor (verify-4 D1/D2). Rule chains that share entry and anchor with a traversal path are folded into it
(`also_matches_rule` on its last step; delta r2 #2): lab path Issues 25 → 19, recall unchanged.

W7-ENGINE (r5 #15) refines the organisation case: `aws:PrincipalOrgID` / `PrincipalOrgPaths` is judged against the
role's own organisation (`organization_id` on the role or its `aws:account:<id>` node, collected by
`organizations:DescribeOrganization`). The own organisation ⇒ not an external entry; a foreign organisation (or an own
account in no organisation) ⇒ an ordinary external entry (lab P21, 8.0); own organisation unknown or denied ⇒ the entry
is kept at **0.3** (`UnknownOrgTrustEntry`, = `ProtectedTrustEntry`), labelled `confidence: inferred` and never
floored. A verified path-rule match on an existing path's hops is folded into it (`also_matches_rule`,
`path_rule_matches`; r5 #3) and never scored as a second path; a verified match traversal did not find is scored by
the traversal path builder (rule hop 0.9 × hop decay, the usual floors, never below the anchor's own score).

### 2.2.0 (2026-10-09)

Engine round 2 (competitive delta review 2026-10-09, shortfall #3: FortiCNAPP published bands with real dynamic
range). Measured on the labelled lab (`internal/risk` `TestSaturationLab`, in-process ingest of
`lab/local/out/estate.findings.json` with path analysis): findings at 10.0 **41 / 62 → 5 / 62 (8 %)**, Critical
**46 → 22** at release (re-measured by Verification 4 on the later tree: **4 / 62 at 10.0, 21 Critical**; after the
V4-ENGINE reachability verdict below: **4 / 62 at 10.0, 20 Critical**); the order of the 50 existing calibration scenarios is unchanged (every order chain holds).

- **Bounded combination replaces the flat cap at 10.** Above the knee (7.0, the High threshold) the raw product is
  compressed with diminishing returns: `score = 7.0 + 3.0 × (1 − e^(−(raw − 7.0) / 4.5))`. The function is
  continuous, strictly increasing and bounded by 10, so ranking by score is ranking by raw product; only raw
  ≥ ≈ 25.4 rounds to 10.0 and Critical needs raw ≥ ≈ 11.9 (it needed 9.0). Below the knee nothing changes. New
  weights rows `combination.knee` 7.0 and `combination.scale` 4.5; the `cap` factor is replaced by a `combination`
  factor ("diminishing returns above 7.0: raw R → S"), and every explanation states the rule with its numbers in
  `explanation.combination`. The off-path ceiling (min(raw, 6.9)) is unchanged.
- **Why not a max-of-two-multipliers or Σ ln rule.** Both still exceed 10 for the lab's CRITICAL × wide ×
  sensitive × production × path findings (base 7.0 × 2.0 path alone is 14) and would need the cap again; a
  monotone compression of the product keeps every published multiplier and its explanation as they are.
- **Band moves** (calibration): a KEV CVE with no exposure or path context 10.0 Critical → 8.6 High; EPSS top-5 %
  9.1 → 8.1 High; IMDSv1 + admin behind 0.0.0.0/0 in production 10.0 → 9.1 (still Critical), narrow 10.0 → 8.6
  High; SCP-denied open admin host on a 9.0 path 9.6 → 8.3 High; crown jewel high 9.6 → 8.3 High. Every
  scenario with raw ≤ 7.0 keeps its score. Off-path findings are untouched (≤ 6.9).
- **Calibration:** 50 → 53 scenarios: `tie_*` (three findings that tied at 10.0 / 10.0 / 9.6 under 2.1.0 now score
  10.0 / 9.9 / 8.3) and the order chain `tie_public_pii_path10 > tie_imds_admin_prod_path > s3_public_pii >
  ec2_imdsv1_open_admin > tie_imds_admin_staging`.
- **Upgrade note:** stored scores and Issue severities move at the next ingest; a finding that was Critical
  only because its product passed 9.0 is now High. The `score_version` on every ranked finding says which rule
  produced it.

### 2.1.0 (2026-10-09)

The finding score now agrees with the path verdict. Measured on the independently authored noise estate
(`make groundtruth`, `TestNoiseEstate`): benign CRITICAL + HIGH open Issues 22 → 0 (target ≤ 5), best
`prioritize` rank of the three true-positive chains #2 / #15 / #13 → #1 / #5 / #4. Labelled lab: every
`expected` finding on a reported path keeps its band; path scores are unchanged (separate formula).

- **New factor `off_path` ×0.5 and ceiling 6.9 (`off_path_cap`).** A finding whose resource is on no complete
  attack path and is not a crown jewel, sensitive data store or admin-level identity is halved and capped at
  Medium, with the reason "no attack path reaches an impact target from this resource". Without path analysis
  (findings-only input) it is `not scored` and nothing is capped. Before, the eight public website buckets of
  the noise estate scored 10.0 Critical with no path anywhere near them.
- **`attack_path` 0.05 / max 1.5 → 0.12 / max 2.0.** The other half of agreeing with the verdict: a finding
  on a 7.0 path is now ×1.84 (was ×1.35), so it outranks the same finding off path by the full off-path
  margin. Needed to keep the labelled lab's on-path admin / trust findings Critical after the
  `identity.admin` cut (P20 at path 5.99: 5.5 × 1.25 × 0.8 × 1.72 = 9.5).
- **`identity.admin` 1.4 → 1.25.** An admin-level identity is an impact target and is exempt from the
  off-path cap, so its weight alone decides its band when no path reaches it. At 1.4 (with the multipliers
  below) the noise estate's SSO-only admin roles scored 9.3 Critical; at 1.25 an unreachable HIGH admin role
  is 6.9 Medium, and on a path it is still Critical. 1.25 stays above `identity.weak` 1.2.
- **`exposure.none` 0.7 → 0.5.** A resource known not to be internet-reachable (private, auth required,
  org-conditioned) now halves; an org-conditioned bucket holding confidential data (exempt from the cap as a
  sensitive store) scores 6.8 Medium instead of 9.6 Critical (lab F08 seeded false positive: 10.0 → 6.8).
- **`compliance.regulated` 1.1 → 1.0, `compliance.privacy` 1.05 → 1.0.** Compliance scope says which auditor
  cares, not how likely or how damaging a breach is (Defender's risk factors and Orca's score do not weight
  it). It inflated every pci-mapped finding by 10 % and helped saturate scores. The factor stays in every
  explanation with the frameworks in its reason.
- **`recent_change.new_finding_24h` 1.05 → 1.0.** On a first ingest every finding is "new", so it multiplied
  the whole population without changing order. `modified_24h` (×1.1) is unchanged.
- **`ownership.orphaned` 1.05 → 1.0.** Ownership routes a finding (owner, SLA); it does not change the risk.
  The factor still names the owner or "orphaned".
- **Data sensitivity:** an explicit non-sensitive classification (`public`, `none`, `synthetic`, `test`,
  `dummy`, `open`, `non_sensitive`, plus `internal`) now wins over the graph's name-heuristic `sensitive`
  flag, as in the path engine; `high` counts as a sensitive label. `halyard-sandbox-public-fixtures`
  (classified none) and `public-pii-redacted-reports` (classified public) were ×1.5 sensitive by name.
- **Calibration:** 29 → 50 scenarios (13 from noise classes, 8 from the labelled lab); the 2.0.0 scenarios
  run as findings-only input. Chains `orphaned > off_attack_path` and `pci_scope > off_attack_path` removed
  (both factors are ×1.0); `info_plain` got the same context as `low_severity_plain` to keep LOW > INFO.
- **Known consequence:** findings of labelled paths the engine does not find yet are off path and lose their
  band: P13 (missed) no-MFA user Medium → Low and admin role High → Medium; P18 (missed) Bedrock agent
  Critical → Low and its role High → Medium; P15 (path 1.44) admin group Critical → High. They return when
  the engine reports those paths.

### 2.0.0 (2026-10-09)

- **One formula.** The score is now multiplicative: `base × Π multipliers`, clamped to 0–10. It replaces two older
  formulas:
  - Go 1.x: `1 + 9·sigmoid(7(0.45·base + 0.55·Σw·f − 0.42))`;
  - Python: a logistic 0–100 with its own weights, which was then shown with Go's band.

  Python now only consumes Go output. `risk_weights.json` holds only `score_version`. The Python linear-model
  override (`--model`, `NIMBUS_RISK_MODEL`) is ignored and prints a warning.
- **Bands.** Medium now starts at 5.0. It was 4.0 in 1.x.
- **New factors:**
  - exposure width (wide / narrow / trusted / none);
  - exploitability from KEV and EPSS (`internal/intel`, offline snapshot dated 2026-10-09);
  - crown-jewel levels (×2.0 / ×1.6 / ×1.2 / ×1.0);
  - compensating controls (hooks for Track B's SCP-deny and for O49).
- **Removed heuristics:**
  - name-based "prod" criticality guessing from the account or resource name;
  - "DATABASE ⇒ sensitive".

  An unclassified data store is now `not scored` for sensitivity.
- **Unknown inputs** are now `not scored` and listed in `explanation.missing`. In 1.x they were silently weighted;
  for example, unknown criticality counted as 0.5.
- **New output fields:** every ranked finding carries `score_version` and `explanation`, and the explanation's
  factors reproduce the score.

## Path score (attack paths, Track B2)

This section covers attack-path scores. The finding score above is unchanged. Path scores rank
paths and do not feed the finding formula, except through the `top_paths` evidence.

- **Impact targets (P1-ENGINE noise round, 2026-10-09, planning decisions 1 and 3):** a path must
  end at an impact target. Priority comes only from typed facts, never from names:
  - a configured crown jewel (`crown_jewels`): its tier;
  - a sensitive data store: tier 4 in production, else 3. An explicit classification tag or attribute
    (`data_classification` / `classification` / `sensitivity`) wins over the graph's name heuristics:
    `public`, `none`, `synthetic`, `non-sensitive`, `test` mean not sensitive (a bucket named
    `public-pii-redacted-reports` classified public is not a target); `pii`, `phi`, `pci`,
    `confidential`, `restricted`, `secret`, `sensitive`, `high` mean sensitive;
  - a crown data store by type (the registry's `Crown` flag: managed databases, DynamoDB, secrets,
    keys): tier 3, unless explicitly classified public;
  - an admin-level identity (the toxic floor's definition below, plus the account root user): tier 4.
  Everything else — clusters, accounts, workloads, plain buckets — is not a target. The former
  built-in name catalog (`*customer*`, `*prod*`, `*admin*`, …) is gone: it gave an ECS service named
  `customer-portal`, every resource in a project called `halyard-prod` and an orphaned user called
  `svc-prod-admin-legacy` top priority on the noise estate.
- **Exposures are not paths (decision 1):** an internet-reachable resource that is not an impact
  target (reached by the internet hop plus exposed-network-control plumbing only) is listed in
  `Analysis.Exposures` (`node_id`, `name`, `type`, `width`, `because`, `finding_ids`), never in
  `paths`, totals, choke points, fixes or path Issues.
- **Anonymous reach (decision 2):** an internet edge counts only when an anonymous attacker can use
  it. From the target's attributes, exposure is `private` (not an entry, listed in `suppressed` with
  the reason) when: the function URL / API requires authentication (`function_url_auth_type` /
  `auth_type` `AWS_IAM`, Cognito, custom / JWT authorizer) — reason `auth required`; every
  `Principal *` statement of `resource_policy` / `policy` / `bucket_policy` carries an
  `aws:PrincipalOrgID` / `PrincipalOrgPaths` / `PrincipalAccount` / `SourceVpc` / `SourceVpce` /
  `SourceAccount` condition — reason `org-conditioned`; or the store disables anonymous access
  (`allow_blob_public_access=false`, `public_network_access=Disabled` on storage, S3 public access
  block on, GCS `public_access_prevention=enforced`). On serverless URLs and object storage with no
  deciding attribute the finding's label stands and the hop carries `evidence.confidence = hint`.
  The rule engine applies the same check to the finding's own attributes.
- **Compensating control on the entry (decision 3):** the hop through an internet-facing load
  balancer / API gateway that authenticates (an `authentication` / `authorizer` / OIDC / Cognito
  attribute) or filters (a WAF web ACL) is ×0.3, its `because` carries `auth-lb ×0.3 (<why>)`
  (`evidence.compensating_control`), and the entry no longer counts as anonymous wide exposure, so
  the toxic floor does not apply.
- **Usable identity (decision 4):** a user's credential weaknesses (`NO_MFA`, `STALE_CREDENTIALS`,
  `WEAK_AUTH`) are an entry only when the user can authenticate. `console_access=false` with no active
  access key (`active_keys=0` or `access_key_N_active=false`): no entry, no path. Console access, an
  active key, a `STALE_CREDENTIALS` finding or a key age: usable. None of those attributes: the entry
  is ×0.5 with `evidence.confidence = hint`.
- **Graph traversal:** `score = min(10, likelihood × priority)`.
  - Priority is 10 / 5 / 2 / 1 for crown-jewel tiers 4 / 3 / 2 / 1.
  - The internet node's out-edges are separate entries and are not capped by `MaxBranching` (the cap
    dropped every exposure past the 25th in store order, which hid noise TP3).
  - `likelihood = entry × Π(hop × 0.95)`.
  - Decay is not applied to initial access from the internet, nor to plumbing hops through an exposed SG / NSG / firewall.
  - Paths with likelihood < 0.1 are not reported.
  - A complete path never scores below the best crown jewel it passes.
  - The per-edge table is in `docs/benchmark.md` ("Path likelihood table"). Each step records its value in `evidence.likelihood`.
- **Toxic-combination floor (B3):** when the entry hop is **wide** internet exposure and the target is
  admin-level (an identity or binding with `OVERPRIVILEGED_IDENTITY` / `CLUSTER_ADMIN`, the
  `cluster-admin` ClusterRole, a project / subscription / account admin role, or a configured crown
  jewel at level `very_high` / `high`) or a sensitive data store, `likelihood = max(likelihood, 0.7)`
  before priority, so such chains score ≥ 7 at priority 10.
  - The last step is tagged `evidence.toxic_combination` = `exposed+admin` / `exposed+sensitive`,
    with a one-line reason appended to its `because`.
  - It never applies to narrow / trusted / private exposure, to an entry behind an authenticating
    load balancer (`auth-lb`), to non-internet entries, to rule chains
    (including `weak_link` ones), or to targets that are neither admin-level nor sensitive.
  - It only lifts paths that are already reported (likelihood ≥ 0.1), so a fix that breaks a hop
    still breaks the path. This mirrors Wiz toxic combinations and Tenable's toxic cloud trilogy.
    Full rule: `docs/benchmark.md` ("Toxic-combination floor").
- **Exposure width:**
  - wide ×1.0;
  - narrow ×0.5;
  - trusted or private: not an entry, listed in `suppressed`. Trusted is decided against `trusted_cidrs`;
    private is a private source range or, since the noise round, a target that requires authentication
    (see "Anonymous reach").
- **Rule chains** (`rules.yaml`):
  - The score is the mean severity weight × link tightness × (1 + 0.25 per extra stage).
  - A chain joined only by `same_account` / `any` is allowed only where the rule declares `allow_same_account` with a justification. It is then marked `weak_link: true` and scores ×0.5.
- **Severity of a path (engine round 2, shortfall #1):** the band of its score, `model.ScoreBand` — Critical ≥ 9,
  High ≥ 7, Medium ≥ 5, Low < 5 — the same scale as the finding score and path Issues
  (`attackpath.PathSeverity`). It applies to traversal paths, rule chains, `Analysis.Grouped()` rows, the plan
  diff and stored path Issues (`TestPathSeverityConsistent`). Before round 2 traversal said Critical ≥ 7 and rule
  chains Critical ≥ 5.5, so `paths` printed `[CRITICAL 5.2]` next to an Issue in band High.
- **CVE exploitability gate (round 2, council decision 5, shortfall #9; `attackpath/cvegate.go`).** A hop that
  exists because a workload runs vulnerable software is priced by exploitation evidence, not by a CVE count:
  CVE in CISA KEV (or node attr `kev=true`) 0.9; EPSS probability ≥ 0.5 → 0.6; ≥ 0.1 → 0.3; < 0.1 → 0.1 (below
  the 0.1 reporting floor once multiplied, so such a path is not reported unless another route exists); CVE ids
  with no KEV / EPSS row, or a CVE count / `UNPATCHED` label with no ids → 0.3 with `evidence.confidence = hint`.
  The credential hop ("RCE, then credential theft") takes the gate value; the internet hop into the workload
  stays reachability (0.8) unless a CVE is in KEV (0.9); an internet → workload `allows_traffic_to` hop is
  max(0.55, gate). KEV / EPSS come from `TraversalOptions.Intel` (default: the embedded snapshot) and the CVE ids
  from node attributes (`cve`, `cves`, `cve_ids`) and `TraversalOptions.NodeCVEs` (`attackpath.CVEIndex(findings)`;
  the graph keeps only a count). Before round 2 every such hop was 0.95 / 0.6. Lab P19 (Log4Shell, KEV) stays
  7.0; the same host with CVE-2023-0002 (EPSS 0.003) reports no path.
- **Identity-entry floor (round 2, shortfall #12; `attackpath/identity.go`).** Like the toxic and CI-entry floors,
  an impact policy: likelihood max(likelihood, 0.7) before priority for paths from a usable identity entry into an
  admin-level target, tagged `toxic_combination`:
  - `idp-entry`: a federated IdP user (Okta / Entra / Google Workspace …) whose credential is usable (status
    `ACTIVE` / `PASSWORD_EXPIRED` / `RECOVERY`, or `account_enabled=true`; `SUSPENDED` / `DEPROVISIONED` /
    `LOCKED_OUT` / `STAGED` / `PROVISIONED` is no entry) and not protected by MFA, whose groups federate into an
    admin role (lab P15: 1.44 → 7.0);
  - `external-trust`: a role an external account can assume without an ExternalId, chained into an admin role
    (P20: 5.99 → 7.0). A trust naming a foreign account's root (`arn:aws:iam::<acct>:root` or a bare account id)
    is an entry at 0.8 (`ExternalRootEntry`; every principal that account's admins allow), another foreign
    principal 0.7, with an ExternalId or SourceIdentity condition 0.3 (`ProtectedTrustEntry`; no floor), a wildcard
    1.0; an organisation-limited trust (`aws:PrincipalOrgID` & co.) is no external entry at all;
  - `privesc`: the path crosses a privilege-escalation edge (`can_assume` with a `technique` attribute from the
    IAM evaluator, e.g. `iam:PassRole+ec2:RunInstances`), priced 0.8 (`EscalationLikelihood`) (P13: 5.32 → 7.0).

  Never for a hint entry (credential usability unknown), an internet entry (the toxic floor decides those), a
  compensated entry, a non-admin target, or below the 0.1 floor.
- **AI agent runtime → role (round 2, IG9 / P18).** An agent (`aws_bedrock_agent`, `aws_bedrockagent_agent`,
  `*ai_agent*`) `runs_as` hop is 0.7 when its input is untrusted — internet exposure, `invoked_by` naming an
  unauthenticated / public / anonymous caller, `publicly_invocable` / `public_invoke` / `unauthenticated` /
  `untrusted_input` true, or `auth_type NONE` — and 0.3 otherwise. Lab P18 (MISSED) → 7.0 (`exposed+admin`).
- **Network reachability (round 2, P2-REACH consumption).** An internet edge, the edge from an exposed network
  control to a workload, or the workload node itself carrying `reachability: blocked` is not an entry: the edge is
  dropped from traversal, nothing behind it is exposed, and the resource is listed in `Analysis.Exposures` with
  `reachability: blocked` and `reason` = `reach_blocker` (not also in `suppressed`). `reachability: unknown`
  keeps the edge with `evidence.confidence = inferred`. `reach_path` / `reach_confidence` on an edge are carried
  as step evidence. Rule chains apply the same verdict (`EvalOptions.Graph`): a REACH-blocked resource loses
  `PUBLIC_NETWORK_EXPOSURE` / `PUBLIC_DATA_STORE`, and an identity whose admin rights an SCP / boundary removes
  (`effective_admin: none`, `neutralised_weaknesses`) loses `OVERPRIVILEGED_IDENTITY` (lab S01).
- **One row per path Issue (round 2, shortfall #11).** `Analysis.Grouped()` groups `Analysis.Paths` by
  `model.PathIssueID` (entry | anchor | rule): one row per Issue with its best-scoring path, the Issue score (max
  over its paths), band, severity, `variants` (other hop lists) and every path id; the full list is lossless.
- **Path-rule matches (W6, competitive delta r4 #7; `attackpath/rulematch.go`).** Traversal evaluates the embedded
  path-rule library (55 Prowler-credited AWS privilege-escalation rules, `cloud-posture risk list`). A **verified**
  match (its `verified_by_edge` proven by a verified graph edge, or a rule declaring itself verified with every
  permission an exact Allow) whose escalation hop lies on a traversal path ending at the match's target becomes its
  own path: the traversal path's steps up to the target, **scored exactly as that traversal path** (no extra
  weight), with the rule id as the path's rule (so its Issue is `PathIssueID(path, entry, target, <rule id>)`), the
  last step tagged `rule_match` = rule id, `rule_confidence`, `rule_because`, `rule_credit`, `tags: [rule_match]`.
  It is cut by the same fixes and never folded into the traversal Issue by `Merge`. Inferred matches, and verified
  matches no entry reaches or whose target is not an impact target, are not paths (`risk test` dry runs list
  them; `Analysis.RuleMatches` lists every verified match with the `path_id` it became). Anchors exclude only
  principals the evaluator allows on `*` across services (a single escalation action on `*`, or an Allow NotAction
  `iam:*`, is not "admin"); a Deny conditioned only on `aws:MultiFactorAuthPresent` = false (or MFA age) does not
  stop an MFA session, so such a match is inferred and says "only from an MFA session". Lab: one rule-match Issue
  (`aws-ec2-privesc-passrole-iam`, dev-sam → ec2-admin-role, same score as P13's traversal path).
