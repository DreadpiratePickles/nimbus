# Metrics

How nimbus (binary `cloud-posture`) measures whether it is working, **with zero telemetry**. nimbus
never phones home. Every number here comes from public data: public pull requests, the public GitHub
REST API, public registries and the project's own benchmark. A user who wants to be counted makes
their usage public. Nothing else counts them.

This page implements plan v3 §8 ([`.planning/IMPLEMENTATION_PLAN_v3.md`](../.planning/IMPLEMENTATION_PLAN_v3.md)).
Repository and image names below are today's (`DreadpiratePickles/nimbus`,
`ghcr.io/dreadpiratepickles/cloud-posture`). They change with the naming decision (O3).

**Status (2026-10-09):** nothing on this page has been collected yet. No pull request emits the footer
until P1-PLANDIFF item D6 lands, and no release has been published. The queries below are written
against the documented GitHub API but have not been executed. They will be re-checked the first time
they run.

## North star: attack paths closed through merged nimbus PRs per week

**Definition.** For an ISO week W, the north star is the sum of `N` over every *public* pull request
that:

1. carries a `nimbus-closes-paths: <N>` footer (written by nimbus when it opens or comments on a fix PR), and
2. was **merged** during week W (Monday 00:00 UTC to Sunday 23:59 UTC by `merged_at`).

`N` is the re-simulated number of path Issues the change closes. It is the same number `cloud-posture
plan` prints for that fix set. PRs that are opened but not merged count zero. A path closed by hand
without a nimbus PR is not counted: the metric measures nimbus's fix loop, not posture in general.

**The PR-body footer** (plan v3 §8; emitted in every PR body nimbus generates; acceptance test
`TestPRFooterPresent`, owned by P1-PLANDIFF):

```text
nimbus-closes-paths: <N>
nimbus-issues: <path-issue-id>[,<path-issue-id>…]
nimbus-version: <semver>
```

Users may delete the footer. That opts the PR out of the count. Private repositories are never
visible to search, so the metric is a **lower bound**.

### The GitHub search query

Search string (GitHub issue/PR search syntax; replace the dates with week W):

```text
"nimbus-closes-paths" in:body is:pr is:merged merged:2026-10-12..2026-10-18 -repo:DreadpiratePickles/nimbus
```

- `in:body` restricts the match to the PR description, where the footer lives.
- `is:merged merged:A..B` gives PRs merged in that inclusive date range (UTC).
- `-repo:DreadpiratePickles/nimbus` drops this repository's own PRs. Those PRs may quote the footer in
  docs or tests. Report dogfooding fixes separately if wanted.
- Web UI: <https://github.com/search?type=pullrequests&q=%22nimbus-closes-paths%22+in%3Abody+is%3Apr+is%3Amerged+merged%3A2026-10-12..2026-10-18+-repo%3ADreadpiratePickles%2Fnimbus>

Counting with the REST search API. This works unauthenticated, at 10 search requests per minute. An
optional `GITHUB_TOKEN` from the environment raises that to 30 per minute. It is never stored or
logged.

```sh
WEEK_START=2026-10-12 WEEK_END=2026-10-18
q="\"nimbus-closes-paths\" in:body is:pr is:merged merged:${WEEK_START}..${WEEK_END} -repo:DreadpiratePickles/nimbus"
curl -fsS -G https://api.github.com/search/issues \
  -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
  ${GITHUB_TOKEN:+-H "Authorization: Bearer $GITHUB_TOKEN"} \
  --data-urlencode "q=$q" --data-urlencode per_page=100 --data-urlencode page=1 |
jq '{prs: .total_count,
     closed_paths: ([.items[] | (.body // "")
                     | capture("nimbus-closes-paths: *(?<n>[0-9]+)")? | .n | tonumber] | add // 0),
     incomplete: .incomplete_results}'
```

- Page through `page=2,3,…` while `total_count > 100 × page`. The search API returns at most 1,000
  results per query. If a week ever exceeds that, split it into days.
- `incomplete_results: true` means GitHub timed out. Re-run before publishing.
- Only the first `nimbus-closes-paths:` line of a body is counted. A PR whose footer has no integer counts 0.
- The weekly script that does this for a range of ISO weeks is `tools/northstar/` (P1-PLANDIFF, not yet
  written). It must use exactly this query and footer regex. Changing either is a metrics-definition
  change, recorded on this page with a date.

**Supporting value metrics from the same data:**
- PRs opened → merged ratio: run the same query with `is:pr` (no `is:merged`, filtered by `created:`)
  as the denominator.
- Paths closed per active install: the north star divided by the number of distinct repositories in
  the result set.
- Path Issue churn (reopened per release): from the `issues` history in the user's own database. It is
  reported only in public benchmark runs on the lab (plan v3 §8).

## Placement metrics (public APIs, no secrets)

| Metric | How to collect | Notes |
|---|---|---|
| GitHub Action dependents | `https://github.com/DreadpiratePickles/nimbus/network/dependents` ("Used by"; repositories whose workflows reference the Action) | There is no REST endpoint, so read the page. Comparators (STRAT §5.1): trivy-action used by 55,417 repos, checkov-action by 7,654 (2026-10-09). |
| Release downloads | the `releases` command below | Archives only (not checksums, signatures or SBOMs). Cumulative; diff successive readings for a weekly rate. |
| Container image pulls | Package page `https://github.com/DreadpiratePickles/nimbus/pkgs/container/cloud-posture` ("Total downloads") | GHCR has no public download-count API. Record the page value with its date. |
| Homebrew installs | Own tap: no public analytics. homebrew-core (after acceptance): `https://formulae.brew.sh/api/analytics/install/30d.json` | homebrew-core eligibility (self-submission): 225 stars or 90 forks or 90 watchers (STRAT §5.1). |
| Stars, forks, watchers | `curl -fsS https://api.github.com/repos/DreadpiratePickles/nimbus \| jq '{stars: .stargazers_count, forks: .forks_count, watchers: .subscribers_count}'` | Reported as context, never as a goal. |
| OpenSSF Scorecard | `curl -fsS https://api.securityscorecards.dev/projects/github.com/DreadpiratePickles/nimbus \| jq .score` | Target ≥ 8 (plan v3 §8; STRAT §5.2). Published by `.github/workflows/scorecard.yml`. |
| PyPI downloads (once the Python layer is published) | `https://pypistats.org/api/packages/<package>/recent` | Not published yet (plan v3 §5.5). |

```sh
# releases: archive download counts across all releases (unauthenticated)
curl -fsS 'https://api.github.com/repos/DreadpiratePickles/nimbus/releases?per_page=100' |
  jq '[.[].assets[] | select(.name | test("[.](tar[.]gz|zip)$")) | .download_count] | add // 0'
```

## Company, community and trust metrics

| Layer | Metric | Instrument |
|---|---|---|
| Companies | Named adopter organisations | Rows in [`ADOPTERS.md`](../ADOPTERS.md). Plan target (plan v2 §1, kept in v3): 100 named adopter organisations before 10k stars. |
| Community | External contributors per month | `is:pr is:merged repo:DreadpiratePickles/nimbus merged:<month> -author:DreadpiratePickles` (same search API); count distinct `user.login`. |
| Community | Maintainers' organisations | [`MAINTAINERS.md`](../MAINTAINERS.md). At least 2 organisations are needed before a CNCF sandbox application ([GOVERNANCE.md](../GOVERNANCE.md)). |
| Trust | Recall, recall@7, precision, precision@7; FP rate per hop kind; unlabelled paths ≥ 5 on the noise estate | [`docs/benchmark.md`](benchmark.md), and a `benchmark.json` asset per release (planned) |
| Trust | IAM corpus pass rate; simulator disagreements | `go test ./internal/iam` (Phase 1) |
| Activation | Share of first runs printing ≥ 1 path within 10 minutes; time to first path | timed `init` in the e2e workflow (planned) and issue reports |
| Content leverage | Share of findings from ingested third-party tools vs native collectors | `cloud-posture query "SELECT source, count(*) FROM findings GROUP BY source"` in benchmark runs |

Targets are set only where a source exists (plan v3 §8). Every other metric is published, not targeted.

## Recording

Each reading goes into the release notes or a dated section of this page, with the date, the exact
command and the raw number. A metric that cannot be collected is reported as "not collected", never
estimated.
