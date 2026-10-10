# Governance: owners, SLAs, digests

Every Issue gets an **owner** and a **due date**. Overdue work is visible per owner, owners get a weekly
digest, and MTTR / on-time rate come from the lifecycle history the store already keeps.

**The bar** (`docs/research/competitive-feature-matrix.md` RP8): Microsoft Defender CSPM governance rules
(owner from a resource tag or an address, due dates by severity, grace period, weekly owner email,
on-time/overdue tracking) and Datadog/Jira one-ticket-per-Issue. **Where we go further:** the rules are YAML
in the repo (reviewed like code, not clicked in a portal), CODEOWNERS is the owner of IaC-origin findings,
every assignment carries a `why` trail, and MTTR is computed from recorded lifecycle transitions instead of
a snapshot.

Status: wired end to end (integration pass 4). Every `scan`, `ingest` and `prioritize` resolves every Issue and
stores the assignment (store migration 7); the CLI, API, dashboard, digest and Jira/GitHub tickets read that one due
date. See [Using it](#using-it); the original wiring list is kept under
[What the integration pass wires](#what-the-integration-pass-wires) with what landed.

## Using it

```bash
cloud-posture issues --overdue                    # open Issues past due (suppressed / resolved are never overdue)
cloud-posture issues --owner @acme/platform       # one owner's Issues; "(unassigned)" for none
cloud-posture issues show <id>                    # owner (source, rule), why, SLA, due, grace, OVERDUE, ticket
cloud-posture issues metrics [--json]             # MTTR by severity, on-time rate, open / overdue by owner
cloud-posture alert --digest [--since 7d] [--dry-run] [--digest-sink slack|stdout]
cloud-posture alert --to jira                     # one Jira ticket per Issue (assignee, duedate); closes on resolve
```

API: `GET /api/issues?overdue=1&owner=<x>` (every Issue JSON carries `owner`, `owner_source`, `owner_rule`,
`owner_why`, `sla_days`, `due_at`, `grace_until`, `overdue`, `ticket_sink`, `ticket_key`, `ticket_url`,
`ticket_state`); `GET /api/governance/metrics` (`mttr_hours_by_severity`, `resolved_by_severity`, `open`,
`suppressed`, `open_past_due`, `open_past_grace`, `on_time`, `late`, `on_time_rate`, `open_by_owner`,
`overdue_by_owner`, `owners` sorted by overdue then open); `GET /api/issues/{id}` page `owner` (`owner`, `source`,
`rule`, `why`, `sla_days`, `due_at`, `grace_until`, `overdue`, `past_grace`) and `ticket`.

Store (migration 7, `issues`): `owner`, `owner_source`, `owner_rule`, `owner_why`, `sla_days`, `due_at`,
`grace_until` (RFC 3339; NULL = no SLA), `ticket_sink`, `ticket_key`, `ticket_url`, `ticket_state`; indexes
`idx_issues_owner (owner, state)`, `idx_issues_due (due_at, state)`. Rebuilds never touch these columns; the
governance step overwrites them on every run so rule edits apply.

**Where the inputs come from.** CODEOWNERS: `governance.codeowners_file` (relative to each root) or
`.github/CODEOWNERS` / `CODEOWNERS` / `docs/CODEOWNERS` under each IaC root (`--iac`, else `scan.iac_paths`), then
the working directory. IaC findings carry a path relative to the scanned root; the file is located under the IaC
roots and matched against the CODEOWNERS whose directory contains it (else the first CODEOWNERS found). Account
owner: `accounts.<name>.owner`, matched by the account name or its identity (AWS account id from `role_arn`,
`subscription_id`, `project_id`, `tenant_id`, `org`, `domain`, `kube_context`). Path Issues take name and
`owner`/`team` tags from the anchor node. Episode start: `CurrentEpisodeStart` over the lifecycle history, else
`first_seen`.

**Metrics.** MTTR and on-time come from `CollectEvents` + `Metrics` (the stored owner and SLA attribute each Issue);
open, overdue and past-grace counts are read from the stored `due_at` / `grace_until`, so `issues --overdue`, the API
filter, the digest and the dashboard can never disagree.

**Digest.** Items are the stored Issues (`DigestItemFromIssue` with the stored assignment; fix command
`cloud-posture fix --id <first evidence finding>`, or `issues show <id>` for path Issues). `Since` = `--since`
(duration back, or a date) else now − `digest.schedule` period. Ledger: `<db dir>/digest-ledger.json`, keys
`<sink>/<owner>` so a stdout preview never suppresses the Slack send. Sinks: `slack` (`integrations.slack.url` /
`url_env`, default `SLACK_WEBHOOK_URL`) and `stdout`; `teams`, `email`, `webhook` return "not implemented yet".

**Tickets.** `alert` routes Jira and GitHub Issues to `integrations.DispatchIssues`: one ticket per Issue at or above
the sink's `min_severity` (never one per finding), idempotent through the stored `ticket_key`, with the body marker
`cloud-posture-issue: <id>` (Jira label `cp-issue-<id>`) as the fallback when the store was lost. Jira: assignee =
the account found by `GET /rest/api/3/user/search?query=<owner e-mail>` (unassigned when the owner is not an e-mail or
no unique account matches), `duedate` = `due_at`; resolved Issue → transition to a `done` status category (prefers
Done/Resolve/Close) + comment; reopened Issue → transition back (prefers Reopen/To Do) + `duedate` updated to the
fresh clock. GitHub: `assignees` = `@user` owners (teams and e-mails are not assignable), owner and due date in the
body (GitHub issues have no due-date field), close as completed / reopen. An Issue whose ticket lives in another
sink is skipped. Suppressed Issues are left alone. Other sinks (Slack, Teams, PagerDuty, SIEM…) still receive
findings.

## Configuration reference

```yaml
governance:
  codeowners_file: .github/CODEOWNERS   # optional; default search: .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS
  rules:                                 # ordered; the FIRST matching rule wins (max 500)
    - id: payments-prod                  # optional; defaults to rule-<N> (1-based); must be unique
      match:                             # every selector that is set must match (AND); at least one is required
        provider: aws                    # case-insensitive glob
        account: "aws-prod*"             # case-insensitive glob
        tag: {team: payments}            # value matches case-insensitively; "*" = tag present; key lookup is case-insensitive
        name_regex: "^payments-"         # Go regexp on the resource name (falls back to the resource id)
        iac_path_glob: "infra/**/*.tf"   # repo-relative IaC file; ** crosses directories, * and ? do not
      owner: payments-oncall@example.com # literal | "tag:<Key>" | "codeowners"
      sla_days: {critical: 3, high: 7}   # per severity; unset severities inherit defaults, then 7/14/30/90
      grace_days: 2                      # unset inherits defaults.grace_days
  defaults:
    owner: secops@example.com            # last-resort owner
    owner_tags: [owner, team]            # tags tried when no rule (or the rule's owner) resolves; default [owner, team]
    sla_days: {critical: 7, high: 14, medium: 30, low: 90}
    grace_days: 3
  digest:
    schedule: weekly                     # weekly (default) | daily
    sink: slack                          # slack | teams | email | webhook | stdout
    group_by: owner                      # owner (default) | account
    dedup_window: 168h                   # unchanged digests are not re-sent inside this window (default: the schedule period)
```

Validation (`config.Load` fails with every problem, matched with `errors.Is`):

| Problem | Field | Sentinel |
|---|---|---|
| missing owner, `tag:` without a key, multi-line owner | `governance.rules[i].owner` | `ErrInvalidOwner` |
| rule with no selector | `governance.rules[i].match` | `ErrEmptySelector` |
| bad `name_regex` | `...match.name_regex` | `ErrInvalidRegex` |
| bad `provider` / `account` / `iac_path_glob` glob | `...match.<field>` | `ErrInvalidGlob` |
| `sla_days.*` or `grace_days` < 0 or > 3650 | `...sla_days.<sev>`, `...grace_days`, `governance.defaults.*` | `ErrInvalidSLA` |
| duplicate rule id | `governance.rules[i].id` | `ErrDuplicateRuleID` |
| unknown schedule / sink / group_by | `governance.digest.<field>` | `ErrInvalidDigest` |
| bad `dedup_window` | `governance.digest.dedup_window` | `ErrInvalidDuration` |
| `min_owner_share` outside (0, 1] | `governance.defaults.min_owner_share` | `ErrInvalidOwner` |

Warnings (non-fatal, `cfg.Warnings()`): more than 500 rules (the rest are dropped); `digest.sink` names an
integration with no `integrations.<sink>` entry.

## How owner resolution works

`governance.NewResolver(cfg.Governance, codeowners).Resolve(subject)` returns an `Assignment`:

```go
type Assignment struct {
    Owner      string    // first owner ("" when unassigned)
    Owners     []string  // every CODEOWNERS owner of the line that matched
    Source     string    // rule | tag | codeowners | account | default | unassigned
    RuleID     string    // matching rule ("" = none)
    SLADays    int       // 0 = no SLA (INFO)
    GraceDays  int
    DueAt      time.Time // OpenedAt + SLADays
    GraceUntil time.Time // DueAt + GraceDays
    Why        string    // e.g. "rule terraform: CODEOWNERS line 4 for infra/payments/main.tf; HIGH SLA 14d (+3d grace)"
}
```

1. **Rules, first match wins.** The matched rule fixes `RuleID`, the SLA table and the grace period.
   Its owner is used as is (`rule`), read from the tag (`tag:<Key>` → `tag`), or looked up in CODEOWNERS
   for the finding's IaC file (`codeowners` → `codeowners`).
2. **Fallback chain** when no rule matches, or the rule's tag is missing/blank, or CODEOWNERS has no owner:
   `defaults.owner_tags` (owner, team) → CODEOWNERS for the IaC file → `accounts.<name>.owner` (`account`) →
   `defaults.account_owners` → `defaults.provider_owners` → `defaults.owner` (all three `default`) → `unassigned`.
   A rule's SLA still applies when its owner fell back. An owner from `defaults.*` is an assignment *by default*:
   `doctor` and `issues metrics` count it apart ("assigned by default: N"; `issues metrics --json` `ownership`),
   and doctor warns when more than half of the open Issues are owned only by default.
3. **Due date.** `SLADays` = rule `sla_days` for the severity, else `defaults.sla_days`, else 7/14/30/90 (critical,
   high, medium, low); INFO has no SLA. `DueAt = OpenedAt + SLADays`; `GraceUntil = DueAt + grace`.
   `OpenedAt` is the start of the **current** open episode: a reopened Issue gets a fresh clock
   (`governance.CurrentEpisodeStart(events, id)`); otherwise `first_seen`.
4. **Overdue vs breached.** `Overdue(now)` is strictly after `DueAt`; `PastGrace(now)` strictly after
   `GraceUntil`. Overdue is what owners see; past grace is the escalation point (digest emphasis, `alert`).
   Suppressed Issues (accepted risk) are never overdue.

Subjects: `governance.SubjectFromFinding(f)` and `governance.SubjectFromIssue(issue, evidenceFindings)`
(resource tags win over finding tags; the first evidence finding by id wins; the IaC path is the finding's
`file`, normalised to forward slashes without `./`). Path Issues have no evidence findings: set `Tags`/`Name`
from the anchor node.

Resolution is pure and deterministic (sorted tag lookups, ordered rules, last-match CODEOWNERS).

### CODEOWNERS

`governance.LoadCodeowners(repoRoot, cfg.Governance.CodeownersFile)` reads the explicit file or the first of
`.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` (GitHub's order); `(nil, nil)` when none exists. GitHub
syntax: the **last** matching line wins; a pattern with a leading or inner `/` is anchored at the repo root,
otherwise it matches at any depth; a trailing `/` matches the directory's contents; `*` stays in one segment,
`**` crosses segments; `docs/*` matches `docs/a.md` but not `docs/x/a.md`; a pattern with no owners makes the
path unowned (and resolution falls back). Lines GitHub skips are skipped and listed in `Codeowners.Errors`:
`!` negation, `[ ]` ranges, `\#` escapes and owners that are not `@user`, `@org/team` or an email. Inline
`# comments` after the owners are allowed.

## Metrics (MTTR, on-time, overdue)

```go
events, err := governance.CollectEvents(st /* *store.Store */, func(is model.Issue) governance.Assignment { ... })
report := governance.Metrics(events, time.Now())
```

`governance.HistoryStore` (`Issues`, `History`, `PathIssueHistory`) is satisfied by `*store.Store` unchanged.
`CollectEvents` builds one timeline per Issue: path Issues from `path_issue_history` (repeated open rows from
secondary-key changes are dropped); single/combination Issues from the union of their evidence findings'
`finding_history` (the Issue is open while any evidence finding is active); Issues with no history from
`first_seen`/`resolved_at`; a current `suppressed`/`resolved` state the history does not end in is appended.

`Report`: `MTTRBySeverity` (mean open→resolved per episode), `ResolvedBySeverity`, `Open`, `Suppressed`,
`OpenPastDue`, `OpenPastGrace`, `OnTime`/`Late`/`OnTimeRate` (resolved episodes with an SLA, resolved by their
due date), `OverdueByOwner`, `OpenByOwner` (`(unassigned)` for no owner).

## Digest

`integrations.BuildDigests(items, DigestOptions{Now, Since, GroupBy, MaxPerSection})` → one `Digest` per owner
(or account), sorted by key, with sections **Overdue** (any severity, oldest due first), **Open critical**, **Open
high** (not yet overdue), **Resolved this period**, each item with its Issue id, due date and fix command, and
exact counts even when a section is truncated (default 15 items). `Text()` is the email/stdout body,
`SlackPayload()`/`SlackJSON()` a Block Kit message (≤ 50 blocks, ≤ 3000 chars per section, mrkdwn escaped).
Goldens: `internal/integrations/testdata/digest/` (regenerate with `go test ./internal/integrations/ -run Digest -update-digest`).

**De-duplication.** `Digest.Fingerprint()` hashes which Issue is in which section — not dates or day counters —
so an unchanged digest is a duplicate. `SendDigests(ctx, digests, ledger, window, now, send)` skips empty
digests and duplicates recorded inside `dedup_window`, records successful sends, and leaves failed ones to be
retried on the next run. Ledgers: `NewMemoryLedger()`, `NewFileLedger(path)` (JSON, atomic rename).
`SlackDigestSender(webhookURL, channel)` is the Slack sender.

## What the integration pass wires

Landed in integration pass 4 as listed, with these differences: migration 7 also adds `sla_days` and the ticket
columns; `model.Issue` carries `OwnerRule`, `OwnerWhy`, `SLADays`, `Overdue` and the ticket fields too; the dashboard
Issue rows show DUE / OWNER columns with a red OVERDUE badge; item 7 keeps the risk keys for one release populated
from governance (docs/scoring.md changelog). The original list:

1. **`scan`** — after `RebuildIssuesWithVerdict` / `RebuildPathIssuesScoped`: load CODEOWNERS once per IaC root
   (`LoadCodeowners(root, cfg.Governance.CodeownersFile)`), build `NewResolver(cfg.Governance, co)`, and for every
   Issue resolve `SubjectFromIssue(issue, store.Findings(issue.FindingIDs))` with `AccountOwner` from
   `cfg.Accounts[account].Owner` and `OpenedAt` from `CurrentEpisodeStart` (or `first_seen`). Persist on the
   `issues` row: `owner TEXT`, `owner_source TEXT`, `owner_rule TEXT`, `due_at TEXT` (RFC 3339, NULL when no SLA),
   `grace_until TEXT`, `owner_why TEXT` — a new store migration (store is read-only to this track), plus
   `model.Issue` fields `Owner`, `OwnerSource`, `DueAt`, `GraceUntil`. Re-resolve on every scan so rule edits
   apply; a manual owner override (if added later) must win over resolution.
2. **`issues --overdue`** (open, `due_at < now`, not suppressed), **`issues --owner <x>`**, and owner/due in
   `issues show` (with `why`); `issues metrics` printing `governance.Metrics(CollectEvents(...))`.
3. **API** — `/api/issues?overdue=1&owner=<x>`; owner, owner_source, due_at, grace_until in every Issue JSON;
   `/api/governance/metrics` returning the `Report`.
4. **Dashboard owners panel** — `OpenByOwner` / `OverdueByOwner`, MTTR by severity, on-time rate; overdue badge
   on Issue rows.
5. **`alert --digest`** — build items with `DigestItemFromIssue(issue, assignment, fixCommand)` (fix command from
   the remediation sidecar, e.g. `cloud-posture fix --issue <id>`), `BuildDigests` with
   `Since = now - cfg.Governance.Digest.Period()`, then `SendDigests` with
   `NewFileLedger(<work_dir>/digest-ledger.json)` and `cfg.Governance.Digest.DedupWindow()`; sender by
   `digest.sink`: slack → `SlackDigestSender`, stdout → print `Text()`; teams/email/webhook senders are not
   written yet (email needs an SMTP config block; secrets via `*_env` only).
6. **Ticketing** — Jira/GitHub sinks should create one ticket per Issue (not per finding) with the assignee
   from `Owner` and the due date from `DueAt` (Datadog/Jira bar).
7. **Risk SLA** — `internal/risk` still carries its own band SLA (7/30/90/180 days from `first_seen`) on
   `Ranked.SLADays/DueAt`; once Issues carry governance due dates, finding-level output should show the
   governance values or drop the risk ones, so users never see two due dates.

## `governance init`: proposals from a clear majority only

`cloud-posture governance init` reads the owner/team tags in the database and proposes `defaults.owner`,
`defaults.account_owners` (per `provider/account`) and `defaults.provider_owners` (only for a provider whose
resources carry owner tags and some of whose accounts got no owner). A value is proposed only when it is the
strict plurality **and** holds at least `governance.defaults.min_owner_share` (default 0.5) of the tagged
resources in that scope; a tie or a weak plurality proposes nothing and the comment says why ("the most common
owner tag "finance" is on 2 of 14 tagged resources (14%), below the 50% min_owner_share"). On the lab this leaves
`defaults.owner` unset, so finance no longer owns the Kubernetes, GitHub and Okta Issues by default (W6-POLISH,
competitive delta r4 #5).

`--write` adds the block: appended when the config has no `governance:` key, put in place of an empty one
(`governance: {}`), and refused for a non-empty block unless `--force`, which replaces only the generated parts
(`owner-tag-*` and `iac-codeowners` rules, `defaults.owner` / `owner_tags` / `account_owners` / `provider_owners`,
`codeowners_file`) and keeps your rules (first, so they still win), other settings and comments. The file is
written through a temporary file and renamed only when the result loads and validates; a symlinked config is
refused and the file keeps its mode.
