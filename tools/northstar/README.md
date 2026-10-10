# northstar — sum the `nimbus-closes-paths` footers

The north-star metric (plan v3 §8) is the number of attack paths that real changes close. nimbus
writes it as a footer line:

| where | footer |
|---|---|
| fix PRs (`cloud-posture fix --auto-pr`, `gitops.PRBody`) | `nimbus-closes-paths: N` |
| plan-diff comments (`cloud-posture pr-comment --plan-json`) | `nimbus-opens-paths: N`, `nimbus-escalates-paths: N`, `nimbus-lowers-paths: N` and `nimbus-closes-paths: N` |

`nimbus-lowers-paths` is de-escalation credit (a surviving path whose band the change drops, e.g.
High → Low); it is summed apart and never added to the closes total.

This tool sums them from GitHub search API responses. It never calls GitHub: fetch the pages
yourself (a token only needs public read for public repositories) and pipe them in.

```sh
# PR bodies (fix PRs)
gh api -X GET search/issues -f q='"nimbus-closes-paths" is:pr' -f per_page=100 --paginate > prs.json
# plan-diff comments are issue comments; search finds the PRs that carry them:
gh api -X GET search/issues -f q='"nimbus-closes-paths" in:comments is:pr' -f per_page=100 --paginate > commented.json

go run ./tools/northstar prs.json            # human summary
go run ./tools/northstar -json prs.json      # machine-readable
```

Rules (so the number cannot be inflated by quoting): a footer counts only when it is a line of its
own; the last footer in a body wins; items are de-duplicated by id across pages; values above
`-max-per-item` (default 10000) are rejected and reported. Note that search results for comment
text return the PR, whose `body` is the PR description: to count plan-diff comments exactly, fetch
each PR's comments (`gh api repos/O/R/issues/N/comments`) and wrap them as `{"items": [...]}`.

Fixture and test: `testdata/search.json`, `go test ./tools/northstar`.
Metric definition: docs/metrics.md; plan-diff design: docs/plan-diff.md.
