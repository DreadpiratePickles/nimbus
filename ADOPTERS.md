# Adopters

Organisations that use nimbus (binary `cloud-posture`) in a real workflow. That means CI on pull
requests, scheduled scans, fix PRs or audit evidence, not a one-off evaluation. Named adopters matter
more to this project than stars: the plan's adoption metric is named organisations
([`docs/metrics.md`](docs/metrics.md)).

**Status:** no adopters are listed yet. nimbus has not yet been run against a live cloud account by
its maintainers ([README](README.md#status)), so early users are effectively design partners. If you
are one, please tell us what broke: open an issue.

| Organisation | How it uses nimbus | Since | Contact / reference (optional) |
|---|---|---|---|
| | | | |

## Add yourself

1. Fork the repository and add one row to the table above, in alphabetical order. Fill in:
   - **Organisation**: the legal or commonly used name, linked to its website if you like.
   - **How it uses nimbus**: one line, for example "Action on every Terraform PR in 40 repos", "nightly
     `scan` of the AWS org, fix PRs into the platform repo", or "evidence ZIP for SOC 2".
   - **Since**: month and year (`2026-11`).
   - **Contact / reference**: optional. A public blog post, talk or GitHub handle. No email addresses.
2. Commit with a DCO sign-off (`git commit -s -m "docs: add <org> to ADOPTERS"`).
3. Open a pull request. A maintainer may ask you to confirm from an address at that organisation. We
   only list organisations that agree to be listed.

To be removed, open a pull request that deletes your row, or email the address in
[SECURITY.md](SECURITY.md). We act on it without questions.

If you cannot be named publicly, you can still help: anonymous feedback in an issue about scale,
false positives or missing coverage shapes the roadmap.
