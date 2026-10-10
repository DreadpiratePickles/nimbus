# AGENTS.md: working in this repository as an AI agent

This file is for any coding agent (Claude Code, Codex, Cursor, Copilot, Aider and others) and for the
humans who run them. It mirrors [`CLAUDE.md`](CLAUDE.md), written for agents in general. If this file and
[`docs/development_methodology_and_coding_rulebook.md`](docs/development_methodology_and_coding_rulebook.md)
disagree, the rulebook wins.

Naming: the project is `nimbus` and the binary is `cloud-posture` until the naming decision (O3)
lands. Use those two names exactly.

## Read order (before you change anything)

1. This file.
2. [`CLAUDE_CONTEXT.md`](CLAUDE_CONTEXT.md): goal, layout, contracts, reference designs.
3. [`docs/development_methodology_and_coding_rulebook.md`](docs/development_methodology_and_coding_rulebook.md): how we plan, build, verify and ship.
4. [`.planning/IMPLEMENTATION_PLAN_v3.md`](.planning/IMPLEMENTATION_PLAN_v3.md): find **your track**,
   its owner package set, items and acceptance tests (§4, §9). Then read
   [`docs/council/decision.md`](docs/council/decision.md) for the binding decisions.
5. The newest file in [`docs/sessions/`](docs/sessions): what happened last, and what is in flight.
6. The domain docs your track touches: [`docs/benchmark.md`](docs/benchmark.md),
   [`docs/scoring.md`](docs/scoring.md), [`docs/checks.md`](docs/checks.md),
   [`docs/research/competitors.md`](docs/research/competitors.md) (research competitors before a new feature).

A track with an independence rule, such as the noise-estate author, must **not** read the files its
brief forbids. It also records every file it did read in its session log.

## Package ownership (parallel agents)

- **One agent per track, and each track edits only its owner package set** (plan v3 §4). Other
  agents may be editing neighbouring packages right now. If you need a change outside your set,
  write it down as a hand-off in the session log. Do not make it.
- Shared contracts (the edge attribute contract in `internal/graph/attr.go`, the path Issue contract in
  `internal/model/issue.go`) change only through their owning track, and are frozen after verifier review.
- **Never run `go mod tidy`** in a parallel session, and never add a dependency outside a
  dependency-owning track.
- An independent verifier re-probes every track before it is accepted. Write your evidence so a
  stranger can re-run it.

## How to make a change

1. **Failing test first.** Write the test, run it, and record the red output (the command plus the
   failing line) in the session log. Then make the smallest change that turns it green. Bug fixes
   include a regression test. New checks or path rules need a true-positive fixture and a near-miss
   fixture that must not fire.
2. **Run the gate before you say "done":**
   ```sh
   export CLOUD_POSTURE_NO_NETWORK=1      # tests must not depend on the network
   go vet ./... && go test ./...          # or: make test
   cd python && python3 -m pytest -q      # or: make python-test
   make groundtruth                       # if you touched attack paths, risk, graph or the lab
   make readme-check                      # if you touched README.md
   make verify                            # the full gate: all of the above plus ui-test, govulncheck, gosec
   ```
   Paste the tail of the output as evidence. Never say "done" without executable evidence. If something
   cannot be verified locally (for example, a live cloud), say so explicitly.
3. **Claims.** A README sentence with a number or a superlative needs a
   `<!-- claim: <Go test | pytest node id | file.md#section> -->` marker that resolves. Do not add a
   capability to a comparison table until it passes its acceptance test on the lab.
4. **Formatting:** `gofmt` on Go files you own. Keep docs in plain, direct English.

## Session logs (mandatory)

- Append to `docs/sessions/YYYY-MM-DD-<topic>.md` **during** the session, not at the end. Start your
  section with `## <track> (<agent/model>)`. Record scope, files read (when an independence rule
  applies), red → green evidence, gates run with results, decisions and why, and what you did not do.
- When context gets long, write the log first, then recontextualise from the log and these
  instruction files rather than from chat memory.

## Hard rules

- **No git operations without explicit authorisation** from the owner: no commit, push, merge, tag,
  release or deploy. When commits are authorised, stage files explicitly (`git add <file>`, never
  `git add -A` or `.`), use conventional-commit titles, and sign off.
- **DCO:** every commit needs `Signed-off-by:`. An agent cannot certify the DCO itself. The human who
  submits the work signs off and takes responsibility for it ([OPEN_SOURCE_PROMISE.md](OPEN_SOURCE_PROMISE.md)).
- **Secrets:** credentials come from the environment only. Never write a secret's value into code,
  tests, logs, session notes, memory, commits or chat. Record only *where* a secret lives. Use
  `testdata/` fixtures, never real account ids or customer data.
- **Supply chain:** pin GitHub Actions by full commit SHA with a `# vX.Y.Z` comment. Never add a
  `curl | sh` install. Never weaken the release signing or verification path.
- **Read-only by design:** the scan path must not need write permissions in a cloud account. Anything
  that writes (onboarding deploys, rollbacks, `fix --apply`, probes) is explicit and separately authorised.
- **Implemented ≠ deployed ≠ verified.** Report each state separately.

## Useful commands

```sh
make build                                        # bin/cloud-posture
./bin/cloud-posture ingest lab/local/out/estate.findings.json --source native \
  --config lab/local/cloud-posture.lab.yaml       # the synthetic lab
./bin/cloud-posture paths --config lab/local/cloud-posture.lab.yaml
./bin/cloud-posture plan  --config lab/local/cloud-posture.lab.yaml
GROUNDTRUTH_STRICT=1 make groundtruth             # strict benchmark (known gaps fail)
make lab-local                                    # regenerate the lab findings after editing estate.yaml
python3 tools/readme-claims/check.py --list       # list every README claim and its evidence
```

## Competitive bar (standing rule)
Before building a capability, read its row in `docs/research/competitive-feature-matrix.md` and the matching "Features nimbus should steal" entry; write the acceptance test so it proves nimbus matches or beats the best-in-class behaviour, and cite the competitor in the test name or comment. After each wave, run the competitive delta review and act on its shortfalls first.
