# nimbus — working notes for agents

Read `CLAUDE_CONTEXT.md` first (goal, layout, contracts, reference designs). Planning lives in `.planning/` (PROJECT, ROADMAP, STATE). Competitor bars: `docs/research/competitors.md`.

Rules: research competitors before a new feature; tests first; `go vet ./... && go test ./...` and `cd python && pytest -q` before claiming done; never `go mod tidy` in parallel sessions; secrets only from env.

Methodology: `docs/development_methodology_and_coding_rulebook.md` is the source of truth for how we plan, build, verify and ship (failing test first, explicit-file staging, no push/merge/deploy without explicit authorization, no "done" without executable evidence). Session logs live in `docs/sessions/YYYY-MM-DD-<topic>.md`.

Competitive bar (standing rule from Bobby): every feature track names the best-in-class competitor behaviour from `docs/research/competitive-feature-matrix.md` and its acceptance test proves the bar is met or beaten; after each wave an independent competitive delta review (`docs/research/competitive-delta-<date>.md`) compares what landed to best-in-class and files shortfalls as the next items. "Exists" is not "done"; "as good as the leader or better" is.
