# nimbus — working notes for agents

Read `CLAUDE_CONTEXT.md` first (goal, layout, contracts, reference designs). Planning lives in `.planning/` (PROJECT, ROADMAP, STATE). Competitor bars: `docs/research/competitors.md`.

Rules: research competitors before a new feature; tests first; `go vet ./... && go test ./...` and `cd python && pytest -q` before claiming done; never `go mod tidy` in parallel sessions; secrets only from env.
