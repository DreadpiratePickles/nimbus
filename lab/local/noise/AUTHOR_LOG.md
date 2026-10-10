# P0-NOISE author log

Author: independent noise-estate author (Opus subagent), 2026-10-09.
Deliverables: `lab/local/noise/estate.yaml`, `lab/noise_truth.yaml`, `lab/local/noise/author_noise.py` (single source for both).

## Independence

The task prompt forbade reading: `internal/attackpath/**`, `internal/risk/**`, `docs/scoring.md`, `lab/ground_truth.yaml`,
`lab/known_gaps.yaml`, `internal/graph/**`, `docs/benchmark.md`, `docs/council/**`, `docs/sessions/**`.
None of these was opened, grepped or listed. Engine source was not read, run or modified. No tests or ground truth were edited. Git was not touched.

## Every file read (complete list)

| File | How | Why |
|---|---|---|
| `lab/local/estate.yaml` | full `cat` | estate schema/format (it also contains the main lab's scenario content, which was visible as a side effect) |
| `lab/local/estate/estate.go` | full `cat` | generator schema (KnownFields, Validate rules, finding emission) |
| `lab/local/gen/main.go` | full `cat` | generator flags (`-in`, `-out` already exist) |
| `internal/model/model.go` | full `cat` | Finding/Resource/AttackPath schema |
| `internal/adapters/adapter.go` | full `cat` | native parser |
| `testdata/native.findings.json` | full `cat` | typed `related` wire form |
| `internal/catalog/catalog.yaml` | lines 1-80, 1085-1230, plus awk/grep summaries of entry → weaknesses → prowler aliases | canonical check ids and weakness vocabulary |
| `.planning/IMPLEMENTATION_PLAN_v3.md` | `grep -n 'P0-NOISE'` (one grep with `-A25` whose output was truncated to a 2 KB preview of the table rows around line 55), then lines 299 and 472 only | P0-NOISE scope and acceptance |
| `Makefile` (repo root) | `grep -n lab` only | check for an existing lab target (`lab-local` exists) |
| `go.sum` | `grep yaml.v3` only | copy two checksum lines into a throwaway scratchpad module used to parse-check the YAML |

Directory listings: `lab/`, `lab/local/`, `lab/local/gen/`, `lab/local/estate/`, `lab/local/out/`.

## Generation

    go run ./lab/local/gen -in lab/local/noise/estate.yaml -out lab/local/out/noise.findings.json
    # -> 311 records (103 seeded weaknesses, 208 inventory) across 300 resources; exit 0

No generator change was needed. To re-author both YAML files: `python3 -I lab/local/noise/author_noise.py .`
