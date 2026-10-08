# STATE (2026-10-08)

- Build: `go build ./...` green on Go 1.26; `go test ./...` and `cd python && pytest` green (see README for counts).
- Nothing has run against a live cloud account yet; collectors/monitor/sinks are covered by fakes and httptest only.
- Known gaps: Kubernetes wildcard roles produce no finding; CloudTrail monitor polls 20 event-name filters per region; GitHub push-protection not checked; `risk_weights.json` not in wheel package-data (built-in copy used).
- Secrets: `nimbus.env` is git-ignored and holds a live GitHub token — rotate if it was ever shared.
