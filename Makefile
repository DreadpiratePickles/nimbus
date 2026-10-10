GO ?= go
BIN ?= bin/cloud-posture

.PHONY: build test lint python-test install dashboard-demo ui-deps ui-test docker release release-snapshot verify vulncheck gosec-high clean lab-local lab-noise groundtruth groundtruth-noise groundtruth-golden lab-golden lab-validate readme-check readme-bench

build:
	$(GO) build -o $(BIN) ./cmd/cloud-posture

install: build
	install -m 0755 $(BIN) $${GOBIN:-$$HOME/go/bin}/cloud-posture
	pip install -e "python[all]"

test:
	$(GO) vet ./... && $(GO) test ./...

python-test:
	cd python && python3 -m pytest -q

lint:
	$(GO) vet ./...

dashboard-demo: build
	$(BIN) ingest testdata -q -o summary && $(BIN) dashboard --out cloud-posture-report/index.html

# Playwright and its Chromium (the install is a no-op when the browser is already present;
# CI installs with --with-deps first).
ui-deps:
	cd tools/ui-smoke && npm ci --silent && npx playwright install chromium

# Playwright smoke test of the cwm dashboard (docs/design/cwm-dashboard-spec.md §9).
ui-test: build ui-deps
	$(BIN) ingest testdata -q -o summary && $(BIN) dashboard --out cloud-posture-report/index.html
	cd tools/ui-smoke && node smoke.mjs ../../cloud-posture-report/index.html

# Local ground-truth lab (docs/benchmark.md): regenerate the seeded estate's native findings.
lab-local:
	$(GO) run ./lab/local/gen -in lab/local/estate.yaml -out lab/local/out/estate.findings.json

# Independently authored noise estate (lab/local/noise, labels in lab/noise_truth.yaml).
lab-noise:
	$(GO) run ./lab/local/gen -in lab/local/noise/estate.yaml -out lab/local/out/noise.findings.json

# Score the engine against both the labelled lab (lab/ground_truth.yaml) and the noise estate
# (lab/noise_truth.yaml) in one run: both tables are printed. Known gaps in lab/known_gaps.yaml
# (`gaps:` and `noise:`) are tolerated; GROUNDTRUTH_STRICT=1 make groundtruth ignores them.
groundtruth:
	$(GO) test ./tests/groundtruth -count=1 -v

# Noise estate only (TestNoiseTruthIntegrity, TestNoiseEstate).
groundtruth-noise:
	$(GO) test ./tests/groundtruth -count=1 -v -run 'Noise'

# Scanner interop only: Checkov/Trivy goldens of lab/terraform ingested through the real adapters and
# scored against lab/golden/expectations.yaml (TestGoldenIntegrity, TestGoldenScannerInterop).
groundtruth-golden:
	$(GO) test ./tests/groundtruth -count=1 -v -run 'Golden'

# Regenerate the Checkov/Trivy goldens (lab/golden/README.md pins the versions; CHECKOV=/TRIVY= override).
lab-golden:
	lab/golden/regen.sh

# Offline `fmt -check` + `validate` of lab/terraform/{aws,azure,gcp} (OpenTofu or Terraform; no credentials).
lab-validate:
	lab/terraform/validate.sh

docker:
	docker build -t ghcr.io/dreadpiratepickles/cloud-posture:latest .

# Local, unsigned, unpublished build of every release artifact (archives, checksums, image) via
# goreleaser. Real releases are cut only by .github/workflows/release.yml on a v* tag.
release-snapshot:
	goreleaser release --snapshot --clean --skip=publish,sign,sbom

release: release-snapshot

GOVULNCHECK ?= $(shell command -v govulncheck 2>/dev/null || echo $${GOBIN:-$$($(GO) env GOPATH)/bin}/govulncheck)

vulncheck:
	@test -x "$(GOVULNCHECK)" || $(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GOVULNCHECK) ./...

# High-severity, high-confidence gosec findings fail; skipped (with a note) when gosec is absent.
gosec-high:
	@if command -v gosec >/dev/null 2>&1; then gosec -quiet -severity high -confidence high ./...; \
	else echo "gosec not installed; skipping (go install github.com/securego/gosec/v2/cmd/gosec@latest)"; fi

# Rewrite the README benchmark block from lab/local/out/benchmark.json (run `make groundtruth` first);
# `go run ./tools/readme-bench -check` fails when the block is stale.
readme-bench:
	$(GO) run ./tools/readme-bench -json lab/local/out/benchmark.json -readme README.md

# README truth (plan v3 §0.2 row 0-6): every sentence with a number or a superlative must carry a
# `<!-- claim: ref -->` marker that resolves to a Go test, a pytest node id or a Markdown section.
readme-check:
	python3 tools/readme-claims/test_check.py -q
	python3 tools/readme-claims/check.py --list README.md

# The gate before any PR or release: Go vet+tests, Python tests, dashboard smoke, vuln + SAST scans.
verify: test python-test ui-test vulncheck gosec-high readme-check
	@echo "make verify: all checks passed"

clean:
	rm -rf bin dist cloud-posture-report cloud-posture-remediation .cloud-posture
