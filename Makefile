GO ?= go
BIN ?= bin/cloud-posture

.PHONY: build test lint python-test install dashboard-demo docker release clean site site-serve

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

docker:
	docker build -t ghcr.io/dreadpiratepickles/cloud-posture:latest .

release:
	GOOS=linux GOARCH=amd64 $(GO) build -o dist/cloud-posture_linux_amd64 ./cmd/cloud-posture
	GOOS=linux GOARCH=arm64 $(GO) build -o dist/cloud-posture_linux_arm64 ./cmd/cloud-posture
	GOOS=darwin GOARCH=amd64 $(GO) build -o dist/cloud-posture_darwin_amd64 ./cmd/cloud-posture
	GOOS=darwin GOARCH=arm64 $(GO) build -o dist/cloud-posture_darwin_arm64 ./cmd/cloud-posture
	GOOS=windows GOARCH=amd64 $(GO) build -o dist/cloud-posture_windows_amd64.exe ./cmd/cloud-posture

# Website + docs (MkDocs, custom cwm theme) -> site/public/
SITE_PY ?= $(if $(wildcard python/.venv/bin/python),python/.venv/bin/python,python3)

site:
	$(SITE_PY) -m pip install -q --disable-pip-version-check -r site/requirements.txt
	$(SITE_PY) -m mkdocs build --strict -f site/mkdocs.yml

site-serve:
	$(SITE_PY) -m mkdocs serve -f site/mkdocs.yml

clean:
	rm -rf bin dist cloud-posture-report cloud-posture-remediation .cloud-posture site/public
