# syntax=docker/dockerfile:1
#
# cloud-posture container image: one static Go binary on distroless, running as non-root.
#
# Two ways to build, one file:
#   * from source (local / `make docker`):   docker build -t cloud-posture .
#   * from goreleaser's prebuilt binaries:   BIN_STAGE=prebuilt (set by .goreleaser.yaml dockers_v2),
#     which copies dist/<platform>/cloud-posture instead of compiling, so the image contains exactly
#     the binary that was checksummed, signed and attested in the release.
# BuildKit only builds the stage that is actually referenced, so the unused stage is skipped.
#
# Base images are pinned by digest (Dependabot's docker ecosystem can bump them). The Python
# intelligence layer and third-party scanners (prowler, checkov, trivy, steampipe) are NOT baked in:
# they were previously installed with `curl | sh` from `main`, which is exactly the supply-chain
# pattern the 2026 Trivy/KICS compromises exploited. Run them in their own pinned images and feed
# their output to `cloud-posture ingest`.
ARG BIN_STAGE=build

FROM golang:1.26@sha256:52d57e3542f28ad72e9a1084e209366d8ca6af04997636134c138d16702a70a6 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=0.1.0-dev
ARG COMMIT=""
ARG DATE=""
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/cloud-posture ./cmd/cloud-posture

FROM scratch AS prebuilt
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/cloud-posture /out/cloud-posture

FROM ${BIN_STAGE} AS bin

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=bin /out/cloud-posture /usr/local/bin/cloud-posture
# distroless "nonroot" is uid/gid 65532; state goes under the mounted working directory.
USER 65532:65532
WORKDIR /work
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cloud-posture"]
CMD ["--help"]
