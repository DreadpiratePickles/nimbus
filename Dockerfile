# Multi-stage: Go binary + Python intelligence layer + the external scanners it aggregates.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/cloud-posture ./cmd/cloud-posture

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/cloud-posture /usr/local/bin/cloud-posture
COPY python /opt/nimbus/python
RUN pip install --no-cache-dir -e "/opt/nimbus/python[all]" prowler checkov \
 && curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
 && (curl -fsSL https://steampipe.io/install/steampipe.sh | sh || true)
ENV NIMBUS_PYTHON_DIR=/opt/nimbus/python
WORKDIR /work
EXPOSE 8080
ENTRYPOINT ["cloud-posture"]
CMD ["--help"]
