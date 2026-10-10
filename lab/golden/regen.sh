#!/usr/bin/env bash
# Regenerate the Checkov and Trivy goldens for lab/terraform/{aws,azure,gcp} (no cloud, no credentials).
#
#   CHECKOV=/path/to/checkov TRIVY=/path/to/trivy lab/golden/regen.sh
#
# Writes lab/golden/<tool>/<version>/{aws,azure,gcp}.json plus cmd.txt and sha256.txt.
# Outputs are the tools' raw JSON with one documented normalisation: Checkov's file_abs_path
# carries the runner's absolute checkout path, which is replaced by /src (see cmd.txt).
# Run from anywhere; paths are resolved against the repository root.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
CHECKOV="${CHECKOV:-checkov}"
TRIVY="${TRIVY:-trivy}"
lab_commit="$(git rev-parse --short HEAD 2>/dev/null || echo 'none (working tree, not a git checkout)')"
now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

ck_ver="$("$CHECKOV" --version | tr -d '[:space:]')"
tv_ver="$("$TRIVY" --version | awk '/^Version:/ {print $2; exit}')"

ck_dir="lab/golden/checkov/$ck_ver"
tv_dir="lab/golden/trivy/$tv_ver"
mkdir -p "$ck_dir" "$tv_dir"
tv_cache="$(mktemp -d)"
trap 'rm -rf "$tv_cache"' EXIT

{
  echo "tool: checkov $ck_ver (pip install checkov==$ck_ver)"
  echo "date: $now"
  echo "lab commit: $lab_commit"
  echo "cwd: repository root"
  echo "normalisation: absolute checkout path in file_abs_path replaced by /src (sed s#<root>#/src#g); nothing else edited"
  echo "exit status 1 means failed checks were found (expected for a deliberately vulnerable lab)"
} > "$ck_dir/cmd.txt"
{
  echo "tool: trivy $tv_ver (brew install trivy; embedded checks via --skip-check-update, so the check set is pinned by the trivy version)"
  echo "date: $now"
  echo "lab commit: $lab_commit"
  echo "cwd: repository root"
  echo "normalisation: none (ReportID and CreatedAt differ per run)"
} > "$tv_dir/cmd.txt"

for cloud in aws azure gcp; do
  cmd=("$CHECKOV" -d "lab/terraform/$cloud" -o json --skip-download)
  echo "command ($cloud): checkov -d lab/terraform/$cloud -o json --skip-download" >> "$ck_dir/cmd.txt"
  set +e
  "${cmd[@]}" 2>/dev/null | sed "s#$root#/src#g" > "$ck_dir/$cloud.json"
  st=${PIPESTATUS[0]}
  set -e
  echo "exit ($cloud): $st" >> "$ck_dir/cmd.txt"
  [ "$st" -le 1 ] || { echo "checkov failed on $cloud ($st)" >&2; exit 1; }

  echo "command ($cloud): trivy config --skip-check-update --cache-dir <tmp> -f json lab/terraform/$cloud" >> "$tv_dir/cmd.txt"
  "$TRIVY" config --quiet --skip-check-update --cache-dir "$tv_cache" -f json "lab/terraform/$cloud" > "$tv_dir/$cloud.json"
  echo "exit ($cloud): 0" >> "$tv_dir/cmd.txt"
done

for d in "$ck_dir" "$tv_dir"; do
  (cd "$d" && shasum -a 256 aws.json azure.json gcp.json > sha256.txt)
done
echo "wrote $ck_dir and $tv_dir"
