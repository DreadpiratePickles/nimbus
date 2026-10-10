#!/usr/bin/env bash
# Offline check of the cloud lab (plan v3 §9 item 1, step 0): `fmt -check` on lab/terraform and
# `init -backend=false` + `validate` on each root module. Needs no cloud credentials; `init` downloads
# the providers from the registry. Each module is validated in a temporary copy, so no .terraform/
# directory or lock file is left in the repository.
#
#   lab/terraform/validate.sh                # uses $TERRAFORM, else tofu, else terraform
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tf="${TERRAFORM:-}"
if [ -z "$tf" ]; then
  if command -v tofu >/dev/null 2>&1; then tf=tofu; elif command -v terraform >/dev/null 2>&1; then tf=terraform; else
    echo "neither tofu nor terraform is installed (brew install opentofu)" >&2; exit 2
  fi
fi
"$tf" version | head -1

echo "== $tf fmt -check -recursive lab/terraform"
"$tf" fmt -check -recursive -diff "$here"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for d in aws azure gcp; do
  cp -R "$here/$d" "$work/$d"
  echo "== $tf validate lab/terraform/$d"
  (cd "$work/$d" && "$tf" init -backend=false -input=false -no-color >/dev/null && "$tf" validate -no-color)
  grep -h -A1 '^provider' "$work/$d/.terraform.lock.hcl" | awk '/^provider/ {p=$2} /version/ {print "   provider " p " " $3}'
done
echo "lab/terraform: fmt and validate passed for aws, azure, gcp (never planned or applied)"
