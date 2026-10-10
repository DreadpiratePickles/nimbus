# Cloud ground-truth lab. UNVERIFIED until lab credentials exist (see docs/benchmark.md).
# Every target refuses to run without NIMBUS_E2E=1; the lab is deliberately vulnerable.
#   NIMBUS_E2E=1 make -C lab/terraform lab-up   TF_VAR_external_account_id=... TF_VAR_expires_at=2026-10-10T06:00:00Z
#   NIMBUS_E2E=1 make -C lab/terraform lab-down
TERRAFORM ?= $(shell command -v tofu >/dev/null 2>&1 && echo tofu || echo terraform)
CLOUD ?= aws

.PHONY: guard lab-up lab-down validate

guard:
	@test "$(NIMBUS_E2E)" = "1" || { echo "set NIMBUS_E2E=1 to touch a real cloud account"; exit 1; }

lab-up: guard
	cd $(CLOUD) && $(TERRAFORM) init -input=false && $(TERRAFORM) apply -input=false -auto-approve -var nimbus_e2e=1

lab-down: guard
	cd $(CLOUD) && $(TERRAFORM) destroy -input=false -auto-approve -var nimbus_e2e=1

# Offline fmt + validate (plan v3 §9 item 1 step 0); needs no credentials, leaves no .terraform/ behind.
validate:
	TERRAFORM=$(TERRAFORM) ./validate.sh
