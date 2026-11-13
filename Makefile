# Carapace — top-level entry point. Measure it, harden it, prove it.
#
#   make demo     see it in ~30s: audit a sample, show its plan, prove the defenses
#   make verify   run every verify slice and print one posture summary
#   make audit    audit a binary:  make audit BIN=path/to/elf
#   make report   full audit + ordered hardening plan: make report BIN=path/to/elf
#   make clean    remove build artifacts

BIN ?= harness/sample/sample_dev
TARGET ?= http://127.0.0.1:11434
CRACKME_BUILD := harness/crackme/build

.PHONY: demo verify audit audit-pe audit-macho report harden harden-pe harden-macho \
        install-skill slice-k-run slice-k-run-mock clean help
.DEFAULT_GOAL := help

demo:
	@echo "### 1/2  MEASURE — audit a sample build + show its hardening plan"
	@$(MAKE) -s -C harness/sample sample_dev
	@python3 skill/carapace.py report harness/sample/sample_dev
	@echo
	@echo "### 2/2  PROVE — demonstrate every countermeasure firing"
	@bash harness/verify/run_all.sh

verify:
	@bash harness/verify/run_all.sh

audit:
	@$(MAKE) -s -C harness/sample sample_dev
	@python3 skill/carapace.py audit "$(BIN)"

audit-pe:
	@python3 harness/audit/pe_exposure_audit.py "$(BIN)"

audit-macho:
	@python3 harness/audit/macho_exposure_audit.py "$(BIN)"

report:
	@$(MAKE) -s -C harness/sample sample_dev
	@python3 skill/carapace.py report "$(BIN)"

harden:
	@$(MAKE) -s -C harness/sample sample_dev
	@python3 skill/carapace.py harden "$(BIN)"

harden-pe:
	@python3 skill/carapace.py harden "$(BIN)"

harden-macho:
	@python3 harness/harden/carapace_macho_strip.py --in "$(BIN)" --out "$(BIN).stripped"

install-skill:
	@python3 skill/carapace.py install

# One command: build the sealed CrackMe pair, drive an attacker agent against the
# baseline AND hardened builds, and print the honest before/after. OPERATOR-GATED:
# run this INSIDE your own isolated VM, pointed at your own model. It downloads no
# model; --target is the endpoint you point it at. Real numbers need your VM +
# chosen model + hardware (see docs/workflow/slice-k-empirical-runbook.md).
slice-k-run:
ifeq ($(strip $(MODEL)),)
	@echo "Usage: make slice-k-run MODEL=<model> [TARGET=http://host:11434]"
	@echo "  Operator-gated: run INSIDE your isolated VM against your own model."
	@echo "  No-model pipeline self-test (safe anywhere): make slice-k-run-mock"
	@exit 2
else
	@echo "### build the sealed CrackMe pair"
	@bash harness/crackme/build_crackme.sh >/dev/null
	@echo "### drive the attacker agent (model=$(MODEL) target=$(TARGET)) and score"
	@python3 harness/measure/slice_k_run.py --backend ollama \
	    --model "$(MODEL)" --target "$(TARGET)" \
	    --baseline-bin $(CRACKME_BUILD)/crackme_baseline \
	    --hardened-bin $(CRACKME_BUILD)/crackme_hardened \
	    --seal $(CRACKME_BUILD)/SEAL.json \
	    --ledger $(CRACKME_BUILD)/crackme_hardened.honey-ledger.json \
	    --out-dir $(CRACKME_BUILD)
endif

# Prove the WHOLE pipeline end-to-end with a deterministic MOCK attacker — no model,
# no network, no VM. Loudly labelled NOT A MEASUREMENT; yields no cost number.
slice-k-run-mock:
	@bash harness/crackme/build_crackme.sh >/dev/null
	@python3 harness/measure/slice_k_run.py --backend mock \
	    --baseline-bin $(CRACKME_BUILD)/crackme_baseline \
	    --hardened-bin $(CRACKME_BUILD)/crackme_hardened \
	    --seal $(CRACKME_BUILD)/SEAL.json \
	    --ledger $(CRACKME_BUILD)/crackme_hardened.honey-ledger.json \
	    --out-dir $(CRACKME_BUILD)

clean:
	@$(MAKE) -s -C harness/sample clean
	@rm -f harness/verify/ptrace_attach_probe core core.*
	@echo "cleaned."

help:
	@echo "Carapace — defensive anti-reverse-engineering hardening & audit harness"
	@echo
	@echo "  make demo     see it in ~30s (audit a sample, show the plan, prove the defenses)"
	@echo "  make verify   run every verify slice and print one posture summary"
	@echo "  make audit    BIN=<elf>   scored exposure report for your own binary"
	@echo "  make audit-pe BIN=<exe>   scored exposure report for a Windows PE"
	@echo "  make audit-macho BIN=<o> scored exposure report for a Mach-O (macOS/iOS)"
	@echo "  make report   BIN=<elf>   full audit + the ordered hardening plan"
	@echo "  make harden   BIN=<elf>   one command: apply every post-build hardening (honest)"
	@echo "  make harden-pe BIN=<exe>  PE harden: COFF/debug strip + decoy overlay + honeytokens"
	@echo "  make harden-macho BIN=<o> strip LOCAL symbols from a Mach-O (strip -x equivalent)"
	@echo "  make install-skill        symlink the skill into .claude/skills/carapace"
	@echo "  make slice-k-run MODEL=<m> [TARGET=url]  empirical before/after (OPERATOR VM; honest)"
	@echo "  make slice-k-run-mock     prove the empirical pipeline with a MOCK attacker (no model)"
	@echo "  make clean    remove build artifacts"
	@echo
	@echo "Blue team only: audit/harden software you own or are authorized to protect."
