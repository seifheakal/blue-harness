# Carapace — top-level entry point. Measure it, harden it, prove it.
#
#   make demo     see it in ~30s: audit a sample, show its plan, prove the defenses
#   make verify   run every verify slice and print one posture summary
#   make audit    audit a binary:  make audit BIN=path/to/elf
#   make report   full audit + ordered hardening plan: make report BIN=path/to/elf
#   make clean    remove build artifacts

BIN ?= harness/sample/sample_dev

.PHONY: demo verify audit audit-pe audit-macho report harden harden-pe harden-macho install-skill clean help
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
	@echo "  make clean    remove build artifacts"
	@echo
	@echo "Blue team only: audit/harden software you own or are authorized to protect."
