# Carapace sample — one source, two builds.
# The ONLY difference between the two targets is -DCARAPACE_HARDENED + the guard
# object, so the audit's absent->present flip is attributable to the guards alone.
#
#   make            -> sample_baseline + sample_hardened
#   make clean

CC      ?= cc
CFLAGS  ?= -O0 -g -Wall -Wextra -fno-omit-frame-pointer
HARDEN  := ../harden
INCLUDE := -I$(HARDEN)

.PHONY: all clean
all: sample_baseline sample_hardened

# Unhardened: no guards linked. Audit should report both guards ABSENT.
sample_baseline: sample_app.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ sample_app.c

# Clean dev artifact (unstripped, with symbols) consumed by the Slice B identity
# transform. Built on demand (`make sample_dev`), not part of `all`.
sample_dev: sample_app.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ sample_app.c

# Hardened: same source + the guard TU, with CARAPACE_HARDENED calling the init.
# Audit should report both guards PRESENT (symbols setrlimit/prctl/ptrace +
# the "/proc/self/status","TracerPid" strings are now referenced).
sample_hardened: sample_app.c $(HARDEN)/carapace_guards.c $(HARDEN)/carapace_guards.h
	$(CC) $(CFLAGS) $(INCLUDE) -DCARAPACE_HARDENED -o $@ \
		sample_app.c $(HARDEN)/carapace_guards.c

# Slice D: integrity/attestation + anti-Frida guards. Built on demand.
# -O1 keeps the hot function a stable, bounded block (end marker right after it).
sample_attest: sample_attest.c $(HARDEN)/carapace_integrity.c $(HARDEN)/carapace_antifrida.c \
               $(HARDEN)/carapace_integrity.h $(HARDEN)/carapace_antifrida.h
	$(CC) -O1 -g -Wall -Wextra $(INCLUDE) -o $@ \
		sample_attest.c $(HARDEN)/carapace_integrity.c $(HARDEN)/carapace_antifrida.c \
		-lpthread -ldl

clean:
	rm -f sample_baseline sample_hardened sample_dev sample_release_* sample_attest sample_attest_*
