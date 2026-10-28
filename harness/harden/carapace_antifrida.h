/* Carapace anti-Frida detector (Slice D).
 *
 * Denies: rea Cluster G — Frida is rea's only in-process MODIFICATION path
 * (start_frida_session + load_frida_script). This scans the process for the
 * observable footprint Frida leaves when it attaches/injects on Linux.
 *
 * Three independent, cheap heuristics (any one trips detection):
 *   MAPS    : /proc/self/maps contains a frida-agent / frida-gadget / gum mapping
 *   THREADS : /proc/self/task/<tid>/comm names a Frida worker (gum-js-loop, …)
 *   PORT    : something is LISTENing on the default frida-server port 27042
 *
 * TIER (CLAUDE.md §3): *Meaningful*. NAMED BYPASS: Frida stalker/stealth modes,
 * a renamed frida-gadget, a non-default port, and an attacker who edits these
 * signatures once found. Combine with the anti-ptrace guard and server-nonce
 * integrity attestation — no single client check is sufficient.
 */
#ifndef CARAPACE_ANTIFRIDA_H
#define CARAPACE_ANTIFRIDA_H

#include <stddef.h>

#define CARAPACE_FRIDA_MAPS    0x1
#define CARAPACE_FRIDA_THREADS 0x2
#define CARAPACE_FRIDA_PORT    0x4

#ifdef __cplusplus
extern "C" {
#endif

/* Scan the current process. Returns a bitmask of CARAPACE_FRIDA_* (0 = clean).
 * If detail != NULL, writes a short human-readable reason (which signals fired).
 */
int carapace_antifrida_scan(char *detail, size_t detail_len);

#ifdef __cplusplus
}
#endif

#endif /* CARAPACE_ANTIFRIDA_H */
