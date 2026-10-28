/* Carapace runtime code-integrity + server-nonce attestation (Slice D).
 *
 * Denies: rea Cluster G — defeats the value of a Frida/debugger PATCH. An
 * attacker who modifies a "hot" function (e.g. NOPs a license check) changes its
 * code bytes; the attestation the client returns to the server then no longer
 * matches, so the server rejects the session.
 *
 * Mechanism:
 *   checksum = SHA-256(bytes of the hot function, as loaded in memory)
 *   response = HMAC-SHA256(key, nonce || checksum)
 * The SERVER issues a fresh random nonce each challenge and holds the known-good
 * checksum; it recomputes HMAC(key, nonce || good_checksum) and compares. A
 * patched binary produces a different checksum -> different response -> reject.
 * A replayed response fails because the nonce changed (see harden/attest_server.py).
 *
 * HONEST TIER (CLAUDE.md §3):
 *   - Client-side self-checksum ALONE: *Meaningful*. Bypass: Frida hooks the
 *     checksum reader to return the pristine bytes, or hooks the HMAC to replay
 *     a captured-good value.
 *   - Server-NONCE binding (this design): pushes toward *Strong* — a one-time
 *     hook at resume isn't enough; the attacker must defeat the check LIVE on
 *     every fresh challenge, and cannot replay. Residual bypass: sustained
 *     hooking / full emulation, and the client key can be extracted (so secrecy
 *     rests on the server nonce + the server holding the good checksum, NOT on
 *     the client key). Real deployments provision the key server-side and store
 *     it in a TEE; the demo key below is illustrative only.
 *
 * This is cost, not prevention. It is NOT a substitute for keeping secrets
 * server-side (the only truly Strong tier).
 */
#ifndef CARAPACE_INTEGRITY_H
#define CARAPACE_INTEGRITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Demo shared key (client + reference server). In production this is provisioned
 * per-device server-side and kept in a TEE — never a compile-time constant. The
 * reference server (attest_server.py) uses this same value via --key. */
#define CARAPACE_ATTEST_KEY_HEX \
    "7c9e6a5f1b2d4e8a0c3f6b9d2e5a8c1f4b7e0a3d6c9f2b5e8a1d4c7f0b3e6a9d"

/* SHA-256 of the hot function's loaded code bytes -> out[32]. */
void carapace_hotfn_checksum(uint8_t out[32]);

/* Attestation response to a server nonce: HMAC-SHA256(key, nonce || checksum).
 * Writes 32 bytes to out_mac. */
void carapace_integrity_response(const uint8_t *nonce, size_t nonce_len,
                                 uint8_t out_mac[32]);

/* Primitives, exposed for tests / reuse. */
void carapace_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void carapace_hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* CARAPACE_INTEGRITY_H */
