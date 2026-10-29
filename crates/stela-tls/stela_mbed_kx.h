/* Checked opaque crypto adapter. Original Stela glue, MIT. */
#ifndef STELA_MBED_KX_H
#define STELA_MBED_KX_H
#include <stddef.h>
struct stela_mbed_kx;
typedef int (*stela_mbed_rng)(void *, unsigned char *, size_t);
/* kind 1: X25519; kind 2: secp256r1. Outputs stay unchanged on failure. */
int stela_mbed_kx_new(unsigned kind, stela_mbed_rng, void *,
                      struct stela_mbed_kx **, unsigned char *, size_t, size_t *);
int stela_mbed_kx_shared(struct stela_mbed_kx *, const unsigned char *, size_t,
                         stela_mbed_rng, void *, unsigned char *, size_t);
void stela_mbed_kx_free(struct stela_mbed_kx *);
#endif
