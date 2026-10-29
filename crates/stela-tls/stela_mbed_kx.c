/* Checked opaque crypto adapter. Original Stela glue, MIT.
 * No primitive implementation: all group, scalar, point and ECDH operations
 * call checked public Mbed TLS 3.6.7 APIs with a mandatory fallible RNG. */
#include "stela_mbed_kx.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include <string.h>

struct stela_mbed_kx {
    mbedtls_ecp_group group;
    mbedtls_mpi scalar;
    mbedtls_ecp_point public_key;
    unsigned kind;
};
void stela_mbed_kx_free(struct stela_mbed_kx *key) {
    if (!key) return;
    mbedtls_ecp_point_free(&key->public_key);
    mbedtls_mpi_free(&key->scalar);
    mbedtls_ecp_group_free(&key->group);
    mbedtls_platform_zeroize(key, sizeof(*key));
    mbedtls_free(key);
}
int stela_mbed_kx_new(unsigned kind, stela_mbed_rng rng, void *rng_context,
                      struct stela_mbed_kx **output, unsigned char *public_key,
                      size_t capacity, size_t *written) {
    if ((kind != 1 && kind != 2) || !rng || !output || !public_key || !written ||
        capacity < (kind == 1 ? 32u : 65u)) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    struct stela_mbed_kx *key = mbedtls_calloc(1, sizeof(*key));
    if (!key) return MBEDTLS_ERR_ECP_ALLOC_FAILED;
    mbedtls_ecp_group_init(&key->group);
    mbedtls_mpi_init(&key->scalar);
    mbedtls_ecp_point_init(&key->public_key);
    key->kind = kind;
    unsigned char encoded[65] = {0};
    size_t length = 0;
    int status = mbedtls_ecp_group_load(&key->group, kind == 1 ?
                         MBEDTLS_ECP_DP_CURVE25519 : MBEDTLS_ECP_DP_SECP256R1);
    if (!status) status = mbedtls_ecp_gen_keypair(&key->group, &key->scalar,
                                                &key->public_key, rng, rng_context);
    if (!status) status = mbedtls_ecp_point_write_binary(&key->group,
                         &key->public_key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                         &length, encoded, sizeof(encoded));
    if (!status && length != (kind == 1 ? 32u : 65u)) status = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!status) {
        memcpy(public_key, encoded, length);
        *written = length;
        *output = key;
    } else {
        stela_mbed_kx_free(key);
    }
    mbedtls_platform_zeroize(encoded, sizeof(encoded));
    return status;
}
int stela_mbed_kx_shared(struct stela_mbed_kx *key, const unsigned char *peer,
                         size_t length, stela_mbed_rng rng, void *rng_context,
                         unsigned char *output, size_t capacity) {
    if (!key || !rng || !peer || !output || capacity != 32 ||
        length != (key->kind == 1 ? 32u : 65u) ||
        (key->kind == 2 && peer[0] != 4)) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    mbedtls_ecp_point point;
    mbedtls_mpi secret;
    mbedtls_ecp_point_init(&point);
    mbedtls_mpi_init(&secret);
    unsigned char encoded[32] = {0};
    int status = mbedtls_ecp_point_read_binary(&key->group, &point, peer, length);
    if (!status) status = mbedtls_ecp_check_pubkey(&key->group, &point);
    if (!status) status = mbedtls_ecdh_compute_shared(&key->group, &secret,
                                                    &point, &key->scalar, rng, rng_context);
    if (!status) status = key->kind == 1 ?
          mbedtls_mpi_write_binary_le(&secret, encoded, sizeof(encoded)) :
          mbedtls_mpi_write_binary(&secret, encoded, sizeof(encoded));
    unsigned nonzero = 0;
    for (size_t i = 0; i < sizeof(encoded); ++i) nonzero |= encoded[i];
    if (!status && !nonzero) status = MBEDTLS_ERR_ECP_INVALID_KEY;
    if (!status) memcpy(output, encoded, sizeof(encoded));
    mbedtls_platform_zeroize(encoded, sizeof(encoded));
    mbedtls_mpi_free(&secret);
    mbedtls_ecp_point_free(&point);
    return status;
}

/* Public signature verification only. Hash selectors are SHA256/384/512;
 * kind: RSA-v1.5=1, RSA-PSS=2, ECDSA-P256=3, ECDSA-P384=4. */
#include "mbedtls/asn1.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
int stela_mbed_verify(unsigned kind, unsigned hash_bits,
                      const unsigned char *public_key, size_t public_bytes,
                      const unsigned char *message, size_t message_bytes,
                      const unsigned char *signature, size_t signature_bytes) {
    if (kind < 1 || kind > 4 || !public_key || !message || !signature)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    mbedtls_md_type_t hash_type = hash_bits == 256 ? MBEDTLS_MD_SHA256 :
                 hash_bits == 384 ? MBEDTLS_MD_SHA384 :
                 hash_bits == 512 ? MBEDTLS_MD_SHA512 : MBEDTLS_MD_NONE;
    const mbedtls_md_info_t *hash_info = mbedtls_md_info_from_type(hash_type);
    if (!hash_info) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    unsigned char hash[64] = {0};
    int status = mbedtls_md(hash_info, message, message_bytes, hash);
    if (status) return status;
    unsigned hash_bytes = mbedtls_md_get_size(hash_info);
    if (kind <= 2) {
        mbedtls_pk_context key;
        mbedtls_pk_init(&key);
        status = mbedtls_pk_parse_public_key(&key, public_key, public_bytes);
        if (!status && (!mbedtls_pk_can_do(&key, MBEDTLS_PK_RSA) ||
                        mbedtls_pk_get_bitlen(&key) < 2048 ||
                        mbedtls_pk_get_bitlen(&key) > 8192))
            status = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        if (!status) {
            mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);
            status = mbedtls_rsa_check_pubkey(rsa);
            if (!status && signature_bytes != mbedtls_rsa_get_len(rsa))
                status = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            if (!status) status = kind == 1 ?
                 mbedtls_rsa_rsassa_pkcs1_v15_verify(rsa, hash_type, hash_bytes, hash, signature) :
                 mbedtls_rsa_rsassa_pss_verify_ext(rsa, hash_type, hash_bytes, hash,
                                                 hash_type, (int)hash_bytes, signature);
        }
        mbedtls_pk_free(&key);
    } else {
        mbedtls_ecp_group group;
        mbedtls_ecp_point point;
        mbedtls_mpi r, s;
        mbedtls_ecp_group_init(&group);
        mbedtls_ecp_point_init(&point);
        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);
        if (public_bytes != (kind == 3 ? 65u : 97u) || public_key[0] != 4)
            status = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        if (!status) status = mbedtls_ecp_group_load(&group, kind == 3 ?
                     MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1);
        if (!status) status = mbedtls_ecp_point_read_binary(&group, &point, public_key, public_bytes);
        if (!status) status = mbedtls_ecp_check_pubkey(&group, &point);
        unsigned char *cursor = (unsigned char *)signature;
        const unsigned char *end = signature + signature_bytes;
        size_t length = 0;
        if (!status) status = mbedtls_asn1_get_tag(&cursor, end, &length,
                              MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (!status && length != (size_t)(end - cursor)) status = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        if (!status) status = mbedtls_asn1_get_mpi(&cursor, end, &r);
        if (!status) status = mbedtls_asn1_get_mpi(&cursor, end, &s);
        if (!status && cursor != end) status = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
        if (!status) status = mbedtls_ecdsa_verify(&group, hash, hash_bytes, &point, &r, &s);
        mbedtls_mpi_free(&s);
        mbedtls_mpi_free(&r);
        mbedtls_ecp_point_free(&point);
        mbedtls_ecp_group_free(&group);
    }
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return status;
}

/* Owned checked digest/HMAC contexts. Mbed frees/wipes its private state;
 * wrapper and scratch storage are explicitly wiped on every exit path. */
struct stela_mbed_md { mbedtls_md_context_t context; unsigned bits; int hmac; };
void stela_mbed_md_free(struct stela_mbed_md *state) {
    if (!state) return;
    mbedtls_md_free(&state->context);
    mbedtls_platform_zeroize(state, sizeof(*state));
    mbedtls_free(state);
}
int stela_mbed_md_new(unsigned bits, int hmac, const unsigned char *key,
                      size_t key_bytes, struct stela_mbed_md **output) {
    if (!output || (hmac != 0 && hmac != 1) || (hmac && !key))
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(bits == 256 ?
         MBEDTLS_MD_SHA256 : bits == 384 ? MBEDTLS_MD_SHA384 : MBEDTLS_MD_NONE);
    if (!info) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    struct stela_mbed_md *state = mbedtls_calloc(1, sizeof(*state));
    if (!state) return MBEDTLS_ERR_MD_ALLOC_FAILED;
    mbedtls_md_init(&state->context);
    state->bits = bits; state->hmac = hmac;
    int status = mbedtls_md_setup(&state->context, info, hmac);
    if (!status) status = hmac ? mbedtls_md_hmac_starts(&state->context, key, key_bytes) :
                                  mbedtls_md_starts(&state->context);
    if (status) stela_mbed_md_free(state);
    else *output = state;
    return status;
}
int stela_mbed_md_clone(const struct stela_mbed_md *source, struct stela_mbed_md **output) {
    if (!source || source->hmac || !output) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    struct stela_mbed_md *state = NULL;
    int status = stela_mbed_md_new(source->bits, 0, NULL, 0, &state);
    if (!status) status = mbedtls_md_clone(&state->context, &source->context);
    if (status) stela_mbed_md_free(state);
    else *output = state;
    return status;
}
int stela_mbed_md_update(struct stela_mbed_md *state, const unsigned char *input, size_t bytes) {
    if (!state || !input) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    return state->hmac ? mbedtls_md_hmac_update(&state->context, input, bytes) :
                         mbedtls_md_update(&state->context, input, bytes);
}
int stela_mbed_md_finish(struct stela_mbed_md *state, unsigned char *output, size_t bytes) {
    if (!state || !output || bytes != state->bits/8) return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    unsigned char result[64] = {0};
    int status = state->hmac ? mbedtls_md_hmac_finish(&state->context, result) :
                              mbedtls_md_finish(&state->context, result);
    if (!status) memcpy(output, result, bytes);
    mbedtls_platform_zeroize(result, sizeof(result));
    return status;
}
