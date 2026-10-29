/* Checked native-client crypto backend. No protocol or symmetric cipher.
 * Official Mbed TLS checked public key operations only. */
#ifndef STELA_MBED_CRYPTO_CONFIG_H
#define STELA_MBED_CRYPTO_CONFIG_H
/* Clang supplies this supported annotation without an MSVC SAL SDK. */
#if defined(__clang__)
#define MBEDTLS_CHECK_RETURN __attribute__((__warn_unused_result__))
#endif
#define MBEDTLS_PLATFORM_C
#include "stela_alloc.h"
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO stela_mbedtls_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO stela_mbedtls_free
#define MBEDTLS_PLATFORM_SNPRINTF_ALT
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_MD_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#endif
