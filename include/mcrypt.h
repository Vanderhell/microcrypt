/*
 * microcrypt - portable C99 crypto primitives.
 *
 * Primitive library only. Not a message protocol and not an AEAD API.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef MCRYPT_H
#define MCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MCRYPT_VERSION_MAJOR 2
#define MCRYPT_VERSION_MINOR 0
#define MCRYPT_VERSION_PATCH 0
#define MCRYPT_VERSION_STRING "2.0.0"

#ifndef MICROCRYPT_ENABLE_AES_CBC
#define MICROCRYPT_ENABLE_AES_CBC 1
#endif

#ifndef MICROCRYPT_ENABLE_LEGACY_API
#define MICROCRYPT_ENABLE_LEGACY_API 1
#endif

#define MCRYPT_SHA256_BLOCK_SIZE 64
#define MCRYPT_SHA256_DIGEST_SIZE 32
#define MCRYPT_HMAC_SHA256_SIZE 32
#define MCRYPT_AES128_KEY_SIZE 16
#define MCRYPT_AES128_BLOCK_SIZE 16

typedef enum mcrypt_status {
    MCRYPT_OK = 0,
    MCRYPT_ERR_INVALID_ARGUMENT = 1,
    MCRYPT_ERR_INVALID_LENGTH = 2,
    MCRYPT_ERR_INVALID_STATE = 3,
    MCRYPT_ERR_OVERFLOW = 4,
    MCRYPT_ERR_UNSUPPORTED = 5,
    MCRYPT_ERR_AUTH_FAILED = 6,
    MCRYPT_ERR_OVERLAP = 7,
    MCRYPT_ERR_INTERNAL = 8
} mcrypt_status_t;

typedef struct mcrypt_sha256 {
    uint32_t magic;
    uint32_t state;
    uint64_t total_bytes;
    size_t buffer_len;
    uint32_t h[8];
    uint8_t buffer[MCRYPT_SHA256_BLOCK_SIZE];
} mcrypt_sha256_t;

typedef struct mcrypt_hmac_sha256 {
    uint32_t magic;
    uint32_t state;
    mcrypt_sha256_t inner;
    uint8_t key_block[MCRYPT_SHA256_BLOCK_SIZE];
    uint8_t inner_pad[MCRYPT_SHA256_BLOCK_SIZE];
    uint8_t outer_pad[MCRYPT_SHA256_BLOCK_SIZE];
} mcrypt_hmac_sha256_t;

typedef struct mcrypt_aes128 {
    uint32_t magic;
    uint32_t state;
    uint32_t round_keys[44];
} mcrypt_aes128_t;

void mcrypt_secure_clear(void *ptr, size_t len);
bool mcrypt_secure_equal(const void *lhs, const void *rhs, size_t len);

mcrypt_status_t mcrypt_sha256_init(mcrypt_sha256_t *ctx);
mcrypt_status_t mcrypt_sha256_update(mcrypt_sha256_t *ctx,
                                     const void *data,
                                     size_t len);
mcrypt_status_t mcrypt_sha256_final(mcrypt_sha256_t *ctx,
                                    uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE]);
mcrypt_status_t mcrypt_sha256_clear(mcrypt_sha256_t *ctx);
mcrypt_status_t mcrypt_sha256(const void *data,
                              size_t len,
                              uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE]);

mcrypt_status_t mcrypt_hmac_sha256_init(mcrypt_hmac_sha256_t *ctx,
                                        const void *key,
                                        size_t key_len);
mcrypt_status_t mcrypt_hmac_sha256_update(mcrypt_hmac_sha256_t *ctx,
                                          const void *data,
                                          size_t len);
mcrypt_status_t mcrypt_hmac_sha256_final(mcrypt_hmac_sha256_t *ctx,
                                         uint8_t mac[MCRYPT_HMAC_SHA256_SIZE]);
mcrypt_status_t mcrypt_hmac_sha256_clear(mcrypt_hmac_sha256_t *ctx);
mcrypt_status_t mcrypt_hmac_sha256(const void *key,
                                   size_t key_len,
                                   const void *data,
                                   size_t data_len,
                                   uint8_t mac[MCRYPT_HMAC_SHA256_SIZE]);
mcrypt_status_t mcrypt_hmac_sha256_verify(const void *key,
                                          size_t key_len,
                                          const void *data,
                                          size_t data_len,
                                          const uint8_t mac[MCRYPT_HMAC_SHA256_SIZE]);

mcrypt_status_t mcrypt_aes128_init(mcrypt_aes128_t *ctx,
                                   const uint8_t key[MCRYPT_AES128_KEY_SIZE]);
mcrypt_status_t mcrypt_aes128_clear(mcrypt_aes128_t *ctx);
mcrypt_status_t mcrypt_aes128_encrypt_block(const mcrypt_aes128_t *ctx,
                                            const uint8_t in[MCRYPT_AES128_BLOCK_SIZE],
                                            uint8_t out[MCRYPT_AES128_BLOCK_SIZE]);
mcrypt_status_t mcrypt_aes128_decrypt_block(const mcrypt_aes128_t *ctx,
                                            const uint8_t in[MCRYPT_AES128_BLOCK_SIZE],
                                            uint8_t out[MCRYPT_AES128_BLOCK_SIZE]);
mcrypt_status_t mcrypt_aes128_cbc_encrypt(const mcrypt_aes128_t *ctx,
                                          const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                          const void *in,
                                          size_t len,
                                          void *out,
                                          uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE]);
mcrypt_status_t mcrypt_aes128_cbc_decrypt(const mcrypt_aes128_t *ctx,
                                          const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                          const void *in,
                                          size_t len,
                                          void *out,
                                          uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* MCRYPT_H */
