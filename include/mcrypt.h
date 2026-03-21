/*
 * microcrypt — Crypto primitives for embedded systems.
 *
 * SHA-256, HMAC-SHA256, AES-128-ECB/CBC. No dependencies, no allocations.
 * For firmware verification, message authentication, and config encryption.
 *
 * WARNING: This is a portable reference implementation. It has NOT been
 * audited for side-channel resistance. For production security-critical
 * applications, use a hardware crypto accelerator or audited library.
 *
 * C99 · Zero dependencies · Zero allocations · Portable
 *
 * SPDX-License-Identifier: MIT
 * https://github.com/Vanderhell/microcrypt
 */

#ifndef MCRYPT_H
#define MCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-256
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MCRYPT_SHA256_BLOCK_SIZE  64
#define MCRYPT_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;                              /**< Total bytes hashed.  */
    uint8_t  buffer[MCRYPT_SHA256_BLOCK_SIZE];   /**< Partial block.       */
} mcrypt_sha256_t;

/** Initialise SHA-256 context. */
void mcrypt_sha256_init(mcrypt_sha256_t *ctx);

/** Feed data into the hash. Can be called multiple times. */
void mcrypt_sha256_update(mcrypt_sha256_t *ctx, const void *data, uint32_t len);

/** Finalise and output the 32-byte digest. */
void mcrypt_sha256_final(mcrypt_sha256_t *ctx, uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE]);

/** One-shot: hash data and output digest. */
void mcrypt_sha256(const void *data, uint32_t len,
                    uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE]);

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MCRYPT_HMAC_SHA256_SIZE 32

typedef struct {
    mcrypt_sha256_t inner;
    uint8_t         o_key_pad[MCRYPT_SHA256_BLOCK_SIZE];
} mcrypt_hmac_sha256_t;

/** Initialise HMAC-SHA256 with a key. */
void mcrypt_hmac_sha256_init(mcrypt_hmac_sha256_t *ctx,
                              const void *key, uint32_t key_len);

/** Feed data into the HMAC. */
void mcrypt_hmac_sha256_update(mcrypt_hmac_sha256_t *ctx,
                                const void *data, uint32_t len);

/** Finalise and output the 32-byte MAC. */
void mcrypt_hmac_sha256_final(mcrypt_hmac_sha256_t *ctx,
                               uint8_t mac[MCRYPT_HMAC_SHA256_SIZE]);

/** One-shot HMAC-SHA256. */
void mcrypt_hmac_sha256(const void *key, uint32_t key_len,
                         const void *data, uint32_t data_len,
                         uint8_t mac[MCRYPT_HMAC_SHA256_SIZE]);

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-128
 * ═══════════════════════════════════════════════════════════════════════════ */

#define MCRYPT_AES128_KEY_SIZE   16
#define MCRYPT_AES128_BLOCK_SIZE 16

typedef struct {
    uint32_t round_keys[44];   /**< Expanded key schedule (11 × 4).       */
} mcrypt_aes128_t;

/** Expand a 16-byte key into the round key schedule. */
void mcrypt_aes128_init(mcrypt_aes128_t *ctx,
                         const uint8_t key[MCRYPT_AES128_KEY_SIZE]);

/** Encrypt one 16-byte block (ECB mode). */
void mcrypt_aes128_encrypt_block(const mcrypt_aes128_t *ctx,
                                  const uint8_t in[MCRYPT_AES128_BLOCK_SIZE],
                                  uint8_t out[MCRYPT_AES128_BLOCK_SIZE]);

/** Decrypt one 16-byte block (ECB mode). */
void mcrypt_aes128_decrypt_block(const mcrypt_aes128_t *ctx,
                                  const uint8_t in[MCRYPT_AES128_BLOCK_SIZE],
                                  uint8_t out[MCRYPT_AES128_BLOCK_SIZE]);

/**
 * AES-128-CBC encrypt.
 *
 * @param ctx   AES context (key expanded).
 * @param iv    16-byte IV (modified in-place to final ciphertext block).
 * @param in    Plaintext (must be multiple of 16 bytes).
 * @param out   Ciphertext output (same size as in).
 * @param len   Data length (must be multiple of 16).
 */
void mcrypt_aes128_cbc_encrypt(const mcrypt_aes128_t *ctx,
                                uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                const uint8_t *in, uint8_t *out,
                                uint32_t len);

/**
 * AES-128-CBC decrypt.
 */
void mcrypt_aes128_cbc_decrypt(const mcrypt_aes128_t *ctx,
                                uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                const uint8_t *in, uint8_t *out,
                                uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* MCRYPT_H */
