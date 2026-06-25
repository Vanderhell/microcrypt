/*
 * microcrypt - checked C99 crypto primitives.
 *
 * SHA-256: FIPS 180-4
 * HMAC-SHA256: RFC 2104 / RFC 4231
 * AES-128: FIPS 197
 *
 * SPDX-License-Identifier: MIT
 */

#define __STDC_WANT_LIB_EXT1__ 1

#include "mcrypt.h"

#include <string.h>

enum {
    MCRYPT_STATE_CLEARED = 0u,
    MCRYPT_STATE_ACTIVE = 1u,
    MCRYPT_STATE_FINALIZED = 2u
};

#define MCRYPT_SHA_MAGIC  0x53484132u
#define MCRYPT_HMAC_MAGIC 0x484d4143u
#define MCRYPT_AES_MAGIC  0x41455331u

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t aes_inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t aes_rcon[10] = {
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u, 0x1bu, 0x36u
};

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    store_be32(p, (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)v);
}

void mcrypt_secure_clear(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0u) {
        return;
    }

#if defined(__STDC_LIB_EXT1__)
    (void)memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len != 0u) {
        *p++ = 0u;
        --len;
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
#endif
}

bool mcrypt_secure_equal(const void *lhs, const void *rhs, size_t len)
{
    const uint8_t *a;
    const uint8_t *b;
    uint8_t diff;
    size_t i;

    if (len == 0u) {
        return true;
    }
    if (lhs == NULL || rhs == NULL) {
        return false;
    }

    a = (const uint8_t *)lhs;
    b = (const uint8_t *)rhs;
    diff = 0u;
    for (i = 0u; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

static bool is_sha_ctx_active(const mcrypt_sha256_t *ctx)
{
    return ctx != NULL &&
           ctx->magic == MCRYPT_SHA_MAGIC &&
           ctx->state == MCRYPT_STATE_ACTIVE;
}

static bool is_hmac_ctx_active(const mcrypt_hmac_sha256_t *ctx)
{
    return ctx != NULL &&
           ctx->magic == MCRYPT_HMAC_MAGIC &&
           ctx->state == MCRYPT_STATE_ACTIVE;
}

static bool is_aes_ctx_active(const mcrypt_aes128_t *ctx)
{
    return ctx != NULL &&
           ctx->magic == MCRYPT_AES_MAGIC &&
           ctx->state == MCRYPT_STATE_ACTIVE;
}

static bool ranges_overlap(const void *lhs, size_t lhs_len,
                           const void *rhs, size_t rhs_len)
{
    uintptr_t la;
    uintptr_t ra;

    if (lhs == NULL || rhs == NULL || lhs_len == 0u || rhs_len == 0u) {
        return false;
    }

    la = (uintptr_t)lhs;
    ra = (uintptr_t)rhs;
    if (la > UINTPTR_MAX - lhs_len || ra > UINTPTR_MAX - rhs_len) {
        return true;
    }
    return la < ra + rhs_len && ra < la + lhs_len;
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    size_t i;

#define ROR32(v, n) (((v) >> (n)) | ((v) << (32u - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32((x), 2u) ^ ROR32((x), 13u) ^ ROR32((x), 22u))
#define EP1(x) (ROR32((x), 6u) ^ ROR32((x), 11u) ^ ROR32((x), 25u))
#define SIG0(x) (ROR32((x), 7u) ^ ROR32((x), 18u) ^ ((x) >> 3u))
#define SIG1(x) (ROR32((x), 17u) ^ ROR32((x), 19u) ^ ((x) >> 10u))

    for (i = 0u; i < 16u; ++i) {
        w[i] = load_be32(block + (i * 4u));
    }
    for (i = 16u; i < 64u; ++i) {
        w[i] = SIG1(w[i - 2u]) + w[i - 7u] + SIG0(w[i - 15u]) + w[i - 16u];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0u; i < 64u; ++i) {
        const uint32_t t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + w[i];
        const uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

#undef SIG1
#undef SIG0
#undef EP1
#undef EP0
#undef MAJ
#undef CH
#undef ROR32
}

static mcrypt_status_t sha256_finish_work(mcrypt_sha256_t *work,
                                          uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE])
{
    size_t idx;
    uint64_t bit_len;

    if (work == NULL || digest == NULL) {
        return MCRYPT_ERR_INTERNAL;
    }

    idx = work->buffer_len;
    if (idx > MCRYPT_SHA256_BLOCK_SIZE) {
        return MCRYPT_ERR_INTERNAL;
    }

    bit_len = work->total_bytes * 8u;

    work->buffer[idx++] = 0x80u;
    if (idx > 56u) {
        while (idx < MCRYPT_SHA256_BLOCK_SIZE) {
            work->buffer[idx++] = 0u;
        }
        sha256_transform(work->h, work->buffer);
        idx = 0u;
    }
    while (idx < 56u) {
        work->buffer[idx++] = 0u;
    }
    store_be64(work->buffer + 56u, bit_len);
    sha256_transform(work->h, work->buffer);

    for (idx = 0u; idx < 8u; ++idx) {
        store_be32(digest + (idx * 4u), work->h[idx]);
    }

    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_sha256_init(mcrypt_sha256_t *ctx)
{
    if (ctx == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    mcrypt_secure_clear(ctx, sizeof *ctx);
    ctx->magic = MCRYPT_SHA_MAGIC;
    ctx->state = MCRYPT_STATE_ACTIVE;
    ctx->h[0] = 0x6a09e667u;
    ctx->h[1] = 0xbb67ae85u;
    ctx->h[2] = 0x3c6ef372u;
    ctx->h[3] = 0xa54ff53au;
    ctx->h[4] = 0x510e527fu;
    ctx->h[5] = 0x9b05688cu;
    ctx->h[6] = 0x1f83d9abu;
    ctx->h[7] = 0x5be0cd19u;
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_sha256_update(mcrypt_sha256_t *ctx,
                                     const void *data,
                                     size_t len)
{
    const uint8_t *input;
    size_t buffered;
    size_t fill;
    size_t copy_len;

    if (!is_sha_ctx_active(ctx)) {
        return MCRYPT_ERR_INVALID_STATE;
    }
    if (len == 0u) {
        return MCRYPT_OK;
    }
    if (data == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }
    if (ctx->buffer_len > MCRYPT_SHA256_BLOCK_SIZE) {
        return MCRYPT_ERR_INVALID_STATE;
    }
    if (len > UINT64_MAX - ctx->total_bytes) {
        return MCRYPT_ERR_OVERFLOW;
    }
    if (ctx->total_bytes + len > (UINT64_MAX / 8u)) {
        return MCRYPT_ERR_INVALID_LENGTH;
    }

    input = (const uint8_t *)data;
    buffered = ctx->buffer_len;
    ctx->total_bytes += (uint64_t)len;

    if (buffered != 0u) {
        fill = MCRYPT_SHA256_BLOCK_SIZE - buffered;
        if (len < fill) {
            memcpy(ctx->buffer + buffered, input, len);
            ctx->buffer_len = buffered + len;
            return MCRYPT_OK;
        }
        memcpy(ctx->buffer + buffered, input, fill);
        sha256_transform(ctx->h, ctx->buffer);
        input += fill;
        len -= fill;
        buffered = 0u;
        ctx->buffer_len = 0u;
    }

    while (len >= MCRYPT_SHA256_BLOCK_SIZE) {
        sha256_transform(ctx->h, input);
        input += MCRYPT_SHA256_BLOCK_SIZE;
        len -= MCRYPT_SHA256_BLOCK_SIZE;
    }

    if (len != 0u) {
        copy_len = len;
        memcpy(ctx->buffer, input, copy_len);
        ctx->buffer_len = copy_len;
    }

    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_sha256_final(mcrypt_sha256_t *ctx,
                                    uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE])
{
    mcrypt_sha256_t work;
    mcrypt_status_t status;

    if (!is_sha_ctx_active(ctx)) {
        if (digest != NULL) {
            mcrypt_secure_clear(digest, MCRYPT_SHA256_DIGEST_SIZE);
        }
        return MCRYPT_ERR_INVALID_STATE;
    }
    if (digest == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    work = *ctx;
    status = sha256_finish_work(&work, digest);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(digest, MCRYPT_SHA256_DIGEST_SIZE);
        return status;
    }

    mcrypt_secure_clear(ctx->h, sizeof ctx->h);
    mcrypt_secure_clear(ctx->buffer, sizeof ctx->buffer);
    ctx->total_bytes = 0u;
    ctx->buffer_len = 0u;
    ctx->state = MCRYPT_STATE_FINALIZED;
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_sha256_clear(mcrypt_sha256_t *ctx)
{
    if (ctx == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    mcrypt_secure_clear(ctx, sizeof *ctx);
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_sha256(const void *data,
                              size_t len,
                              uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE])
{
    mcrypt_sha256_t ctx;
    mcrypt_status_t status;

    if (digest == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    status = mcrypt_sha256_init(&ctx);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(digest, MCRYPT_SHA256_DIGEST_SIZE);
        return status;
    }

    status = mcrypt_sha256_update(&ctx, data, len);
    if (status == MCRYPT_OK) {
        status = mcrypt_sha256_final(&ctx, digest);
    }
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(digest, MCRYPT_SHA256_DIGEST_SIZE);
    }
    mcrypt_sha256_clear(&ctx);
    return status;
}

mcrypt_status_t mcrypt_hmac_sha256_init(mcrypt_hmac_sha256_t *ctx,
                                        const void *key,
                                        size_t key_len)
{
    uint8_t normalized[MCRYPT_SHA256_BLOCK_SIZE];
    uint8_t hashed_key[MCRYPT_SHA256_DIGEST_SIZE];
    size_t i;
    mcrypt_status_t status;

    if (ctx == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }
    if (key_len != 0u && key == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    mcrypt_secure_clear(ctx, sizeof *ctx);
    ctx->magic = MCRYPT_HMAC_MAGIC;
    ctx->state = MCRYPT_STATE_ACTIVE;

    if (key_len > MCRYPT_SHA256_BLOCK_SIZE) {
        status = mcrypt_sha256(key, key_len, hashed_key);
        if (status != MCRYPT_OK) {
            mcrypt_secure_clear(hashed_key, sizeof hashed_key);
            mcrypt_secure_clear(normalized, sizeof normalized);
            mcrypt_hmac_sha256_clear(ctx);
            return status;
        }
        memcpy(normalized, hashed_key, MCRYPT_SHA256_DIGEST_SIZE);
        memset(normalized + MCRYPT_SHA256_DIGEST_SIZE,
               0,
               MCRYPT_SHA256_BLOCK_SIZE - MCRYPT_SHA256_DIGEST_SIZE);
    } else {
        if (key_len != 0u) {
            memcpy(normalized, key, key_len);
        }
        if (key_len < MCRYPT_SHA256_BLOCK_SIZE) {
            memset(normalized + key_len,
                   0,
                   MCRYPT_SHA256_BLOCK_SIZE - key_len);
        }
    }

    for (i = 0u; i < MCRYPT_SHA256_BLOCK_SIZE; ++i) {
        ctx->inner_pad[i] = (uint8_t)(normalized[i] ^ 0x36u);
        ctx->outer_pad[i] = (uint8_t)(normalized[i] ^ 0x5cu);
        ctx->key_block[i] = normalized[i];
    }

    status = mcrypt_sha256_init(&ctx->inner);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(normalized, sizeof normalized);
        mcrypt_hmac_sha256_clear(ctx);
        return status;
    }

    status = mcrypt_sha256_update(&ctx->inner, ctx->inner_pad, MCRYPT_SHA256_BLOCK_SIZE);
    mcrypt_secure_clear(normalized, sizeof normalized);
    mcrypt_secure_clear(hashed_key, sizeof hashed_key);
    if (status != MCRYPT_OK) {
        mcrypt_hmac_sha256_clear(ctx);
        return status;
    }

    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_hmac_sha256_update(mcrypt_hmac_sha256_t *ctx,
                                          const void *data,
                                          size_t len)
{
    if (!is_hmac_ctx_active(ctx)) {
        return MCRYPT_ERR_INVALID_STATE;
    }
    return mcrypt_sha256_update(&ctx->inner, data, len);
}

mcrypt_status_t mcrypt_hmac_sha256_final(mcrypt_hmac_sha256_t *ctx,
                                         uint8_t mac[MCRYPT_HMAC_SHA256_SIZE])
{
    mcrypt_sha256_t outer;
    uint8_t inner_digest[MCRYPT_SHA256_DIGEST_SIZE];
    mcrypt_status_t status;

    if (!is_hmac_ctx_active(ctx)) {
        if (mac != NULL) {
            mcrypt_secure_clear(mac, MCRYPT_HMAC_SHA256_SIZE);
        }
        return MCRYPT_ERR_INVALID_STATE;
    }
    if (mac == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    status = mcrypt_sha256_final(&ctx->inner, inner_digest);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(mac, MCRYPT_HMAC_SHA256_SIZE);
        return status;
    }

    status = mcrypt_sha256_init(&outer);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(inner_digest, sizeof inner_digest);
        mcrypt_secure_clear(mac, MCRYPT_HMAC_SHA256_SIZE);
        return status;
    }
    status = mcrypt_sha256_update(&outer, ctx->outer_pad, MCRYPT_SHA256_BLOCK_SIZE);
    if (status == MCRYPT_OK) {
        status = mcrypt_sha256_update(&outer, inner_digest, MCRYPT_SHA256_DIGEST_SIZE);
    }
    if (status == MCRYPT_OK) {
        status = mcrypt_sha256_final(&outer, mac);
    }

    mcrypt_secure_clear(inner_digest, sizeof inner_digest);
    mcrypt_secure_clear(&outer, sizeof outer);
    mcrypt_secure_clear(ctx->inner_pad, sizeof ctx->inner_pad);
    mcrypt_secure_clear(ctx->outer_pad, sizeof ctx->outer_pad);
    mcrypt_secure_clear(ctx->key_block, sizeof ctx->key_block);
    mcrypt_secure_clear(ctx->inner.h, sizeof ctx->inner.h);
    mcrypt_secure_clear(ctx->inner.buffer, sizeof ctx->inner.buffer);
    ctx->inner.magic = 0u;
    ctx->inner.state = MCRYPT_STATE_CLEARED;
    ctx->inner.total_bytes = 0u;
    ctx->inner.buffer_len = 0u;
    ctx->magic = MCRYPT_HMAC_MAGIC;
    ctx->state = MCRYPT_STATE_FINALIZED;

    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(mac, MCRYPT_HMAC_SHA256_SIZE);
    }
    return status;
}

mcrypt_status_t mcrypt_hmac_sha256_clear(mcrypt_hmac_sha256_t *ctx)
{
    if (ctx == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    mcrypt_secure_clear(ctx, sizeof *ctx);
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_hmac_sha256(const void *key,
                                   size_t key_len,
                                   const void *data,
                                   size_t data_len,
                                   uint8_t mac[MCRYPT_HMAC_SHA256_SIZE])
{
    mcrypt_hmac_sha256_t ctx;
    mcrypt_status_t status;

    if (mac == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    status = mcrypt_hmac_sha256_init(&ctx, key, key_len);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(mac, MCRYPT_HMAC_SHA256_SIZE);
        return status;
    }

    status = mcrypt_hmac_sha256_update(&ctx, data, data_len);
    if (status == MCRYPT_OK) {
        status = mcrypt_hmac_sha256_final(&ctx, mac);
    }
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(mac, MCRYPT_HMAC_SHA256_SIZE);
    }
    mcrypt_hmac_sha256_clear(&ctx);
    return status;
}

mcrypt_status_t mcrypt_hmac_sha256_verify(const void *key,
                                          size_t key_len,
                                          const void *data,
                                          size_t data_len,
                                          const uint8_t mac[MCRYPT_HMAC_SHA256_SIZE])
{
    uint8_t actual[MCRYPT_HMAC_SHA256_SIZE];
    mcrypt_status_t status;
    bool match;

    if (mac == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    status = mcrypt_hmac_sha256(key, key_len, data, data_len, actual);
    if (status != MCRYPT_OK) {
        mcrypt_secure_clear(actual, sizeof actual);
        return status;
    }

    match = mcrypt_secure_equal(actual, mac, sizeof actual);
    mcrypt_secure_clear(actual, sizeof actual);
    return match ? MCRYPT_OK : MCRYPT_ERR_AUTH_FAILED;
}

static uint8_t aes_xtime(uint8_t x)
{
    return (uint8_t)((x << 1u) ^ (uint8_t)(((x >> 7u) & 1u) * 0x1bu));
}

static uint8_t aes_mul2(uint8_t x) { return aes_xtime(x); }
static uint8_t aes_mul4(uint8_t x) { return aes_xtime(aes_xtime(x)); }
static uint8_t aes_mul8(uint8_t x) { return aes_xtime(aes_mul4(x)); }
static uint8_t aes_mul9(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ x); }
static uint8_t aes_mul11(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ aes_mul2(x) ^ x); }
static uint8_t aes_mul13(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ aes_mul4(x) ^ x); }
static uint8_t aes_mul14(uint8_t x) { return (uint8_t)(aes_mul8(x) ^ aes_mul4(x) ^ aes_mul2(x)); }

static void aes_add_round_key(uint8_t state[16], const uint32_t *round_key)
{
    size_t i;
    for (i = 0u; i < 4u; ++i) {
        state[(i * 4u) + 0u] ^= (uint8_t)(round_key[i] >> 24);
        state[(i * 4u) + 1u] ^= (uint8_t)(round_key[i] >> 16);
        state[(i * 4u) + 2u] ^= (uint8_t)(round_key[i] >> 8);
        state[(i * 4u) + 3u] ^= (uint8_t)round_key[i];
    }
}

static void aes_sub_bytes(uint8_t state[16])
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        state[i] = aes_sbox[state[i]];
    }
}

static void aes_inv_sub_bytes(uint8_t state[16])
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        state[i] = aes_inv_sbox[state[i]];
    }
}

static void aes_shift_rows(uint8_t state[16])
{
    uint8_t t;

    t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;

    t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

static void aes_inv_shift_rows(uint8_t state[16])
{
    uint8_t t;

    t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;

    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;

    t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
}

static void aes_mix_columns(uint8_t state[16])
{
    size_t col;
    for (col = 0u; col < 4u; ++col) {
        uint8_t *c = state + (col * 4u);
        uint8_t t = (uint8_t)(c[0] ^ c[1] ^ c[2] ^ c[3]);
        uint8_t u = c[0];

        c[0] ^= (uint8_t)(t ^ aes_xtime((uint8_t)(c[0] ^ c[1])));
        c[1] ^= (uint8_t)(t ^ aes_xtime((uint8_t)(c[1] ^ c[2])));
        c[2] ^= (uint8_t)(t ^ aes_xtime((uint8_t)(c[2] ^ c[3])));
        c[3] ^= (uint8_t)(t ^ aes_xtime((uint8_t)(c[3] ^ u)));
    }
}

static void aes_inv_mix_columns(uint8_t state[16])
{
    size_t col;
    for (col = 0u; col < 4u; ++col) {
        uint8_t *c = state + (col * 4u);
        uint8_t a0 = c[0];
        uint8_t a1 = c[1];
        uint8_t a2 = c[2];
        uint8_t a3 = c[3];

        c[0] = (uint8_t)(aes_mul14(a0) ^ aes_mul11(a1) ^ aes_mul13(a2) ^ aes_mul9(a3));
        c[1] = (uint8_t)(aes_mul9(a0) ^ aes_mul14(a1) ^ aes_mul11(a2) ^ aes_mul13(a3));
        c[2] = (uint8_t)(aes_mul13(a0) ^ aes_mul9(a1) ^ aes_mul14(a2) ^ aes_mul11(a3));
        c[3] = (uint8_t)(aes_mul11(a0) ^ aes_mul13(a1) ^ aes_mul9(a2) ^ aes_mul14(a3));
    }
}

static void aes_encrypt_work(const mcrypt_aes128_t *ctx,
                             const uint8_t in[16],
                             uint8_t out[16])
{
    uint8_t state[16];
    size_t round;

    memcpy(state, in, 16u);
    aes_add_round_key(state, ctx->round_keys);
    for (round = 1u; round < 10u; ++round) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, ctx->round_keys + (round * 4u));
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, ctx->round_keys + 40u);
    memcpy(out, state, 16u);
    mcrypt_secure_clear(state, sizeof state);
}

static void aes_decrypt_work(const mcrypt_aes128_t *ctx,
                             const uint8_t in[16],
                             uint8_t out[16])
{
    uint8_t state[16];
    size_t round;

    memcpy(state, in, 16u);
    aes_add_round_key(state, ctx->round_keys + 40u);
    for (round = 9u; round > 0u; --round) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, ctx->round_keys + (round * 4u));
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, ctx->round_keys);
    memcpy(out, state, 16u);
    mcrypt_secure_clear(state, sizeof state);
}

mcrypt_status_t mcrypt_aes128_init(mcrypt_aes128_t *ctx,
                                   const uint8_t key[MCRYPT_AES128_KEY_SIZE])
{
    size_t i;
    uint32_t temp;

    if (ctx == NULL || key == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    mcrypt_secure_clear(ctx, sizeof *ctx);
    ctx->magic = MCRYPT_AES_MAGIC;
    ctx->state = MCRYPT_STATE_ACTIVE;

    for (i = 0u; i < 4u; ++i) {
        ctx->round_keys[i] = load_be32(key + (i * 4u));
    }

    for (i = 4u; i < 44u; ++i) {
        temp = ctx->round_keys[i - 1u];
        if ((i & 3u) == 0u) {
            temp = ((uint32_t)aes_sbox[(temp >> 16) & 0xffu] << 24) |
                   ((uint32_t)aes_sbox[(temp >> 8) & 0xffu] << 16) |
                   ((uint32_t)aes_sbox[temp & 0xffu] << 8) |
                   (uint32_t)aes_sbox[(temp >> 24) & 0xffu];
            temp ^= ((uint32_t)aes_rcon[(i / 4u) - 1u] << 24);
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4u] ^ temp;
    }

    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_aes128_clear(mcrypt_aes128_t *ctx)
{
    if (ctx == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }

    mcrypt_secure_clear(ctx, sizeof *ctx);
    return MCRYPT_OK;
}

static mcrypt_status_t aes_validate_block(const mcrypt_aes128_t *ctx,
                                          const void *in,
                                          const void *out,
                                          size_t len)
{
    if (!is_aes_ctx_active(ctx)) {
        return MCRYPT_ERR_INVALID_STATE;
    }
    if (in == NULL || out == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }
    if (len != 0u && in != out && ranges_overlap(in, len, out, len)) {
        return MCRYPT_ERR_OVERLAP;
    }
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_aes128_encrypt_block(const mcrypt_aes128_t *ctx,
                                            const uint8_t in[MCRYPT_AES128_BLOCK_SIZE],
                                            uint8_t out[MCRYPT_AES128_BLOCK_SIZE])
{
    mcrypt_status_t status;
    uint8_t block[16];

    status = aes_validate_block(ctx, in, out, MCRYPT_AES128_BLOCK_SIZE);
    if (status != MCRYPT_OK) {
        if (out != NULL) {
            mcrypt_secure_clear(out, MCRYPT_AES128_BLOCK_SIZE);
        }
        return status;
    }

    memcpy(block, in, 16u);
    aes_encrypt_work(ctx, block, out);
    mcrypt_secure_clear(block, sizeof block);
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_aes128_decrypt_block(const mcrypt_aes128_t *ctx,
                                            const uint8_t in[MCRYPT_AES128_BLOCK_SIZE],
                                            uint8_t out[MCRYPT_AES128_BLOCK_SIZE])
{
    mcrypt_status_t status;
    uint8_t block[16];

    status = aes_validate_block(ctx, in, out, MCRYPT_AES128_BLOCK_SIZE);
    if (status != MCRYPT_OK) {
        if (out != NULL) {
            mcrypt_secure_clear(out, MCRYPT_AES128_BLOCK_SIZE);
        }
        return status;
    }

    memcpy(block, in, 16u);
    aes_decrypt_work(ctx, block, out);
    mcrypt_secure_clear(block, sizeof block);
    return MCRYPT_OK;
}

#if MICROCRYPT_ENABLE_AES_CBC
static mcrypt_status_t aes_validate_cbc(const mcrypt_aes128_t *ctx,
                                        const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                        const void *in,
                                        size_t len,
                                        const void *out)
{
    if (!is_aes_ctx_active(ctx)) {
        return MCRYPT_ERR_INVALID_STATE;
    }
    if (iv == NULL || out == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }
    if ((len & (MCRYPT_AES128_BLOCK_SIZE - 1u)) != 0u) {
        return MCRYPT_ERR_INVALID_LENGTH;
    }
    if (len != 0u && in == NULL) {
        return MCRYPT_ERR_INVALID_ARGUMENT;
    }
    if (len != 0u && in != out && ranges_overlap(in, len, out, len)) {
        return MCRYPT_ERR_OVERLAP;
    }
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_aes128_cbc_encrypt(const mcrypt_aes128_t *ctx,
                                          const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                          const void *in,
                                          size_t len,
                                          void *out,
                                          uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE])
{
    const uint8_t *input;
    uint8_t *output;
    uint8_t chain[16];
    uint8_t block[16];
    size_t offset;
    mcrypt_status_t status;

    status = aes_validate_cbc(ctx, iv, in, len, out);
    if (status != MCRYPT_OK) {
        if (status != MCRYPT_ERR_INVALID_LENGTH && out != NULL && len != 0u) {
            mcrypt_secure_clear(out, len);
        }
        return status;
    }
    if (len == 0u) {
        return MCRYPT_OK;
    }

    input = (const uint8_t *)in;
    output = (uint8_t *)out;
    memcpy(chain, iv, 16u);
    for (offset = 0u; offset < len; offset += 16u) {
        size_t i;
        for (i = 0u; i < 16u; ++i) {
            block[i] = (uint8_t)(input[offset + i] ^ chain[i]);
        }
        aes_encrypt_work(ctx, block, output + offset);
        memcpy(chain, output + offset, 16u);
    }
    if (final_iv != NULL) {
        memcpy(final_iv, chain, 16u);
    }
    mcrypt_secure_clear(block, sizeof block);
    mcrypt_secure_clear(chain, sizeof chain);
    return MCRYPT_OK;
}

mcrypt_status_t mcrypt_aes128_cbc_decrypt(const mcrypt_aes128_t *ctx,
                                          const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                          const void *in,
                                          size_t len,
                                          void *out,
                                          uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE])
{
    const uint8_t *input;
    uint8_t *output;
    uint8_t chain[16];
    uint8_t saved_ct[16];
    uint8_t block[16];
    size_t offset;
    mcrypt_status_t status;

    status = aes_validate_cbc(ctx, iv, in, len, out);
    if (status != MCRYPT_OK) {
        if (status != MCRYPT_ERR_INVALID_LENGTH && out != NULL && len != 0u) {
            mcrypt_secure_clear(out, len);
        }
        return status;
    }
    if (len == 0u) {
        return MCRYPT_OK;
    }

    input = (const uint8_t *)in;
    output = (uint8_t *)out;
    memcpy(chain, iv, 16u);
    for (offset = 0u; offset < len; offset += 16u) {
        size_t i;
        memcpy(saved_ct, input + offset, 16u);
        aes_decrypt_work(ctx, saved_ct, block);
        for (i = 0u; i < 16u; ++i) {
            output[offset + i] = (uint8_t)(block[i] ^ chain[i]);
        }
        memcpy(chain, saved_ct, 16u);
    }
    if (final_iv != NULL) {
        memcpy(final_iv, chain, 16u);
    }
    mcrypt_secure_clear(saved_ct, sizeof saved_ct);
    mcrypt_secure_clear(block, sizeof block);
    mcrypt_secure_clear(chain, sizeof chain);
    return MCRYPT_OK;
}
#else
mcrypt_status_t mcrypt_aes128_cbc_encrypt(const mcrypt_aes128_t *ctx,
                                          const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                          const void *in,
                                          size_t len,
                                          void *out,
                                          uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE])
{
    (void)ctx;
    (void)iv;
    (void)in;
    (void)len;
    (void)out;
    (void)final_iv;
    return MCRYPT_ERR_UNSUPPORTED;
}

mcrypt_status_t mcrypt_aes128_cbc_decrypt(const mcrypt_aes128_t *ctx,
                                          const uint8_t iv[MCRYPT_AES128_BLOCK_SIZE],
                                          const void *in,
                                          size_t len,
                                          void *out,
                                          uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE])
{
    (void)ctx;
    (void)iv;
    (void)in;
    (void)len;
    (void)out;
    (void)final_iv;
    return MCRYPT_ERR_UNSUPPORTED;
}
#endif
