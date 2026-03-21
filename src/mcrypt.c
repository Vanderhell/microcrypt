/*
 * microcrypt — Implementation.
 *
 * SHA-256: FIPS 180-4
 * AES-128: FIPS 197
 * HMAC: RFC 2104
 *
 * SPDX-License-Identifier: MIT
 * https://github.com/Vanderhell/microcrypt
 */

#include "mcrypt.h"
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-256
 * ═══════════════════════════════════════════════════════════════════════════ */

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROR32(x,2)  ^ ROR32(x,13) ^ ROR32(x,22))
#define EP1(x)       (ROR32(x,6)  ^ ROR32(x,11) ^ ROR32(x,25))
#define SIG0(x)      (ROR32(x,7)  ^ ROR32(x,18) ^ ((x) >> 3))
#define SIG1(x)      (ROR32(x,17) ^ ROR32(x,19) ^ ((x) >> 10))

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 |
           (uint32_t)p[2]<<8  | (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16);
    p[2]=(uint8_t)(v>>8);  p[3]=(uint8_t)(v);
}

static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p,   (uint32_t)(v >> 32));
    put_be32(p+4, (uint32_t)(v));
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = be32(block + i*4);
    for (int i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t e=state[4], f=state[5], g=state[6], h=state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }

    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

void mcrypt_sha256_init(mcrypt_sha256_t *ctx)
{
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count = 0;
}

void mcrypt_sha256_update(mcrypt_sha256_t *ctx, const void *data, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t buf_idx = (uint32_t)(ctx->count % 64);

    ctx->count += len;

    /* Fill partial block */
    if (buf_idx > 0) {
        uint32_t fill = 64 - buf_idx;
        if (len < fill) {
            memcpy(ctx->buffer + buf_idx, p, len);
            return;
        }
        memcpy(ctx->buffer + buf_idx, p, fill);
        sha256_transform(ctx->state, ctx->buffer);
        p += fill;
        len -= fill;
    }

    /* Process full blocks */
    while (len >= 64) {
        sha256_transform(ctx->state, p);
        p += 64;
        len -= 64;
    }

    /* Buffer remainder */
    if (len > 0) {
        memcpy(ctx->buffer, p, len);
    }
}

void mcrypt_sha256_final(mcrypt_sha256_t *ctx, uint8_t digest[32])
{
    uint32_t buf_idx = (uint32_t)(ctx->count % 64);
    uint64_t bits = ctx->count * 8;

    /* Pad: 0x80, zeros, 64-bit length (big-endian) */
    ctx->buffer[buf_idx++] = 0x80;

    if (buf_idx > 56) {
        memset(ctx->buffer + buf_idx, 0, 64 - buf_idx);
        sha256_transform(ctx->state, ctx->buffer);
        buf_idx = 0;
    }
    memset(ctx->buffer + buf_idx, 0, 56 - buf_idx);
    put_be64(ctx->buffer + 56, bits);
    sha256_transform(ctx->state, ctx->buffer);

    for (int i = 0; i < 8; i++)
        put_be32(digest + i*4, ctx->state[i]);
}

void mcrypt_sha256(const void *data, uint32_t len, uint8_t digest[32])
{
    mcrypt_sha256_t ctx;
    mcrypt_sha256_init(&ctx);
    mcrypt_sha256_update(&ctx, data, len);
    mcrypt_sha256_final(&ctx, digest);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256
 * ═══════════════════════════════════════════════════════════════════════════ */

void mcrypt_hmac_sha256_init(mcrypt_hmac_sha256_t *ctx,
                              const void *key, uint32_t key_len)
{
    uint8_t k_pad[MCRYPT_SHA256_BLOCK_SIZE];

    /* If key > block size, hash it first */
    if (key_len > MCRYPT_SHA256_BLOCK_SIZE) {
        uint8_t hashed_key[MCRYPT_SHA256_DIGEST_SIZE];
        mcrypt_sha256(key, key_len, hashed_key);
        memcpy(k_pad, hashed_key, MCRYPT_SHA256_DIGEST_SIZE);
        memset(k_pad + MCRYPT_SHA256_DIGEST_SIZE, 0,
               MCRYPT_SHA256_BLOCK_SIZE - MCRYPT_SHA256_DIGEST_SIZE);
    } else {
        memcpy(k_pad, key, key_len);
        memset(k_pad + key_len, 0, MCRYPT_SHA256_BLOCK_SIZE - key_len);
    }

    /* Inner: SHA256(K ^ ipad || message) */
    uint8_t i_key_pad[MCRYPT_SHA256_BLOCK_SIZE];
    for (int i = 0; i < MCRYPT_SHA256_BLOCK_SIZE; i++) {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        ctx->o_key_pad[i] = k_pad[i] ^ 0x5c;
    }

    mcrypt_sha256_init(&ctx->inner);
    mcrypt_sha256_update(&ctx->inner, i_key_pad, MCRYPT_SHA256_BLOCK_SIZE);
}

void mcrypt_hmac_sha256_update(mcrypt_hmac_sha256_t *ctx,
                                const void *data, uint32_t len)
{
    mcrypt_sha256_update(&ctx->inner, data, len);
}

void mcrypt_hmac_sha256_final(mcrypt_hmac_sha256_t *ctx,
                               uint8_t mac[MCRYPT_HMAC_SHA256_SIZE])
{
    uint8_t inner_hash[MCRYPT_SHA256_DIGEST_SIZE];
    mcrypt_sha256_final(&ctx->inner, inner_hash);

    /* Outer: SHA256(K ^ opad || inner_hash) */
    mcrypt_sha256_t outer;
    mcrypt_sha256_init(&outer);
    mcrypt_sha256_update(&outer, ctx->o_key_pad, MCRYPT_SHA256_BLOCK_SIZE);
    mcrypt_sha256_update(&outer, inner_hash, MCRYPT_SHA256_DIGEST_SIZE);
    mcrypt_sha256_final(&outer, mac);
}

void mcrypt_hmac_sha256(const void *key, uint32_t key_len,
                         const void *data, uint32_t data_len,
                         uint8_t mac[MCRYPT_HMAC_SHA256_SIZE])
{
    mcrypt_hmac_sha256_t ctx;
    mcrypt_hmac_sha256_init(&ctx, key, key_len);
    mcrypt_hmac_sha256_update(&ctx, data, data_len);
    mcrypt_hmac_sha256_final(&ctx, mac);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-128
 * ═══════════════════════════════════════════════════════════════════════════ */

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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
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
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static const uint8_t rcon[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

/* GF(2^8) multiply by 2 */
static inline uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void mcrypt_aes128_init(mcrypt_aes128_t *ctx,
                         const uint8_t key[MCRYPT_AES128_KEY_SIZE])
{
    /* Copy key into first 4 words */
    for (int i = 0; i < 4; i++) {
        ctx->round_keys[i] = be32(key + i*4);
    }

    /* Expand key schedule */
    for (int i = 4; i < 44; i++) {
        uint32_t temp = ctx->round_keys[i-1];
        if (i % 4 == 0) {
            /* RotWord + SubWord + Rcon */
            temp = ((uint32_t)aes_sbox[(temp >> 16) & 0xff] << 24) |
                   ((uint32_t)aes_sbox[(temp >>  8) & 0xff] << 16) |
                   ((uint32_t)aes_sbox[(temp      ) & 0xff] <<  8) |
                   ((uint32_t)aes_sbox[(temp >> 24) & 0xff]);
            temp ^= (uint32_t)rcon[i/4 - 1] << 24;
        }
        ctx->round_keys[i] = ctx->round_keys[i-4] ^ temp;
    }
}

/* State is 4×4 column-major in a flat uint8_t[16] */

static void add_round_key(uint8_t s[16], const uint32_t *rk)
{
    for (int i = 0; i < 4; i++) {
        s[i*4+0] ^= (uint8_t)(rk[i] >> 24);
        s[i*4+1] ^= (uint8_t)(rk[i] >> 16);
        s[i*4+2] ^= (uint8_t)(rk[i] >>  8);
        s[i*4+3] ^= (uint8_t)(rk[i]);
    }
}

static void sub_bytes(uint8_t s[16])
{
    for (int i = 0; i < 16; i++) s[i] = aes_sbox[s[i]];
}

static void inv_sub_bytes(uint8_t s[16])
{
    for (int i = 0; i < 16; i++) s[i] = aes_inv_sbox[s[i]];
}

static void shift_rows(uint8_t s[16])
{
    uint8_t t;
    /* s[col*4 + row]: row 0 = no shift */
    /* Row 1: shift left 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* Row 2: shift left 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* Row 3: shift left 3 = shift right 1 */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_shift_rows(uint8_t s[16])
{
    uint8_t t;
    /* Row 1: shift right 1 */
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    /* Row 2: shift right 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* Row 3: shift right 3 = shift left 1 */
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void mix_columns(uint8_t s[16])
{
    for (int i = 0; i < 4; i++) {
        uint8_t *c = s + i*4;
        uint8_t a0=c[0], a1=c[1], a2=c[2], a3=c[3];
        c[0] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        c[1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        c[2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        c[3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

static void inv_mix_columns(uint8_t s[16])
{
    for (int i = 0; i < 4; i++) {
        uint8_t *c = s + i*4;
        uint8_t a0=c[0], a1=c[1], a2=c[2], a3=c[3];
        /* Multiply by inverse matrix in GF(2^8) */
        uint8_t x2_0=xtime(a0), x2_1=xtime(a1), x2_2=xtime(a2), x2_3=xtime(a3);
        uint8_t x4_0=xtime(x2_0), x4_1=xtime(x2_1), x4_2=xtime(x2_2), x4_3=xtime(x2_3);
        uint8_t x8_0=xtime(x4_0), x8_1=xtime(x4_1), x8_2=xtime(x4_2), x8_3=xtime(x4_3);
        /* 0x0e=8^4^2, 0x0b=8^2^1, 0x0d=8^4^1, 0x09=8^1 */
        c[0] = (x8_0^x4_0^x2_0) ^ (x8_1^x2_1^a1) ^ (x8_2^x4_2^a2) ^ (x8_3^a3);
        c[1] = (x8_0^a0) ^ (x8_1^x4_1^x2_1) ^ (x8_2^x2_2^a2) ^ (x8_3^x4_3^a3);
        c[2] = (x8_0^x4_0^a0) ^ (x8_1^a1) ^ (x8_2^x4_2^x2_2) ^ (x8_3^x2_3^a3);
        c[3] = (x8_0^x2_0^a0) ^ (x8_1^x4_1^a1) ^ (x8_2^a2) ^ (x8_3^x4_3^x2_3);
    }
}

void mcrypt_aes128_encrypt_block(const mcrypt_aes128_t *ctx,
                                  const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    memcpy(s, in, 16);

    add_round_key(s, ctx->round_keys);

    for (int r = 1; r < 10; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, ctx->round_keys + r*4);
    }

    /* Last round (no MixColumns) */
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, ctx->round_keys + 40);

    memcpy(out, s, 16);
}

void mcrypt_aes128_decrypt_block(const mcrypt_aes128_t *ctx,
                                  const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    memcpy(s, in, 16);

    add_round_key(s, ctx->round_keys + 40);

    for (int r = 9; r >= 1; r--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, ctx->round_keys + r*4);
        inv_mix_columns(s);
    }

    /* First round */
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, ctx->round_keys);

    memcpy(out, s, 16);
}

void mcrypt_aes128_cbc_encrypt(const mcrypt_aes128_t *ctx,
                                uint8_t iv[16],
                                const uint8_t *in, uint8_t *out,
                                uint32_t len)
{
    for (uint32_t i = 0; i < len; i += 16) {
        /* XOR plaintext with IV/previous ciphertext */
        uint8_t block[16];
        for (int j = 0; j < 16; j++)
            block[j] = in[i+j] ^ iv[j];

        mcrypt_aes128_encrypt_block(ctx, block, out + i);
        memcpy(iv, out + i, 16);
    }
}

void mcrypt_aes128_cbc_decrypt(const mcrypt_aes128_t *ctx,
                                uint8_t iv[16],
                                const uint8_t *in, uint8_t *out,
                                uint32_t len)
{
    for (uint32_t i = 0; i < len; i += 16) {
        uint8_t block[16];
        mcrypt_aes128_decrypt_block(ctx, in + i, block);

        for (int j = 0; j < 16; j++)
            out[i+j] = block[j] ^ iv[j];

        memcpy(iv, in + i, 16);
    }
}
