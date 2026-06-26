/*
 * microcrypt checked API test suite.
 */

#define MTEST_IMPLEMENTATION
#include "mtest.h"
#include "mcrypt.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#if defined(MICROCRYPT_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int hex_to_bytes_exact(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len;
    size_t i;

    if (hex == NULL || out == NULL) {
        return 0;
    }

    hex_len = strlen(hex);
    if (hex_len != out_len * 2u) {
        return 0;
    }

    for (i = 0u; i < out_len; ++i) {
        int hi = hex_value((unsigned char)hex[i * 2u]);
        int lo = hex_value((unsigned char)hex[(i * 2u) + 1u]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int hex_equals_bytes(const char *hex, const uint8_t *data, size_t len)
{
    uint8_t expected[64];
    if (len > sizeof expected) {
        return 0;
    }
    if (!hex_to_bytes_exact(hex, expected, len)) {
        return 0;
    }
    return memcmp(expected, data, len) == 0;
}

static void fill_incrementing(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0u; i < len; ++i) {
        buf[i] = (uint8_t)(i & 0xffu);
    }
}

static void fill_repeat(uint8_t *buf, size_t len, uint8_t value)
{
    size_t i;
    for (i = 0u; i < len; ++i) {
        buf[i] = value;
    }
}

static uint64_t rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

#if defined(MICROCRYPT_HAVE_OPENSSL)
static void write_random_bytes(uint64_t *seed, uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0u; i < len; ++i) {
        buf[i] = (uint8_t)rng_next(seed);
    }
}
#endif

static void expect_zero(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0u; i < len; ++i) {
        MTEST_ASSERT_EQ(0, buf[i]);
    }
}

static void expect_value(const uint8_t *buf, size_t len, uint8_t value)
{
    size_t i;
    for (i = 0u; i < len; ++i) {
        MTEST_ASSERT_EQ((int)value, (int)buf[i]);
    }
}

static void sha_one_shot_and_stream(const uint8_t *msg, size_t len, uint8_t digest[32], uint8_t streamed[32])
{
    mcrypt_sha256_t ctx;
    size_t offset = 0u;
    mcrypt_status_t status;

    status = mcrypt_sha256(msg, len, digest);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);

    status = mcrypt_sha256_init(&ctx);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    while (offset < len) {
        size_t step = len - offset;
        if (step > 7u) {
            step = (offset % 13u) + 1u;
            if (step > len - offset) {
                step = len - offset;
            }
        }
        status = mcrypt_sha256_update(&ctx, msg + offset, step);
        MTEST_ASSERT_EQ(MCRYPT_OK, status);
        offset += step;
    }
    status = mcrypt_sha256_update(&ctx, NULL, 0u);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    status = mcrypt_sha256_final(&ctx, streamed);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
}

#if defined(MICROCRYPT_HAVE_OPENSSL)
static void openssl_sha256(const uint8_t *msg, size_t len, uint8_t digest[32])
{
    EVP_MD_CTX *ctx;
    unsigned int out_len = 0u;

    ctx = EVP_MD_CTX_new();
    MTEST_ASSERT_TRUE(ctx != NULL);
    MTEST_ASSERT_EQ(1, EVP_DigestInit_ex(ctx, EVP_sha256(), NULL));
    if (len != 0u) {
        MTEST_ASSERT_EQ(1, EVP_DigestUpdate(ctx, msg, len));
    }
    MTEST_ASSERT_EQ(1, EVP_DigestFinal_ex(ctx, digest, &out_len));
    MTEST_ASSERT_EQ((unsigned int)32u, out_len);
    EVP_MD_CTX_free(ctx);
}

static void openssl_hmac_sha256(const uint8_t *key,
                                size_t key_len,
                                const uint8_t *msg,
                                size_t len,
                                uint8_t mac[32])
{
    unsigned int out_len = 0u;

    MTEST_ASSERT_TRUE(HMAC(EVP_sha256(),
                           key,
                           (int)key_len,
                           msg,
                           len,
                           mac,
                           &out_len) != NULL);
    MTEST_ASSERT_EQ((unsigned int)32u, out_len);
}

static void openssl_aes128_encrypt_block(const uint8_t key[16],
                                         const uint8_t in[16],
                                         uint8_t out[16])
{
    EVP_CIPHER_CTX *ctx;
    int produced = 0;
    int tail = 0;

    ctx = EVP_CIPHER_CTX_new();
    MTEST_ASSERT_TRUE(ctx != NULL);
    MTEST_ASSERT_EQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL));
    MTEST_ASSERT_EQ(1, EVP_CIPHER_CTX_set_padding(ctx, 0));
    MTEST_ASSERT_EQ(1, EVP_EncryptUpdate(ctx, out, &produced, in, 16));
    MTEST_ASSERT_EQ(16, produced);
    MTEST_ASSERT_EQ(1, EVP_EncryptFinal_ex(ctx, out + produced, &tail));
    MTEST_ASSERT_EQ(0, tail);
    EVP_CIPHER_CTX_free(ctx);
}

static void openssl_aes128_decrypt_block(const uint8_t key[16],
                                         const uint8_t in[16],
                                         uint8_t out[16])
{
    EVP_CIPHER_CTX *ctx;
    int produced = 0;
    int tail = 0;

    ctx = EVP_CIPHER_CTX_new();
    MTEST_ASSERT_TRUE(ctx != NULL);
    MTEST_ASSERT_EQ(1, EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL));
    MTEST_ASSERT_EQ(1, EVP_CIPHER_CTX_set_padding(ctx, 0));
    MTEST_ASSERT_EQ(1, EVP_DecryptUpdate(ctx, out, &produced, in, 16));
    MTEST_ASSERT_EQ(16, produced);
    MTEST_ASSERT_EQ(1, EVP_DecryptFinal_ex(ctx, out + produced, &tail));
    MTEST_ASSERT_EQ(0, tail);
    EVP_CIPHER_CTX_free(ctx);
}

static void openssl_aes128_cbc_encrypt(const uint8_t key[16],
                                       const uint8_t iv[16],
                                       const uint8_t *in,
                                       size_t len,
                                       uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int produced = 0;
    int tail = 0;
    uint8_t local_iv[16];

    ctx = EVP_CIPHER_CTX_new();
    MTEST_ASSERT_TRUE(ctx != NULL);
    memcpy(local_iv, iv, sizeof local_iv);
    MTEST_ASSERT_EQ(1, EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, local_iv));
    MTEST_ASSERT_EQ(1, EVP_CIPHER_CTX_set_padding(ctx, 0));
    if (len != 0u) {
        MTEST_ASSERT_EQ(1, EVP_EncryptUpdate(ctx, out, &produced, in, (int)len));
        MTEST_ASSERT_EQ((int)len, produced);
    }
    MTEST_ASSERT_EQ(1, EVP_EncryptFinal_ex(ctx, out + produced, &tail));
    MTEST_ASSERT_EQ(0, tail);
    EVP_CIPHER_CTX_free(ctx);
}

static void openssl_aes128_cbc_decrypt(const uint8_t key[16],
                                       const uint8_t iv[16],
                                       const uint8_t *in,
                                       size_t len,
                                       uint8_t *out)
{
    EVP_CIPHER_CTX *ctx;
    int produced = 0;
    int tail = 0;
    uint8_t local_iv[16];

    ctx = EVP_CIPHER_CTX_new();
    MTEST_ASSERT_TRUE(ctx != NULL);
    memcpy(local_iv, iv, sizeof local_iv);
    MTEST_ASSERT_EQ(1, EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, local_iv));
    MTEST_ASSERT_EQ(1, EVP_CIPHER_CTX_set_padding(ctx, 0));
    if (len != 0u) {
        MTEST_ASSERT_EQ(1, EVP_DecryptUpdate(ctx, out, &produced, in, (int)len));
        MTEST_ASSERT_EQ((int)len, produced);
    }
    MTEST_ASSERT_EQ(1, EVP_DecryptFinal_ex(ctx, out + produced, &tail));
    MTEST_ASSERT_EQ(0, tail);
    EVP_CIPHER_CTX_free(ctx);
}
#endif

MTEST(test_secure_equal_and_clear) {
    const uint8_t a[4] = {1, 2, 3, 4};
    const uint8_t b[4] = {1, 2, 3, 4};
    const uint8_t c[4] = {1, 2, 3, 5};
    uint8_t clear_me[8];

    fill_repeat(clear_me, sizeof clear_me, 0xaa);
    MTEST_ASSERT_TRUE(mcrypt_secure_equal(NULL, NULL, 0u));
    MTEST_ASSERT_TRUE(!mcrypt_secure_equal(NULL, a, 4u));
    MTEST_ASSERT_TRUE(mcrypt_secure_equal(a, b, 4u));
    MTEST_ASSERT_TRUE(!mcrypt_secure_equal(a, c, 4u));
    mcrypt_secure_clear(clear_me, sizeof clear_me);
    expect_zero(clear_me, sizeof clear_me);
}

MTEST(test_sha256_vectors) {
    const char *abc = "abc";
    const char *vec448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[32];

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256("", 0u, digest));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855", digest, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(abc, 3u, digest));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad", digest, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(vec448, strlen(vec448), digest));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1", digest, 32u));

    fill_repeat(digest, sizeof digest, 0x5a);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(NULL, 0u, digest));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855", digest, 32u));
}

MTEST(test_sha256_boundaries_and_streaming) {
    uint8_t msg[129];
    uint8_t one_shot[32];
    uint8_t streamed[32];
    size_t lengths[] = {1u, 55u, 56u, 57u, 63u, 64u, 65u, 127u, 128u, 129u};
    size_t i;

    fill_incrementing(msg, sizeof msg);
    for (i = 0u; i < sizeof lengths / sizeof lengths[0]; ++i) {
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(msg, lengths[i], one_shot));
        sha_one_shot_and_stream(msg, lengths[i], streamed, one_shot);
        MTEST_ASSERT_MEM_EQ(one_shot, streamed, 32u);
    }
}

MTEST(test_sha256_byte_by_byte) {
    uint8_t msg[130];
    uint8_t digest[32];
    uint8_t stream[32];
    mcrypt_sha256_t ctx;
    size_t i;

    fill_incrementing(msg, sizeof msg);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(msg, sizeof msg, digest));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&ctx));
    for (i = 0u; i < sizeof msg; ++i) {
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_update(&ctx, msg + i, 1u));
    }
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_final(&ctx, stream));
    MTEST_ASSERT_MEM_EQ(digest, stream, 32u);
}

MTEST(test_sha256_million_a) {
    uint8_t block[1000];
    uint8_t digest[32];
    mcrypt_sha256_t ctx;
    size_t i;
    size_t rounds;

    fill_repeat(block, sizeof block, (uint8_t)'a');
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&ctx));
    for (rounds = 0u; rounds < 1000u; ++rounds) {
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_update(&ctx, block, sizeof block));
    }
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_final(&ctx, digest));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "cdc76e5c9914fb9281a1c7e284d73e67"
        "f1809a48a497200e046d39ccc7112cd0", digest, 32u));
    for (i = 0u; i < sizeof block; ++i) {
        MTEST_ASSERT_EQ((int)'a', (int)block[i]);
    }
}

MTEST(test_sha256_lifecycle_and_failure_paths) {
    uint8_t digest[32];
    uint8_t snapshot[sizeof(mcrypt_sha256_t)];
    mcrypt_sha256_t ctx;
    mcrypt_status_t status;

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&ctx));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_update(&ctx, "abc", 3u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_final(&ctx, digest));
    fill_repeat(digest, sizeof digest, 0x99);
    status = mcrypt_sha256_final(&ctx, digest);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_STATE, status);
    expect_zero(digest, sizeof digest);

    status = mcrypt_sha256_update(&ctx, "x", 1u);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_STATE, status);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_clear(&ctx));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&ctx));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&ctx));
    ctx.total_bytes = UINT64_MAX / 8u;
    ctx.buffer_len = 0u;
    memcpy(snapshot, &ctx, sizeof ctx);
    status = mcrypt_sha256_update(&ctx, "x", 1u);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_LENGTH, status);
    MTEST_ASSERT_MEM_EQ(snapshot, &ctx, sizeof ctx);

    ctx.total_bytes = UINT64_MAX - 1u;
    memcpy(snapshot, &ctx, sizeof ctx);
    status = mcrypt_sha256_update(&ctx, "xy", 2u);
    MTEST_ASSERT_EQ(MCRYPT_ERR_OVERFLOW, status);
    MTEST_ASSERT_MEM_EQ(snapshot, &ctx, sizeof ctx);

    fill_repeat(digest, sizeof digest, 0x88);
    status = mcrypt_sha256(NULL, 1u, digest);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
    expect_zero(digest, sizeof digest);
    status = mcrypt_sha256_update(&ctx, NULL, 1u);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
    MTEST_ASSERT_MEM_EQ(snapshot, &ctx, sizeof ctx);
}

MTEST(test_hmac_vectors_and_incremental) {
    uint8_t mac[32];
    uint8_t stream[32];
    mcrypt_hmac_sha256_t ctx;
    uint8_t key1[20];
    uint8_t key3[20];
    uint8_t key4[25];
    uint8_t key5[20];
    uint8_t key6[131];
    uint8_t key7[131];
    uint8_t data3[50];
    uint8_t data4[50];
    uint8_t data6[54];
    uint8_t data7[152];
    size_t i;

    fill_repeat(key1, sizeof key1, 0x0b);
    fill_repeat(key3, sizeof key3, 0xaa);
    for (i = 0u; i < sizeof key4; ++i) {
        key4[i] = (uint8_t)(i + 1u);
    }
    fill_repeat(key5, sizeof key5, 0x0c);
    fill_repeat(key6, sizeof key6, 0xaa);
    fill_repeat(key7, sizeof key7, 0xaa);
    fill_repeat(data3, sizeof data3, 0xdd);
    fill_repeat(data4, sizeof data4, 0xcd);
    MTEST_ASSERT_TRUE(hex_to_bytes_exact(
        "54657374205573696e67204c61726765"
        "72205468616e20426c6f636b2d53697a"
        "65204b6579202d2048617368204b6579"
        "204669727374", data6, sizeof data6));
    MTEST_ASSERT_TRUE(hex_to_bytes_exact(
        "54686973206973206120746573742075"
        "73696e672061206c6172676572207468"
        "616e20626c6f636b2d73697a65206b65"
        "7920616e642061206c61726765722074"
        "68616e20626c6f636b2d73697a652064"
        "6174612e20546865206b6579206e6565"
        "647320746f2062652068617368656420"
        "6265666f7265206265696e6720757365"
        "642062792074686520484d414320616c"
        "676f726974686d2e", data7, sizeof data7));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key1, sizeof key1, "Hi There", 8u, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7", mac, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256("Jefe", 4u, "what do ya want for nothing?", 28u, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843", mac, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key3, sizeof key3, data3, sizeof data3, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "773ea91e36800e46854db8ebd09181a7"
        "2959098b3ef8c122d9635514ced565fe", mac, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_init(&ctx, "Jefe", 4u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_update(&ctx, "what do ya ", 11u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_update(&ctx, "want for nothing?", 17u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_final(&ctx, stream));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843", stream, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key4, sizeof key4, data4, sizeof data4, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "82558a389a443c0ea4cc819899f2083a"
        "85f0faa3e578f8077a2e3ff46729665b", mac, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key5, sizeof key5, "Test With Truncation", 20u, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "a3b6167473100ee06e0c796c2955552b", mac, 16u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key6, sizeof key6, data6, sizeof data6, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "60e431591ee0b67f0d8a26aacbf5b77f"
        "8e0bc6213728c5140546040f0ee37f54", mac, 32u));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key7, sizeof key7, data7, sizeof data7, mac));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "9b09ffa71b942fcb27635fbcd5b0e944"
        "bfdc63644f0713938a7f51535c3a35e2", mac, 32u));
}

MTEST(test_hmac_verification_and_cleanup) {
    uint8_t mac[32];
    uint8_t modified[32];
    mcrypt_hmac_sha256_t ctx;
    size_t i;
    mcrypt_status_t status;

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256("Jefe", 4u, "what do ya want for nothing?", 28u, mac));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_verify("Jefe", 4u, "what do ya want for nothing?", 28u, mac));
    for (i = 0u; i < sizeof mac; ++i) {
        memcpy(modified, mac, sizeof mac);
        modified[i] ^= 0x01u;
        status = mcrypt_hmac_sha256_verify("Jefe", 4u, "what do ya want for nothing?", 28u, modified);
        MTEST_ASSERT_EQ(MCRYPT_ERR_AUTH_FAILED, status);
    }

    fill_repeat(modified, sizeof modified, 0x7au);
    status = mcrypt_hmac_sha256(NULL, 1u, "x", 1u, modified);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
    expect_zero(modified, sizeof modified);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_init(&ctx, "Jefe", 4u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_update(&ctx, "abc", 3u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_final(&ctx, mac));
    expect_zero(ctx.inner_pad, sizeof ctx.inner_pad);
    expect_zero(ctx.outer_pad, sizeof ctx.outer_pad);
    expect_zero(ctx.key_block, sizeof ctx.key_block);
    expect_zero((const uint8_t *)ctx.inner.h, sizeof ctx.inner.h);
    expect_zero(ctx.inner.buffer, sizeof ctx.inner.buffer);
    MTEST_ASSERT_EQ(2, (int)ctx.state);
    status = mcrypt_hmac_sha256_update(&ctx, "x", 1u);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_STATE, status);
}

MTEST(test_hmac_zero_length_and_null_rules) {
    uint8_t mac[32];
    uint8_t stream[32];
    mcrypt_hmac_sha256_t ctx;
    mcrypt_status_t status;

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(NULL, 0u, NULL, 0u, mac));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_init(&ctx, NULL, 0u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_final(&ctx, stream));
    MTEST_ASSERT_MEM_EQ(mac, stream, 32u);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_init(&ctx, NULL, 0u));
    status = mcrypt_hmac_sha256_update(&ctx, NULL, 0u);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_final(&ctx, mac));

    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, mcrypt_hmac_sha256(NULL, 1u, "x", 1u, mac));
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, mcrypt_hmac_sha256("k", 1u, NULL, 1u, mac));
    status = mcrypt_hmac_sha256_verify(NULL, 0u, NULL, 0u, NULL);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
}

MTEST(test_aes128_block_vectors_and_inplace) {
    uint8_t key[16];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t dec[16];
    uint8_t zero[16] = {0};
    mcrypt_aes128_t aes;

    MTEST_ASSERT_TRUE(hex_to_bytes_exact("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof key));
    MTEST_ASSERT_TRUE(hex_to_bytes_exact("6bc1bee22e409f96e93d7e117393172a", pt, sizeof pt));
    MTEST_ASSERT_TRUE(hex_to_bytes_exact("3ad77bb40d7a3660a89ecaf32466ef97", ct, sizeof ct));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_encrypt_block(&aes, pt, dec));
    MTEST_ASSERT_MEM_EQ(ct, dec, 16u);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_decrypt_block(&aes, dec, dec));
    MTEST_ASSERT_MEM_EQ(pt, dec, 16u);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_encrypt_block(&aes, zero, zero));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "7df76b0c1ab899b33e42f047b91b546f", zero, 16u));

    MTEST_ASSERT_TRUE(hex_to_bytes_exact("00000000000000000000000000000000", zero, sizeof zero));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, zero));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_encrypt_block(&aes, zero, zero));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "66e94bd4ef8a2c3b884cfa59ca342b2e", zero, 16u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_decrypt_block(&aes, zero, zero));
    expect_zero(zero, sizeof zero);

    MTEST_ASSERT_TRUE(hex_to_bytes_exact("6bc1bee22e409f96e93d7e117393172a", pt, sizeof pt));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_encrypt_block(&aes, pt, pt));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "3ad77bb40d7a3660a89ecaf32466ef97", pt, 16u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_decrypt_block(&aes, pt, pt));
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "6bc1bee22e409f96e93d7e117393172a", pt, 16u));
}

MTEST(test_aes128_block_overlap_and_lifecycle) {
    uint8_t buf[48];
    uint8_t out[16];
    uint8_t key[16] = {0};
    mcrypt_aes128_t aes;
    mcrypt_status_t status;

    fill_incrementing(buf, sizeof buf);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_STATE, mcrypt_aes128_encrypt_block(NULL, buf, out));
    expect_zero(out, sizeof out);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    status = mcrypt_aes128_encrypt_block(&aes, buf, buf + 1u);
    MTEST_ASSERT_EQ(MCRYPT_ERR_OVERLAP, status);
    status = mcrypt_aes128_decrypt_block(&aes, buf + 1u, buf);
    MTEST_ASSERT_EQ(MCRYPT_ERR_OVERLAP, status);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_clear(&aes));
    status = mcrypt_aes128_encrypt_block(&aes, buf, out);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_STATE, status);
    expect_zero(out, sizeof out);

    status = mcrypt_aes128_init(&aes, NULL);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
}

static void aes_cbc_vector_check(void)
{
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t out[64];
    uint8_t chaining[16];
    mcrypt_aes128_t aes;

    MTEST_ASSERT_TRUE(hex_to_bytes_exact("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof key));
    MTEST_ASSERT_TRUE(hex_to_bytes_exact("000102030405060708090a0b0c0d0e0f", iv, sizeof iv));
    MTEST_ASSERT_TRUE(hex_to_bytes_exact(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710", pt, sizeof pt));
    MTEST_ASSERT_TRUE(hex_to_bytes_exact(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7", ct, sizeof ct));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_encrypt(&aes, iv, pt, sizeof pt, out, chaining));
    MTEST_ASSERT_MEM_EQ(ct, out, sizeof ct);
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "3ff1caa1681fac09120eca307586e1a7", chaining, 16u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_decrypt(&aes, iv, ct, sizeof ct, out, chaining));
    MTEST_ASSERT_MEM_EQ(pt, out, sizeof pt);
    MTEST_ASSERT_TRUE(hex_equals_bytes(
        "3ff1caa1681fac09120eca307586e1a7", chaining, 16u));
}

MTEST(test_aes128_cbc_zero_length_null_and_overlaps) {
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t out[16];
    uint8_t buf[64];
    uint8_t chaining[16];
    mcrypt_aes128_t aes;
    size_t offset;
    mcrypt_status_t status;

    fill_repeat(out, sizeof out, 0xaa);
    fill_repeat(chaining, sizeof chaining, 0xbb);
    fill_incrementing(buf, sizeof buf);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));

    status = mcrypt_aes128_cbc_encrypt(&aes, iv, NULL, 0u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    expect_value(out, sizeof out, 0xaa);
    fill_repeat(out, sizeof out, 0xaa);
    status = mcrypt_aes128_cbc_decrypt(&aes, iv, NULL, 0u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    expect_value(out, sizeof out, 0xaa);

    status = mcrypt_aes128_cbc_encrypt(&aes, NULL, buf, 16u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
    status = mcrypt_aes128_cbc_encrypt(&aes, iv, NULL, 16u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);
    status = mcrypt_aes128_cbc_encrypt(&aes, iv, buf, 16u, NULL, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_ARGUMENT, status);

    for (offset = 1u; offset <= 15u; ++offset) {
        status = mcrypt_aes128_cbc_encrypt(&aes, iv, buf, 32u, buf + offset, chaining);
        MTEST_ASSERT_EQ(MCRYPT_ERR_OVERLAP, status);
        status = mcrypt_aes128_cbc_decrypt(&aes, iv, buf + offset, 32u, buf, chaining);
        MTEST_ASSERT_EQ(MCRYPT_ERR_OVERLAP, status);
    }

    status = mcrypt_aes128_cbc_encrypt(&aes, iv, buf, 1u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_LENGTH, status);
    status = mcrypt_aes128_cbc_encrypt(&aes, iv, buf, 17u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_LENGTH, status);
    status = mcrypt_aes128_cbc_encrypt(&aes, iv, buf, SIZE_MAX - 1u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_LENGTH, status);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_clear(&aes));
    status = mcrypt_aes128_cbc_encrypt(&aes, iv, buf, 16u, out, chaining);
    MTEST_ASSERT_EQ(MCRYPT_ERR_INVALID_STATE, status);
    expect_zero(out, sizeof out);
}

static void cbc_in_place_roundtrip(size_t blocks, uint64_t seed)
{
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t plain[16 * 16];
    uint8_t ref_ct[16 * 16];
    uint8_t work[16 * 16];
    uint8_t dec[16 * 16];
    uint8_t chaining[16];
    mcrypt_aes128_t aes;
    size_t len = blocks * 16u;
    mcrypt_status_t status;
    size_t i;
    uint64_t rng = seed;

    fill_repeat(key, sizeof key, 0x11);
    memset(plain, 0, sizeof plain);
    memset(work, 0, sizeof work);
    memset(dec, 0, sizeof dec);
    for (i = 0u; i < sizeof iv; ++i) {
        iv[i] = (uint8_t)rng_next(&rng);
    }
    for (i = 0u; i < len; ++i) {
        plain[i] = (uint8_t)rng_next(&rng);
    }
    memcpy(work, plain, len);
    memcpy(dec, plain, len);

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    status = mcrypt_aes128_cbc_encrypt(&aes, iv, plain, len, ref_ct, chaining);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);

    status = mcrypt_aes128_cbc_encrypt(&aes, iv, work, len, work, chaining);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    MTEST_ASSERT_MEM_EQ(ref_ct, work, len);

    status = mcrypt_aes128_cbc_decrypt(&aes, iv, ref_ct, len, dec, chaining);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    MTEST_ASSERT_MEM_EQ(plain, dec, len);

    memcpy(dec, ref_ct, len);
    status = mcrypt_aes128_cbc_decrypt(&aes, iv, dec, len, dec, chaining);
    MTEST_ASSERT_EQ(MCRYPT_OK, status);
    MTEST_ASSERT_MEM_EQ(plain, dec, len);
}

MTEST(test_aes128_cbc_in_place_and_randomized) {
    size_t blocks;
    uint64_t seed = 0x4d435259707421u;

    cbc_in_place_roundtrip(1u, seed);
    cbc_in_place_roundtrip(2u, seed + 1u);
    cbc_in_place_roundtrip(4u, seed + 2u);
    for (blocks = 1u; blocks <= 8u; ++blocks) {
        cbc_in_place_roundtrip(blocks, seed + (uint64_t)(blocks * 17u));
    }
}

MTEST(test_fuzz_smoke) {
    uint64_t seed = 0xdecafbad12345678ull;
    uint8_t buf[256];
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t out[256];
    uint8_t mac[32];
    uint8_t digest[32];
    mcrypt_sha256_t sha;
    mcrypt_hmac_sha256_t hmac;
    mcrypt_aes128_t aes;
    size_t cases;

    fill_repeat(key, sizeof key, 0x22);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    for (cases = 0u; cases < 200u; ++cases) {
        size_t len = (size_t)(rng_next(&seed) % sizeof buf);
        size_t blocks = len - (len % 16u);
        size_t j;

        for (j = 0u; j < len; ++j) {
            buf[j] = (uint8_t)rng_next(&seed);
        }
        for (j = 0u; j < sizeof iv; ++j) {
            iv[j] = (uint8_t)rng_next(&seed);
        }

        if (blocks == 0u) {
            MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(buf, len, digest));
            MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key, sizeof key, buf, len, mac));
            continue;
        }

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&sha));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_update(&sha, buf, len));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_final(&sha, digest));

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_init(&hmac, key, sizeof key));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_update(&hmac, buf, len));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_final(&hmac, mac));

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_encrypt(&aes, iv, buf, blocks, out, NULL));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_decrypt(&aes, iv, out, blocks, out, NULL));
        MTEST_ASSERT_MEM_EQ(buf, out, blocks);
    }
}

#if defined(MICROCRYPT_HAVE_OPENSSL)
static void run_differential_sha256_cases(void)
{
    uint64_t seed = 0x5348413235364441ull;
    uint8_t msg[512];
    uint8_t digest[32];
    uint8_t oracle[32];
    size_t cases;

    for (cases = 0u; cases < 512u; ++cases) {
        size_t len = (size_t)(rng_next(&seed) % sizeof msg);
        write_random_bytes(&seed, msg, len);
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(msg, len, digest));
        openssl_sha256(msg, len, oracle);
        MTEST_ASSERT_MEM_EQ(oracle, digest, sizeof digest);
    }
}

static void run_differential_hmac_cases(void)
{
    uint64_t seed = 0x484d414336353641ull;
    uint8_t key[96];
    uint8_t msg[512];
    uint8_t mac[32];
    uint8_t oracle[32];
    size_t cases;

    for (cases = 0u; cases < 512u; ++cases) {
        size_t key_len = (size_t)(rng_next(&seed) % sizeof key);
        size_t msg_len = (size_t)(rng_next(&seed) % sizeof msg);
        write_random_bytes(&seed, key, key_len);
        write_random_bytes(&seed, msg, msg_len);
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(key, key_len, msg, msg_len, mac));
        openssl_hmac_sha256(key, key_len, msg, msg_len, oracle);
        MTEST_ASSERT_MEM_EQ(oracle, mac, sizeof mac);
    }
}

static void run_differential_aes_block_cases(void)
{
    uint64_t seed = 0x414553313238424cull;
    uint8_t key[16];
    uint8_t plain[16];
    uint8_t expected_plain[16];
    uint8_t cipher[16];
    uint8_t decrypted[16];
    uint8_t oracle[16];
    mcrypt_aes128_t aes;
    size_t cases;

    for (cases = 0u; cases < 512u; ++cases) {
        write_random_bytes(&seed, key, sizeof key);
        write_random_bytes(&seed, plain, sizeof plain);
        memcpy(expected_plain, plain, sizeof expected_plain);

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_encrypt_block(&aes, plain, cipher));
        openssl_aes128_encrypt_block(key, plain, oracle);
        MTEST_ASSERT_MEM_EQ(oracle, cipher, sizeof cipher);

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_decrypt_block(&aes, cipher, decrypted));
        openssl_aes128_decrypt_block(key, oracle, plain);
        MTEST_ASSERT_MEM_EQ(expected_plain, decrypted, sizeof decrypted);
        MTEST_ASSERT_MEM_EQ(expected_plain, plain, sizeof plain);
    }
}

static void run_differential_aes_cbc_cases(void)
{
    uint64_t seed = 0x4145532d43424331ull;
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t plain[16 * 8];
    uint8_t cipher[16 * 8];
    uint8_t decrypted[16 * 8];
    uint8_t oracle_cipher[16 * 8];
    uint8_t oracle_plain[16 * 8];
    uint8_t oracle_decrypted[16 * 8];
    uint8_t final_iv[16];
    uint8_t oracle_final_iv[16];
    mcrypt_aes128_t aes;
    size_t cases;

    for (cases = 0u; cases < 256u; ++cases) {
        size_t blocks = (size_t)((rng_next(&seed) % 8u) + 1u);
        size_t len = blocks * 16u;

        write_random_bytes(&seed, key, sizeof key);
        write_random_bytes(&seed, iv, sizeof iv);
        write_random_bytes(&seed, plain, len);

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_encrypt(&aes, iv, plain, len, cipher, final_iv));
        openssl_aes128_cbc_encrypt(key, iv, plain, len, oracle_cipher);
        memcpy(oracle_final_iv, oracle_cipher + (len - 16u), sizeof oracle_final_iv);
        MTEST_ASSERT_MEM_EQ(oracle_cipher, cipher, len);
        MTEST_ASSERT_MEM_EQ(oracle_final_iv, final_iv, sizeof final_iv);

        MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_decrypt(&aes, iv, cipher, len, decrypted, final_iv));
        memcpy(oracle_plain, oracle_cipher, len);
        openssl_aes128_cbc_decrypt(key, iv, oracle_plain, len, oracle_decrypted);
        MTEST_ASSERT_MEM_EQ(plain, decrypted, len);
        MTEST_ASSERT_MEM_EQ(plain, oracle_decrypted, len);
        MTEST_ASSERT_MEM_EQ(oracle_final_iv, final_iv, sizeof final_iv);
    }
}
#endif

MTEST(test_differential_oracle_or_skip) {
#if defined(MICROCRYPT_HAVE_OPENSSL)
    run_differential_sha256_cases();
    run_differential_hmac_cases();
    run_differential_aes_block_cases();
    run_differential_aes_cbc_cases();
#else
    printf("NOT VERIFIED: OpenSSL oracle unavailable\n");
    MTEST_ASSERT_TRUE(1);
#endif
}

MTEST(test_null_zero_length_rules) {
    uint8_t digest[32];
    uint8_t mac[32];
    uint8_t buf[16];
    uint8_t iv[16] = {0};
    mcrypt_sha256_t sha;
    mcrypt_hmac_sha256_t hmac;
    mcrypt_aes128_t aes;
    uint8_t key[16] = {0};

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256(NULL, 0u, digest));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_init(&sha));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_update(&sha, NULL, 0u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_sha256_final(&sha, digest));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256(NULL, 0u, NULL, 0u, mac));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_init(&hmac, NULL, 0u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_update(&hmac, NULL, 0u));
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_hmac_sha256_final(&hmac, mac));

    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_init(&aes, key));
    fill_repeat(buf, sizeof buf, 0x55);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_encrypt(&aes, iv, NULL, 0u, buf, NULL));
    expect_value(buf, sizeof buf, 0x55);
    MTEST_ASSERT_EQ(MCRYPT_OK, mcrypt_aes128_cbc_decrypt(&aes, iv, NULL, 0u, buf, NULL));
    expect_value(buf, sizeof buf, 0x55);
}

MTEST(test_aes128_cbc_vector_check) {
    aes_cbc_vector_check();
}

MTEST(test_footprint_measurement) {
    printf("sizeof(mcrypt_sha256_t)=%zu\n", sizeof(mcrypt_sha256_t));
    printf("sizeof(mcrypt_hmac_sha256_t)=%zu\n", sizeof(mcrypt_hmac_sha256_t));
    printf("sizeof(mcrypt_aes128_t)=%zu\n", sizeof(mcrypt_aes128_t));
    MTEST_ASSERT_TRUE(1);
}

MTEST_SUITE(crypto) {
    MTEST_RUN(test_secure_equal_and_clear);
    MTEST_RUN(test_sha256_vectors);
    MTEST_RUN(test_sha256_boundaries_and_streaming);
    MTEST_RUN(test_sha256_byte_by_byte);
    MTEST_RUN(test_sha256_million_a);
    MTEST_RUN(test_sha256_lifecycle_and_failure_paths);
    MTEST_RUN(test_hmac_vectors_and_incremental);
    MTEST_RUN(test_hmac_verification_and_cleanup);
    MTEST_RUN(test_hmac_zero_length_and_null_rules);
    MTEST_RUN(test_aes128_block_vectors_and_inplace);
    MTEST_RUN(test_aes128_block_overlap_and_lifecycle);
    MTEST_RUN(test_aes128_cbc_zero_length_null_and_overlaps);
    MTEST_RUN(test_aes128_cbc_vector_check);
    MTEST_RUN(test_aes128_cbc_in_place_and_randomized);
    MTEST_RUN(test_fuzz_smoke);
    MTEST_RUN(test_differential_oracle_or_skip);
    MTEST_RUN(test_null_zero_length_rules);
    MTEST_RUN(test_footprint_measurement);
}

int main(int argc, char **argv)
{
    MTEST_BEGIN(argc, argv);
    MTEST_SUITE_RUN(crypto);
    return MTEST_END();
}
