/*
 * microcrypt test suite — NIST/RFC test vectors.
 *
 * Build: gcc -std=c99 -Wall -Wextra -Wpedantic -Werror \
 *        -I../include -I../../microtest/include \
 *        ../src/mcrypt.c test_all.c -lm -o test_all
 */

#define MTEST_IMPLEMENTATION
#include "mtest.h"
#include "mcrypt.h"

/* ── Hex helper ────────────────────────────────────────────────────────── */

static void hex_to_bytes(const char *hex, uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + i*2, "%2x", &val);
        out[i] = (uint8_t)val;
    }
}

static int bytes_match_hex(const uint8_t *data, int len, const char *hex)
{
    for (int i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + i*2, "%2x", &val);
        if (data[i] != (uint8_t)val) return 0;
    }
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SHA-256 tests — NIST FIPS 180-4 test vectors
 * ═══════════════════════════════════════════════════════════════════════════ */

MTEST(test_sha256_empty) {
    /* SHA-256("") */
    uint8_t digest[32];
    mcrypt_sha256("", 0, digest);
    MTEST_ASSERT_TRUE(bytes_match_hex(digest, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

MTEST(test_sha256_abc) {
    /* SHA-256("abc") — NIST example */
    uint8_t digest[32];
    mcrypt_sha256("abc", 3, digest);
    MTEST_ASSERT_TRUE(bytes_match_hex(digest, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

MTEST(test_sha256_448bit) {
    /* SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") */
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[32];
    mcrypt_sha256(msg, (uint32_t)strlen(msg), digest);
    MTEST_ASSERT_TRUE(bytes_match_hex(digest, 32,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

MTEST(test_sha256_incremental) {
    /* Same as abc but fed byte-by-byte */
    mcrypt_sha256_t ctx;
    mcrypt_sha256_init(&ctx);
    mcrypt_sha256_update(&ctx, "a", 1);
    mcrypt_sha256_update(&ctx, "b", 1);
    mcrypt_sha256_update(&ctx, "c", 1);
    uint8_t digest[32];
    mcrypt_sha256_final(&ctx, digest);
    MTEST_ASSERT_TRUE(bytes_match_hex(digest, 32,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

MTEST(test_sha256_long) {
    /* 64 bytes (exactly one block after padding boundary) */
    const char *msg = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    uint8_t digest[32];
    mcrypt_sha256(msg, 64, digest);
    /* Just verify it produces 32 bytes without crashing */
    MTEST_ASSERT_TRUE(digest[0] != 0 || digest[1] != 0);
}

MTEST(test_sha256_multi_block) {
    /* 128 bytes — crosses block boundary */
    uint8_t data[128];
    for (int i = 0; i < 128; i++) data[i] = (uint8_t)i;

    uint8_t d1[32], d2[32];
    mcrypt_sha256(data, 128, d1);

    /* Same via incremental (split at 70) */
    mcrypt_sha256_t ctx;
    mcrypt_sha256_init(&ctx);
    mcrypt_sha256_update(&ctx, data, 70);
    mcrypt_sha256_update(&ctx, data + 70, 58);
    mcrypt_sha256_final(&ctx, d2);

    MTEST_ASSERT_MEM_EQ(d1, d2, 32);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 tests — RFC 4231 test vectors
 * ═══════════════════════════════════════════════════════════════════════════ */

MTEST(test_hmac_rfc4231_1) {
    /* Test Case 1: key = 0x0b×20, data = "Hi There" */
    uint8_t key[20];
    memset(key, 0x0b, 20);

    uint8_t mac[32];
    mcrypt_hmac_sha256(key, 20, "Hi There", 8, mac);
    MTEST_ASSERT_TRUE(bytes_match_hex(mac, 32,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

MTEST(test_hmac_rfc4231_2) {
    /* Test Case 2: key = "Jefe", data = "what do ya want for nothing?" */
    uint8_t mac[32];
    mcrypt_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, mac);
    MTEST_ASSERT_TRUE(bytes_match_hex(mac, 32,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

MTEST(test_hmac_rfc4231_3) {
    /* Test Case 3: key = 0xaa×20, data = 0xdd×50 */
    uint8_t key[20], data[50];
    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);

    uint8_t mac[32];
    mcrypt_hmac_sha256(key, 20, data, 50, mac);
    MTEST_ASSERT_TRUE(bytes_match_hex(mac, 32,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
}

MTEST(test_hmac_incremental) {
    /* Same as test case 2 but fed in parts */
    mcrypt_hmac_sha256_t ctx;
    mcrypt_hmac_sha256_init(&ctx, "Jefe", 4);
    mcrypt_hmac_sha256_update(&ctx, "what do ya ", 11);
    mcrypt_hmac_sha256_update(&ctx, "want for nothing?", 17);
    uint8_t mac[32];
    mcrypt_hmac_sha256_final(&ctx, mac);
    MTEST_ASSERT_TRUE(bytes_match_hex(mac, 32,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

MTEST(test_hmac_long_key) {
    /* Key longer than block size → key gets hashed first */
    uint8_t key[100];
    memset(key, 0x42, 100);
    uint8_t mac[32];
    mcrypt_hmac_sha256(key, 100, "test", 4, mac);
    /* Just verify no crash and output is non-zero */
    MTEST_ASSERT_TRUE(mac[0] != 0 || mac[1] != 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-128 tests — NIST FIPS 197 test vectors
 * ═══════════════════════════════════════════════════════════════════════════ */

MTEST(test_aes128_ecb_encrypt) {
    /* NIST AES-128 ECB test vector:
     * Key:       2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext: 6bc1bee22e409f96e93d7e117393172a
     * Cipher:    3ad77bb40d7a3660a89ecaf32466ef97 */
    uint8_t key[16], pt[16], ct[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", pt, 16);
    hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97", expected, 16);

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_encrypt_block(&aes, pt, ct);

    MTEST_ASSERT_MEM_EQ(expected, ct, 16);
}

MTEST(test_aes128_ecb_decrypt) {
    uint8_t key[16], ct[16], pt[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97", ct, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", expected, 16);

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_decrypt_block(&aes, ct, pt);

    MTEST_ASSERT_MEM_EQ(expected, pt, 16);
}

MTEST(test_aes128_ecb_roundtrip) {
    uint8_t key[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                         0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    uint8_t pt[16]  = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                         0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    uint8_t ct[16], dec[16];

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_encrypt_block(&aes, pt, ct);
    mcrypt_aes128_decrypt_block(&aes, ct, dec);

    MTEST_ASSERT_MEM_EQ(pt, dec, 16);
}

MTEST(test_aes128_ecb_nist_vector2) {
    /* Second NIST vector:
     * Key:       2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext: ae2d8a571e03ac9c9eb76fac45af8e51
     * Cipher:    f5d3d58503b9699de785895a96fdbaaf */
    uint8_t key[16], pt[16], ct[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("ae2d8a571e03ac9c9eb76fac45af8e51", pt, 16);
    hex_to_bytes("f5d3d58503b9699de785895a96fdbaaf", expected, 16);

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_encrypt_block(&aes, pt, ct);

    MTEST_ASSERT_MEM_EQ(expected, ct, 16);
}

/* ── AES-128-CBC ───────────────────────────────────────────────────────── */

MTEST(test_aes128_cbc_encrypt) {
    /* NIST AES-128-CBC test:
     * Key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  000102030405060708090a0b0c0d0e0f
     * PT:  6bc1bee22e409f96e93d7e117393172a
     * CT:  7649abac8119b246cee98e9b12e9197d */
    uint8_t key[16], iv[16], pt[16], ct[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", pt, 16);
    hex_to_bytes("7649abac8119b246cee98e9b12e9197d", expected, 16);

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_cbc_encrypt(&aes, iv, pt, ct, 16);

    MTEST_ASSERT_MEM_EQ(expected, ct, 16);
}

MTEST(test_aes128_cbc_decrypt) {
    uint8_t key[16], iv[16], ct[16], pt[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv, 16);
    hex_to_bytes("7649abac8119b246cee98e9b12e9197d", ct, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", expected, 16);

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_cbc_decrypt(&aes, iv, ct, pt, 16);

    MTEST_ASSERT_MEM_EQ(expected, pt, 16);
}

MTEST(test_aes128_cbc_multi_block) {
    /* Encrypt 64 bytes (4 blocks), decrypt, verify roundtrip */
    uint8_t key[16] = {0};
    uint8_t iv_enc[16] = {0};
    uint8_t iv_dec[16] = {0};
    uint8_t pt[64], ct[64], dec[64];

    for (int i = 0; i < 64; i++) pt[i] = (uint8_t)i;

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);

    mcrypt_aes128_cbc_encrypt(&aes, iv_enc, pt, ct, 64);
    mcrypt_aes128_cbc_decrypt(&aes, iv_dec, ct, dec, 64);

    MTEST_ASSERT_MEM_EQ(pt, dec, 64);
}

MTEST(test_aes128_cbc_iv_chains) {
    /* Verify IV is updated to last ciphertext block (chaining) */
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t pt[32] = {0};
    uint8_t ct[32];

    mcrypt_aes128_t aes;
    mcrypt_aes128_init(&aes, key);
    mcrypt_aes128_cbc_encrypt(&aes, iv, pt, ct, 32);

    /* IV should now equal ct[16..31] (last ciphertext block) */
    MTEST_ASSERT_MEM_EQ(ct + 16, iv, 16);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Suites + Main
 * ═══════════════════════════════════════════════════════════════════════════ */

MTEST_SUITE(sha256) {
    MTEST_RUN(test_sha256_empty);
    MTEST_RUN(test_sha256_abc);
    MTEST_RUN(test_sha256_448bit);
    MTEST_RUN(test_sha256_incremental);
    MTEST_RUN(test_sha256_long);
    MTEST_RUN(test_sha256_multi_block);
}

MTEST_SUITE(hmac_sha256) {
    MTEST_RUN(test_hmac_rfc4231_1);
    MTEST_RUN(test_hmac_rfc4231_2);
    MTEST_RUN(test_hmac_rfc4231_3);
    MTEST_RUN(test_hmac_incremental);
    MTEST_RUN(test_hmac_long_key);
}

MTEST_SUITE(aes128_ecb) {
    MTEST_RUN(test_aes128_ecb_encrypt);
    MTEST_RUN(test_aes128_ecb_decrypt);
    MTEST_RUN(test_aes128_ecb_roundtrip);
    MTEST_RUN(test_aes128_ecb_nist_vector2);
}

MTEST_SUITE(aes128_cbc) {
    MTEST_RUN(test_aes128_cbc_encrypt);
    MTEST_RUN(test_aes128_cbc_decrypt);
    MTEST_RUN(test_aes128_cbc_multi_block);
    MTEST_RUN(test_aes128_cbc_iv_chains);
}

int main(int argc, char **argv) {
    MTEST_BEGIN(argc, argv);

    MTEST_SUITE_RUN(sha256);
    MTEST_SUITE_RUN(hmac_sha256);
    MTEST_SUITE_RUN(aes128_ecb);
    MTEST_SUITE_RUN(aes128_cbc);

    return MTEST_END();
}
