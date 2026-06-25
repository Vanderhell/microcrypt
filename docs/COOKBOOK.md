# Cookbook

This file contains checked-API examples that match the shipped `mcrypt.h` surface.

## SHA-256 one-shot

```c
#include "mcrypt.h"

uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE];
mcrypt_status_t status = mcrypt_sha256("abc", 3u, digest);
if (status != MCRYPT_OK) {
    /* handle error */
}
```

## SHA-256 incremental

```c
#include "mcrypt.h"

uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE];
mcrypt_sha256_t ctx;

if (mcrypt_sha256_init(&ctx) != MCRYPT_OK) {
    /* handle error */
}
if (mcrypt_sha256_update(&ctx, part1, part1_len) != MCRYPT_OK ||
    mcrypt_sha256_update(&ctx, part2, part2_len) != MCRYPT_OK ||
    mcrypt_sha256_final(&ctx, digest) != MCRYPT_OK) {
    (void)mcrypt_sha256_clear(&ctx);
    /* handle error */
}
```

## HMAC create and verify

```c
#include "mcrypt.h"

uint8_t mac[MCRYPT_HMAC_SHA256_SIZE];
mcrypt_hmac_sha256_t ctx;

if (mcrypt_hmac_sha256_init(&ctx, key, key_len) != MCRYPT_OK) {
    /* handle error */
}
if (mcrypt_hmac_sha256_update(&ctx, data, data_len) != MCRYPT_OK ||
    mcrypt_hmac_sha256_final(&ctx, mac) != MCRYPT_OK) {
    (void)mcrypt_hmac_sha256_clear(&ctx);
    /* handle error */
}

if (mcrypt_hmac_sha256_verify(key, key_len, data, data_len, mac) != MCRYPT_OK) {
    /* handle authentication failure */
}
```

## AES-128 block usage

```c
#include "mcrypt.h"

uint8_t input[MCRYPT_AES128_BLOCK_SIZE];
uint8_t output[MCRYPT_AES128_BLOCK_SIZE];
mcrypt_aes128_t aes;

if (mcrypt_aes128_init(&aes, key) != MCRYPT_OK) {
    /* handle error */
}
if (mcrypt_aes128_encrypt_block(&aes, input, output) != MCRYPT_OK) {
    (void)mcrypt_aes128_clear(&aes);
    /* handle error */
}
```

## AES-128-CBC usage

```c
#include "mcrypt.h"

uint8_t iv[MCRYPT_AES128_BLOCK_SIZE] = {0};
uint8_t final_iv[MCRYPT_AES128_BLOCK_SIZE];
uint8_t ciphertext[32];
mcrypt_aes128_t aes;

if (mcrypt_aes128_init(&aes, key) != MCRYPT_OK) {
    /* handle error */
}
if (mcrypt_aes128_cbc_encrypt(&aes, iv, plaintext, sizeof plaintext,
                              ciphertext, final_iv) != MCRYPT_OK) {
    (void)mcrypt_aes128_clear(&aes);
    /* handle error */
}
```

CBC provides confidentiality only. It does not authenticate the ciphertext or the IV.

## Secure clear

```c
#include "mcrypt.h"

uint8_t secret[32];

mcrypt_secure_clear(secret, sizeof secret);
```

## Error handling

Every checked API returns `mcrypt_status_t`.

```c
mcrypt_status_t status = mcrypt_sha256(data, len, digest);
if (status == MCRYPT_OK) {
    /* use digest */
} else {
    /* inspect the status and clear any temporary buffers if needed */
}
```
