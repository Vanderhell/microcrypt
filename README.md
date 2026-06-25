# microcrypt

Portable C99 cryptographic primitives for embedded and constrained systems.

`microcrypt` is a low-level primitive library. It provides SHA-256, HMAC-SHA256, AES-128 block transforms, and AES-128-CBC helpers. It does not provide AEAD, padding, or a message encryption protocol.

## Security notice

This repository does not claim audit status, formal proof, FIPS validation, or side-channel resistance. AES uses lookup tables and is not suitable against cache/timing/power/EM attackers on observable platforms. CBC provides confidentiality only and must be used with authenticated designs.

## Features

- SHA-256 with checked init/update/final lifecycle
- HMAC-SHA256 with checked verification
- AES-128 block encrypt/decrypt
- AES-128-CBC with explicit chaining output
- Secure clearing helpers for secret material

## Build

```bash
cmake -S . -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

## Install

The CMake package exports `microcrypt::microcrypt`.

```cmake
find_package(microcrypt CONFIG REQUIRED)
target_link_libraries(app PRIVATE microcrypt::microcrypt)
```

## Documentation

- [Cookbook](docs/COOKBOOK.md)
- [Verification](docs/VERIFICATION.md)
- [Release process](docs/RELEASE.md)
- [Issue triage](docs/ISSUES.md)
- [Security policy](SECURITY.md)

## Usage

```c
#include "mcrypt.h"

uint8_t digest[MCRYPT_SHA256_DIGEST_SIZE];
mcrypt_status_t status = mcrypt_sha256("abc", 3, digest);
if (status != MCRYPT_OK) {
    /* handle error */
}
```

```c
mcrypt_hmac_sha256_t ctx;
uint8_t mac[MCRYPT_HMAC_SHA256_SIZE];

if (mcrypt_hmac_sha256_init(&ctx, key, key_len) == MCRYPT_OK &&
    mcrypt_hmac_sha256_update(&ctx, data, data_len) == MCRYPT_OK &&
    mcrypt_hmac_sha256_final(&ctx, mac) == MCRYPT_OK) {
    /* mac is ready */
}
```

## Version

Current version: `2.0.0`
