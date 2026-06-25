# Footprint

## Context sizes

Measured from the Debug MSVC build of `tests/test_all.c`:

- `sizeof(mcrypt_sha256_t)`: 120
- `sizeof(mcrypt_hmac_sha256_t)`: 320
- `sizeof(mcrypt_aes128_t)`: 184

## Code size

Measured from `build-check\Debug\microcrypt.lib`:

- `mcrypt.obj` text section: 13,738 bytes
- `mcrypt.lib` archive length: 52,408 bytes
- Primitive-by-primitive split: not separately verified in this object-only layout

## Static tables

- SHA-256 round constants: 256 bytes
- AES S-box: 256 bytes
- AES inverse S-box: 256 bytes
- AES Rcon: 10 bytes
- Total static table bytes: 778

## Stack usage

Collected from GCC `-fstack-usage` output in `build-gcc-stack`:

- `sha256_transform`: 368 bytes
- `mcrypt_hmac_sha256`: 592 bytes
- `mcrypt_hmac_sha256_init`: 288 bytes
- `mcrypt_hmac_sha256_final`: 224 bytes
- `mcrypt_aes128_cbc_decrypt`: 176 bytes
- `mcrypt_aes128_cbc_encrypt`: 144 bytes
- `mcrypt_sha256_final`: 240 bytes

## Notes

This document will be updated only with measurements gathered during the verification run, not stale planning text.
