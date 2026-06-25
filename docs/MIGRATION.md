# Migration

## From void APIs to checked APIs

The checked API returns `mcrypt_status_t` and uses `size_t` lengths. Update call sites to handle failures explicitly.

## SHA-256

- `mcrypt_sha256_init`, `mcrypt_sha256_update`, and `mcrypt_sha256_final` now return status.
- Zero-length updates are valid.
- Finalization is one-shot; repeated final fails.

## HMAC-SHA256

- Use `mcrypt_hmac_sha256_verify` for constant-time verification.
- Temporary MACs and key-derived context material are cleared when practical.

## AES-128 and CBC

- AES block primitives require an initialized context.
- Exact in-place block encrypt/decrypt is supported.
- CBC uses a const IV input and an optional final chaining output.
- CBC requires block-aligned input because no padding API is provided.

## Build-system changes

- The package exports `microcrypt::microcrypt`.
- The library is installable through CMake package config files.
