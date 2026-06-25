# Design Notes

## Scope

`microcrypt` is a primitive library:

- SHA-256
- HMAC-SHA256
- AES-128 block encryption and decryption
- AES-128-CBC chaining helpers

It is not a protocol layer and it does not provide padding, AEAD, key exchange, or storage for keys.

## Memory model

- No heap allocation in the portable core
- Caller-owned contexts
- Deterministic memory use
- Explicit byte-oriented APIs
- No hidden mutable global state

## CBC boundary

CBC is confidentiality-only. It does not provide authenticity or integrity, and ciphertext is malleable. IV reuse under the same key leaks information. CBC input must be block aligned because this library does not provide padding.

## Security posture

The AES implementation uses lookup tables and is not constant-time on platforms where memory access patterns are observable. HMAC verification compares MAC bytes without an early exit on content differences, but that is not a whole-program constant-time proof.

## Compatibility

The checked API returns `mcrypt_status_t` and uses `size_t` lengths. Legacy compatibility is not the primary interface. Current public version is `2.0.0`.
