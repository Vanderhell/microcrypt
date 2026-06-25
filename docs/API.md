# API Reference

## Status model

All checked APIs return `mcrypt_status_t`:

- `MCRYPT_OK`
- `MCRYPT_ERR_INVALID_ARGUMENT`
- `MCRYPT_ERR_INVALID_LENGTH`
- `MCRYPT_ERR_INVALID_STATE`
- `MCRYPT_ERR_OVERFLOW`
- `MCRYPT_ERR_UNSUPPORTED`
- `MCRYPT_ERR_AUTH_FAILED`
- `MCRYPT_ERR_OVERLAP`
- `MCRYPT_ERR_INTERNAL`

## Null and zero-length rules

- `data == NULL && len == 0` is valid for SHA-256 and HMAC-SHA256 update and one-shot hashing.
- `data == NULL && len > 0` returns `MCRYPT_ERR_INVALID_ARGUMENT`.
- Empty HMAC keys are valid.
- `key == NULL && key_len > 0` returns `MCRYPT_ERR_INVALID_ARGUMENT`.
- Required `ctx`, `out`, `key`, and `iv` pointers must be non-null.

## Lifecycle

- SHA/HMAC contexts start uninitialized, become active after init, become finalized after final, and become cleared after clear.
- SHA/HMAC update and final require the active state.
- Update after final fails.
- Repeated final fails.
- Re-init after final or clear works.
- AES contexts are active after init and invalid after clear.

## Overlap and in-place behavior

- AES block encrypt/decrypt allow exact `in == out`.
- Partial overlap is rejected with `MCRYPT_ERR_OVERLAP`.
- CBC encrypt/decrypt allow exact in-place operation for aligned buffers.
- CBC rejects partial overlap before accessing the input buffer.

## CBC chaining

- The checked CBC APIs accept a const IV input.
- They do not mutate the IV argument.
- Optional `final_iv` receives the final chaining value when provided.

## Failure behavior

- Output buffers are cleared on failure when the output size is known and the pointer is non-null.
- Rejected operations do not mutate active contexts.

## Limits

- SHA-256 tracks total message length in bytes and rejects overflow or messages exceeding the 64-bit bit-length limit.
- CBC requires block-aligned input because this library does not provide padding.

## Threading

- Contexts are caller-owned and independent.
- There is no hidden mutable global state.
- Reentrant use is supported across distinct contexts.

## Legacy compatibility

Legacy wrappers are not the primary interface. New code should use the checked APIs directly.
