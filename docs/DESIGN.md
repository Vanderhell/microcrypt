# Design Rationale

## 1. Bitwise, not table-based (SHA-256)
SHA-256 uses a 256-byte constant table (K values). No large lookup tables beyond that. The transform function is the standard 64-round compression.

## 2. Full S-box for AES (512 bytes)
AES requires S-box (256 bytes) and inverse S-box (256 bytes). These are the standard FIPS 197 tables. On very constrained MCUs, you could compute them on-the-fly, but the 512-byte cost is acceptable for most targets.

## 3. No side-channel protection
Constant-time implementations add complexity and are hard to verify without hardware testing. This implementation is for integrity checks and non-critical encryption, not for protecting against physical attackers with oscilloscopes.

## 4. Incremental API
SHA-256 and HMAC support init/update/final pattern. Hash firmware in 64-byte chunks without buffering the entire image.

## 5. CBC only (no CTR/GCM)
CBC is simpler and sufficient for config encryption. GCM would add authenticated encryption but requires GF multiplication — future work.

| Decision | Gains | Costs |
|----------|-------|-------|
| Standard tables | Correct, fast | 512 bytes for AES S-boxes |
| No side-channel | Simple, portable | Not for physical attacks |
| Incremental | Low memory for large data | Slightly more complex API |
| CBC only | Simple, sufficient | No authenticated encryption |
