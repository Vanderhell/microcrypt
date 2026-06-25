# Side-Channel Scope

`microcrypt` does not claim side-channel resistance.

## AES

- AES uses lookup tables for S-box and inverse S-box operations.
- That design is not constant-time on cache-visible or memory-observable platforms.
- It is not suitable against local, physical, timing, cache, power, or EM attackers.

## HMAC

- The MAC comparison helper compares every byte without content-based early exit.
- That only limits one obvious timing leak; it is not a whole-program constant-time proof.

## Verification

- No formal side-channel proof was performed.
- Release-assembly inspection, dudect, and ctgrind are only reported when available in the execution environment.
