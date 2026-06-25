# CBC Security

AES-128-CBC in `microcrypt` is a low-level confidentiality primitive. It is not an authentication mechanism and it is not a full message encryption protocol.

## Properties

- CBC provides confidentiality only when used correctly.
- CBC ciphertext is malleable.
- CBC does not provide integrity or authenticity.
- IV reuse under one key leaks information.
- Encryption IVs must satisfy protocol unpredictability or uniqueness requirements.
- IVs are not secret, but authenticated designs must bind the IV to the ciphertext.
- Unauthenticated CBC decryption can trigger parser or padding-oracle issues in caller code.

## Operational rules

- Input must be block aligned because the library does not implement padding.
- The caller owns IV management.
- The checked API uses a const IV input and returns the final chaining value separately when requested.

## Design advice

Prefer an audited AEAD construction for new protocols. Do not invent a custom CBC-plus-HMAC format inside this library.
