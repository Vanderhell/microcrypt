# Security Policy

`microcrypt` is a portable primitive library, not a hardened security product.

## Supported scope

- SHA-256, HMAC-SHA256, AES-128 block transforms, and AES-128-CBC helpers
- Checked APIs with explicit status returns
- Secure clearing helpers for secret material

## Not claimed

- Audit status
- FIPS validation
- Formal proof
- Cache/timing/power/EM resistance
- Fault-injection resistance
- Physical hardware key protection
- Production protocol integration

## CBC warning

CBC provides confidentiality only and is malleable. It does not authenticate data. Use authenticated designs for new protocols.

## Reporting

Report security concerns through the repository issue tracker or the maintainers' preferred private channel if one is established for the project.
