# Changelog

## [2.0.0] - 2026-06-25

### Changed
- Replaced void crypto entry points with checked status-returning APIs.
- Added explicit lifecycle validation for SHA-256, HMAC-SHA256, and AES-128 contexts.
- Added secure clearing and constant-time MAC comparison helpers.
- Documented CBC as confidentiality-only and not an authentication scheme.
- Added installable CMake package exports for `microcrypt::microcrypt`.

### Added
- Checked HMAC verification API.
- Build-system options for tests, strict warnings, differential tests, fuzz smoke, examples, legacy compatibility, and CBC enablement.
- Security and verification documentation.
- Release workflow, issue templates, cookbook examples, and release/process documentation.
- OpenSSL-backed differential test coverage when libcrypto is available.
