# Release

This repository uses tagged source releases.

## Verified release inputs

- Source tree state at the tagged commit
- Build and test logs captured in `docs/VERIFICATION.md`
- Install and consumer smoke tests
- A clean `git diff --check` result before tagging, with any remaining line-ending warnings recorded in the verification log

## Release tag

Current release tag: `v2.0.0`

## Build checks

Release verification covers:

- CMake configure/build/CTest on supported local toolchains
- Install tree export for `microcrypt::microcrypt`
- Consumer `find_package(microcrypt CONFIG REQUIRED)` smoke test
- OpenSSL-backed differential tests when libcrypto is available

## What is not claimed

- Binary publishing
- Hardware execution
- macOS or ESP-IDF verification unless those commands were actually run
