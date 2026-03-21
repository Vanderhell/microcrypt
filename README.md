# microcrypt

[![CI](https://github.com/Vanderhell/microcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanderhell/microcrypt/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![C99](https://img.shields.io/badge/C-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)

Portable crypto primitives for embedded systems in pure C99 with zero dependencies and zero dynamic allocations.

## Security notice

This project is a portable reference implementation. It has **not** been audited for side-channel resistance (timing/power/cache attacks). For high-security production systems, use audited libraries or hardware accelerators.

## Features

- SHA-256 (FIPS 180-4), one-shot and incremental API
- HMAC-SHA256 (RFC 2104 / RFC 4231), one-shot and incremental API
- AES-128 ECB encrypt/decrypt (FIPS 197)
- AES-128 CBC encrypt/decrypt with IV chaining
- Test vectors from NIST and RFC sources

## Project structure

- `include/mcrypt.h` public API
- `src/mcrypt.c` implementation
- `tests/test_all.c` vector tests
- `tests/mtest.h` minimal local test framework
- `docs/DESIGN.md` design notes

## Build and test

Linux/macOS:

```bash
cd tests
make
```

Windows (clang example):

```powershell
clang -std=c99 -Wall -Wextra -Wpedantic -Werror -Iinclude src/mcrypt.c tests/test_all.c -o tests/test_all.exe
./tests/test_all.exe
```

## Minimal usage

```c
#include "mcrypt.h"

uint8_t digest[32];
mcrypt_sha256(data, data_len, digest);
```

## Versioning

Current release: `1.0.0` (see [CHANGELOG.md](CHANGELOG.md)).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).
