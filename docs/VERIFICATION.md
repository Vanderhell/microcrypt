# Verification

## Baseline

- Command: `git status --short`
  Result: `?? prompts/`
- Command: `git branch --show-current`
  Result: `master`
- Command: `git log -1 --oneline`
  Result: `d3734d1 build: add CMake project`
- Command: `git tag --list`
  Result: no tags
- Command: `cd tests; make clean; make`
  Result: `make` not installed in this environment
- Command: `cmake -S . -B build-baseline -DMICROCRYPT_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug`
  Result: configured with MSVC 19.42.34444.0
- Command: `cmake --build build-baseline --parallel`
  Result: failed before tests because `tests/test_all.c` used deprecated `sscanf` warnings treated as errors
- Command: `ctest --test-dir build-baseline --output-on-failure`
  Result: not run successfully; `microcrypt_selftest` was not built

## Debug Build

- Command: `cmake -S . -B build-check`
  Result: configured with MSVC 19.42.34444.0
- Command: `cmake --build build-check --config Debug --parallel`
  Result: built `microcrypt.lib` and `test_microcrypt.exe`
- Command: `ctest --test-dir build-check -C Debug --output-on-failure`
  Result: `1/1` tests passed
- Command: `./build-check/Debug/test_microcrypt.exe`
  Result: `Suites: 1  Tests: 18  Assertions: 4830  Failures: 0`
  Result: `NOT VERIFIED: OpenSSL oracle unavailable`
  Result: `sizeof(mcrypt_sha256_t)=120`
  Result: `sizeof(mcrypt_hmac_sha256_t)=320`
  Result: `sizeof(mcrypt_aes128_t)=184`

## GCC Debug

- Command: `cmake -S . -B build-gcc-debug -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc`
  Result: configured with GNU 16.1.0
- Command: `cmake --build build-gcc-debug --parallel`
  Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
- Command: `ctest --test-dir build-gcc-debug --output-on-failure`
  Result: `1/1` tests passed

## GCC Release

- Command: `cmake -S . -B build-gcc-release -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc`
  Result: configured with GNU 16.1.0
- Command: `cmake --build build-gcc-release --parallel`
  Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
- Command: `ctest --test-dir build-gcc-release --output-on-failure`
  Result: `1/1` tests passed

## Clang Debug

- Command: `cmake -S . -B build-clang-debug -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang`
  Result: configured with Clang 22.1.8 and MinGW target auto-detection
- Command: `cmake --build build-clang-debug --parallel`
  Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
  Result: warnings about unused `--gcc-toolchain` argument remained non-fatal
- Command: `ctest --test-dir build-clang-debug --output-on-failure`
  Result: `1/1` tests passed

## Clang Release

- Command: `cmake -S . -B build-clang-release -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang`
  Result: configured with Clang 22.1.8 and MinGW target auto-detection
- Command: `cmake --build build-clang-release --parallel`
  Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
  Result: warnings about unused `--gcc-toolchain` argument remained non-fatal
- Command: `ctest --test-dir build-clang-release --output-on-failure`
  Result: `1/1` tests passed

## Release LTO

- Command: `cmake -S . -B build-gcc-lto -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON`
  Result: configured with GNU 16.1.0 and IPO enabled
- Command: `cmake --build build-gcc-lto --parallel`
  Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
- Command: `ctest --test-dir build-gcc-lto --output-on-failure`
  Result: `1/1` tests passed

## Stack Usage

- Command: `cmake -S . -B build-gcc-stack -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS=-fstack-usage`
  Result: configured with GNU 16.1.0
- Command: `cmake --build build-gcc-stack --parallel`
  Result: generated `build-gcc-stack/CMakeFiles/microcrypt.dir/src/mcrypt.c.su`
- Command: `ctest --test-dir build-gcc-stack --output-on-failure`
  Result: `1/1` tests passed

## Consumer Tests

- Command: `cmake -S tests/consumer -B build-consumer -Dmicrocrypt_DIR=C:/Users/vande/Desktop/github/microcrypt/microcrypt/build-check`
  Result: configured against the build tree package
- Command: `cmake --build build-consumer --config Debug --parallel`
  Result: built `consumer.exe`
- Command: `./build-consumer/Debug/consumer.exe`
  Result: `ba7816bf`
- Command: `cmake --install build-check --config Debug --prefix C:/Users/vande/Desktop/github/microcrypt/microcrypt/stage-install`
  Result: installed `microcrypt.lib`, `mcrypt.h`, and CMake package files
- Command: `cmake -S tests/consumer -B build-consumer-install -DCMAKE_PREFIX_PATH=C:/Users/vande/Desktop/github/microcrypt/microcrypt/stage-install`
  Result: configured against the install tree package
- Command: `cmake --build build-consumer-install --config Debug --parallel`
  Result: built `consumer.exe`
- Command: `./build-consumer-install/Debug/consumer.exe`
  Result: `ba7816bf`

## Tool Availability

- Command: `Get-Command openssl`
  Result: not installed
- Command: `Get-Command make`
  Result: not installed
- Command: `cmake -S . -B build-sanitize -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"`
  Result: failed because the Clang MinGW sanitizer runtimes were unavailable
- Command: `cmake -S . -B build-sanitize -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"`
  Result: failed because the MinGW GCC sanitizer libraries were unavailable

## Git Hygiene

- Command: `git diff --check`
  Result: no diff errors; only line-ending warnings for files that were rewritten in this workspace
- Command: `git status --short`
  Result: repository had modified source files, new docs, new consumer files, and generated build directories
- Command: `git log --oneline --decorate -10`
  Result: `HEAD -> master` was still `d3734d1 build: add CMake project`
