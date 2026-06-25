# Verification

## Current Release Closure

### MSYS2 UCRT64

- `cmake -S . -B build-msys2-gcc-debug -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=gcc`
  - Result: configured with GNU 16.1.0; OpenSSL found
- `cmake --build build-msys2-gcc-debug --parallel`
  - Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
- `ctest --test-dir build-msys2-gcc-debug --output-on-failure`
  - Result: `1/1` tests passed
- `./build-msys2-gcc-debug/test_microcrypt.exe`
  - Result: `Suites: 1  Tests: 18  Assertions: 26332  Failures: 0`
  - Result: no `NOT VERIFIED: OpenSSL oracle unavailable` line
- `cmake -S . -B build-msys2-gcc-release -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc`
  - Result: configured with GNU 16.1.0; OpenSSL found
- `cmake --build build-msys2-gcc-release --parallel`
  - Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
- `ctest --test-dir build-msys2-gcc-release --output-on-failure`
  - Result: `1/1` tests passed
- `cmake -S . -B build-msys2-clang-debug -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang`
  - Result: configured with Clang 22.1.7 and MinGW target auto-detection; OpenSSL found
- `cmake --build build-msys2-clang-debug --parallel`
  - Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
  - Result: warnings about unused `--gcc-toolchain` argument remained non-fatal
- `ctest --test-dir build-msys2-clang-debug --output-on-failure`
  - Result: `1/1` tests passed
- `cmake -S . -B build-msys2-clang-release -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang`
  - Result: configured with Clang 22.1.7 and MinGW target auto-detection; OpenSSL found
- `cmake --build build-msys2-clang-release --parallel`
  - Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
  - Result: warnings about unused `--gcc-toolchain` argument remained non-fatal
- `ctest --test-dir build-msys2-clang-release --output-on-failure`
  - Result: `1/1` tests passed
- `cmake -S . -B build-msys2-gcc-lto -G Ninja -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON`
  - Result: configured with GNU 16.1.0; OpenSSL found and IPO enabled
- `cmake --build build-msys2-gcc-lto --parallel`
  - Result: built `libmicrocrypt.a` and `test_microcrypt.exe`
- `ctest --test-dir build-msys2-gcc-lto --output-on-failure`
  - Result: `1/1` tests passed

### Makefile Path

- `cd tests && make clean && make`
  - Result: built and ran `test_all`
  - Result: `Suites: 1  Tests: 18  Assertions: 26332  Failures: 0`
  - Result: no `NOT VERIFIED: OpenSSL oracle unavailable` line

### MSVC Release

- `cmake -S . -B build-msvc-release-ninja2 -G Ninja -DCMAKE_MAKE_PROGRAM=C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe -DMICROCRYPT_BUILD_TESTS=ON -DMICROCRYPT_BUILD_DIFFERENTIAL_TESTS=ON -DMICROCRYPT_STRICT_WARNINGS=ON -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl`
  - Result: configured with MSVC 19.42.34444.0; OpenSSL found
- `cmake --build build-msvc-release-ninja2 --parallel`
  - Result: built `microcrypt.lib` and `test_microcrypt.exe`
- `ctest --test-dir build-msvc-release-ninja2 --output-on-failure`
  - Result: `1/1` tests passed

### Install / Consumer

- `cmake --install build-msvc-release-ninja2 --config Release --prefix C:/Users/vande/Desktop/github/microcrypt/microcrypt/stage-install-msvc`
  - Result: installed `microcrypt.lib`, `mcrypt.h`, and CMake package files
- `cmake -S tests/consumer -B build-consumer-msvc-install -G Ninja -DCMAKE_MAKE_PROGRAM=C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe -DCMAKE_PREFIX_PATH=C:/Users/vande/Desktop/github/microcrypt/microcrypt/stage-install-msvc -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl`
  - Result: configured against the install tree package
- `cmake --build build-consumer-msvc-install --parallel`
  - Result: built `consumer.exe`
- `build-consumer-msvc-install/consumer.exe`
  - Result: `ba7816bf`

### ARM Smoke

- `arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -specs=nosys.specs -Iinclude -c arm_smoke.c -o arm_smoke.o`
  - Result: compiled successfully
- `arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -specs=nosys.specs -Iinclude -c src/mcrypt.c -o mcrypt_arm.o`
  - Result: compiled successfully
- `arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -specs=nosys.specs arm_smoke.o mcrypt_arm.o -o microcrypt-arm.elf`
  - Result: linked successfully with `nosys` warnings for `_close`, `_lseek`, `_read`, and `_write`

### Analysis

- `cppcheck --project=build-analysis/compile_commands.json --enable=warning,style,performance,portability --inline-suppr --suppress=missingIncludeSystem`
  - Result: no warnings after the current source cleanup
- `clang-tidy -p build-analysis src/mcrypt.c tests/test_all.c --checks=clang-analyzer-core.*,-clang-analyzer-security.insecureAPI.*,-clang-analyzer-deadcode.*`
  - Result: completed with no diagnostics

### WSL Ubuntu

- `wsl.exe -l -v`
  - Result: `Windows Subsystem for Linux has no installed distributions.`
  - Result: WSL Ubuntu sanitizer and differential verification could not be executed in this workspace

### Notes

- OpenSSL-backed differential tests are enabled when libcrypto is found.
- The test binary no longer prints `NOT VERIFIED: OpenSSL oracle unavailable` when OpenSSL is available.
