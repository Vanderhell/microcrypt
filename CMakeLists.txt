cmake_minimum_required(VERSION 3.16)
project(microcrypt VERSION 1.0.0 LANGUAGES C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(MICROCRYPT_BUILD_TESTS "Build microcrypt self-tests" ON)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wconversion
        -Werror
    )
endif()

add_library(microcrypt STATIC
    src/mcrypt.c
)
target_include_directories(microcrypt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(MICROCRYPT_BUILD_TESTS)
    enable_testing()
    add_executable(test_microcrypt tests/test_all.c)
    target_include_directories(test_microcrypt PRIVATE tests)
    target_link_libraries(test_microcrypt PRIVATE microcrypt)
    if(NOT MSVC)
        target_link_libraries(test_microcrypt PRIVATE m)
    endif()
    add_test(NAME microcrypt_selftest COMMAND test_microcrypt)
endif()

install(TARGETS microcrypt)
install(FILES include/mcrypt.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
