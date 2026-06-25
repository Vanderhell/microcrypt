cmake_minimum_required(VERSION 3.20)

if(WIN32 AND DEFINED CMAKE_C_COMPILER AND CMAKE_C_COMPILER MATCHES "clang(\\.exe)?$")
    if(NOT CMAKE_C_COMPILER MATCHES "clang-cl(\\.exe)?$")
        find_program(MICROCRYPT_GCC_EXE gcc)
        if(MICROCRYPT_GCC_EXE)
            get_filename_component(MICROCRYPT_GCC_BIN "${MICROCRYPT_GCC_EXE}" DIRECTORY)
            get_filename_component(MICROCRYPT_GCC_TOOLCHAIN "${MICROCRYPT_GCC_BIN}" DIRECTORY)
            set(CMAKE_C_COMPILER_TARGET x86_64-w64-windows-gnu CACHE STRING "" FORCE)
            set(CMAKE_C_COMPILER_EXTERNAL_TOOLCHAIN "${MICROCRYPT_GCC_TOOLCHAIN}" CACHE PATH "" FORCE)
        endif()
    endif()
endif()

project(microcrypt VERSION 2.0.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(MICROCRYPT_BUILD_TESTS "Build microcrypt self-tests" ${PROJECT_IS_TOP_LEVEL})
option(MICROCRYPT_BUILD_DIFFERENTIAL_TESTS "Build differential oracle tests when available" ON)
option(MICROCRYPT_BUILD_FUZZERS "Build fuzz smoke tests" ON)
option(MICROCRYPT_BUILD_EXAMPLES "Build example programs" OFF)
option(MICROCRYPT_STRICT_WARNINGS "Treat portability warnings as errors" ON)
option(MICROCRYPT_ENABLE_LEGACY_API "Expose legacy compatibility wrappers" ON)
option(MICROCRYPT_ENABLE_AES_CBC "Enable AES-128-CBC helpers" ON)

set(MICROCRYPT_PACKAGE_NAME microcrypt)
set(MICROCRYPT_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${MICROCRYPT_PACKAGE_NAME})

if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_C_COMPILER_TARGET MATCHES "w64-windows-gnu")
    set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
endif()

function(microcrypt_apply_warnings target)
    if(NOT MICROCRYPT_STRICT_WARNINGS)
        return()
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    else()
        target_compile_options(
            ${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wsign-conversion
            -Wshadow
            -Wformat=2
            -Wundef
            -Wcast-align
            -Wstrict-prototypes
            -Wmissing-prototypes
            -Wvla
        )
        if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
            target_compile_options(${target} PRIVATE -Wno-error=unused-command-line-argument)
        endif()
    endif()
endfunction()

add_library(microcrypt src/mcrypt.c)
add_library(microcrypt::microcrypt ALIAS microcrypt)

target_compile_features(microcrypt PUBLIC c_std_99)
target_include_directories(microcrypt
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(microcrypt
    PUBLIC
        MICROCRYPT_ENABLE_AES_CBC=$<BOOL:${MICROCRYPT_ENABLE_AES_CBC}>
        MICROCRYPT_ENABLE_LEGACY_API=$<BOOL:${MICROCRYPT_ENABLE_LEGACY_API}>
)
microcrypt_apply_warnings(microcrypt)

set_target_properties(microcrypt PROPERTIES
    OUTPUT_NAME microcrypt
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
)

if(MICROCRYPT_BUILD_TESTS)
    add_executable(test_microcrypt tests/test_all.c)
    target_link_libraries(test_microcrypt PRIVATE microcrypt)
    target_include_directories(test_microcrypt PRIVATE tests)
    microcrypt_apply_warnings(test_microcrypt)

    add_test(NAME microcrypt_selftest COMMAND test_microcrypt)
endif()

if(MICROCRYPT_BUILD_EXAMPLES)
    message(STATUS "Examples are not bundled in this repository snapshot")
endif()

if(MICROCRYPT_BUILD_DIFFERENTIAL_TESTS)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        message(STATUS "OpenSSL found: differential oracle support available")
    else()
        message(STATUS "OpenSSL not found: differential tests will report NOT VERIFIED")
    endif()
endif()

install(TARGETS microcrypt
    EXPORT microcryptTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES include/mcrypt.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/microcryptConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}Config.cmake
    INSTALL_DESTINATION ${MICROCRYPT_CMAKE_DIR}
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}ConfigVersion.cmake
    DESTINATION ${MICROCRYPT_CMAKE_DIR}
)

install(EXPORT microcryptTargets
    NAMESPACE microcrypt::
    DESTINATION ${MICROCRYPT_CMAKE_DIR}
)

export(EXPORT microcryptTargets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}Targets.cmake
    NAMESPACE microcrypt::
)

file(WRITE
    ${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}Config.cmake
    "include(\"${CMAKE_CURRENT_BINARY_DIR}/${MICROCRYPT_PACKAGE_NAME}Targets.cmake\")\n"
)
