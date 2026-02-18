cmake_minimum_required(VERSION 3.20)

# ==================== Google Test ====================
# Use FetchContent to download GoogleTest if not found
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
)
# Prevent overriding parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ==================== Unit Tests ====================

add_executable(ncp_tests
    crypto_test.cpp
    test_dpi.cpp
    test_integration.cpp
    test_license.cpp
    test_network.cpp
    test_e2e.cpp
    test_paranoid.cpp
    test_secure_memory.cpp
    test_i2p.cpp
    test_critical_fixes.cpp  # NEW: Critical security fixes tests (Issue #17)
)

target_link_libraries(ncp_tests
    PRIVATE
        ncp_core
        gtest
        gtest_main
)

target_include_directories(ncp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(ncp_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# ==================== Windows DLL Copy ====================
# Copy vcpkg DLLs next to ncp_tests.exe so ctest can find them
# at runtime (fixes 0xC0000135 on CI).
if (WIN32)
    # Determine vcpkg bin directory
    if (DEFINED VCPKG_INSTALLED_DIR)
        set(_vcpkg_bin_dir "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin")
    elseif (DEFINED CMAKE_TOOLCHAIN_FILE AND
            CMAKE_TOOLCHAIN_FILE MATCHES "vcpkg.cmake")
        # Standard path on GitHub Actions runners
        set(_vcpkg_bin_dir "C:/vcpkg/installed/${VCPKG_TARGET_TRIPLET}/bin")
    endif()

    if (DEFINED _vcpkg_bin_dir AND EXISTS "${_vcpkg_bin_dir}")
        add_custom_command(TARGET ncp_tests POST_BUILD
            COMMAND "${CMAKE_COMMAND}" -E copy_directory
                    "${_vcpkg_bin_dir}"
                    "$<TARGET_FILE_DIR:ncp_tests>"
            COMMENT "Copying vcpkg DLLs to ncp_tests output dir")
    endif()
endif()

# ==================== Test Registration ====================
# NOTE: gtest_discover_tests is intentionally NOT used here.
# It runs the test binary at CMake/MSBuild time (before DLLs are
# available on PATH), which causes exit code 0xC0000135 on Windows CI.
# Tests are run via ctest after the build, when DLLs are already present.
#
# include(GoogleTest)
# gtest_discover_tests(ncp_tests
#     WORKING_DIRECTORY $<TARGET_FILE_DIR:ncp_tests>
#     DISCOVERY_TIMEOUT 10
# )

add_test(NAME ncp_tests COMMAND ncp_tests)
