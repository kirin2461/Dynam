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
    test_csprng.cpp          # Phase 1: CSPRNG unit tests
    test_dpi.cpp
    test_integration.cpp
    test_license.cpp
    test_network.cpp
    test_e2e.cpp
    test_paranoid.cpp
    test_secure_memory.cpp
    test_i2p.cpp
    test_critical_fixes.cpp  # Critical security fixes tests (Issue #17)
    test_l3_l2_stealth.cpp   # L3/L2 Stealth tests (Phase 1-3)
    # --- New comprehensive test suite ---
    test_orchestrator.cpp
    test_adversarial.cpp
    test_flow_shaper.cpp
    test_burst_morpher.cpp
    test_protocol_morph.cpp
    test_port_knock.cpp
    test_probe_resist.cpp
    test_geneva.cpp
    test_packet_interceptor.cpp
    test_spoofer.cpp
    test_db.cpp
    test_doh.cpp
    test_security_classes.cpp
    # --- R11-R13 fixes test suite ---
    test_r13_fixes.cpp       # Tests for R11-R13 critical fixes
    test_thread_safety.cpp   # Thread safety verification tests
)

target_link_libraries(ncp_tests
    PRIVATE
        ncp_core
        gtest
        gtest_main
)
add_dependencies(ncp_tests ncp_core)

target_include_directories(ncp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src
)

# ==================== Compiler Warning Suppression ====================
if(MSVC)
    target_compile_options(ncp_tests PRIVATE
        /W3
        /wd4267
        /wd4244
        /wd4996
        /wd4100
        /wd4101
        /wd4189
        /wd4127
    )
else()
    target_compile_options(ncp_tests PRIVATE
        -Wall -Wextra
        -Wno-unused-parameter
        -Wno-unused-variable
    )
endif()

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
# Register as a single CTest test with a 3-minute timeout to prevent
# CI from hanging on unreachable network endpoints or infinite loops.
add_test(NAME ncp_tests COMMAND ncp_tests)
set_tests_properties(ncp_tests PROPERTIES TIMEOUT 180)
