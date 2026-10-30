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
    test_tor_manager.cpp      # Managed Tor + PT tests
    test_kill_switch.cpp        # Kill switch filter tests
    test_critical_fixes.cpp  # Critical security fixes tests (Issue #17)
    test_l3_l2_stealth.cpp   # L3/L2 Stealth tests (Phase 1-3)
    # --- New comprehensive test suite ---
    test_orchestrator.cpp
    test_adversarial.cpp
    test_flow_shaper.cpp
    test_burst_morpher.cpp
    test_protocol_morph.cpp
    test_port_knock.cpp
    test_reality.cpp
    test_stegodns.cpp
    test_porthop.cpp            # M2: port-hopping transport tests
    test_mimicry_stats.cpp      # M5: statistical profile tests
    test_reference_profile_catalog.cpp  # Этап 1A: reference profile catalog tests
    test_profile_transition.cpp    # Generic per-session profile transition tests
    test_udp_profile_transition.cpp # Real UDP client/server transition tests
    test_mimicry_autopilot.cpp     # UDP/mimicry decision-loop tests
    test_mimicry_session.cpp       # Per-session E2E/mimicry adapter tests
    test_transport_config.cpp      # G2.2: versioned transport-config migration/coexistence tests
    test_datagram_path_budget.cpp  # G3: authoritative path MTU/PMTU sizing
    test_turn_client.cpp           # G5: STUN/TURN codec and transaction tests
    test_turn_server.cpp           # G5: TURN-over-UDP server tests
    test_mimicry_fsm.cpp           # Per-session FSM timing/shape tests
    test_mimicry_catalog_io.cpp    # Signed catalog binary IO tests
    test_connection_director.cpp   # Per-session director/registry + CLI wiring tests
    test_orchestrator_mimicry_provider.cpp  # Read-only per-session provider tests
    test_mimicry_session_fsm.cpp   # FSM runtime integration in the session adapter
    test_mimicry_sibling_binding.cpp  # I-SIB-1: hash-bound family IS the variant group
    test_cli_mimicry_flags.cpp     # Operator CLI mimicry flags/helpers tests
    test_mimicry_session_v2.cpp    # Transition protocol v2 (arbitrary masks) tests
    test_udp_profile_transition_v2.cpp  # Real-UDP v2 evidence (loss parity, storm recovery)
    test_desync_confuse.cpp   # M3: TCP state confusion builders tests
    test_aemm.cpp             # M9: Reed-Solomon erasure coding tests
    test_fog.cpp               # M7: fog mesh relay tests
    test_semfluid.cpp          # M8: semantic fluid transport tests
    test_xdp.cpp
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
    test_bypass_features.cpp # Hostlist/proxy/blockcheck/zapret-import/detector
    test_blockcheck_parallel.cpp # Parallel probes, stable validation, concurrent learning
    test_spa.cpp            # Enterprise SPA (Ed25519 + ipset) tests
    test_awg31_hardening.cpp  # AWG 3.1: header protection, padding, timers, CPS
    test_scoped_trust.cpp     # Scoped trust (NUЦ containment) tests
    test_preset_autopilot.cpp  # PresetAutoPilot: selection/switch/cooldown/JSON
    test_geneva_fitness.cpp    # Geneva GA probe: ServerHello required, alert != bypass
    ${CMAKE_SOURCE_DIR}/src/cli/geneva_fitness.cpp  # probe under test (cli TU)
    # --- Zone F: previously unconnected gtest files ---
    test_e2e_extended.cpp    # X448 / ECDH_P256 E2E encryption tests
    test_ech.cpp             # HPKE-based ECH unit tests
    test_ech_cache.cpp       # ECH config cache / retry tests
)

target_link_libraries(ncp_tests
    PRIVATE
        ncp_core
        gtest
        gtest_main
)
add_dependencies(ncp_tests ncp_core)

find_library(MSQUIC_LIBRARY NAMES msquic libmsquic.so.2)
if(MSQUIC_LIBRARY)
    target_sources(ncp_tests PRIVATE
        test_real_quic.cpp
        test_quic_director_adapter.cpp)
endif()

target_include_directories(ncp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/cli
)

# ==================== Standalone functional check ====================
# End-to-end functional verification of the core library (crypto, E2E, DoH,
# QUIC/ipfrag, hostlists, zapret import, presets, detector, license, network,
# mimicry). Not a gtest: run directly as `ncp_functional_check`.
add_executable(ncp_functional_check functional_check.cpp)
target_link_libraries(ncp_functional_check PRIVATE ncp_core)
add_dependencies(ncp_functional_check ncp_core)
target_include_directories(ncp_functional_check PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
)
set_target_properties(ncp_functional_check PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Register ncp_functional_check in CTest (it was previously build-only).
# It performs live DoH lookups, so label it: CI sandboxes without internet
# can exclude it via `ctest -LE network`.
add_test(NAME ncp_functional_check COMMAND ncp_functional_check)
set_tests_properties(ncp_functional_check PROPERTIES
    TIMEOUT 180
    LABELS "functional;network"
)

# ==================== Standalone assert-based tests ====================
# Zone F: these test files predate the gtest suite and use assert()-style
# checks with their own main(). Build each as a separate ctest target.
set(NCP_STANDALONE_TESTS
    test_advanced_dpi
    test_ech_pipeline
    test_l3_stealth
    test_mimicry_roundtrip
    test_dpi_advanced_integration
)
# The core compiles one of two ECHConfig parser variants: HPKE builds
# (OpenSSL >= 3.2, HAVE_ECH_HPKE is PRIVATE to ncp_core) parse a simplified
# layout, fallback builds parse the full wire format. Mirror the version
# check so test_ech_pipeline feeds the parser its native blob layout.
find_package(OpenSSL QUIET)
if(OPENSSL_VERSION AND OPENSSL_VERSION VERSION_GREATER_EQUAL "3.2")
    set(NCP_TEST_ECH_HPKE_PARSER ON)
else()
    set(NCP_TEST_ECH_HPKE_PARSER OFF)
endif()
foreach(t IN LISTS NCP_STANDALONE_TESTS)
    add_executable(${t} ${t}.cpp)
    target_link_libraries(${t} PRIVATE ncp_core)
    add_dependencies(${t} ncp_core)
    if(${t} STREQUAL "test_ech_pipeline" AND NCP_TEST_ECH_HPKE_PARSER)
        target_compile_definitions(${t} PRIVATE NCP_TEST_ECH_HPKE_PARSER)
    endif()
    target_include_directories(${t} PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core/include
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src
    )
    set_target_properties(${t} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )
    add_test(NAME ${t} COMMAND ${t})
    # Exit code 77 = graceful skip (environment/feature unavailable)
    set_tests_properties(${t} PROPERTIES
        TIMEOUT 120
        SKIP_RETURN_CODE 77
    )
endforeach()

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
