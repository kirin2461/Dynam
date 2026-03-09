cmake_minimum_required(VERSION 3.20)

# NCP Core Library
# Core library has NO Qt6 dependency

# Source files in root of core/
set(NCP_CORE_ROOT_SOURCES
    NetworkManager.cpp
    InterfaceSelector.cpp
)

set(NCP_CORE_ROOT_HEADERS
    NetworkManager.hpp
    ConnectionMonitor.hpp
    InterfaceSelector.hpp
)

# Source files in src/ subdirectory
set(NCP_CORE_SRC_SOURCES
    src/crypto.cpp
    src/doh.cpp
    src/db.cpp
    src/license.cpp
    src/network.cpp
    src/spoofer.cpp
    src/ncp_dpi.cpp
    src/ncp_dpi_zapret.cpp
    src/tls_fingerprint.cpp
    src/dpi_advanced.cpp
    src/secure_buffer.cpp
    src/ncp_arp.cpp
    src/ncp_thread_pool.cpp
    src/ncp_dummy.cpp
    src/ncp_timing.cpp
    src/ncp_identity.cpp
    src/ncp_entropy_masking.cpp
    src/ncp_geneva_engine.cpp
    src/ncp_geneva_ga.cpp           # Geneva GA evolutionary DPI strategy engine
    src/ncp_protocol_morph.cpp      # Protocol morphing / polymorphic framing
    src/ncp_paranoid.cpp
    src/ncp_secure_memory.cpp
    # Anti ML-TSPU modules (Phase 1-5)
    src/ncp_adversarial.cpp      # Phase 1: adversarial padding
    src/ncp_flow_shaper.cpp      # Phase 2: flow-level traffic shaping
    src/ncp_probe_resist.cpp     # Phase 3: active probing resistance
    src/ncp_orchestrator.cpp     # Phase 4: unified pipeline orchestrator
    src/ncp_port_knock.cpp       # Phase 5: port knocking (TOTP/SPA/covert)
    # L3/L2 Stealth modules (Anti-ISP fingerprinting)
    src/ncp_l3_stealth.cpp       # Phase 1: IPID/TTL/MSS/FlowLabel normalization
    src/ncp_packet_interceptor.cpp # Phase 2: NFQUEUE/WinDivert packet interception + tunneling
    src/ncp_l2_stealth.cpp       # Phase 3: ARP/LLDP/VLAN (Npcap-optional)
    # Phase 5: ML-guided burst perturbation engine
    src/ncp_burst_morpher.cpp
    # ===== NEW Anti-TSPU modules (Priority 1-3) =====
    # Priority 1 — Critical
    src/ncp_packet_pipeline.cpp           # Unified packet processing pipeline
    src/ncp_dns_leak_prevention.cpp       # DNS leak prevention (WFP/iptables)
    src/ncp_session_fragmenter.cpp        # TCP session fragmentation (anti-statistical)
    src/ncp_cross_layer_correlator.cpp    # Cross-layer coherence validation
    # Priority 2 — Anti-ML
    src/ncp_rtt_equalizer.cpp             # RTT equalization (anti-dMAP)
    src/ncp_volume_normalizer.cpp         # Volume normalization to web-browsing buckets
    src/ncp_behavioral_cloak.cpp          # Chrome browsing behavior emulation
    src/ncp_time_correlation_breaker.cpp  # Inter-session timing decorrelation
    # Priority 3 — Advanced
    src/ncp_covert_channel.cpp            # DNS/HTTP steganography channels
    src/ncp_wf_defense.cpp                # Website Fingerprinting defense (Tamaraw)
    src/ncp_self_test_monitor.cpp         # Self-attack testing monitor
    src/ncp_transport_manager.cpp         # Protocol rotation + AS routing + Geo obfuscation
    # Hybrid network backend sources
    src/network_raw_socket.cpp
    src/dhcp_spoofer.cpp
    src/smbios_hook.cpp
    # ECH (Encrypted Client Hello) sources
    src/ncp_ech.cpp
    src/ncp_ech_cache.cpp
    src/ncp_ech_fetch.cpp
    src/ncp_ech_retry.cpp
    # NOTE: ncp_mimicry.cpp removed — mimicry.cpp is the canonical implementation
    #       with Russian TSPU/Roskomnadzor whitelist domains
    # Additional anti-TSPU / TLS modules
    src/ncp_adversary_tester.cpp
    src/ncp_rotation_coordinator.cpp
    src/tls_record_padding.cpp
    # NOTE: Some headers below may be listed in both NCP_CORE_SRC_SOURCES and NCP_CORE_INCLUDE_HEADERS.
    # CMake deduplicates automatically, but this should be cleaned up.
    # Headers bundled with src
    include/ncp_arp.hpp
    include/ncp_dummy.hpp
    include/ncp_timing.hpp
    include/ncp_identity.hpp
    include/ncp_entropy_masking.hpp
    include/ncp_geneva_engine.hpp
    include/ncp_adversarial.hpp
    include/ncp_flow_shaper.hpp
    include/ncp_probe_resist.hpp
    include/ncp_orchestrator.hpp
    include/ncp_port_knock.hpp
    # New Anti-TSPU headers
    include/ncp_packet_pipeline.hpp
    include/ncp_dns_leak_prevention.hpp
    include/ncp_session_fragmenter.hpp
    include/ncp_cross_layer_correlator.hpp
    include/ncp_rtt_equalizer.hpp
    include/ncp_volume_normalizer.hpp
    include/ncp_behavioral_cloak.hpp
    include/ncp_time_correlation_breaker.hpp
    include/ncp_covert_channel.hpp
    include/ncp_wf_defense.hpp
    include/ncp_self_test_monitor.hpp
    include/ncp_transport_manager.hpp
)

# Conditionally add sources that depend on optional libraries
if(ENABLE_LIBOQS OR HAVE_LIBOQS)
    # e2e.cpp uses liboqs for post-quantum key exchange
endif()

# WebSocket Tunnel Transport (Phase 3) - REQUIRED
list(APPEND NCP_CORE_SRC_SOURCES
    src/ncp_ws_tunnel.cpp
)

# Always compile these with #ifdef guards inside
# NOTE: ConnectionMonitor.cpp removed — security.cpp is the canonical source
#       for ncp::ConnectionMonitor
list(APPEND NCP_CORE_SRC_SOURCES
    src/e2e.cpp
    src/mimicry.cpp
    src/i2p.cpp
    src/security.cpp
)

# Header files in include/ subdirectory
set(NCP_CORE_INCLUDE_HEADERS
    include/ncp_crypto.hpp
    include/ncp_crypto_constants.hpp
    include/ncp_csprng.hpp
    include/ncp_doh.hpp
    include/ncp_db.hpp
    include/ncp_license.hpp
    include/ncp_dpi.hpp
    include/ncp_dpi_zapret.hpp
    include/ncp_network.hpp
    include/ncp_spoofer.hpp
    include/ncp_tls_fingerprint.hpp
    include/ncp_e2e.hpp
    include/ncp_dpi_advanced.hpp
    include/ncp_mimicry.hpp
    include/ncp_i2p.hpp
    include/ncp_security.hpp
    include/ncp_config.hpp
    include/ncp_logger.hpp
    include/ncp_paranoid.hpp
    include/ncp_secure_memory.hpp
    include/ncp_secure_buffer.hpp
    include/ncp_thread_pool.hpp
    # Anti ML-TSPU headers (Phase 1-5)
    include/ncp_adversarial.hpp
    include/ncp_flow_shaper.hpp
    include/ncp_probe_resist.hpp
    include/ncp_orchestrator.hpp
    include/ncp_port_knock.hpp
    # Geneva / Protocol Morph headers
    include/ncp_geneva_ga.hpp
    include/ncp_protocol_morph.hpp
    # Burst morpher header
    include/ncp_burst_morpher.hpp
    # New Anti-TSPU headers (include section)
    include/ncp_packet_pipeline.hpp
    include/ncp_dns_leak_prevention.hpp
    include/ncp_session_fragmenter.hpp
    include/ncp_cross_layer_correlator.hpp
    include/ncp_rtt_equalizer.hpp
    include/ncp_volume_normalizer.hpp
    include/ncp_behavioral_cloak.hpp
    include/ncp_time_correlation_breaker.hpp
    include/ncp_covert_channel.hpp
    include/ncp_wf_defense.hpp
    include/ncp_self_test_monitor.hpp
    include/ncp_transport_manager.hpp
    # L3/L2 Stealth headers
    include/ncp_l3_stealth.hpp
    include/ncp_packet_interceptor.hpp
    include/ncp_l2_stealth.hpp
    # Hybrid network backend headers
    include/ncp_network_backend.hpp
    include/ncp_winsock_raii.hpp
    include/ncp_dhcp_spoofer.hpp
    # ECH headers
    include/ncp_ech.hpp
    include/ncp_ech_cache.hpp
    include/ncp_ech_fetch.hpp
    include/ncp_ech_retry.hpp
    # WebSocket tunnel header (REQUIRED)
    include/ncp_ws_tunnel.hpp
)

# Combine all sources and headers
set(NCP_CORE_SOURCES
    ${NCP_CORE_ROOT_SOURCES}
    ${NCP_CORE_SRC_SOURCES}
)

set(NCP_CORE_HEADERS
    ${NCP_CORE_ROOT_HEADERS}
    ${NCP_CORE_INCLUDE_HEADERS}
)

# Create core library
add_library(ncp_core STATIC
    ${NCP_CORE_SOURCES}
    ${NCP_CORE_HEADERS}
)

# ==================== Compiler Warning Suppression ====================
if(MSVC)
    target_compile_options(ncp_core PRIVATE
        /W3          # Warning level 3 (balanced)
        /wd4267      # 'conversion': conversion from 'size_t' to 'type', possible loss of data
        /wd4244      # 'conversion': conversion from 'type1' to 'type2', possible loss of data
        /wd4996      # deprecated functions (strncpy, sscanf, etc.)
        /wd4005      # 'macro': macro redefinition
        /wd4100      # 'identifier': unreferenced formal parameter
        /wd4101      # 'identifier': unreferenced local variable
        /wd4189      # 'identifier': local variable is initialized but not referenced
        /wd4456      # declaration hides previous local declaration
        /wd4458      # declaration hides class member
        /wd4702      # unreachable code
        /wd4127      # conditional expression is constant (e.g., while(true))
    )
else()
    target_compile_options(ncp_core PRIVATE
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -Wno-unused-variable
    )
endif()

# ==================== Required: libsodium ====================
# Try vcpkg first (unofficial-sodium)
find_package(unofficial-sodium CONFIG QUIET)
if(unofficial-sodium_FOUND)
    message(STATUS "Found libsodium via vcpkg")
    target_link_libraries(ncp_core PUBLIC unofficial-sodium::sodium)
    target_compile_definitions(ncp_core PRIVATE HAVE_SODIUM)
else()
    # Fallback: manual search
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
        target_link_libraries(ncp_core PUBLIC ${SODIUM_LIBRARY})
        target_include_directories(ncp_core PRIVATE ${SODIUM_INCLUDE_DIR})
        target_compile_definitions(ncp_core PRIVATE HAVE_SODIUM)
    else()
        message(FATAL_ERROR
            "libsodium is REQUIRED but was not found!\n"
            "Please install libsodium:\n"
            "  Ubuntu/Debian: sudo apt-get install libsodium-dev\n"
            "  Fedora/RHEL:   sudo dnf install libsodium-devel\n"
            "  macOS:         brew install libsodium\n"
            "  Windows:       vcpkg install libsodium:x64-windows\n"
            "  Then pass: -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake\n"
        )
    endif()
endif()

# ==================== Optional: libpcap ====================
if(UNIX)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PCAP QUIET libpcap)
        if(PCAP_FOUND)
            target_compile_definitions(ncp_core PUBLIC HAVE_PCAP)
            target_link_libraries(ncp_core PUBLIC ${PCAP_LIBRARIES})
            target_include_directories(ncp_core PUBLIC ${PCAP_INCLUDE_DIRS})
            message(STATUS "Found libpcap: ${PCAP_LIBRARIES}")
        else()
            message(STATUS "libpcap not found - L2 raw packet features disabled")
        endif()
    endif()

    find_package(Threads QUIET)
    if(Threads_FOUND)
        target_link_libraries(ncp_core PUBLIC Threads::Threads)
    endif()

elseif(WIN32)
    # Windows: use Npcap SDK if available
    if(DEFINED NPCAP_SDK_DIR AND EXISTS "${NPCAP_SDK_DIR}/Include")
        target_include_directories(ncp_core PRIVATE "${NPCAP_SDK_DIR}/Include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_directories(ncp_core PUBLIC "${NPCAP_SDK_DIR}/Lib/x64")
        else()
            target_link_directories(ncp_core PUBLIC "${NPCAP_SDK_DIR}/Lib")
        endif()
        target_link_libraries(ncp_core PUBLIC wpcap Packet ws2_32)
        target_compile_definitions(ncp_core PUBLIC HAVE_PCAP)
        message(STATUS "Found Npcap SDK at ${NPCAP_SDK_DIR}")
    else()
        message(STATUS "Npcap SDK not found - using raw socket fallback on Windows (L2 features limited)")
    endif()

    # Windows networking libraries for hybrid backend (always needed)
    target_link_libraries(ncp_core PUBLIC ws2_32 iphlpapi)

    # bcrypt.lib for CSPRNG in anti-TSPU modules
    target_link_libraries(ncp_core PUBLIC bcrypt)

    # Advapi32 for SCM/Registry cleanup of stale WinDivert service (error 1058 fix)
    target_link_libraries(ncp_core PUBLIC advapi32)
endif()

# ==================== Optional: WinDivert (FIX #83) ====================
# WinDivert provides userspace packet interception on Windows.
# Replaces the non-functional WFP placeholder backend.
# Download from: https://reqrypt.org/windivert.html
if(WIN32)
    if(DEFINED WINDIVERT_DIR AND EXISTS "${WINDIVERT_DIR}/include")
        target_include_directories(ncp_core PRIVATE "${WINDIVERT_DIR}/include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_directories(ncp_core PUBLIC "${WINDIVERT_DIR}/x64")
        else()
            target_link_directories(ncp_core PUBLIC "${WINDIVERT_DIR}/x86")
        endif()
        target_link_libraries(ncp_core PUBLIC WinDivert)
        target_compile_definitions(ncp_core PRIVATE HAVE_WINDIVERT)
        message(STATUS "Found WinDivert SDK at ${WINDIVERT_DIR}")
    else()
        find_library(WINDIVERT_LIBRARY NAMES WinDivert)
        find_path(WINDIVERT_INCLUDE_DIR NAMES windivert.h)
        if(WINDIVERT_LIBRARY AND WINDIVERT_INCLUDE_DIR)
            target_link_libraries(ncp_core PUBLIC ${WINDIVERT_LIBRARY})
            target_include_directories(ncp_core PRIVATE ${WINDIVERT_INCLUDE_DIR})
            target_compile_definitions(ncp_core PRIVATE HAVE_WINDIVERT)
            message(STATUS "Found WinDivert: ${WINDIVERT_LIBRARY}")
        else()
            message(STATUS "WinDivert not found - Windows packet interception will use WFP placeholder (limited)")
        endif()
    endif()

    # WFP library for legacy WFP backend
    target_link_libraries(ncp_core PUBLIC fwpuclnt)
endif()

# ==================== Optional: libnetfilter_queue ====================
if(UNIX AND NOT APPLE)
    find_library(NFQ_LIBRARY NAMES netfilter_queue)
    find_path(NFQ_INCLUDE_DIR NAMES libnetfilter_queue/libnetfilter_queue.h)
    if(NFQ_LIBRARY AND NFQ_INCLUDE_DIR)
        target_link_libraries(ncp_core PUBLIC ${NFQ_LIBRARY})
        target_include_directories(ncp_core PRIVATE ${NFQ_INCLUDE_DIR})
        target_compile_definitions(ncp_core PRIVATE HAVE_NFQUEUE)
        message(STATUS "Found libnetfilter_queue: ${NFQ_LIBRARY}")
    else()
        message(STATUS "libnetfilter_queue not found - NFQUEUE packet interception disabled")
    endif()
endif()

# ==================== Optional: liboqs ====================
if(ENABLE_LIBOQS AND liboqs_FOUND)
    target_link_libraries(ncp_core PUBLIC OQS::oqs)
    target_compile_definitions(ncp_core PRIVATE HAVE_LIBOQS)
endif()

# ==================== Required: libwebsockets ====================
# WebSocket tunneling is REQUIRED for secure tunneling functionality
if(TARGET websockets_shared)
    target_link_libraries(ncp_core PUBLIC websockets_shared)
elseif(TARGET websockets)
    target_link_libraries(ncp_core PUBLIC websockets)
else()
    find_library(WEBSOCKETS_LIB NAMES websockets)
    if(WEBSOCKETS_LIB)
        target_link_libraries(ncp_core PUBLIC ${WEBSOCKETS_LIB})
    else()
        message(FATAL_ERROR "libwebsockets library not found!\n"
                            "Please install libwebsockets:\n"
                            "  vcpkg: vcpkg install libwebsockets:x64-windows\n"
                            "  Conan: conan install libwebsockets/4.3.3@")
    endif()
endif()
target_compile_definitions(ncp_core PRIVATE HAVE_LIBWEBSOCKETS)

# Include directories
target_include_directories(ncp_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
)

# Set target properties
set_target_properties(ncp_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# ==================== Required: OpenSSL ====================
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    target_link_libraries(ncp_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(ncp_core PRIVATE HAVE_OPENSSL)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
    
    # ECH requires OpenSSL 3.2+ for HPKE support
    if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.2")
        target_compile_definitions(ncp_core PRIVATE HAVE_ECH_HPKE)
        message(STATUS "ECH with HPKE support enabled (OpenSSL ${OPENSSL_VERSION})")
    else()
        message(STATUS "ECH unavailable (requires OpenSSL 3.2+, found ${OPENSSL_VERSION})")
    endif()
else()
    message(FATAL_ERROR "OpenSSL is REQUIRED but was not found")
endif()

# ==================== Install targets ====================
# NOTE: libsodium is already linked above (vcpkg or manual fallback)

install(TARGETS ncp_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/ncp
    FILES_MATCHING PATTERN "*.hpp"
)

install(FILES ${NCP_CORE_ROOT_HEADERS}
    DESTINATION include/ncp
)
