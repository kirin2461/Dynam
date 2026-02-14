cmake_minimum_required(VERSION 3.20)

# NCP Core Library
# Core library has NO Qt6 dependency

# Source files in root of core/
set(NCP_CORE_ROOT_SOURCES
    NetworkManager.cpp
    ConnectionMonitor.cpp
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
    src/ncp_paranoid.cpp
    src/ncp_secure_memory.cpp
        include/ncp_arp.hpp
    include/ncp_dummy.hpp
    include/ncp_timing.hpp
    include/ncp_identity.hpp
    include/ncp_entropy_masking.hpp
    include/ncp_geneva_engine.hpp
)

# Conditionally add sources that depend on optional libraries
if(ENABLE_LIBOQS OR HAVE_LIBOQS)
    # e2e.cpp uses liboqs for post-quantum key exchange
endif()

if(ENABLE_WEBSOCKETS OR HAVE_LIBWEBSOCKETS)
    # mimicry.cpp uses libwebsockets
endif()

# Always compile these with #ifdef guards inside
list(APPEND NCP_CORE_SRC_SOURCES
    src/e2e.cpp
    src/mimicry.cpp
    src/i2p.cpp
    src/security.cpp
)

# Header files in include/ subdirectory
set(NCP_CORE_INCLUDE_HEADERS
    include/ncp_crypto.hpp
    include/ncp_doh.hpp
    include/ncp_db.hpp
    include/ncp_license.hpp
    include/ncp_dpi.hpp
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
            message(STATUS "libpcap not found - packet capture disabled")
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
        message(STATUS "Npcap SDK not found - packet capture disabled on Windows")
    endif()
endif()

# ==================== Optional: libnetfilter_queue ====================
if(UNIX AND NOT APPLE)
    find_library(NFQ_LIBRARY NAMES netfilter_queue)
    if(NFQ_LIBRARY)
        target_link_libraries(ncp_core PUBLIC ${NFQ_LIBRARY})
        target_compile_definitions(ncp_core PRIVATE HAVE_NFQUEUE)
        message(STATUS "Found libnetfilter_queue: ${NFQ_LIBRARY}")
    else()
        message(STATUS "libnetfilter_queue not found - DPI driver mode disabled")
    endif()
endif()

# ==================== Optional: liboqs ====================
if(ENABLE_LIBOQS AND liboqs_FOUND)
    target_link_libraries(ncp_core PUBLIC OQS::oqs)
    target_compile_definitions(ncp_core PRIVATE HAVE_LIBOQS)
endif()

# ==================== Optional: libwebsockets ====================
if(ENABLE_WEBSOCKETS AND Libwebsockets_FOUND)
    # vcpkg provides websockets_shared, apt provides websockets
    if(TARGET websockets_shared)
        target_link_libraries(ncp_core PUBLIC websockets_shared)
    elseif(TARGET websockets)
        target_link_libraries(ncp_core PUBLIC websockets)
    else()
        find_library(WEBSOCKETS_LIB NAMES websockets)
        if(WEBSOCKETS_LIB)
            target_link_libraries(ncp_core PUBLIC ${WEBSOCKETS_LIB})
        endif()
    endif()
    target_compile_definitions(ncp_core PRIVATE HAVE_LIBWEBSOCKETS)
endif()

# Include directories
target_include_directories(ncp_core PUBLIC
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
else()
    message(FATAL_ERROR "OpenSSL is REQUIRED but was not found")
endif()

# ==================== Install targets ====================
install(TARGETS ncp_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/ncp
    FILES_MATCHING PATTERN "*.hpp"
)

install(FILES
    ${NCP_CORE_ROOT_HEADERS}
    DESTINATION include/ncp
)
