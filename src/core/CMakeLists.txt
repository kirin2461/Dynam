cmake_minimum_required(VERSION 3.20)

# NCP Core Library CMakeLists.txt
# Core library does NOT depend on Qt6 - only CLI/GUI do

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
    src/e2e.cpp
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

# Find libpcap on Unix systems (optional)
if(UNIX)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(PCAP libpcap)
        if(PCAP_FOUND)
            target_compile_definitions(ncp_core PRIVATE HAVE_PCAP)
            target_link_libraries(ncp_core PUBLIC ${PCAP_LIBRARIES})
            target_include_directories(ncp_core PUBLIC ${PCAP_INCLUDE_DIRS})
        endif()
    endif()
    find_package(Threads)
    if(Threads_FOUND)
        target_link_libraries(ncp_core PUBLIC Threads::Threads)
    endif()
endif()

# Find sodium (REQUIRED - no fallback implementations allowed)
# Security: libsodium is mandatory for all cryptographic operations
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
        "libsodium is mandatory for secure cryptographic operations.\n"
        "Please install libsodium:\n"
        "  Ubuntu/Debian: sudo apt-get install libsodium-dev\n"
        "  Fedora/RHEL: sudo dnf install libsodium-devel\n"
        "  macOS: brew install libsodium\n"
        "  Windows: vcpkg install libsodium\n"
    )
endif()

# Find libnetfilter_queue for DPI bypass (Linux only)
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
