cmake_minimum_required(VERSION 3.20)
project(ncp-cpp
    VERSION 1.2.0    DESCRIPTION "Network Control Protocol - C++ Implementation"
    LANGUAGES CXX
)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(ENABLE_TESTS "Enable unit tests" ON)
option(ENABLE_GUI "Enable Qt6 GUI application (requires Qt6)" OFF)
option(ENABLE_CLI "Enable CLI tool" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

# Advanced feature options
option(ENABLE_LIBOQS "Enable post-quantum cryptography via liboqs" OFF)
option(ENABLE_WEBSOCKETS "Enable WebSocket tunneling" OFF)
option(ENABLE_TOR_PROXY "Enable Tor proxy support" OFF)
option(ENABLE_FUZZING "Enable fuzzing tests (requires Clang with LibFuzzer)" OFF)

# Platform-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
        add_definitions(-D_WIN32_WINNT=0x0600)
    if(MSVC)
        set(CMAKE_CXX_FLAGS_RELEASE "/O2")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi")
    endif()

    # Npcap SDK for packet capture on Windows
    set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk" CACHE PATH "Path to Npcap SDK")
    if(EXISTS "${NPCAP_SDK_DIR}/Include")
        message(STATUS "Npcap SDK found at ${NPCAP_SDK_DIR}")
        include_directories("${NPCAP_SDK_DIR}/Include")
        link_directories("${NPCAP_SDK_DIR}/Lib/x64")
    else()
        message(WARNING "Npcap SDK not found at ${NPCAP_SDK_DIR}. "
                        "Download from https://npcap.com/#download and extract to ${NPCAP_SDK_DIR}")
    endif()

elseif(UNIX)
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic")
    find_package(Threads REQUIRED)
endif()

# Qt6 configuration - only if GUI enabled
if(ENABLE_GUI)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Charts)
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)

# ==================== Required Dependencies ====================
# OpenSSL is always required for cryptographic functions
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL development package.")
endif()

# ==================== Optional Dependencies ====================
# These are OFF by default - only searched when explicitly enabled

if(ENABLE_LIBOQS)
    find_package(liboqs QUIET)
    if(liboqs_FOUND)
        add_definitions(-DHAVE_LIBOQS)
        message(STATUS "liboqs found - Post-quantum crypto enabled")
    else()
        message(WARNING "liboqs not found. Building without post-quantum crypto.\n"
                        "Install from https://github.com/open-quantum-safe/liboqs")
        set(ENABLE_LIBOQS OFF)
    endif()
endif()

if(ENABLE_WEBSOCKETS)
    find_package(Libwebsockets QUIET)
    if(Libwebsockets_FOUND)
        add_definitions(-DHAVE_LIBWEBSOCKETS)
        message(STATUS "libwebsockets found - WebSocket tunneling enabled")
    else()
        message(WARNING "libwebsockets not found. Building without WebSocket tunneling.")
        set(ENABLE_WEBSOCKETS OFF)
    endif()
endif()

if(ENABLE_TOR_PROXY)
    find_program(TOR_EXECUTABLE tor)
    if(TOR_EXECUTABLE)
        add_definitions(-DHAVE_TOR)
        message(STATUS "Tor found at ${TOR_EXECUTABLE}")
    else()
        message(WARNING "Tor not found. Building without Tor proxy support.")
        set(ENABLE_TOR_PROXY OFF)
    endif()
endif()

# ==================== Subdirectories ====================
# Always build core library
add_subdirectory(src/core)

# CLI tool (no Qt6 dependency)
if(ENABLE_CLI)
    add_subdirectory(src/cli)
endif()

# GUI application (requires Qt6)
if(ENABLE_GUI)
    add_subdirectory(src/gui)
    add_subdirectory(src)
endif()

# Tests (now ON by default, uses GoogleTest)
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Fuzzing tests (requires Clang with LibFuzzer)
if(ENABLE_FUZZING)
    add_subdirectory(tests/fuzz)
endif()

# Print configuration
message(STATUS "")
message(STATUS "==============================")
message(STATUS "NCP C++ Configuration:")
message(STATUS "  Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "  ENABLE_CLI:       ${ENABLE_CLI}")
message(STATUS "  ENABLE_GUI:       ${ENABLE_GUI}")
message(STATUS "  ENABLE_TESTS:     ${ENABLE_TESTS}")
message(STATUS "  ENABLE_LIBOQS:    ${ENABLE_LIBOQS}")
message(STATUS "  ENABLE_WEBSOCKETS:${ENABLE_WEBSOCKETS}")
message(STATUS "  ENABLE_TOR_PROXY: ${ENABLE_TOR_PROXY}")
message(STATUS "  ENABLE_FUZZING:   ${ENABLE_FUZZING}")
message(STATUS "==============================")

# ==================== Install Targets ====================
# Install core library
install(TARGETS ncp_core
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install CLI tool if enabled
if(ENABLE_CLI)
    install(TARGETS ncp-cli
        RUNTIME DESTINATION bin
    )
endif()

# Install GUI application if enabled
if(ENABLE_GUI)
    install(TARGETS ncp-gui
        RUNTIME DESTINATION bin
    )
endif()

# Install header files
install(DIRECTORY src/core/include/
    DESTINATION include/ncp
    FILES_MATCHING PATTERN "*.hpp"
)
