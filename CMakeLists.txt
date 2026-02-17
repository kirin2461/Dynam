cmake_minimum_required(VERSION 3.20)
project(ncp-cpp
    VERSION 1.2.0
    DESCRIPTION "Network Control Protocol - C++ Implementation"
    LANGUAGES CXX
)

# ==================== C++ Standard Configuration ====================
# FIXED Issue #17.4: Allow C++20/23 for modern safety features
# Default to C++17 for compatibility, but allow user override
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard version (17, 20, or 23)")
else()
    set(CMAKE_CXX_STANDARD ${CMAKE_CXX_STANDARD} CACHE STRING "C++ standard version (17, 20, or 23)")
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Validate C++ standard
if(NOT CMAKE_CXX_STANDARD MATCHES "^(17|20|23)$")
    message(WARNING "Unsupported C++ standard ${CMAKE_CXX_STANDARD}. Falling back to C++17.")
    set(CMAKE_CXX_STANDARD 17)
endif()

message(STATUS "Using C++ standard: C++${CMAKE_CXX_STANDARD}")

# ==================== Build Options ====================
option(ENABLE_TESTS "Enable unit tests" ON)
option(ENABLE_GUI "Enable Qt6 GUI application (requires Qt6)" OFF)
option(ENABLE_CLI "Enable CLI tool" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_DOCS "Generate Doxygen documentation" OFF)

# ==================== Advanced Feature Options ====================
option(ENABLE_LIBOQS "Enable post-quantum cryptography via liboqs" OFF)
option(ENABLE_WEBSOCKETS "Enable WebSocket tunneling" OFF)
option(ENABLE_TOR_PROXY "Enable Tor proxy support" OFF)
option(ENABLE_FUZZING "Enable fuzzing tests (requires Clang with LibFuzzer)" OFF)

# ==================== Compilation Fixes ====================
# Allow insecure ECH stub (TEMPORARY - should implement real ECH or remove)
add_definitions(-DNCP_ALLOW_INSECURE_ECH_STUB)

# ==================== Platform-specific Settings ====================
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-D_WIN32_WINNT=0x0600)
    
    if(MSVC)
        set(CMAKE_CXX_FLAGS_RELEASE "/O2")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi")
        # Enable modern C++ warnings
        add_compile_options(/W4 /permissive-)
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

# ==================== Qt6 Configuration ====================
# Only if GUI enabled
if(ENABLE_GUI)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Charts)
endif()

# ==================== Output Directories ====================
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ==================== Include Directories ====================
include_directories(${CMAKE_SOURCE_DIR}/src)

# ==================== Required Dependencies ====================
# libsodium is the primary cryptographic library (always required)
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(SODIUM libsodium)
    if(SODIUM_FOUND)
        add_definitions(-DHAVE_SODIUM)
        include_directories(${SODIUM_INCLUDE_DIRS})
        link_directories(${SODIUM_LIBRARY_DIRS})
        message(STATUS "libsodium found: ${SODIUM_VERSION}")
    else()
        message(FATAL_ERROR "libsodium not found. Please install libsodium development package.")
    endif()
else()
    # Fallback for systems without pkg-config
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium)
    if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
        add_definitions(-DHAVE_SODIUM)
        include_directories(${SODIUM_INCLUDE_DIR})
        message(STATUS "libsodium found: ${SODIUM_LIBRARY}")
    else()
        message(FATAL_ERROR "libsodium not found. Please install libsodium development package.")
    endif()
endif()

# ==================== Optional Dependencies ====================

# FIXED Issue #17.9: OpenSSL is now OPTIONAL (libsodium is primary)
# Only needed for specific legacy compatibility features
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    add_definitions(-DHAVE_OPENSSL)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION} (optional features enabled)")
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(STATUS "OpenSSL not found. Building with libsodium only (recommended).")
endif()

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

# ==================== Documentation ====================
# FIXED Issue #17.11: Add Doxygen documentation generation
if(ENABLE_DOCS)
    find_package(Doxygen QUIET)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_IN ${CMAKE_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_BINARY_DIR}/Doxyfile)
        
        if(EXISTS ${DOXYGEN_IN})
            configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
            add_custom_target(docs ALL
                COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
                WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                COMMENT "Generating API documentation with Doxygen"
                VERBATIM
            )
            message(STATUS "Doxygen documentation will be generated")
        else()
            message(WARNING "Doxyfile.in not found at ${DOXYGEN_IN}")
        endif()
    else()
        message(STATUS "Doxygen not found. Documentation will not be generated.")
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

# ==================== Configuration Summary ====================
message(STATUS "")
message(STATUS "==============================")
message(STATUS "NCP C++ Configuration:")
message(STATUS "  Version:          ${PROJECT_VERSION}")
message(STATUS "  C++ Standard:     C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared libs:      ${BUILD_SHARED_LIBS}")
message(STATUS "")
message(STATUS "Components:")
message(STATUS "  ENABLE_CLI:       ${ENABLE_CLI}")
message(STATUS "  ENABLE_GUI:       ${ENABLE_GUI}")
message(STATUS "  ENABLE_TESTS:     ${ENABLE_TESTS}")
message(STATUS "  ENABLE_DOCS:      ${ENABLE_DOCS}")
message(STATUS "")
message(STATUS "Cryptography:")
message(STATUS "  libsodium:        REQUIRED (primary)")
if(OPENSSL_FOUND)
    message(STATUS "  OpenSSL:          ${OPENSSL_VERSION} (optional)")
else()
    message(STATUS "  OpenSSL:          Not found (optional)")
endif()
message(STATUS "  ENABLE_LIBOQS:    ${ENABLE_LIBOQS}")
message(STATUS "")
message(STATUS "Network Features:")
message(STATUS "  ENABLE_WEBSOCKETS:${ENABLE_WEBSOCKETS}")
message(STATUS "  ENABLE_TOR_PROXY: ${ENABLE_TOR_PROXY}")
message(STATUS "")
message(STATUS "Development:")
message(STATUS "  ENABLE_FUZZING:   ${ENABLE_FUZZING}")
message(STATUS "==============================")
message(STATUS "")

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

# Install documentation if generated
if(ENABLE_DOCS AND DOXYGEN_FOUND)
    install(DIRECTORY ${CMAKE_BINARY_DIR}/docs/html
        DESTINATION share/doc/ncp
        OPTIONAL
    )
endif()
