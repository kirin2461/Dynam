cmake_minimum_required(VERSION 3.20)
project(ncp-cpp
    VERSION 1.2.0
    DESCRIPTION "Network Control Protocol - C++ Implementation"
    LANGUAGES CXX
)

# ==================== C++ Standard Configuration ====================
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 17 CACHE STRING "C++ standard version (17, 20, or 23)")
else()
    set(CMAKE_CXX_STANDARD ${CMAKE_CXX_STANDARD} CACHE STRING "C++ standard version (17, 20, or 23)")
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

# ==================== Optional Feature Options ====================
# NOTE: ENABLE_WEBSOCKETS is now REQUIRED (removed option)
option(ENABLE_LIBOQS "Enable post-quantum cryptography via liboqs" OFF)
option(ENABLE_TOR_PROXY "Enable Tor proxy support" OFF)
option(ENABLE_FUZZING "Enable fuzzing tests (requires Clang with LibFuzzer)" OFF)

# ==================== Platform-specific Settings ====================
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-D_WIN32_WINNT=0x0A00)

    if(MSVC)
        set(CMAKE_CXX_FLAGS_RELEASE "/O2")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi")
        add_compile_options(/W3 /permissive-)
        # Suppress common MSVC warnings globally
        add_compile_definitions(_CRT_SECURE_NO_WARNINGS)        # Suppress C4996 for CRT functions
        add_compile_definitions(_WINSOCK_DEPRECATED_NO_WARNINGS) # Suppress deprecated Winsock warnings
        # Note: NOMINMAX is already set above via add_definitions(-DNOMINMAX)
    endif()

    # Npcap SDK for raw packet capture/injection on Windows
    # Search order: explicit -D flag -> project-local -> common install paths -> Program Files
    set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk" CACHE PATH "Path to Npcap SDK")
    set(_npcap_found FALSE)
    # List of candidate directories
    set(_npcap_candidates
        "${NPCAP_SDK_DIR}"
        "C:/npcap-sdk"
        "C:/npcap"
        "C:/npcap-sdk-1.13"
        "$ENV{USERPROFILE}/npcap-sdk"
        "$ENV{USERPROFILE}/Desktop/npcap-sdk"
        "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.13"
        "$ENV{NPCAP_SDK}"
        "C:/Program Files/Npcap/sdk"
        "C:/Program Files (x86)/Npcap/sdk"
        "C:/Program Files/WinPcap"
    )
    foreach(_npcap_dir ${_npcap_candidates})
        if(EXISTS "${_npcap_dir}/Include" AND (EXISTS "${_npcap_dir}/Lib/x64/wpcap.lib" OR EXISTS "${_npcap_dir}/Lib/wpcap.lib"))
            set(NPCAP_SDK_DIR "${_npcap_dir}" CACHE PATH "Path to Npcap SDK" FORCE)
            set(_npcap_found TRUE)
            break()
        endif()
    endforeach()
    if(_npcap_found)
        message(STATUS "Npcap SDK found at ${NPCAP_SDK_DIR}")
        include_directories("${NPCAP_SDK_DIR}/Include")
        if(EXISTS "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib")
            link_directories("${NPCAP_SDK_DIR}/Lib/x64")
        else()
            link_directories("${NPCAP_SDK_DIR}/Lib")
        endif()
        add_definitions(-DHAVE_NPCAP)
        add_definitions(-DHAVE_PCAP)
    else()
        # Diagnostic: check if the directory exists but structure is wrong
        foreach(_npcap_dir ${_npcap_candidates})
            if(IS_DIRECTORY "${_npcap_dir}")
                if(NOT EXISTS "${_npcap_dir}/Include")
                    message(WARNING "Npcap SDK directory found at ${_npcap_dir} but 'Include' subfolder is missing. "
                                    "Expected structure: ${_npcap_dir}/Include/pcap.h and ${_npcap_dir}/Lib/x64/wpcap.lib. "
                                    "Re-download from https://npcap.com/#download (Npcap SDK zip)")
                elseif(NOT EXISTS "${_npcap_dir}/Lib/x64/wpcap.lib" AND NOT EXISTS "${_npcap_dir}/Lib/wpcap.lib")
                    message(WARNING "Npcap SDK directory found at ${_npcap_dir} with Include/ but 'Lib/x64/wpcap.lib' is missing. "
                                    "Re-download from https://npcap.com/#download (Npcap SDK zip)")
                endif()
                break()
            endif()
        endforeach()
        message(WARNING "Npcap SDK not found. Searched: project-local, C:/npcap-sdk, Program Files. "
                        "ARP/DHCP spoofing and packet capture will be disabled. "
                        "Download Npcap SDK from https://npcap.com/#download and extract to C:/npcap-sdk. "
                        "Or set -DNPCAP_SDK_DIR=<path>")
    endif()

    # WinDivert for userspace packet interception
    # Search order: explicit -D flag -> project-local -> common install paths
    set(WINDIVERT_DIR "${CMAKE_SOURCE_DIR}/WinDivert" CACHE PATH "Path to WinDivert SDK")
    set(_windivert_found FALSE)
    set(_windivert_candidates
        "${WINDIVERT_DIR}"
        "${CMAKE_SOURCE_DIR}/deps/WinDivert"
        "C:/WinDivert"
        "C:/WinDivert-2.2.2-A"
        "C:/WinDivert-2.2.1-A"
        "C:/WinDivert-2.2.0-A"
        "C:/WinDivert-master"
        "$ENV{USERPROFILE}/WinDivert"
        "$ENV{USERPROFILE}/WinDivert-2.2.2-A"
        "$ENV{USERPROFILE}/Desktop/WinDivert"
        "$ENV{USERPROFILE}/Desktop/WinDivert-2.2.2-A"
        "$ENV{USERPROFILE}/Downloads/WinDivert-2.2.2-A"
        "$ENV{WINDIVERT_DIR}"
        "C:/Program Files/WinDivert"
        "C:/Program Files (x86)/WinDivert"
    )
    foreach(_wd_dir ${_windivert_candidates})
        if(EXISTS "${_wd_dir}/include/windivert.h" OR EXISTS "${_wd_dir}/include/WinDivert.h")
            # Found include, now check lib
            if(EXISTS "${_wd_dir}/x64/WinDivert.lib" OR EXISTS "${_wd_dir}/lib/WinDivert.lib")
                set(WINDIVERT_DIR "${_wd_dir}" CACHE PATH "Path to WinDivert SDK" FORCE)
                set(_windivert_found TRUE)
                break()
            else()
                message(WARNING "WinDivert header found at ${_wd_dir}/include/ but WinDivert.lib is MISSING. "
                                "This looks like the GitHub SOURCE code, not the compiled release. "
                                "Download the pre-built release from: https://github.com/basil00/WinDivert/releases "
                                "(WinDivert-2.2.2-A.zip) and extract to C:/WinDivert-2.2.2-A")
            endif()
        endif()
    endforeach()
    if(_windivert_found)
        message(STATUS "WinDivert SDK found at ${WINDIVERT_DIR}")
        if(EXISTS "${WINDIVERT_DIR}/include")
            include_directories("${WINDIVERT_DIR}/include")
        endif()
        if(EXISTS "${WINDIVERT_DIR}/x64/WinDivert.lib")
            link_directories("${WINDIVERT_DIR}/x64")
        elseif(EXISTS "${WINDIVERT_DIR}/lib/WinDivert.lib")
            link_directories("${WINDIVERT_DIR}/lib")
        endif()
        add_definitions(-DHAVE_WINDIVERT)
    else()
        message(WARNING "WinDivert SDK not found. Searched: project-local, C:/WinDivert, C:/WinDivert-master, Program Files. "
                        "Packet interception will use legacy WFP backend (limited). "
                        "Download pre-built release: https://github.com/basil00/WinDivert/releases "
                        "(WinDivert-2.2.2-A.zip) and extract to C:/WinDivert-2.2.2-A "
                        "Or set -DWINDIVERT_DIR=<path>")
    endif()

elseif(UNIX)
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic")
    find_package(Threads REQUIRED)
    
    # Linux: Check for libnetfilter_queue
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(NFQUEUE libnetfilter_queue)
        if(NFQUEUE_FOUND)
            add_definitions(-DHAVE_NFQUEUE)
            message(STATUS "libnetfilter_queue found: ${NFQUEUE_VERSION}")
            include_directories(${NFQUEUE_INCLUDE_DIRS})
            link_directories(${NFQUEUE_LIBRARY_DIRS})
        else()
            message(STATUS "libnetfilter_queue not found - NFQUEUE backend disabled")
        endif()
    endif()
endif()

# ==================== Qt6 Configuration ====================
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
# libsodium (REQUIRED) — cross-platform detection
# Try vcpkg first, then system pkg-config, then manual fallback
find_package(unofficial-sodium CONFIG QUIET)
if(unofficial-sodium_FOUND)
    message(STATUS "Found libsodium via vcpkg")
    add_definitions(-DHAVE_SODIUM)
else()
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(SODIUM QUIET libsodium)
    endif()
    if(NOT SODIUM_FOUND)
        find_library(SODIUM_LIBRARY NAMES sodium libsodium)
        find_path(SODIUM_INCLUDE_DIR NAMES sodium.h)
    endif()
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
        add_definitions(-DHAVE_SODIUM)
        include_directories(${SODIUM_INCLUDE_DIR})
    elseif(SODIUM_FOUND)
        message(STATUS "Found libsodium via pkg-config: ${SODIUM_VERSION}")
        add_definitions(-DHAVE_SODIUM)
        include_directories(${SODIUM_INCLUDE_DIRS})
    else()
        message(FATAL_ERROR "libsodium is REQUIRED but was not found!\n"
                            "  Ubuntu/Debian: sudo apt-get install libsodium-dev\n"
                            "  Fedora/RHEL:   sudo dnf install libsodium-devel\n"
                            "  macOS:         brew install libsodium\n"
                            "  Windows:       vcpkg install libsodium:x64-windows")
    endif()
endif()

# ==================== Optional Dependencies ====================
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    add_definitions(-DHAVE_OPENSSL)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(STATUS "OpenSSL not found")
endif()

# NOTE: ECH check moved to src/core/CMakeLists.txt to ensure
# ncp_core gets HAVE_ECH_HPKE definition correctly

if(ENABLE_LIBOQS)
    find_package(liboqs QUIET)
    if(liboqs_FOUND)
        add_definitions(-DHAVE_LIBOQS)
        message(STATUS "liboqs found")
    else()
        message(WARNING "liboqs not found")
        set(ENABLE_LIBOQS OFF)
    endif()
endif()

# ==================== Required: libwebsockets ====================
# WebSocket tunneling is REQUIRED for secure tunneling functionality
# Uses vcpkg's libwebsockets-config.cmake (CONFIG mode required)

find_package(libwebsockets CONFIG QUIET)

if(libwebsockets_FOUND)
    add_definitions(-DHAVE_LIBWEBSOCKETS)
    message(STATUS "libwebsockets found via vcpkg (REQUIRED)")
else()
    message(FATAL_ERROR "libwebsockets not found!\n"
                        "Please install via vcpkg:\n"
                        "  vcpkg install libwebsockets:x64-windows")
endif()

if(ENABLE_TOR_PROXY)
    find_program(TOR_EXECUTABLE tor)
    if(TOR_EXECUTABLE)
        add_definitions(-DHAVE_TOR)
        message(STATUS "Tor found at ${TOR_EXECUTABLE}")
    else()
        message(WARNING "Tor not found")
        set(ENABLE_TOR_PROXY OFF)
    endif()
endif()

# ==================== Documentation ====================
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
                COMMENT "Generating API documentation"
                VERBATIM
            )
            message(STATUS "Doxygen documentation enabled")
        else()
            message(WARNING "Doxyfile.in not found")
        endif()
    else()
        message(STATUS "Doxygen not found")
    endif()
endif()

# ==================== Subdirectories ====================
add_subdirectory(src/core)

if(ENABLE_CLI)
    add_subdirectory(src/cli)
endif()

if(ENABLE_GUI)
    add_subdirectory(src/gui)
    add_subdirectory(src)
endif()

if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

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
message(STATUS "")
message(STATUS "Components:")
message(STATUS "  ENABLE_CLI:       ${ENABLE_CLI}")
message(STATUS "  ENABLE_GUI:       ${ENABLE_GUI}")
message(STATUS "  ENABLE_TESTS:     ${ENABLE_TESTS}")
message(STATUS "")
message(STATUS "Cryptography:")
message(STATUS "  libsodium:        REQUIRED")
if(OPENSSL_FOUND)
    message(STATUS "  OpenSSL:          ${OPENSSL_VERSION}")
    if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.2")
        message(STATUS "  ECH/HPKE:         ENABLED")
    else()
        message(STATUS "  ECH/HPKE:         Requires OpenSSL 3.2+")
    endif()
else()
    message(STATUS "  OpenSSL:          Not found")
endif()
message(STATUS "  ENABLE_LIBOQS:    ${ENABLE_LIBOQS}")
message(STATUS "")
message(STATUS "==============================")
message(STATUS "")

# ==================== Install Targets ====================
# NOTE: ncp_core install is in src/core/CMakeLists.txt

if(ENABLE_CLI)
    install(TARGETS ncp-cli
        RUNTIME DESTINATION bin
    )
endif()

if(ENABLE_GUI)
    install(TARGETS ncp
        RUNTIME DESTINATION bin
    )
endif()

install(DIRECTORY src/core/include/
    DESTINATION include/ncp
    FILES_MATCHING PATTERN "*.hpp"
)

if(ENABLE_DOCS AND DOXYGEN_FOUND)
    install(DIRECTORY ${CMAKE_BINARY_DIR}/docs/html
        DESTINATION share/doc/ncp
        OPTIONAL
    )
endif()
