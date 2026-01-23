cmake_minimum_required(VERSION 3.20)

project(ncp-cpp
    VERSION 1.0.0
    DESCRIPTION "Network Control Protocol - C++ Implementation"
    LANGUAGES CXX
)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options - GUI disabled by default (requires Qt6)
option(ENABLE_TESTS "Enable unit tests" OFF)
option(ENABLE_GUI "Enable Qt6 GUI application (requires Qt6)" OFF)
option(ENABLE_CLI "Enable CLI tool" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)

# Platform-specific settings
if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    # Use MSVC flags
    if(MSVC)
        set(CMAKE_CXX_FLAGS_RELEASE "/O2")
        set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi")
    endif()
elseif(UNIX)
    set(CMAKE_CXX_FLAGS_RELEASE "-O3")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra")
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

# Tests
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Print configuration
message(STATUS "NCP C++ Configuration:")
message(STATUS "  ENABLE_CLI: ${ENABLE_CLI}")
message(STATUS "  ENABLE_GUI: ${ENABLE_GUI}")
message(STATUS "  ENABLE_TESTS: ${ENABLE_TESTS}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
