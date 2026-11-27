# ONNX Runtime — REQUIRED dependency for shadow classifiers.
#
# If ONNX Runtime is not found, configuration FAILS with an error.
# There are no stubs or fallbacks — the code does not compile without ORT.
#
# Usage:
#   include(cmake/ncp_onnx_classifier.cmake)
#
# In src/core/CMakeLists.txt:
#   target_link_libraries(ncp_core PRIVATE onnxruntime::onnxruntime)
#   target_compile_definitions(ncp_core PRIVATE NCP_HAS_ONNXRUNTIME)
#   target_sources(ncp_core PRIVATE src/ncp_onnx_classifier.cpp)

# ── Strategy 1: vcpkg / config-mode ──
find_package(onnxruntime QUIET CONFIG)

# ── Strategy 2: pkg-config ──
if(NOT onnxruntime_FOUND)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(ONNXRUNTIME QUIET onnxruntime)
    endif()
endif()

# ── Strategy 3: Manual find ──
if(NOT onnxruntime_FOUND AND NOT ONNXRUNTIME_FOUND)
    set(_onnx_include
        "$ENV{VCPKG_ROOT}/installed/x64-windows/include"
        "$ENV{VCPKG_ROOT}/installed/x64-windows-static/include"
        "$ENV{VCPKG_ROOT}/installed/x64-linux/include"
        "$ENV{USERPROFILE}/.nuget/packages/microsoft.ml.onnxruntime/native/include"
        "C:/onnxruntime/include"
        "$ENV{ONNXRUNTIME_ROOT}/include"
        "/opt/homebrew/include"
        "/usr/local/include"
        "/usr/local/opt/onnxruntime/include"
        "/usr/include"
        "/usr/include/onnxruntime"
        "/usr/local/include/onnxruntime"
    )
    set(_onnxlib
        "$ENV{VCPKG_ROOT}/installed/x64-windows/lib"
        "$ENV{VCPKG_ROOT}/installed/x64-windows-static/lib"
        "$ENV{VCPKG_ROOT}/installed/x64-linux/lib"
        "$ENV{USERPROFILE}/.nuget/packages/microsoft.ml.onnxruntime/native/lib"
        "C:/onnxruntime/lib"
        "$ENV{ONNXRUNTIME_ROOT}/lib"
        "/opt/homebrew/lib"
        "/usr/local/lib"
        "/usr/local/opt/onnxruntime/lib"
        "/usr/lib"
        "/usr/lib/x86_64-linux-gnu"
    )

    find_path(ONNXRUNTIME_INCLUDE_DIR NAMES onnxruntime_cxx_api.h PATHS ${_onnxinclude})
    find_library(ONNXRUNTIME_LIBRARY NAMES onnxruntime PATHS ${_onnxlib})

    if(ONNXRUNTIME_INCLUDE_DIR AND ONNXRUNTIME_LIBRARY)
        message(STATUS "ONNX Runtime: ${ONNXRUNTIME_LIBRARY}")
        set(onnxruntime_FOUND TRUE)
    endif()
endif()

# ── Create imported target ──
if((onnxruntime_FOUND OR ONNXRUNTIME_FOUND) AND NOT TARGET onnxruntime::onnxruntime)
    add_library(onnxruntime::onnxruntime UNKNOWN IMPORTED)
    if(ONNXRUNTIME_LIBRARY AND ONNXRUNTIME_INCLUDE_DIR)
        set_target_properties(onnxruntime::onnxruntime PROPERTIES
            IMPORTED_LOCATION "${ONNXRUNTIME_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${ONNXRUNTIME_INCLUDE_DIR}")
    endif()
    if(WIN32)
        set_property(TARGET onnxruntime::onnxruntime APPEND PROPERTY
            INTERFACE_LINK_LIBRARIES shlwapi)
    endif()
endif()

# ── HARD FAIL if not found ──
if(NOT TARGET onnxruntime::onnxruntime)
    message(FATAL_ERROR
        "ONNX Runtime is REQUIRED but was not found.\n"
        "Install it:\n"
        "  Ubuntu:  sudo apt install libonnxruntime-dev\n"
        "  macOS:   brew install onnxruntime\n"
        "  Windows: vcpkg install onnxruntime:x64-windows\n"
        "           Or NuGet: Microsoft.ML.OnnxRuntime\n"
        "  Manual:  Set ONNXRUNTIME_ROOT or VCPKG_ROOT\n"
        "\n"
        "The project does NOT compile without ONNX Runtime.")
endif()

message(STATUS "ONNX Runtime: OK — shadow classifiers enabled")
