cmake_minimum_required(VERSION 3.20)

add_executable(ncp-cli main.cpp)

target_link_libraries(ncp-cli PRIVATE
    ncp_core
)

target_include_directories(ncp-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
)

set_target_properties(ncp-cli PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    OUTPUT_NAME ncp
)

# ── UAC: require administrator on Windows ──────────────────────────────────
# Embeds ncp.manifest into ncp.exe so Windows shows UAC elevation prompt.
# Key: do NOT add .manifest to target_sources — that triggers MSVC's
# automatic manifest merging which conflicts with /MANIFESTINPUT.
# Instead, pass everything via linker flags only.
if(WIN32 AND MSVC)
    set(NCP_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/ncp.manifest")
    if(EXISTS "${NCP_MANIFEST}")
        target_link_options(ncp-cli PRIVATE
            "/MANIFEST:EMBED"
            "/MANIFESTUAC:NO"
            "/MANIFESTINPUT:${NCP_MANIFEST}"
        )
        message(STATUS "ncp-cli: UAC manifest embedded (requireAdministrator)")
    else()
        message(WARNING "ncp.manifest not found at ${NCP_MANIFEST} - UAC elevation disabled")
    endif()
endif()

# Suppress unused parameter warnings in CLI command handlers
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(ncp-cli PRIVATE -Wno-unused-parameter)
endif()

install(TARGETS ncp-cli DESTINATION bin)

# ── Copy WinDivert runtime files next to ncp.exe ─────────────────────────
# WinDivert requires WinDivert.dll and WinDivert64.sys in the same directory.
if(WIN32 AND DEFINED WINDIVERT_DIR)
    set(_WD_RUNTIME_DIR "")
    if(EXISTS "${WINDIVERT_DIR}/x64/WinDivert.dll")
        set(_WD_RUNTIME_DIR "${WINDIVERT_DIR}/x64")
    elseif(EXISTS "${WINDIVERT_DIR}/WinDivert.dll")
        set(_WD_RUNTIME_DIR "${WINDIVERT_DIR}")
    endif()
    if(_WD_RUNTIME_DIR)
        add_custom_command(TARGET ncp-cli POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_WD_RUNTIME_DIR}/WinDivert.dll"
                $<TARGET_FILE_DIR:ncp-cli>/WinDivert.dll
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_WD_RUNTIME_DIR}/WinDivert64.sys"
                $<TARGET_FILE_DIR:ncp-cli>/WinDivert64.sys
            COMMENT "Copying WinDivert runtime files next to ncp.exe"
        )
        message(STATUS "WinDivert: will copy DLL+SYS from ${_WD_RUNTIME_DIR}")
    endif()
endif()
