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

include(GoogleTest)

# ==================== Unit Tests ====================
add_executable(ncp_tests
    crypto_test.cpp
    test_dpi.cpp
    test_integration.cpp
    test_license.cpp
    test_network.cpp
)

target_link_libraries(ncp_tests
    PRIVATE
        ncp_core
                gtest
                gtest_main
)

target_include_directories(ncp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(ncp_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

gtest_discover_tests(ncp_tests)
