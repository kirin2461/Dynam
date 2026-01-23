cmake_minimum_required(VERSION 3.20)

# Find Google Test
find_package(GTest REQUIRED CONFIG)
include(GoogleTest)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)

# Unit test executable
add_executable(ncp_tests
    test_crypto.cpp
    test_license.cpp
    test_network.cpp
    test_dpi.cpp
)

target_link_libraries(ncp_tests
    ncp_core
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(ncp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(ncp_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Integration test executable (Phase 6)
add_executable(ncp_integration_tests
    test_integration.cpp
)

target_link_libraries(ncp_integration_tests
    ncp_core
    Qt6::Core
    Qt6::Network
    Qt6::Test
    GTest::gtest
    GTest::gtest_main
)

target_include_directories(ncp_integration_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core
    ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(ncp_integration_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    AUTOMOC ON
)

# Register unit tests
gtest_discover_tests(ncp_tests)

# Register integration tests
gtest_discover_tests(ncp_integration_tests
    TEST_PREFIX "Integration."
)
