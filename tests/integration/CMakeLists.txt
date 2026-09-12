# CMakeLists.txt for integration tests
# Included from the root CMakeLists.txt via add_subdirectory(tests/integration)
# under ENABLE_TESTS. gtest targets come from tests/CMakeLists.txt
# (FetchContent), ncp_core from src/core.
cmake_minimum_required(VERSION 3.20)

add_executable(test_dpi_fixes
    test_dpi_fixes.cpp
)

target_link_libraries(test_dpi_fixes
    PRIVATE
        ncp_core
        gtest
)
add_dependencies(test_dpi_fixes ncp_core)

target_include_directories(test_dpi_fixes
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/core/include
        ${CMAKE_SOURCE_DIR}/src/core
        ${CMAKE_SOURCE_DIR}/src
)

set_target_properties(test_dpi_fixes PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# The tests bind loopback proxy ports (18080-18083) and spawn threads;
# no docker or external network is required. Label them so CI can
# select/exclude the group with `ctest -L integration` / `-LE integration`.
add_test(NAME integration_tests COMMAND test_dpi_fixes)
set_tests_properties(integration_tests PROPERTIES
    TIMEOUT 120
    LABELS "integration"
)
