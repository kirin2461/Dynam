# CMakeLists.txt for integration tests
cmake_minimum_required(VERSION 3.15)

project(ncp_integration_tests)

find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(test_dpi_fixes
    test_dpi_fixes.cpp
)

target_link_libraries(test_dpi_fixes
    PRIVATE
        ncp_core
        GTest::gtest
        GTest::gtest_main
        ${SODIUM_LIBRARIES}
)

target_include_directories(test_dpi_fixes
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src/core/include
        ${SODIUM_INCLUDE_DIRS}
)

# Enable testing
enable_testing()
add_test(NAME integration_tests COMMAND test_dpi_fixes)

# Add ThreadSanitizer and Helgrind tests
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    add_test(
        NAME integration_tests_tsan
        COMMAND ${CMAKE_COMMAND} -E env TSAN_OPTIONS=detect_deadlocks=1 $<TARGET_FILE:test_dpi_fixes>
    )
    
    find_program(VALGRIND_EXECUTABLE valgrind)
    if(VALGRIND_EXECUTABLE)
        add_test(
            NAME integration_tests_helgrind
            COMMAND ${VALGRIND_EXECUTABLE} --tool=helgrind --error-exitcode=1 $<TARGET_FILE:test_dpi_fixes>
        )
    endif()
endif()
