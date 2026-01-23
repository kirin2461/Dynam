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

install(TARGETS ncp-cli DESTINATION bin)
