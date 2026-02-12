# Fuzzing tests for Dynam/NCP
# Requires LLVM LibFuzzer (Clang with -fsanitize=fuzzer)

set(FUZZ_COMPILE_FLAGS "-fsanitize=fuzzer,address -fno-omit-frame-pointer")
set(FUZZ_LINK_FLAGS "-fsanitize=fuzzer,address")

# Fuzz target: packet parser
add_executable(fuzz_packet_parser fuzz_packet_parser.cpp)
target_link_libraries(fuzz_packet_parser PRIVATE ncp_core)
target_compile_options(fuzz_packet_parser PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_packet_parser PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: DPI config validation
add_executable(fuzz_dpi_config fuzz_dpi_config.cpp)
target_link_libraries(fuzz_dpi_config PRIVATE ncp_core)
target_compile_options(fuzz_dpi_config PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_dpi_config PRIVATE ${FUZZ_LINK_FLAGS})

# Fuzz target: crypto operations
add_executable(fuzz_crypto fuzz_crypto.cpp)
target_link_libraries(fuzz_crypto PRIVATE ncp_core)
target_compile_options(fuzz_crypto PRIVATE ${FUZZ_COMPILE_FLAGS})
target_link_options(fuzz_crypto PRIVATE ${FUZZ_LINK_FLAGS})
