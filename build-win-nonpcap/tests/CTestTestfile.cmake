# CMake generated Testfile for 
# Source directory: /root/work/Dynam/tests
# Build directory: /root/work/Dynam/build-win-nonpcap/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test("ncp_tests" "/root/work/Dynam/build-win-nonpcap/bin/ncp_tests.exe")
set_tests_properties("ncp_tests" PROPERTIES  TIMEOUT "180" _BACKTRACE_TRIPLES "/root/work/Dynam/tests/CMakeLists.txt;131;add_test;/root/work/Dynam/tests/CMakeLists.txt;0;")
subdirs("../_deps/googletest-build")
