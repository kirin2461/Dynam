cmake_minimum_required(VERSION 3.20)

# NCP GUI Application CMakeLists.txt

# Source files for main application
set(NCP_APP_SOURCES
    Application.cpp
    main.cpp
)

set(NCP_APP_HEADERS
    Application.hpp
)

# Create the GUI executable
add_executable(ncp
    ${NCP_APP_SOURCES}
    ${NCP_APP_HEADERS}
)

# Link libraries
target_link_libraries(ncp PRIVATE
    ncp_core
    ncp_gui
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Charts
    ${PCAP_LIBRARIES}
)

# The #ifdef ENABLE_GUI blocks in Application.cpp gate Qt construction
# and main window creation — without this define they all compile out.
target_compile_definitions(ncp PRIVATE ENABLE_GUI)

if(UNIX AND NOT APPLE)
    target_link_libraries(ncp PRIVATE Threads::Threads)
endif()

# Include directories
target_include_directories(ncp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

# Set target properties
set_target_properties(ncp PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
    OUTPUT_NAME "ncp"
)

# Install
install(TARGETS ncp
    RUNTIME DESTINATION bin
    BUNDLE DESTINATION .
)
