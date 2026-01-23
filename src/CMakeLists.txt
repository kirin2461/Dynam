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
