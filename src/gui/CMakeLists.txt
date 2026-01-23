# NCP GUI Library CMakeLists.txt

# Source files
set(NCP_GUI_SOURCES
    MainWindow.cpp
)

set(NCP_GUI_HEADERS
    MainWindow.hpp
)

# Create GUI library
add_library(ncp_gui STATIC
    ${NCP_GUI_SOURCES}
    ${NCP_GUI_HEADERS}
)

# Link Qt6 libraries
target_link_libraries(ncp_gui PUBLIC
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Charts
    ncp_core
)

# Include directories
target_include_directories(ncp_gui PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

# Set target properties
set_target_properties(ncp_gui PROPERTIES
    AUTOMOC ON
    AUTORCC ON
    AUTOUIC ON
)
