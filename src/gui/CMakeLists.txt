# NCP Qt6 GUI application (ncp-qt)

set(NCP_QT_SOURCES
    main.cpp
    MainWindow.cpp
    ProxyController.cpp
    LicenseVerifier.cpp
    SettingsDialog.cpp
    widgets/StatusPanel.cpp
    widgets/NetworkMonitor.cpp
    widgets/DPIControl.cpp
    widgets/TrafficAnalytics.cpp
    widgets/SystemStats.cpp
    widgets/ActivityLog.cpp
    widgets/LicenseInfo.cpp
)

set(NCP_QT_HEADERS
    MainWindow.hpp
    ProxyController.hpp
    LicenseVerifier.hpp
    SettingsDialog.hpp
    widgets/StatusPanel.hpp
    widgets/NetworkMonitor.hpp
    widgets/DPIControl.hpp
    widgets/TrafficAnalytics.hpp
    widgets/SystemStats.hpp
    widgets/ActivityLog.hpp
    widgets/LicenseInfo.hpp
)

add_executable(ncp-qt ${NCP_QT_SOURCES} ${NCP_QT_HEADERS})

target_link_libraries(ncp-qt PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Charts
    ncp_core
)

if(UNIX AND NOT APPLE)
    target_link_libraries(ncp-qt PRIVATE Threads::Threads)
endif()

target_include_directories(ncp-qt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/src
)

# libsodium headers (LicenseVerifier uses crypto_sign_*)
if(SODIUM_INCLUDE_DIR)
    target_include_directories(ncp-qt PRIVATE ${SODIUM_INCLUDE_DIR})
endif()

set_target_properties(ncp-qt PROPERTIES
    AUTOMOC ON
    AUTOUIC ON
    WIN32_EXECUTABLE TRUE
    OUTPUT_NAME "ncp-qt"
)

install(TARGETS ncp-qt RUNTIME DESTINATION bin)
