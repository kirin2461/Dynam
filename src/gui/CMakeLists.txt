# NCP Qt6 GUI application (ncp-qt)
#
# Merged with PR #118 (upstream Qt GUI): the target stays the shipping
# ncp-qt executable (controller backend driving external ncp.exe), with the
# upstream header-only tool widgets added to the header list so AUTOMOC
# processes their Q_OBJECT macros.

set(NCP_QT_SOURCES
    main.cpp
    MainWindow.cpp
    ProxyController.cpp
    DriverController.cpp
    Launcher.cpp
    LicenseVerifier.cpp
    SettingsDialog.cpp
    widgets/StatusPanel.cpp
    widgets/NetworkMonitor.cpp
    widgets/DPIControl.cpp
    widgets/TrafficAnalytics.cpp
    widgets/SystemStats.cpp
    widgets/ActivityLog.cpp
    widgets/LicenseInfo.cpp
    widgets/ModulesPanel.cpp
    widgets/LeakTestPanel.cpp
)

set(NCP_QT_HEADERS
    MainWindow.hpp
    ProxyController.hpp
    DriverController.hpp
    Launcher.hpp
    LicenseVerifier.hpp
    SettingsDialog.hpp
    widgets/StatusPanel.hpp
    widgets/NetworkMonitor.hpp
    widgets/DPIControl.hpp
    widgets/TrafficAnalytics.hpp
    widgets/SystemStats.hpp
    widgets/ActivityLog.hpp
    widgets/LicenseInfo.hpp
    widgets/ModulesPanel.hpp
    widgets/LeakTestPanel.hpp
    # PR #118 tool panels (header-only)
    widgets/UiSettingsDialog.hpp
    widgets/CryptoPanel.hpp
    widgets/LicenseActivationDialog.hpp
    widgets/AboutDialog.hpp
    widgets/IdentityPanel.hpp
    widgets/DPIMetricsPanel.hpp
    widgets/Themes.hpp
    widgets/OnboardingWizard.hpp
    widgets/StatusSummary.hpp
    widgets/DiagnosticsDialog.hpp
    widgets/DnsLookupPanel.hpp
    widgets/UrlProbePanel.hpp
    widgets/DPIStrategyEditor.hpp
    widgets/Profiles.hpp
    widgets/PollerEngine.hpp
    widgets/PollerPanel.hpp
    widgets/AdvancedSettingsPanel.hpp
    widgets/SiteScraperPanel.hpp
    widgets/ScanCommon.hpp
    widgets/BulkScanDialog.hpp
    widgets/CrawlerDialog.hpp
    widgets/SparklineWidget.hpp
    widgets/BulkDiffDialog.hpp
    widgets/EnterprisePanel.hpp
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

if(APPLE)
    # macOS packaging (scripts/build_macos_gui_app.sh) expects the GUI as a
    # bundle at build-gui/bin/ncp.app with the executable named "ncp"
    # (CI smoke greps for dist/Dynam.app/Contents/MacOS/ncp).
    set_target_properties(ncp-qt PROPERTIES
        MACOSX_BUNDLE TRUE
        OUTPUT_NAME "ncp"
    )
endif()

install(TARGETS ncp-qt RUNTIME DESTINATION bin BUNDLE DESTINATION .)
