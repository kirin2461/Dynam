# NCP GUI Library CMakeLists.txt

# Source files
set(NCP_GUI_SOURCES
    MainWindow.cpp
)

set(NCP_GUI_HEADERS
    MainWindow.hpp
    widgets/StatusPanel.hpp
    widgets/NetworkMonitor.hpp
    widgets/DPIControl.hpp
    widgets/TrafficAnalytics.hpp
    widgets/SystemStats.hpp
    widgets/ActivityLog.hpp
    widgets/LicenseInfo.hpp
    widgets/SettingsDialog.hpp
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
