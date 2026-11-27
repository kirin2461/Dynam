cmake_minimum_required(VERSION 3.21)
project(DynamGUI VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# ─── Find Qt6 ────────────────────────────────────────────────────────────────
find_package(Qt6 REQUIRED COMPONENTS 
    Core 
    Widgets 
    Gui 
    Network 
    WebSockets
    LinguistTools
    Svg
    Charts
)

qt_standard_project_setup()

# ─── Sources ─────────────────────────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/core/I18nManager.cpp
    src/core/ThemeManager.cpp
    src/core/RestClient.cpp
    src/core/WebSocketClient.cpp
    src/models/TrafficModel.cpp
    src/models/ConfigModel.cpp
    src/models/LogModel.cpp
    src/widgets/TrafficMonitorWidget.cpp
    src/widgets/ConfigWidget.cpp
    src/widgets/LogWidget.cpp
    src/widgets/StealthMonitorWidget.cpp
    src/widgets/StatsWidget.cpp
    src/widgets/SettingsWidget.cpp
    src/widgets/AdversaryTestWidget.cpp
    src/MainWindow.cpp
)

set(HEADERS
    src/core/I18nManager.hpp
    src/core/ThemeManager.hpp
    src/core/RestClient.hpp
    src/core/WebSocketClient.hpp
    src/models/TrafficModel.hpp
    src/models/ConfigModel.hpp
    src/models/LogModel.hpp
    src/widgets/TrafficMonitorWidget.hpp
    src/widgets/ConfigWidget.hpp
    src/widgets/LogWidget.hpp
    src/widgets/StealthMonitorWidget.hpp
    src/widgets/StatsWidget.hpp
    src/widgets/SettingsWidget.hpp
    src/widgets/AdversaryTestWidget.hpp
    src/MainWindow.hpp
)

set(RESOURCES
    resources/resources.qrc
)

# ─── Translations ────────────────────────────────────────────────────────────
set(TS_FILES
    translations/dynam_ru.ts
    translations/dynam_en.ts
)

# resources.qrc embeds translations/*.qm from the SOURCE tree (qrc paths are
# relative to the .qrc file, so build-dir .qm cannot be referenced). Compile
# the .ts files at configure time so a fresh clone builds without a manual
# lrelease pass.
find_program(NCP_LRELEASE NAMES lrelease-qt6 lrelease HINTS /usr/lib/qt6/bin)
if(NOT NCP_LRELEASE)
    message(FATAL_ERROR "lrelease not found — install qt6-l10n-tools")
endif()
foreach(_ts ${TS_FILES})
    get_filename_component(_qm_name ${_ts} NAME_WE)
    execute_process(
        COMMAND ${NCP_LRELEASE} -silent
                ${CMAKE_CURRENT_SOURCE_DIR}/${_ts}
                -qm ${CMAKE_CURRENT_SOURCE_DIR}/translations/${_qm_name}.qm
        RESULT_VARIABLE _lrelease_rc)
    if(NOT _lrelease_rc EQUAL 0)
        message(WARNING "lrelease failed for ${_ts}")
    endif()
endforeach()

# ─── Executable ──────────────────────────────────────────────────────────────
qt_add_executable(dynam-gui
    ${SOURCES}
    ${HEADERS}
    ${RESOURCES}
)

# ─── Translations ────────────────────────────────────────────────────────────
qt_add_translations(dynam-gui
    TS_FILES ${TS_FILES}
    QM_FILES_OUTPUT_VARIABLE QM_FILES
)

# ─── Link libraries ──────────────────────────────────────────────────────────
target_link_libraries(dynam-gui PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Gui
    Qt6::Network
    Qt6::WebSockets
    Qt6::Svg
    Qt6::Charts
)

target_include_directories(dynam-gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ─── Install ─────────────────────────────────────────────────────────────────
install(TARGETS dynam-gui
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# macOS bundle
if(APPLE)
    set_target_properties(dynam-gui PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER com.dynam.gui
        MACOSX_BUNDLE_BUNDLE_NAME "Dynam"
        MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
        MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION}
    )
endif()

# Windows
if(WIN32)
    set_target_properties(dynam-gui PROPERTIES
        WIN32_EXECUTABLE TRUE
    )
endif()
