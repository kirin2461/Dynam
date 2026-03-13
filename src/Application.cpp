#include "Application.hpp"
#include "core/include/ncp_logger.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>

namespace ncp {

Application::Application(int& argc, char** argv)
    : initialized_(false)
    , gui_mode_(false)
    , argc_(argc)
    , argv_(argv)
{
    NCP_SCOPE_TRACE();
    NCP_TRACE("Application::Application() argc=" + std::to_string(argc));
    parseArguments();
    NCP_TRACE("parseArguments() done, gui_mode=" + std::to_string(gui_mode_));

#ifdef ENABLE_GUI
    if (gui_mode_) {
        NCP_DEBUG("GUI mode enabled, creating QApplication");
        qt_app_ = std::make_unique<QApplication>(argc_, argv_);
        qt_app_->setApplicationName("NCP - Network Control Protocol");
        qt_app_->setApplicationVersion("1.0.0");
        qt_app_->setOrganizationName("NCP Project");
        NCP_DEBUG("QApplication created successfully");
    }
#endif
}

Application::~Application() {
    NCP_SCOPE_TRACE();
    NCP_TRACE("Application::~Application() calling shutdown()");
    shutdown();
}

int Application::run() {
    NCP_SCOPE_TRACE();
    NCP_TRACE("Application::run() initialized_=" + std::to_string(initialized_));
    if (!initialized_) {
        NCP_DEBUG("Not initialized, calling initialize()");
        initialize();
    }

#ifdef ENABLE_GUI
    if (gui_mode_ && main_window_) {
        NCP_INFO("Entering Qt event loop");
        main_window_->show();
        int ret = qt_app_->exec();
        NCP_INFO("Qt event loop exited with code " + std::to_string(ret));
        return ret;
    }
#endif

    // CLI mode - run core logic
    NCP_LOG_INFO("NCP running in CLI mode");
    NCP_TRACE("Application::run() returning 0 (CLI mode)");
    return 0;
}

void Application::loadConfig(const std::string& config_path) {
    NCP_SCOPE_TRACE();
    NCP_TRACE("loadConfig() path='" + config_path + "'");
    config_path_ = config_path;
    auto& cfg = ncp::Config::instance();
    if (!cfg.loadFromFile(config_path)) {
        NCP_LOG_WARN("Config file not found: " + config_path + ", using defaults");
    } else {
        NCP_LOG_INFO("Configuration loaded from: " + config_path);
        NCP_TRACE("Config loaded successfully");
    }
}

void Application::saveConfig(const std::string& config_path) const {
    NCP_SCOPE_TRACE();
    NCP_TRACE("saveConfig() path='" + config_path + "'");
    auto& cfg = ncp::Config::instance();
    if (cfg.saveToFile(config_path)) {
        NCP_LOG_INFO("Configuration saved to: " + config_path);
    } else {
        NCP_LOG_ERROR("Failed to save configuration to: " + config_path);
    }
}

void Application::initialize() {
    NCP_SCOPE_TRACE();
    NCP_TRACE("Application::initialize() called, initialized_=" + std::to_string(initialized_));
    if (initialized_) {
        NCP_DEBUG("initialize() called but already initialized, skipping");
        return;
    }

    NCP_TRACE("Step 1/4: initializeLogging()");
    initializeLogging();
    NCP_LOG_INFO("Initializing NCP Application v1.0.0");

    NCP_TRACE("Step 2/4: initializeSecurity()");
    initializeSecurity();

    NCP_TRACE("Step 3/4: initializeCore()");
    initializeCore();

#ifdef ENABLE_GUI
    if (gui_mode_) {
        NCP_TRACE("Step 4/4: initializeGui() + connectSignals()");
        initializeGui();
        connectSignals();
    }
#endif

    initialized_ = true;
    NCP_LOG_INFO("NCP Application initialized successfully");
    NCP_TRACE("Application::initialize() complete");
}

void Application::shutdown() {
    NCP_SCOPE_TRACE();
    NCP_TRACE("Application::shutdown() initialized_=" + std::to_string(initialized_));
    if (!initialized_) {
        NCP_DEBUG("shutdown() called but not initialized, skipping");
        return;
    }
    NCP_LOG_INFO("Shutting down NCP Application");

#ifdef ENABLE_GUI
    NCP_TRACE("Releasing main_window_");
    main_window_.reset();
#endif

    NCP_TRACE("Releasing network_manager_");
    network_manager_.reset();
    initialized_ = false;
    NCP_TRACE("Application::shutdown() complete");
}

void Application::initializeCore() {
    NCP_SCOPE_TRACE();
    NCP_LOG_DEBUG("Initializing core components");
    NCP_TRACE("Creating NetworkManager");
    network_manager_ = std::make_unique<NetworkManager>();
    NCP_CHECK(network_manager_ != nullptr, "NetworkManager creation failed");
    NCP_TRACE("NetworkManager created successfully");
}

void Application::initializeLogging() {
    NCP_SCOPE_TRACE();
    auto& log = ncp::Logger::instance();
    auto& cfg = ncp::Config::instance();
    std::string level_str = cfg.get("log.level", "info");
    NCP_TRACE("initializeLogging() level='" + level_str + "'");
    log.setLevel(Logger::levelFromString(level_str));
    log.setConsoleOutput(cfg.getBool("log.console", true));
    std::string log_file = cfg.get("log.file");
    if (!log_file.empty()) {
        NCP_TRACE("Setting log file output: '" + log_file + "'");
        log.setFileOutput(log_file);
    }
    NCP_TRACE("initializeLogging() complete");
}

void Application::initializeSecurity() {
    NCP_SCOPE_TRACE();
    NCP_LOG_DEBUG("Initializing security subsystem");
    // Security initialization handled by SecurityManager
    NCP_TRACE("Security subsystem initialization stub complete");
}

void Application::parseArguments() {
    NCP_SCOPE_TRACE();
    NCP_TRACE("parseArguments() argc_=" + std::to_string(argc_));
    for (int i = 1; i < argc_; ++i) {
        std::string arg(argv_[i]);
        NCP_TRACE("argv[" + std::to_string(i) + "]=" + arg);
        if (arg == "--gui") {
            gui_mode_ = true;
            NCP_DEBUG("GUI mode flag detected");
        } else if (arg == "--config" && i + 1 < argc_) {
            std::string cfg_path(argv_[++i]);
            NCP_TRACE("Config path argument: '" + cfg_path + "'");
            loadConfig(cfg_path);
        } else {
            NCP_WARN("Unknown argument: '" + arg + "'");
        }
    }
    NCP_TRACE("parseArguments() done");
}

#ifdef ENABLE_GUI
void Application::initializeGui() {
    NCP_SCOPE_TRACE();
    NCP_LOG_DEBUG("Initializing GUI components");
    main_window_ = std::make_unique<MainWindow>();
    NCP_CHECK(main_window_ != nullptr, "MainWindow creation failed");
    NCP_TRACE("MainWindow created");
}

void Application::connectSignals() {
    NCP_SCOPE_TRACE();
    NCP_LOG_DEBUG("Connecting signals and slots");
    // Connect GUI signals to core slots here
    NCP_TRACE("connectSignals() stub complete");
}
#endif

} // namespace ncp
