#include "Application.hpp"
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
    parseArguments();

#ifdef ENABLE_GUI
    if (gui_mode_) {
        qt_app_ = std::make_unique<QApplication>(argc_, argv_);
        qt_app_->setApplicationName("NCP - Network Control Protocol");
        qt_app_->setApplicationVersion("1.0.0");
        qt_app_->setOrganizationName("NCP Project");
    }
#endif
}

Application::~Application() {
    shutdown();
}

int Application::run() {
    if (!initialized_) {
        initialize();
    }

#ifdef ENABLE_GUI
    if (gui_mode_ && main_window_) {
        main_window_->show();
        return qt_app_->exec();
    }
#endif

    // CLI mode - run core logic
    NCP_LOG_INFO("NCP running in CLI mode");
    return 0;
}

void Application::loadConfig(const std::string& config_path) {
    config_path_ = config_path;
    auto& cfg = ncp::Config::instance();
    if (!cfg.loadFromFile(config_path)) {
        NCP_LOG_WARN("Config file not found: " + config_path + ", using defaults");
    } else {
        NCP_LOG_INFO("Configuration loaded from: " + config_path);
    }
}

void Application::saveConfig(const std::string& config_path) const {
    auto& cfg = ncp::Config::instance();
    if (cfg.saveToFile(config_path)) {
        NCP_LOG_INFO("Configuration saved to: " + config_path);
    } else {
        NCP_LOG_ERROR("Failed to save configuration to: " + config_path);
    }
}

void Application::initialize() {
    if (initialized_) return;

    initializeLogging();
    NCP_LOG_INFO("Initializing NCP Application v1.0.0");

    initializeSecurity();
    initializeCore();

#ifdef ENABLE_GUI
    if (gui_mode_) {
        initializeGui();
        connectSignals();
    }
#endif

    initialized_ = true;
    NCP_LOG_INFO("NCP Application initialized successfully");
}

void Application::shutdown() {
    if (!initialized_) return;

    NCP_LOG_INFO("Shutting down NCP Application");

#ifdef ENABLE_GUI
    main_window_.reset();
#endif

    network_manager_.reset();
    initialized_ = false;
}

void Application::initializeCore() {
    NCP_LOG_DEBUG("Initializing core components");
    network_manager_ = std::make_unique<NetworkManager>();
}

void Application::initializeLogging() {
    auto& log = ncp::Logger::instance();
    auto& cfg = ncp::Config::instance();

    std::string level_str = cfg.get("log.level", "info");
    log.setLevel(Logger::levelFromString(level_str));
    log.setConsoleOutput(cfg.getBool("log.console", true));

    std::string log_file = cfg.get("log.file");
    if (!log_file.empty()) {
        log.setFileOutput(log_file);
    }
}

void Application::initializeSecurity() {
    NCP_LOG_DEBUG("Initializing security subsystem");
    // Security initialization handled by SecurityManager
}

void Application::parseArguments() {
    for (int i = 1; i < argc_; ++i) {
        std::string arg(argv_[i]);
        if (arg == "--gui") {
            gui_mode_ = true;
        } else if (arg == "--config" && i + 1 < argc_) {
            loadConfig(std::string(argv_[++i]));
        }
    }
}

#ifdef ENABLE_GUI
void Application::initializeGui() {
    NCP_LOG_DEBUG("Initializing GUI components");
    main_window_ = std::make_unique<MainWindow>();
}

void Application::connectSignals() {
    NCP_LOG_DEBUG("Connecting signals and slots");
    // Connect GUI signals to core slots here
}
#endif

} // namespace ncp
