#include "Application.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>

namespace ncp {

Application::Application(int& argc, char** argv)
    : initialized_(false) {
    // Create Qt application
    qt_app_ = std::make_unique<QApplication>(argc, argv);
    qt_app_->setApplicationName("NCP - Network Control Protocol");
    qt_app_->setApplicationVersion("1.0.0");
    qt_app_->setOrganizationName("NCP Project");
}

Application::~Application() {
    shutdown();
}

int Application::run() {
    if (!initialized_) {
        initialize();
    }

    // Show main window
    main_window_->show();

    // Run Qt event loop
    return qt_app_->exec();
}

void Application::loadConfig(const std::string& config_path) {
    config_path_ = config_path;
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cerr << "Warning: Could not open config file: " << config_path << std::endl;
        return;
    }
    // TODO: Parse configuration file
    file.close();
}

void Application::saveConfig(const std::string& config_path) const {
    std::ofstream file(config_path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not save config file: " + config_path);
    }
    // TODO: Write configuration
    file.close();
}

void Application::initialize() {
    if (initialized_) return;

    initializeLogging();
    initializeCore();
    initializeGui();
    connectSignals();

    initialized_ = true;
}

void Application::shutdown() {
    if (!initialized_) return;

    // Stop packet capture if running
    if (packet_capture_ && packet_capture_->isCapturing()) {
        packet_capture_->stopCapture();
    }

    // Cleanup in reverse order
    main_window_.reset();
    packet_capture_.reset();
    network_manager_.reset();

    initialized_ = false;
}

void Application::connectSignals() {
    // Connect NetworkManager signals to MainWindow
    QObject::connect(network_manager_.get(), &NetworkManager::statsUpdated,
                     main_window_.get(), &MainWindow::updateStats);

    QObject::connect(network_manager_.get(), &NetworkManager::connectionChanged,
                     main_window_.get(), &MainWindow::updateNetworkFlow);

    // Connect PacketCapture signals
    QObject::connect(packet_capture_.get(), &PacketCapture::packetCaptured,
                     main_window_.get(), &MainWindow::updateActivityLog);
}

void Application::initializeCore() {
    // Create network manager
    network_manager_ = std::make_unique<NetworkManager>();

    // Create packet capture
    packet_capture_ = std::make_unique<PacketCapture>();
}

void Application::initializeGui() {
    // Create main window with core components
    main_window_ = std::make_unique<MainWindow>(
        network_manager_.get(),
        packet_capture_.get()
    );

    // Set window properties
    main_window_->setWindowTitle("NCP - Network Control Protocol");
    main_window_->resize(1200, 800);
}

void Application::initializeLogging() {
    // TODO: Initialize logging system
    std::cout << "NCP Application initializing..." << std::endl;
}

} // namespace ncp
