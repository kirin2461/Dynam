#ifndef NCP_APPLICATION_HPP
#define NCP_APPLICATION_HPP

#include <memory>
#include <string>
#include <functional>

#include "core/NetworkManager.hpp"
#include "core/include/ncp_config.hpp"
#include "core/include/ncp_logger.hpp"
#include "core/include/ncp_security.hpp"

#ifdef ENABLE_GUI
#include <QApplication>
#include "gui/MainWindow.hpp"
#endif

namespace NCP {

/**
 * @brief Main application orchestrator for NCP
 *
 * Works in both CLI and GUI modes.
 * GUI components are conditionally compiled only when Qt6 is available.
 */
class Application {
public:
    Application(int& argc, char** argv);
    ~Application();

    // Prevent copying
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;

    // Run the application
    int run();

    // Configuration
    void loadConfig(const std::string& config_path);
    void saveConfig(const std::string& config_path) const;

    // Component access
    NetworkManager* networkManager() const { return network_manager_.get(); }
    Config& config() { return NCP::Config::instance(); }
    Logger& logger() { return NCP::Logger::instance(); }

#ifdef ENABLE_GUI
    MainWindow* mainWindow() const { return main_window_.get(); }
#endif

    // Lifecycle management
    void initialize();
    void shutdown();

    // Mode detection
    bool isGuiMode() const { return gui_mode_; }
    bool isInitialized() const { return initialized_; }

private:
    // Core components
    std::unique_ptr<NetworkManager> network_manager_;

#ifdef ENABLE_GUI
    std::unique_ptr<QApplication> qt_app_;
    std::unique_ptr<MainWindow> main_window_;
    void initializeGui();
    void connectSignals();
#endif

    // Application state
    bool initialized_;
    bool gui_mode_;
    std::string config_path_;
    int argc_;
    char** argv_;

    // Private initialization helpers
    void initializeCore();
    void initializeLogging();
    void initializeSecurity();
    void parseArguments();
};

} // namespace NCP

#endif // NCP_APPLICATION_HPP
