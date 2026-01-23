#ifndef NCP_APPLICATION_HPP
#define NCP_APPLICATION_HPP

#include <QApplication>
#include <memory>
#include <string>
#include "core/NetworkManager.hpp"
#include "core/PacketCapture.hpp"
#include "gui/MainWindow.hpp"

namespace ncp {

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
    PacketCapture* packetCapture() const { return packet_capture_.get(); }
    MainWindow* mainWindow() const { return main_window_.get(); }

    // Lifecycle management
    void initialize();
    void shutdown();

    // Signals and slots connections
    void connectSignals();

private:
    // Qt application instance
    std::unique_ptr<QApplication> qt_app_;

    // Core components
    std::unique_ptr<NetworkManager> network_manager_;
    std::unique_ptr<PacketCapture> packet_capture_;

    // GUI components
    std::unique_ptr<MainWindow> main_window_;

    // Application state
    bool initialized_;
    std::string config_path_;

    // Private initialization helpers
    void initializeCore();
    void initializeGui();
    void initializeLogging();
};

} // namespace ncp

#endif // NCP_APPLICATION_HPP
