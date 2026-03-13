#include "Application.hpp"
#include "core/include/ncp_logger.hpp"
#include <iostream>
#include <cstdlib>
#include <string>

int main(int argc, char* argv[]) {
    // Bootstrap logger with console output before Application is created
    // so we capture crashes during very early init
    ncp::Logger::instance().setConsoleOutput(true);
    NCP_INFO("=== NCP startup: main() entered, argc=" + std::to_string(argc) + " ===");

    for (int i = 0; i < argc; ++i) {
        NCP_TRACE("argv[" + std::to_string(i) + "]=" + std::string(argv[i]));
    }

    try {
        NCP_TRACE("Creating ncp::Application");
        // Create application instance
        ncp::Application app(argc, argv);
        NCP_TRACE("ncp::Application created successfully");

        // Load configuration if exists
        const char* config_env = std::getenv("NCP_CONFIG");
        if (config_env) {
            NCP_INFO(std::string("NCP_CONFIG env var set: '") + config_env + "'");
            app.loadConfig(config_env);
        } else {
            NCP_DEBUG("NCP_CONFIG env var not set, using default: 'config/ncp.conf'");
            app.loadConfig("config/ncp.conf");
        }

        // Initialize and run the application
        NCP_TRACE("Calling app.initialize()");
        app.initialize();
        NCP_TRACE("app.initialize() returned, calling app.run()");
        int ret = app.run();
        NCP_INFO("app.run() returned " + std::to_string(ret) + ", exiting cleanly");
        return ret;

    } catch (const std::exception& e) {
        NCP_FATAL(std::string("Unhandled std::exception in main(): ") + e.what());
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        NCP_FATAL("Unhandled unknown exception in main()");
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return EXIT_FAILURE;
    }
}
