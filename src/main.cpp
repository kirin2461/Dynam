#include "Application.hpp"
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    try {
        // Create application instance
        ncp::Application app(argc, argv);

        // Load configuration if exists
        const char* config_env = std::getenv("NCP_CONFIG");
        if (config_env) {
            app.loadConfig(config_env);
        } else {
            app.loadConfig("config/ncp.conf");
        }

        // Initialize and run the application
        app.initialize();
        return app.run();

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return EXIT_FAILURE;
    }
}
