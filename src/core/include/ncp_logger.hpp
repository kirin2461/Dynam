#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <ctime>

namespace ncp {

/**
 * @brief Logging levels for NCP
 */
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4,
    FATAL = 5,
    NONE  = 6
};

/**
 * @brief Thread-safe logger for NCP
 *
 * Supports console and file output, configurable log levels,
 * and timestamped messages.
 */
class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void setLevel(LogLevel level) {
        std::lock_guard<std::mutex> lock(mtx_);
        level_ = level;
    }

    void setConsoleOutput(bool enabled) {
        std::lock_guard<std::mutex> lock(mtx_);
        console_enabled_ = enabled;
    }

    bool setFileOutput(const std::string& path) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
        file_enabled_ = file_.is_open();
        return file_enabled_;
    }

    void trace(const std::string& msg) { log(LogLevel::TRACE, msg); }
    void debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
    void info(const std::string& msg)  { log(LogLevel::INFO,  msg); }
    void warn(const std::string& msg)  { log(LogLevel::WARN,  msg); }
    void error(const std::string& msg) { log(LogLevel::ERROR, msg); }
    void fatal(const std::string& msg) { log(LogLevel::FATAL, msg); }

    void log(LogLevel level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (level < level_) return;

        std::string formatted = formatMessage(level, msg);

        if (console_enabled_) {
            if (level >= LogLevel::ERROR) {
                std::cerr << formatted << std::endl;
            } else {
                std::cout << formatted << std::endl;
            }
        }

        if (file_enabled_ && file_.is_open()) {
            file_ << formatted << std::endl;
            file_.flush();
        }
    }

    static LogLevel levelFromString(const std::string& s) {
        if (s == "trace") return LogLevel::TRACE;
        if (s == "debug") return LogLevel::DEBUG;
        if (s == "info")  return LogLevel::INFO;
        if (s == "warn" || s == "warning") return LogLevel::WARN;
        if (s == "error") return LogLevel::ERROR;
        if (s == "fatal") return LogLevel::FATAL;
        if (s == "none")  return LogLevel::NONE;
        return LogLevel::INFO;
    }

private:
    Logger()
        : level_(LogLevel::INFO)
        , console_enabled_(true)
        , file_enabled_(false)
    {}

    ~Logger() {
        if (file_.is_open()) file_.close();
    }

    std::string formatMessage(LogLevel level, const std::string& msg) {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::ostringstream oss;
        oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count()
            << " [" << levelToString(level) << "] " << msg;
        return oss.str();
    }

    static const char* levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::TRACE: return "TRACE";
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO:  return "INFO ";
            case LogLevel::WARN:  return "WARN ";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::FATAL: return "FATAL";
            default:              return "?????";
        }
    }

    LogLevel level_;
    bool console_enabled_;
    bool file_enabled_;
    std::ofstream file_;
    std::mutex mtx_;
};

// Convenience macros
#define NCP_LOG_TRACE(msg) ncp::Logger::instance().trace(msg)
#define NCP_LOG_DEBUG(msg) ncp::Logger::instance().debug(msg)
#define NCP_LOG_INFO(msg)  ncp::Logger::instance().info(msg)
#define NCP_LOG_WARN(msg)  ncp::Logger::instance().warn(msg)
#define NCP_LOG_ERROR(msg) ncp::Logger::instance().error(msg)
#define NCP_LOG_FATAL(msg) ncp::Logger::instance().fatal(msg)

} // namespace ncp
