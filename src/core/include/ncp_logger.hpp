#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <thread>
#include <atomic>

// Windows defines ERROR as a macro, which conflicts with enum values
#ifdef ERROR
#undef ERROR
#endif

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
 * timestamped messages, thread IDs, and source location.
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
    void info (const std::string& msg) { log(LogLevel::INFO,  msg); }
    void warn (const std::string& msg) { log(LogLevel::WARN,  msg); }
    void error(const std::string& msg) { log(LogLevel::ERROR, msg); }
    void fatal(const std::string& msg) { log(LogLevel::FATAL, msg); }

    // Extended: log with source location
    void log_at(LogLevel level,
                const std::string& msg,
                const char* file,
                int line,
                const char* func)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (level < level_) return;
        std::string formatted = formatMessageAt(level, msg, file, line, func);
        writeFormatted(level, formatted);
    }

    void log(LogLevel level, const std::string& msg) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (level < level_) return;
        std::string formatted = formatMessage(level, msg);
        writeFormatted(level, formatted);
    }

    static LogLevel levelFromString(const std::string& s) {
        if (s == "trace")                return LogLevel::TRACE;
        if (s == "debug")                return LogLevel::DEBUG;
        if (s == "info")                 return LogLevel::INFO;
        if (s == "warn" || s == "warning") return LogLevel::WARN;
        if (s == "error")                return LogLevel::ERROR;
        if (s == "fatal")                return LogLevel::FATAL;
        if (s == "none")                 return LogLevel::NONE;
        return LogLevel::INFO;
    }

private:
    Logger() : level_(LogLevel::INFO), console_enabled_(true), file_enabled_(false) {}
    ~Logger() { if (file_.is_open()) file_.close(); }

    void writeFormatted(LogLevel level, const std::string& formatted) {
        if (console_enabled_) {
            if (level >= LogLevel::ERROR)
                std::cerr << formatted << std::endl;
            else
                std::cout << formatted << std::endl;
        }
        if (file_enabled_ && file_.is_open()) {
            file_ << formatted << std::endl;
            file_.flush();
        }
    }

    std::string formatMessage(LogLevel level, const std::string& msg) {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()) % 1000;
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count()
            << " [" << levelToString(level) << "] "
            << "[tid:" << std::this_thread::get_id() << "] "
            << msg;
        return oss.str();
    }

    std::string formatMessageAt(LogLevel level,
                                const std::string& msg,
                                const char* file,
                                int line,
                                const char* func)
    {
        auto now = std::chrono::system_clock::now();
        auto t   = std::chrono::system_clock::to_time_t(now);
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()) % 1000;
        // Extract only the filename, not the full path
        std::string fname(file ? file : "?");
        auto slash = fname.find_last_of("/\\");
        if (slash != std::string::npos) fname = fname.substr(slash + 1);

        std::ostringstream oss;
        oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count()
            << " [" << levelToString(level) << "] "
            << "[tid:" << std::this_thread::get_id() << "] "
            << fname << ":" << line << " (" << (func ? func : "?") << ") "
            << msg;
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

    LogLevel       level_;
    bool           console_enabled_;
    bool           file_enabled_;
    std::ofstream  file_;
    std::mutex     mtx_;
};

// =============================================================================
// Basic convenience macros (no location info)
// =============================================================================
#define NCP_LOG_TRACE(msg) ncp::Logger::instance().trace(msg)
#define NCP_LOG_DEBUG(msg) ncp::Logger::instance().debug(msg)
#define NCP_LOG_INFO(msg)  ncp::Logger::instance().info(msg)
#define NCP_LOG_WARN(msg)  ncp::Logger::instance().warn(msg)
#define NCP_LOG_ERROR(msg) ncp::Logger::instance().error(msg)
#define NCP_LOG_FATAL(msg) ncp::Logger::instance().fatal(msg)

// =============================================================================
// Location-aware macros: always embed __FILE__ / __LINE__ / __func__
// Use these everywhere you want "where did this happen" in the log.
// =============================================================================
#define NCP_TRACE(msg) \
    ncp::Logger::instance().log_at(ncp::LogLevel::TRACE, (msg), __FILE__, __LINE__, __func__)
#define NCP_DEBUG(msg) \
    ncp::Logger::instance().log_at(ncp::LogLevel::DEBUG, (msg), __FILE__, __LINE__, __func__)
#define NCP_INFO(msg) \
    ncp::Logger::instance().log_at(ncp::LogLevel::INFO,  (msg), __FILE__, __LINE__, __func__)
#define NCP_WARN(msg) \
    ncp::Logger::instance().log_at(ncp::LogLevel::WARN,  (msg), __FILE__, __LINE__, __func__)
#define NCP_ERROR(msg) \
    ncp::Logger::instance().log_at(ncp::LogLevel::ERROR, (msg), __FILE__, __LINE__, __func__)
#define NCP_FATAL(msg) \
    ncp::Logger::instance().log_at(ncp::LogLevel::FATAL, (msg), __FILE__, __LINE__, __func__)

// =============================================================================
// ScopeTracer: RAII object that logs ENTER/EXIT of a scope with timing.
// Usage:  NCP_SCOPE_TRACE("MyFunction");
//         NCP_SCOPE_TRACE_MSG("MyFunction", "arg=" + std::to_string(x));
// =============================================================================
struct ScopeTracer {
    const char* file_;
    int         line_;
    const char* func_;
    std::string label_;
    std::chrono::steady_clock::time_point start_;

    ScopeTracer(const char* file, int line, const char* func,
                const std::string& label = "")
        : file_(file), line_(line), func_(func)
        , label_(label.empty() ? std::string(func) : label)
        , start_(std::chrono::steady_clock::now())
    {
        ncp::Logger::instance().log_at(
            ncp::LogLevel::TRACE,
            ">>> ENTER " + label_,
            file_, line_, func_);
    }

    ~ScopeTracer() {
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start_).count();
        ncp::Logger::instance().log_at(
            ncp::LogLevel::TRACE,
            "<<< EXIT  " + label_ + " [" + std::to_string(elapsed) + " us]",
            file_, line_, func_);
    }
};

#define NCP_SCOPE_TRACE() \
    ncp::ScopeTracer _scope_tracer_(__FILE__, __LINE__, __func__)

#define NCP_SCOPE_TRACE_MSG(label) \
    ncp::ScopeTracer _scope_tracer_(__FILE__, __LINE__, __func__, (label))

// =============================================================================
// ReturnTracer: log a value right before returning it.
// Usage:  return NCP_RETURN(some_value);
// =============================================================================
#define NCP_RETURN(val) \
    [&]() { \
        auto _ret_val_ = (val); \
        ncp::Logger::instance().log_at( \
            ncp::LogLevel::TRACE, \
            std::string("RETURN ") + #val, \
            __FILE__, __LINE__, __func__); \
        return _ret_val_; \
    }()

// =============================================================================
// NCP_CHECK: assert-like macro that logs ERROR and continues (no abort).
// Usage:  NCP_CHECK(ptr != nullptr, "ptr must not be null");
// =============================================================================
#define NCP_CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            ncp::Logger::instance().log_at( \
                ncp::LogLevel::ERROR, \
                std::string("CHECK FAILED: (" #cond ") -- ") + (msg), \
                __FILE__, __LINE__, __func__); \
        } \
    } while(0)

// =============================================================================
// NCP_ASSERT: like NCP_CHECK but also throws std::logic_error in debug builds.
// =============================================================================
#ifndef NDEBUG
#define NCP_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            ncp::Logger::instance().log_at( \
                ncp::LogLevel::FATAL, \
                std::string("ASSERT FAILED: (" #cond ") -- ") + (msg), \
                __FILE__, __LINE__, __func__); \
            throw std::logic_error(std::string("NCP_ASSERT: ") + (msg)); \
        } \
    } while(0)
#else
#define NCP_ASSERT(cond, msg) NCP_CHECK(cond, msg)
#endif

} // namespace ncp
