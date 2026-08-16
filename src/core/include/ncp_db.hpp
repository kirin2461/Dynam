#ifndef NCP_DB_HPP
#define NCP_DB_HPP

#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <map>

// Forward declaration - sqlite3 is optional
#ifdef HAVE_SQLITE
struct sqlite3;
#endif

namespace ncp {

class Database {
public:
    Database();
    ~Database();

    // Query result structure
    struct QueryResult {
        bool success = false;
        std::vector<std::string> columns;
        std::vector<std::vector<std::string>> rows;
    };

    // Connection management
    bool open(const std::string& db_path, const std::string& password = "");
    void close();
    bool is_connected() const;
    std::string get_last_error() const;

    // Query execution
    bool execute(const std::string& sql);
    QueryResult query(const std::string& sql);

    // Transaction management
    bool begin_transaction();
    bool commit();
    bool rollback();

    // Table management
    bool create_table(const std::string& table_name,
                      const std::vector<std::pair<std::string, std::string>>& columns);
    bool table_exists(const std::string& table_name);

    // Data operations - using parameterized where clause
    bool insert(const std::string& table_name,
                const std::map<std::string, std::string>& data);
    
    bool update(const std::string& table_name,
                const std::map<std::string, std::string>& data,
                const std::string& where_column,
                const std::string& where_value);
    
    bool remove(const std::string& table_name,
                const std::string& where_column,
                const std::string& where_value);

    // Activity log — used by the GUI. In-memory ring buffer backed by an
    // append-only text file (one entry per line) so the log survives
    // process restarts. The file path can be overridden for tests; the
    // default lives under $HOME/.dynam/activity.log on POSIX,
    // %APPDATA%\Dynam\activity.log on Windows. Calling
    // set_activity_log_path("") disables file persistence (memory only).
    void log_activity(const std::string& category, const std::string& message);
    std::vector<std::string> get_recent_activity(size_t limit) const;
    void set_activity_log_path(const std::string& path);

private:
#ifdef HAVE_SQLITE
    sqlite3* db_handle_;
#endif
    std::string db_path_;
    bool is_connected_;
    std::string last_error_;
    mutable std::vector<std::string> activity_log_;
    std::string activity_log_path_;  // empty = memory-only; non-empty = file-backed
};

} // namespace ncp

#endif // NCP_DB_HPP
