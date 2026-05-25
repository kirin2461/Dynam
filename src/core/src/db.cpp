/**
 * @file db.cpp
 * @brief Database operations for NCP
 * @note Requires sqlite3 when HAVE_SQLITE is defined
 *
 * PATTERN NOTE (Full-table encryption):
 * If using application-level encryption on top of SQLite:
 *   1. Always wrap decrypt → modify → re-encrypt in a transaction
 *   2. Use begin_transaction() / commit() / rollback()
 *   3. If re-encryption fails after decryption, rollback() will
 *      restore the original encrypted data.
 *   4. Never call close() between decrypt and re-encrypt.
 */

#include "../include/ncp_db.hpp"
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <algorithm>
#include <filesystem>
#include <cstdlib>
#include <system_error>

#ifdef HAVE_SQLITE
#include <sqlite3.h>

// RAII guard for sqlite3_stmt — ensures finalize() is called on all paths
namespace {
struct SqliteStmtGuard {
    sqlite3_stmt* stmt;
    explicit SqliteStmtGuard(sqlite3_stmt* s) : stmt(s) {}
    ~SqliteStmtGuard() { if (stmt) sqlite3_finalize(stmt); }
    SqliteStmtGuard(const SqliteStmtGuard&) = delete;
    SqliteStmtGuard& operator=(const SqliteStmtGuard&) = delete;
};
} // anonymous namespace
#endif

namespace ncp {

// ==================== Constructor/Destructor ====================

#ifdef HAVE_SQLITE
Database::Database() : db_handle_(nullptr), is_connected_(false) {}
#else
Database::Database() : is_connected_(false) {}
#endif

Database::~Database() {
    close();
}

// ==================== Connection Management ====================

bool Database::open(const std::string& db_path, const std::string& password) {
    if (is_connected_) {
        close();
    }

#ifdef HAVE_SQLITE
    int rc = sqlite3_open(db_path.c_str(), &db_handle_);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        sqlite3_close(db_handle_);
        db_handle_ = nullptr;
        return false;
    }

    if (!password.empty()) {
        rc = sqlite3_key_v2(db_handle_, "main", password.c_str(), password.length());
        if (rc != SQLITE_OK) {
            last_error_ = "Failed to set encryption key";
            sqlite3_close(db_handle_);
            db_handle_ = nullptr;
            return false;
        }
    }

    is_connected_ = true;
    db_path_ = db_path;
    return true;
#else
    (void)password;
    db_path_ = db_path;
    is_connected_ = true;
    return true;
#endif
}

void Database::close() {
#ifdef HAVE_SQLITE
    if (db_handle_) {
        sqlite3_close(db_handle_);
        db_handle_ = nullptr;
    }
#endif
    is_connected_ = false;
}

bool Database::is_connected() const {
    return is_connected_;
}

std::string Database::get_last_error() const {
    return last_error_;
}

// ==================== Query Execution ====================

bool Database::execute(const std::string& sql) {
#ifdef HAVE_SQLITE
    if (!is_connected_ || !db_handle_) {
        last_error_ = "Database not connected";
        return false;
    }

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_handle_, sql.c_str(), nullptr, nullptr, &err_msg);

    if (rc != SQLITE_OK) {
        last_error_ = err_msg ? err_msg : "Unknown error";
        sqlite3_free(err_msg);
        return false;
    }
    return true;
#else
    if (!is_connected_) {
        last_error_ = "Database not connected";
        return false;
    }
    std::ofstream log(db_path_ + ".log", std::ios::app);
    log << sql << std::endl;
    return true;
#endif
}

Database::QueryResult Database::query(const std::string& sql) {
    QueryResult result;
    result.success = false;

#ifdef HAVE_SQLITE
    if (!is_connected_ || !db_handle_) {
        last_error_ = "Database not connected";
        return result;
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return result;
    }

    // FIX: RAII guard ensures finalize() even on early return / exception
    SqliteStmtGuard guard(stmt);

    int col_count = sqlite3_column_count(stmt);

    for (int i = 0; i < col_count; ++i) {
        result.columns.push_back(sqlite3_column_name(stmt, i));
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::vector<std::string> row;
        for (int i = 0; i < col_count; ++i) {
            const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            row.push_back(text ? text : "");
        }
        result.rows.push_back(row);
    }

    // Guard will call sqlite3_finalize(stmt) in destructor

    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return result;
    }

    result.success = true;
#else
    (void)sql;
    if (!is_connected_) {
        last_error_ = "Database not connected";
        return result;
    }
    result.success = true;
#endif
    return result;
}

// ==================== Transaction Management ====================

bool Database::begin_transaction() {
    return execute("BEGIN TRANSACTION");
}

bool Database::commit() {
    return execute("COMMIT");
}

bool Database::rollback() {
    return execute("ROLLBACK");
}

// ==================== Table Management ====================

bool Database::create_table(const std::string& table_name,
                           const std::vector<std::pair<std::string, std::string>>& columns) {
    std::ostringstream sql;
    sql << "CREATE TABLE IF NOT EXISTS " << table_name << " (";

    for (size_t i = 0; i < columns.size(); ++i) {
        sql << columns[i].first << " " << columns[i].second;
        if (i < columns.size() - 1) sql << ", ";
    }
    sql << ")";

    return execute(sql.str());
}

bool Database::table_exists(const std::string& table_name) {
#ifdef HAVE_SQLITE
    const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    sqlite3_stmt* stmt = nullptr;

    int rc = sqlite3_prepare_v2(db_handle_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    SqliteStmtGuard guard(stmt);

    sqlite3_bind_text(stmt, 1, table_name.c_str(), -1, SQLITE_TRANSIENT);

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = true;
    }

    return exists;
#else
    (void)table_name;
    return true;
#endif
}

// ==================== Data Operations ====================

bool Database::insert(const std::string& table_name,
                       const std::map<std::string, std::string>& data) {
#ifdef HAVE_SQLITE
    if (!is_connected_ || !db_handle_) {
        last_error_ = "Database not connected";
        return false;
    }

    if (data.empty()) {
        last_error_ = "No data to insert";
        return false;
    }

    std::ostringstream sql;
    sql << "INSERT INTO " << table_name << " (";

    std::ostringstream placeholders;
    std::vector<std::string> values;

    bool first = true;
    for (const auto& pair : data) {
        if (!first) {
            sql << ", ";
            placeholders << ", ";
        }
        sql << pair.first;
        placeholders << "?";
        values.push_back(pair.second);
        first = false;
    }

    sql << ") VALUES (" << placeholders.str() << ")";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.str().c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    SqliteStmtGuard guard(stmt);

    for (size_t i = 0; i < values.size(); ++i) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), values[i].c_str(), -1, SQLITE_TRANSIENT);
    }

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    return true;
#else
    (void)table_name;
    (void)data;
    if (!is_connected_) {
        last_error_ = "Database not connected";
        return false;
    }
    return true;
#endif
}

bool Database::update(const std::string& table_name,
                       const std::map<std::string, std::string>& data,
                       const std::string& where_column,
                       const std::string& where_value) {
#ifdef HAVE_SQLITE
    if (!is_connected_ || !db_handle_) {
        last_error_ = "Database not connected";
        return false;
    }

    if (data.empty()) {
        last_error_ = "No data to update";
        return false;
    }

    std::ostringstream sql;
    sql << "UPDATE " << table_name << " SET ";

    std::vector<std::string> values;

    bool first = true;
    for (const auto& pair : data) {
        if (!first) sql << ", ";
        sql << pair.first << " = ?";
        values.push_back(pair.second);
        first = false;
    }

    if (!where_column.empty()) {
        sql << " WHERE " << where_column << " = ?";
        values.push_back(where_value);
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.str().c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    SqliteStmtGuard guard(stmt);

    for (size_t i = 0; i < values.size(); ++i) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), values[i].c_str(), -1, SQLITE_TRANSIENT);
    }

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    return true;
#else
    (void)table_name;
    (void)data;
    (void)where_column;
    (void)where_value;
    if (!is_connected_) {
        last_error_ = "Database not connected";
        return false;
    }
    return true;
#endif
}


bool Database::remove(const std::string& table_name,
                       const std::string& where_column,
                       const std::string& where_value) {
#ifdef HAVE_SQLITE
    if (!is_connected_ || !db_handle_) {
        last_error_ = "Database not connected";
        return false;
    }

    std::ostringstream sql;
    sql << "DELETE FROM " << table_name;

    if (!where_column.empty()) {
        sql << " WHERE " << where_column << " = ?";
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.str().c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    SqliteStmtGuard guard(stmt);

    if (!where_column.empty()) {
        sqlite3_bind_text(stmt, 1, where_value.c_str(), -1, SQLITE_TRANSIENT);
    }

    rc = sqlite3_step(stmt);

    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }

    return true;
#else
    (void)table_name;
    (void)where_column;
    (void)where_value;
    if (!is_connected_) {
        last_error_ = "Database not connected";
        return false;
    }
    return true;
#endif
}

// ── Activity log ──────────────────────────────────────────────────────────
// In-memory ring buffer backed by an append-only text file. The file is
// rewritten in full when we trim past kMaxEntries so it stays bounded; the
// alternative (rotating files) is overkill for an activity log that's
// already capped at 500 lines.
namespace {
constexpr size_t kMaxEntries = 500;

// $HOME/.dynam/activity.log on POSIX, %APPDATA%\Dynam\activity.log on Win.
std::string default_activity_log_path() {
#ifdef _WIN32
    const char* base = std::getenv("APPDATA");
    if (!base) return "";
    std::string dir  = std::string(base) + "\\Dynam";
    std::string path = dir + "\\activity.log";
#else
    const char* home = std::getenv("HOME");
    if (!home) return "";
    std::string dir  = std::string(home) + "/.dynam";
    std::string path = dir + "/activity.log";
#endif
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return path;
}
}  // namespace

void Database::set_activity_log_path(const std::string& path) {
    activity_log_path_ = path;
    activity_log_.clear();
    if (path.empty()) return;
    // Load existing entries (last kMaxEntries lines) so the GUI shows
    // history immediately on startup.
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) activity_log_.push_back(line);
    }
    if (activity_log_.size() > kMaxEntries) {
        activity_log_.erase(activity_log_.begin(),
                            activity_log_.begin() + (activity_log_.size() - kMaxEntries));
    }
}

void Database::log_activity(const std::string& category, const std::string& message) {
    // Lazily pick the default file path the first time anyone logs, so
    // callers that explicitly want memory-only can opt out by calling
    // set_activity_log_path("") before the first log.
    if (activity_log_path_.empty() && activity_log_.empty()) {
        set_activity_log_path(default_activity_log_path());
    }

    const std::string entry = "[" + category + "] " + message;
    activity_log_.push_back(entry);

    if (activity_log_.size() > kMaxEntries) {
        activity_log_.erase(activity_log_.begin(),
                            activity_log_.begin() + (activity_log_.size() - kMaxEntries));
        // Rewrite the file in full to stay bounded.
        if (!activity_log_path_.empty()) {
            std::ofstream out(activity_log_path_, std::ios::trunc);
            for (const auto& line : activity_log_) out << line << '\n';
        }
    } else if (!activity_log_path_.empty()) {
        // Fast path: just append.
        std::ofstream out(activity_log_path_, std::ios::app);
        if (out) out << entry << '\n';
    }
}

std::vector<std::string> Database::get_recent_activity(size_t limit) const {
    if (activity_log_.empty() || limit == 0) return {};
    const size_t n = std::min(limit, activity_log_.size());
    return std::vector<std::string>(activity_log_.end() - n, activity_log_.end());
}

} // namespace ncp
