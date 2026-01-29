/**
 * @file db.cpp
 * @brief Database operations for NCP
 * @note Requires sqlite3 when HAVE_SQLITE is defined
 */

#include "../include/ncp_db.hpp"
#include <stdexcept>
#include <sstream>
#include <iostream>
#include <fstream>
#include <map>

#ifdef HAVE_SQLITE
#include <sqlite3.h>
#endif

namespace NCP {

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

    // Enable SQLCipher encryption if password provided
        // Enable SQLCipher encryption if password provided
    if (!password.empty()) {
        // Use sqlite3_key_v2 API instead of SQL injection-prone PRAGMA
        rc = sqlite3_key_v2(db_handle_, "main", password.c_str(), password.length());
        if (rc != SQLITE_OK) {
            last_error_ = "Failed to set encryption key";
            sqlite3_close(db_handle_);
            db_handle_ = nullptr;
            return false;
        }
    }
return true;
#else
    // Fallback: use file-based storage
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
    // Fallback: log SQL to file
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

    int col_count = sqlite3_column_count(stmt);
    
    // Get column names
    for (int i = 0; i < col_count; ++i) {
        result.columns.push_back(sqlite3_column_name(stmt, i));
    }

    // Get rows
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::vector<std::string> row;
        for (int i = 0; i < col_count; ++i) {
            const char* text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            row.push_back(text ? text : "");
        }
        result.rows.push_back(row);
    }

    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return result;
    }

    result.success = true;
#else
    // Fallback: return empty result
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
    // Use prepared statement to prevent SQL injection
    const char* sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    sqlite3_stmt* stmt = nullptr;
    
    int rc = sqlite3_prepare_v2(db_handle_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    // Bind table_name parameter
    sqlite3_bind_text(stmt, 1, table_name.c_str(), -1, SQLITE_TRANSIENT);
    
    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = true;
    }
    
    sqlite3_finalize(stmt);
    return exists;
#else
    return true; // Assume exists in fallback mode
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
    
    // Build SQL with placeholders
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
    
    // Prepare statement
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.str().c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    // Bind all values
    for (size_t i = 0; i < values.size(); ++i) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), values[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    
    // Execute
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    return true;
#else
    // Fallback: log to file
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
    
    // Build SQL with placeholders for SET clause
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
    
        // Add parameterized WHERE clause
    if (!where_column.empty()) {
        sql << " WHERE " << where_column << " = ?";
        values.push_back(where_value);
    }


    // Prepare statement
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.str().c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    // Bind SET values
    for (size_t i = 0; i < values.size(); ++i) {
        sqlite3_bind_text(stmt, static_cast<int>(i + 1), values[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    
    // Execute
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    return true;
#else
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
    
    // Build DELETE SQL
        // Build parameterized DELETE SQL
    std::ostringstream sql;
    sql << "DELETE FROM " << table_name;
    
    // Add parameterized WHERE clause
    if (!where_column.empty()) {
        sql << " WHERE " << where_column << " = ?";
    }


    // Use prepared statement for execution
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_handle_, sql.str().c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    // Bind WHERE value if provided
    if (!where_column.empty()) {
        sqlite3_bind_text(stmt, 1, where_value.c_str(), -1, SQLITE_TRANSIENT);
    }

    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_handle_);
        return false;
    }
    
    return true;
#else
    if (!is_connected_) {
        last_error_ = "Database not connected";
        return false;
    }
    return true;
#endif
}

} // namespace NCP
