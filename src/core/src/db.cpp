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
    if (!password.empty()) {
        std::string key_pragma = "PRAGMA key = '" + password + "';";
        char* err_msg = nullptr;
        rc = sqlite3_exec(db_handle_, key_pragma.c_str(), nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            last_error_ = err_msg ? err_msg : "Failed to set encryption key";
            sqlite3_free(err_msg);
            sqlite3_close(db_handle_);
            db_handle_ = nullptr;
            return false;
        }
    }

    is_connected_ = true;
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
    std::string sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='" + table_name + "'";
    auto result = query(sql);
    return result.success && !result.rows.empty();
#else
    return true; // Assume exists in fallback mode
#endif
}

// ==================== Data Operations ====================

bool Database::insert(const std::string& table_name,
                     const std::map<std::string, std::string>& data) {
    std::ostringstream sql;
    sql << "INSERT INTO " << table_name << " (";
    
    std::ostringstream values;
    values << "VALUES (";
    
    bool first = true;
    for (const auto& pair : data) {
        if (!first) {
            sql << ", ";
            values << ", ";
        }
        sql << pair.first;
        values << "'" << pair.second << "'";
        first = false;
    }
    
    sql << ") " << values.str() << ")";
    return execute(sql.str());
}

bool Database::update(const std::string& table_name,
                     const std::map<std::string, std::string>& data,
                     const std::string& where_clause) {
    std::ostringstream sql;
    sql << "UPDATE " << table_name << " SET ";
    
    bool first = true;
    for (const auto& pair : data) {
        if (!first) sql << ", ";
        sql << pair.first << " = '" << pair.second << "'";
        first = false;
    }
    
    if (!where_clause.empty()) {
        sql << " WHERE " << where_clause;
    }
    
    return execute(sql.str());
}

bool Database::remove(const std::string& table_name, const std::string& where_clause) {
    std::string sql = "DELETE FROM " + table_name;
    if (!where_clause.empty()) {
        sql += " WHERE " + where_clause;
    }
    return execute(sql);
}

} // namespace NCP
