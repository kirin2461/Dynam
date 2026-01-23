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

namespace NCP {

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

    // Data operations
    bool insert(const std::string& table_name,
               const std::map<std::string, std::string>& data);
    bool update(const std::string& table_name,
               const std::map<std::string, std::string>& data,
               const std::string& where_clause);
    bool remove(const std::string& table_name, const std::string& where_clause);

private:
#ifdef HAVE_SQLITE
    sqlite3* db_handle_;
#endif
    std::string db_path_;
    bool is_connected_;
    std::string last_error_;
};

} // namespace NCP

#endif // NCP_DB_HPP
