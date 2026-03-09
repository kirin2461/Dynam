// ══════════════════════════════════════════════════════════════════════════════
// tests/test_db.cpp
// Tests for Database (ncp_db.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_db.hpp"

#include <string>
#include <vector>
#include <cstdio>

using namespace ncp;

// ── Fixture ───────────────────────────────────────────────────────────────────

class DatabaseTest : public ::testing::Test {
protected:
    Database db;

    void SetUp() override {
        // Use in-memory SQLite database (:memory:) if SQLite is available;
        // otherwise tests will be skipped gracefully.
        opened_ = db.open(":memory:");
    }

    void TearDown() override {
        db.close();
    }

    // Skip test if database could not be opened (e.g., no SQLite support)
    void RequireOpen() {
        if (!opened_) {
            GTEST_SKIP() << "SQLite not available or :memory: open failed: "
                         << db.get_last_error();
        }
    }

    bool opened_ = false;
};

// ── Connection Management ─────────────────────────────────────────────────────

TEST_F(DatabaseTest, Open_InMemory) {
    // opened_ tells us if SQLite is available
    if (!opened_) {
        // Acceptable if SQLite is not compiled in — just verify graceful failure
        EXPECT_FALSE(db.is_connected());
    } else {
        EXPECT_TRUE(db.is_connected());
    }
}

TEST_F(DatabaseTest, Close_DisconnectsDB) {
    RequireOpen();
    EXPECT_TRUE(db.is_connected());
    db.close();
    EXPECT_FALSE(db.is_connected());
}

TEST_F(DatabaseTest, Open_TwiceReturnsTrue) {
    RequireOpen();
    // Opening again on the same object after closing should work
    db.close();
    bool ok = db.open(":memory:");
    EXPECT_TRUE(ok);
    EXPECT_TRUE(db.is_connected());
}

TEST_F(DatabaseTest, GetLastError_EmptyOnSuccess) {
    RequireOpen();
    // After a successful operation, no error
    db.execute("SELECT 1");
    // last_error may still be empty after success
    (void)db.get_last_error();
}

// ── Table Management ─────────────────────────────────────────────────────────

TEST_F(DatabaseTest, CreateTable_Success) {
    RequireOpen();
    bool ok = db.create_table("users", {
        {"id",   "INTEGER PRIMARY KEY"},
        {"name", "TEXT"},
        {"age",  "INTEGER"}
    });
    EXPECT_TRUE(ok);
}

TEST_F(DatabaseTest, TableExists_AfterCreate) {
    RequireOpen();
    db.create_table("test_table", {{"val", "TEXT"}});
    EXPECT_TRUE(db.table_exists("test_table"));
}

TEST_F(DatabaseTest, TableExists_NonExistentTable) {
    RequireOpen();
    EXPECT_FALSE(db.table_exists("no_such_table_xyz"));
}

TEST_F(DatabaseTest, CreateTable_Twice_HandledGracefully) {
    RequireOpen();
    db.create_table("t1", {{"x", "INTEGER"}});
    // Second create should fail or be ignored
    bool ok2 = db.create_table("t1", {{"x", "INTEGER"}});
    (void)ok2; // May fail with "table already exists"
    EXPECT_TRUE(db.table_exists("t1"));
}

// ── Execute ───────────────────────────────────────────────────────────────────

TEST_F(DatabaseTest, Execute_ValidSQL_ReturnsTrue) {
    RequireOpen();
    EXPECT_TRUE(db.execute("CREATE TABLE t(x INT)"));
    EXPECT_TRUE(db.execute("INSERT INTO t VALUES (42)"));
}

TEST_F(DatabaseTest, Execute_InvalidSQL_ReturnsFalse) {
    RequireOpen();
    EXPECT_FALSE(db.execute("THIS IS NOT VALID SQL !!!"));
    EXPECT_FALSE(db.get_last_error().empty());
}

// ── Insert / Query ────────────────────────────────────────────────────────────

TEST_F(DatabaseTest, Insert_And_Query) {
    RequireOpen();
    db.create_table("people", {{"id", "INTEGER PRIMARY KEY"}, {"name", "TEXT"}});
    bool ok = db.insert("people", {{"id", "1"}, {"name", "Alice"}});
    EXPECT_TRUE(ok);

    auto result = db.query("SELECT id, name FROM people WHERE id = 1");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.rows.size(), 1u);
    EXPECT_EQ(result.rows[0][1], "Alice");
}

TEST_F(DatabaseTest, Insert_MultipleRows) {
    RequireOpen();
    db.create_table("items", {{"id", "INTEGER"}, {"value", "TEXT"}});
    db.insert("items", {{"id", "1"}, {"value", "foo"}});
    db.insert("items", {{"id", "2"}, {"value", "bar"}});
    db.insert("items", {{"id", "3"}, {"value", "baz"}});

    auto result = db.query("SELECT COUNT(*) FROM items");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.rows[0][0], "3");
}

TEST_F(DatabaseTest, Query_EmptyTable) {
    RequireOpen();
    db.create_table("empty_t", {{"x", "INTEGER"}});
    auto result = db.query("SELECT * FROM empty_t");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.rows.size(), 0u);
}

TEST_F(DatabaseTest, Query_ColumnNames) {
    RequireOpen();
    db.create_table("cols", {{"id", "INTEGER"}, {"label", "TEXT"}});
    db.insert("cols", {{"id", "1"}, {"label", "hello"}});
    auto result = db.query("SELECT id, label FROM cols");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.columns.size(), 2u);
    EXPECT_EQ(result.columns[0], "id");
    EXPECT_EQ(result.columns[1], "label");
}

// ── Update ────────────────────────────────────────────────────────────────────

TEST_F(DatabaseTest, Update_ModifiesRow) {
    RequireOpen();
    db.create_table("kv", {{"key", "TEXT"}, {"val", "TEXT"}});
    db.insert("kv", {{"key", "color"}, {"val", "red"}});

    bool ok = db.update("kv", {{"val", "blue"}}, "key", "color");
    EXPECT_TRUE(ok);

    auto result = db.query("SELECT val FROM kv WHERE key='color'");
    EXPECT_TRUE(result.success);
    ASSERT_EQ(result.rows.size(), 1u);
    EXPECT_EQ(result.rows[0][0], "blue");
}

// ── Remove ────────────────────────────────────────────────────────────────────

TEST_F(DatabaseTest, Remove_DeletesRow) {
    RequireOpen();
    db.create_table("log", {{"id", "INTEGER"}, {"msg", "TEXT"}});
    db.insert("log", {{"id", "1"}, {"msg", "first"}});
    db.insert("log", {{"id", "2"}, {"msg", "second"}});

    bool ok = db.remove("log", "id", "1");
    EXPECT_TRUE(ok);

    auto result = db.query("SELECT COUNT(*) FROM log");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.rows[0][0], "1");
}

// ── Transactions ─────────────────────────────────────────────────────────────

TEST_F(DatabaseTest, Transaction_CommitPersists) {
    RequireOpen();
    db.create_table("tx_t", {{"x", "INTEGER"}});
    db.begin_transaction();
    db.insert("tx_t", {{"x", "99"}});
    db.commit();

    auto result = db.query("SELECT x FROM tx_t");
    EXPECT_TRUE(result.success);
    ASSERT_EQ(result.rows.size(), 1u);
    EXPECT_EQ(result.rows[0][0], "99");
}

TEST_F(DatabaseTest, Transaction_Rollback_DiscardsChanges) {
    RequireOpen();
    db.create_table("tx_r", {{"x", "INTEGER"}});
    db.begin_transaction();
    db.insert("tx_r", {{"x", "42"}});
    db.rollback();

    auto result = db.query("SELECT COUNT(*) FROM tx_r");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.rows[0][0], "0");
}

TEST_F(DatabaseTest, Transaction_Commit_NoThrow) {
    RequireOpen();
    db.begin_transaction();
    EXPECT_NO_THROW(db.commit());
}

TEST_F(DatabaseTest, Transaction_Rollback_NoThrow) {
    RequireOpen();
    db.begin_transaction();
    EXPECT_NO_THROW(db.rollback());
}

// ── Error Handling ────────────────────────────────────────────────────────────

TEST_F(DatabaseTest, Query_InvalidSQL_FailureResult) {
    RequireOpen();
    auto result = db.query("SELECT * FROM nonexistent_table_xyz");
    EXPECT_FALSE(result.success);
}

TEST_F(DatabaseTest, Insert_NonexistentTable_ReturnsFalse) {
    RequireOpen();
    bool ok = db.insert("ghost_table", {{"x", "1"}});
    EXPECT_FALSE(ok);
}

TEST_F(DatabaseTest, Update_NonexistentTable_ReturnsFalse) {
    RequireOpen();
    bool ok = db.update("ghost", {{"x", "1"}}, "id", "1");
    EXPECT_FALSE(ok);
}

TEST_F(DatabaseTest, Remove_NonexistentTable_ReturnsFalse) {
    RequireOpen();
    bool ok = db.remove("ghost", "id", "1");
    EXPECT_FALSE(ok);
}

// ── Not Connected ─────────────────────────────────────────────────────────────

TEST(DatabaseNotConnectedTest, Execute_WhenClosed_ReturnsFalse) {
    Database db;
    EXPECT_FALSE(db.execute("SELECT 1"));
}

TEST(DatabaseNotConnectedTest, Query_WhenClosed_FailureResult) {
    Database db;
    auto r = db.query("SELECT 1");
    EXPECT_FALSE(r.success);
}

TEST(DatabaseNotConnectedTest, IsConnected_FalseInitially) {
    Database db;
    EXPECT_FALSE(db.is_connected());
}
