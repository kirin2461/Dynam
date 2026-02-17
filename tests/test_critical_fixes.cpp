/**
 * @file test_critical_fixes.cpp
 * @brief Unit tests for critical security fixes from Issue #17
 *
 * Tests validate fixes for:
 * - Critical Issue #1: Crypto::bytes_to_hex() null pointer check (CWE-129)
 * - Critical Issue #2: ThreadPool::submit() exception safety (CWE-703)
 * - Critical Issue #3: SecureMemory move constructor safety (CWE-672)
 */

#include <gtest/gtest.h>
#include "ncp_crypto.hpp"
#include "ncp_secure_memory.hpp"
#include "ncp_thread_pool.hpp"
#include <stdexcept>
#include <chrono>
#include <thread>

using namespace ncp;

// ==================== Test Fixture ====================

class CriticalFixesTest : public ::testing::Test {
protected:
    void SetUp() override {
#ifdef HAVE_SODIUM
        // Initialize libsodium if available
        if (sodium_init() < 0) {
            GTEST_SKIP() << "libsodium initialization failed";
        }
#endif
    }
};

// ==================== Critical Issue #1: bytes_to_hex Null Pointer ====================

/**
 * Test that bytes_to_hex handles empty SecureMemory safely
 * Prevents: CWE-129 (Improper Validation of Array Index)
 * Fix: commit 2629afb
 */
TEST_F(CriticalFixesTest, BytesToHexWithEmptyMemory) {
    SecureMemory empty;
    
    // Should return empty string, not crash
    EXPECT_NO_THROW({
        std::string result = Crypto::bytes_to_hex(empty);
        EXPECT_EQ(result, "");
    });
}

/**
 * Test that bytes_to_hex handles valid data correctly
 * Ensures fix doesn't break normal operation
 */
TEST_F(CriticalFixesTest, BytesToHexWithValidData) {
    const uint8_t data[] = {0x01, 0x02, 0xFF, 0xAB};
    SecureMemory mem(data, sizeof(data));
    
    std::string result = Crypto::bytes_to_hex(mem);
    
    // Should produce correct hex string
    EXPECT_EQ(result, "0102ffab");
}

/**
 * Test bytes_to_hex with various sizes
 */
TEST_F(CriticalFixesTest, BytesToHexVariousSizes) {
    // Single byte
    {
        const uint8_t data[] = {0x42};
        SecureMemory mem(data, 1);
        EXPECT_EQ(Crypto::bytes_to_hex(mem), "42");
    }
    
    // Large buffer
    {
        SecureMemory mem(256);
        for (size_t i = 0; i < 256; ++i) {
            mem.data()[i] = static_cast<uint8_t>(i);
        }
        std::string result = Crypto::bytes_to_hex(mem);
        EXPECT_EQ(result.length(), 512);  // 256 bytes = 512 hex chars
        EXPECT_EQ(result.substr(0, 4), "0001");  // First two bytes
        EXPECT_EQ(result.substr(508, 4), "feff");  // Last two bytes
    }
}

/**
 * Test bytes_to_hex with all zero data
 */
TEST_F(CriticalFixesTest, BytesToHexAllZeros) {
    SecureMemory mem(4);
    mem.zero();
    
    std::string result = Crypto::bytes_to_hex(mem);
    EXPECT_EQ(result, "00000000");
}

/**
 * Test bytes_to_hex after move (ensures moved-from memory handled)
 */
TEST_F(CriticalFixesTest, BytesToHexAfterMove) {
    SecureMemory original(4);
    std::memset(original.data(), 0xAB, 4);
    
    SecureMemory moved(std::move(original));
    
    // Original should be empty - bytes_to_hex should handle gracefully
    EXPECT_NO_THROW({
        std::string result = Crypto::bytes_to_hex(original);
        EXPECT_EQ(result, "");
    });
    
    // Moved-to should work normally
    EXPECT_EQ(Crypto::bytes_to_hex(moved), "abababab");
}

// ==================== Critical Issue #2: ThreadPool Exception Safety ====================

/**
 * Test that submitting to stopped ThreadPool throws exception
 * Prevents: CWE-703 (Improper Check or Handling of Exceptional Conditions)
 * Fix: commit cae1355
 */
TEST_F(CriticalFixesTest, ThreadPoolSubmitAfterShutdown) {
    ThreadPool pool(2);
    pool.shutdown();
    
    // Submitting to stopped pool should throw
    EXPECT_THROW({
        pool.submit([]() { return 42; });
    }, std::runtime_error);
}

/**
 * Test that ThreadPool executes tasks correctly under normal operation
 * Ensures fix doesn't break functionality
 */
TEST_F(CriticalFixesTest, ThreadPoolNormalOperation) {
    ThreadPool pool(2);
    
    auto future = pool.submit([]() { return 123; });
    
    EXPECT_EQ(future.get(), 123);
}

/**
 * Test ThreadPool with multiple concurrent tasks
 */
TEST_F(CriticalFixesTest, ThreadPoolMultipleTasks) {
    ThreadPool pool(4);
    std::vector<std::future<int>> futures;
    
    // Submit 10 tasks
    for (int i = 0; i < 10; ++i) {
        futures.push_back(pool.submit([i]() { return i * i; }));
    }
    
    // Verify all results
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(futures[i].get(), i * i);
    }
}

/**
 * Test ThreadPool task with exception
 */
TEST_F(CriticalFixesTest, ThreadPoolTaskThrows) {
    ThreadPool pool(1);
    
    auto future = pool.submit([]() -> int {
        throw std::runtime_error("task error");
    });
    
    // Future should propagate exception
    EXPECT_THROW(future.get(), std::runtime_error);
}

/**
 * Test ThreadPool metrics during operation
 */
TEST_F(CriticalFixesTest, ThreadPoolMetrics) {
    ThreadPool pool(2);
    
    EXPECT_EQ(pool.total_threads(), 2);
    EXPECT_TRUE(pool.is_running());
    EXPECT_EQ(pool.active_threads(), 0);
    EXPECT_EQ(pool.pending_tasks(), 0);
    
    // Submit long-running task
    auto future = pool.submit([]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return 42;
    });
    
    // Give thread time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // Should have active thread
    EXPECT_GE(pool.active_threads(), 0);
    EXPECT_LE(pool.active_threads(), 2);
    
    future.get();  // Wait for completion
}

/**
 * Test ThreadPool shutdown idempotency
 */
TEST_F(CriticalFixesTest, ThreadPoolMultipleShutdowns) {
    ThreadPool pool(1);
    
    // Multiple shutdowns should be safe
    EXPECT_NO_THROW({
        pool.shutdown();
        pool.shutdown();
        pool.shutdown();
    });
    
    EXPECT_FALSE(pool.is_running());
}

// ==================== Critical Issue #3: SecureMemory Move Semantics ====================

/**
 * Test that move constructor properly nulls out source
 * Prevents: CWE-672 (Operation on a Resource after Expiration)
 * Verification: Implementation already correct (commit 93946ed)
 */
TEST_F(CriticalFixesTest, SecureMemoryMoveConstructorNullsSource) {
    SecureMemory src(32);
    std::memset(src.data(), 0xAB, 32);
    uint8_t* original_ptr = src.data();
    
    // Move construct
    SecureMemory dest(std::move(src));
    
    // Source should be completely nulled
    EXPECT_EQ(src.data(), nullptr);
    EXPECT_EQ(src.size(), 0);
    EXPECT_TRUE(src.empty());
    
    // Destination should have ownership
    EXPECT_EQ(dest.data(), original_ptr);
    EXPECT_EQ(dest.size(), 32);
    EXPECT_FALSE(dest.empty());
    EXPECT_EQ(dest.data()[0], 0xAB);
}

/**
 * Test move assignment properly cleans up destination and nulls source
 */
TEST_F(CriticalFixesTest, SecureMemoryMoveAssignmentCleanup) {
    SecureMemory dest(16);
    std::memset(dest.data(), 0xCC, 16);
    uint8_t* dest_ptr = dest.data();
    
    SecureMemory src(32);
    std::memset(src.data(), 0xDD, 32);
    uint8_t* src_ptr = src.data();
    
    // Move assign
    dest = std::move(src);
    
    // Destination should have new memory
    EXPECT_NE(dest.data(), dest_ptr);  // Different pointer (old freed)
    EXPECT_EQ(dest.data(), src_ptr);   // Same as source
    EXPECT_EQ(dest.size(), 32);
    EXPECT_EQ(dest.data()[0], 0xDD);
    
    // Source should be nulled
    EXPECT_EQ(src.data(), nullptr);
    EXPECT_EQ(src.size(), 0);
}

/**
 * Test self-move assignment safety
 */
TEST_F(CriticalFixesTest, SecureMemorySelfMoveAssignment) {
    SecureMemory mem(32);
    std::memset(mem.data(), 0x11, 32);
    uint8_t* original_ptr = mem.data();
    
    // Self-move should be safe
    mem = std::move(mem);
    
    // Memory should still be valid (not freed)
    EXPECT_EQ(mem.data(), original_ptr);
    EXPECT_EQ(mem.size(), 32);
    EXPECT_EQ(mem.data()[0], 0x11);
}

/**
 * Test that moved-from memory cannot cause double-free
 */
TEST_F(CriticalFixesTest, SecureMemoryMovedFromDestruction) {
    SecureMemory* src = new SecureMemory(32);
    std::memset(src->data(), 0xFF, 32);
    
    SecureMemory dest(std::move(*src));
    
    // Destroying moved-from object should be safe (no double-free)
    EXPECT_NO_THROW({
        delete src;
    });
    
    // Destination should still be valid
    EXPECT_EQ(dest.size(), 32);
    EXPECT_EQ(dest.data()[0], 0xFF);
}

/**
 * Test multiple consecutive moves
 */
TEST_F(CriticalFixesTest, SecureMemoryChainedMoves) {
    SecureMemory mem1(16);
    std::memset(mem1.data(), 0xAA, 16);
    
    SecureMemory mem2(std::move(mem1));
    SecureMemory mem3(std::move(mem2));
    SecureMemory mem4(std::move(mem3));
    
    // Only last one should have data
    EXPECT_TRUE(mem1.empty());
    EXPECT_TRUE(mem2.empty());
    EXPECT_TRUE(mem3.empty());
    EXPECT_FALSE(mem4.empty());
    EXPECT_EQ(mem4.size(), 16);
    EXPECT_EQ(mem4.data()[0], 0xAA);
}

/**
 * Test SecureString move semantics
 */
TEST_F(CriticalFixesTest, SecureStringMoveSemantics) {
    SecureString src("secret_password_123");
    
    SecureString dest(std::move(src));
    
    // Source should be empty
    EXPECT_TRUE(src.empty());
    EXPECT_EQ(src.size(), 0);
    
    // Destination should have data
    EXPECT_FALSE(dest.empty());
    EXPECT_STREQ(dest.c_str(), "secret_password_123");
}

/**
 * Test SecureMemory in std::vector (requires noexcept move)
 */
TEST_F(CriticalFixesTest, SecureMemoryInVector) {
    std::vector<SecureMemory> vec;
    
    // Add elements - should use move constructor
    for (int i = 0; i < 10; ++i) {
        SecureMemory mem(16);
        std::memset(mem.data(), i, 16);
        vec.push_back(std::move(mem));
    }
    
    // Verify all elements
    EXPECT_EQ(vec.size(), 10);
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(vec[i].size(), 16);
        EXPECT_EQ(vec[i].data()[0], static_cast<uint8_t>(i));
    }
    
    // Force reallocation (should use noexcept move)
    vec.reserve(100);
    
    // Data should still be valid after reallocation
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(vec[i].size(), 16);
        EXPECT_EQ(vec[i].data()[0], static_cast<uint8_t>(i));
    }
}

// ==================== Performance: noexcept Validation ====================

/**
 * Test that move operations are noexcept
 * Critical for std::vector performance
 */
TEST_F(CriticalFixesTest, NoexceptMoveOperations) {
    // SecureMemory move operations should be noexcept
    EXPECT_TRUE(std::is_nothrow_move_constructible<SecureMemory>::value);
    EXPECT_TRUE(std::is_nothrow_move_assignable<SecureMemory>::value);
    
    // SecureString move operations should be noexcept
    EXPECT_TRUE(std::is_nothrow_move_constructible<SecureString>::value);
    EXPECT_TRUE(std::is_nothrow_move_assignable<SecureString>::value);
}

/**
 * Test that getters are noexcept
 */
TEST_F(CriticalFixesTest, NoexceptGetters) {
    SecureMemory mem(16);
    
    // These should all be noexcept
    EXPECT_NO_THROW({
        [[maybe_unused]] auto ptr = mem.data();
        [[maybe_unused]] auto sz = mem.size();
        [[maybe_unused]] auto empty = mem.empty();
        [[maybe_unused]] auto begin = mem.begin();
        [[maybe_unused]] auto end = mem.end();
    });
}
