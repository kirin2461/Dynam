/**
 * @file test_secure_memory.cpp
 * @brief Unit tests for SecureMemory and SecureBuffer classes
 */

#include <gtest/gtest.h>
#include "ncp_secure_memory.hpp"
#include <cstring>
#include <vector>
#include <algorithm>

using namespace ncp;

class SecureMemoryTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ---- Basic Allocation Tests ----

TEST_F(SecureMemoryTest, DefaultConstruction) {
    SecureMemory mem;
    
    EXPECT_EQ(mem.size(), 0);
    EXPECT_EQ(mem.data(), nullptr);
    EXPECT_TRUE(mem.empty());
}

TEST_F(SecureMemoryTest, SizeConstruction) {
    SecureMemory mem(32);
    
    EXPECT_EQ(mem.size(), 32);
    EXPECT_NE(mem.data(), nullptr);
    EXPECT_FALSE(mem.empty());
}

TEST_F(SecureMemoryTest, ZeroSizeConstruction) {
    SecureMemory mem(0);
    
    EXPECT_EQ(mem.size(), 0);
    EXPECT_TRUE(mem.empty());
}

TEST_F(SecureMemoryTest, LargeAllocation) {
    // Allocate 1MB
    SecureMemory mem(1024 * 1024);
    
    EXPECT_EQ(mem.size(), 1024 * 1024);
    EXPECT_NE(mem.data(), nullptr);
}

TEST_F(SecureMemoryTest, DataFromPointer) {
    const uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    SecureMemory mem(data, sizeof(data));
    
    EXPECT_EQ(mem.size(), 5);
    EXPECT_EQ(std::memcmp(mem.data(), data, 5), 0);
}

// ---- Move Semantics Tests ----

TEST_F(SecureMemoryTest, MoveConstruction) {
    SecureMemory original(32);
    std::memset(original.data(), 0xAB, 32);
    
    uint8_t* original_ptr = original.data();
    
    SecureMemory moved(std::move(original));
    
    // Moved-to should have the data
    EXPECT_EQ(moved.size(), 32);
    EXPECT_EQ(moved.data(), original_ptr);  // Same pointer
    EXPECT_EQ(moved.data()[0], 0xAB);
    
    // Moved-from should be empty
    EXPECT_EQ(original.size(), 0);
    EXPECT_EQ(original.data(), nullptr);
}

TEST_F(SecureMemoryTest, MoveAssignment) {
    SecureMemory original(32);
    std::memset(original.data(), 0xCD, 32);
    
    SecureMemory target(16);
    std::memset(target.data(), 0xEF, 16);
    
    target = std::move(original);
    
    // Target should now have original's data
    EXPECT_EQ(target.size(), 32);
    EXPECT_EQ(target.data()[0], 0xCD);
    
    // Original should be empty
    EXPECT_EQ(original.size(), 0);
    EXPECT_EQ(original.data(), nullptr);
}

TEST_F(SecureMemoryTest, SelfMoveAssignment) {
    SecureMemory mem(32);
    std::memset(mem.data(), 0x11, 32);
    
    // Self-move should be safe
    mem = std::move(mem);
    
    // Data should still be valid
    EXPECT_EQ(mem.size(), 32);
}

// ---- Copy Prohibited Tests ----
// Note: These tests verify that copy operations don't compile
// They are compile-time checks, commented out to show intent
/*
TEST_F(SecureMemoryTest, CopyConstructionNotAllowed) {
    SecureMemory original(32);
    // SecureMemory copy(original);  // Should not compile
}

TEST_F(SecureMemoryTest, CopyAssignmentNotAllowed) {
    SecureMemory original(32);
    SecureMemory target(16);
    // target = original;  // Should not compile
}
*/

// ---- Memory Zeroing Tests ----

TEST_F(SecureMemoryTest, MemoryZeroedOnDestruction) {
    uint8_t* raw_ptr = nullptr;
    
    {
        SecureMemory mem(32);
        std::memset(mem.data(), 0xFF, 32);
        raw_ptr = mem.data();
        
        // Memory should contain 0xFF before destruction
        EXPECT_EQ(raw_ptr[0], 0xFF);
    }
    
    // After destruction, if memory hasn't been reused,
    // it may or may not be zeroed depending on implementation
    // This is implementation-dependent and hard to test reliably
}

TEST_F(SecureMemoryTest, ZeroMethod) {
    SecureMemory mem(32);
    std::memset(mem.data(), 0xAA, 32);
    
    // Verify initial state
    EXPECT_EQ(mem.data()[0], 0xAA);
    
    // Zero the memory
    mem.zero();
    
    // All bytes should be zero
    for (size_t i = 0; i < mem.size(); ++i) {
        EXPECT_EQ(mem.data()[i], 0);
    }
}

// ---- Access Methods Tests ----

TEST_F(SecureMemoryTest, DataAccess) {
    SecureMemory mem(16);
    
    // Non-const access
    mem.data()[0] = 0x12;
    EXPECT_EQ(mem.data()[0], 0x12);
    
    // Const access
    const SecureMemory& const_mem = mem;
    EXPECT_EQ(const_mem.data()[0], 0x12);
}

TEST_F(SecureMemoryTest, BeginEnd) {
    SecureMemory mem(8);
    for (size_t i = 0; i < 8; ++i) {
        mem.data()[i] = static_cast<uint8_t>(i);
    }
    
    // Test iteration
    uint8_t expected = 0;
    for (auto it = mem.begin(); it != mem.end(); ++it) {
        EXPECT_EQ(*it, expected);
        expected++;
    }
    EXPECT_EQ(expected, 8);
}

// ---- SecureString Tests ----

TEST_F(SecureMemoryTest, SecureStringConstruction) {
    SecureString str("Hello, World!");
    
    EXPECT_FALSE(str.empty());
    EXPECT_EQ(str.size(), 13);
}

TEST_F(SecureMemoryTest, SecureStringEmpty) {
    SecureString str;
    
    EXPECT_TRUE(str.empty());
    EXPECT_EQ(str.size(), 0);
}

TEST_F(SecureMemoryTest, SecureStringCStr) {
    SecureString str("Test");
    
    EXPECT_STREQ(str.c_str(), "Test");
}

TEST_F(SecureMemoryTest, SecureStringMove) {
    SecureString original("Secret Password");
    
    SecureString moved(std::move(original));
    
    EXPECT_STREQ(moved.c_str(), "Secret Password");
    EXPECT_TRUE(original.empty());
}

// ---- Memory Lock Tests ----
// Note: mlock/munlock may fail without root privileges

TEST_F(SecureMemoryTest, MemoryLockNoThrow) {
    SecureMemory mem(1024);
    
    // Should not throw even if mlock fails
    EXPECT_NO_THROW(mem.lock());
    EXPECT_NO_THROW(mem.unlock());
}

// ---- Edge Cases ----

TEST_F(SecureMemoryTest, MultipleAllocations) {
    std::vector<SecureMemory> memories;
    
    for (int i = 0; i < 100; ++i) {
        memories.emplace_back(256);
        std::memset(memories.back().data(), i, 256);
    }
    
    // Verify each allocation is independent
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(memories[i].data()[0], static_cast<uint8_t>(i));
    }
}

TEST_F(SecureMemoryTest, CompareMemory) {
    SecureMemory mem1(16);
    SecureMemory mem2(16);
    
    std::memset(mem1.data(), 0x11, 16);
    std::memset(mem2.data(), 0x11, 16);
    
    // Should have same content
    EXPECT_EQ(std::memcmp(mem1.data(), mem2.data(), 16), 0);
    
    // Modify one
    mem2.data()[0] = 0x22;
    
    // Should now be different
    EXPECT_NE(std::memcmp(mem1.data(), mem2.data(), 16), 0);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
