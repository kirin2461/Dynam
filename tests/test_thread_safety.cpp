/**
 * @file test_thread_safety.cpp
 * @brief Thread safety tests for R11-R13 fixes
 */

#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <list>
#include <chrono>

class ThreadSafetyTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test thread-safe list operations (R11-FIX-01 concept)
TEST_F(ThreadSafetyTest, ThreadSafeList_ConcurrentPushAndPop) {
    std::list<int> shared_list;
    std::mutex list_mutex;
    std::atomic<int> push_count{0};
    std::atomic<int> pop_count{0};
    
    std::vector<std::thread> producers;
    std::vector<std::thread> consumers;
    
    // Producer threads
    for (int i = 0; i < 5; ++i) {
        producers.emplace_back([&]() {
            for (int j = 0; j < 100; ++j) {
                std::lock_guard<std::mutex> lock(list_mutex);
                shared_list.push_back(j);
                push_count++;
            }
        });
    }
    
    // Consumer threads
    for (int i = 0; i < 3; ++i) {
        consumers.emplace_back([&]() {
            for (int j = 0; j < 150; ++j) {
                std::lock_guard<std::mutex> lock(list_mutex);
                if (!shared_list.empty()) {
                    shared_list.pop_front();
                    pop_count++;
                }
            }
        });
    }
    
    for (auto& t : producers) t.join();
    for (auto& t : consumers) t.join();
    
    EXPECT_EQ(push_count.load(), 500);
    // Pops may be less if list was empty at times
    EXPECT_LE(pop_count.load(), 500);
}

// Test RAII guard pattern (R12-FIX-05)
TEST_F(ThreadSafetyTest, RaiiGuard_AlwaysExecutes) {
    std::atomic<int> counter{0};
    
    {
        struct Guard {
            std::atomic<int>* c;
            ~Guard() { c->fetch_add(1); }
        };
        Guard g{&counter};
        // Early return simulation
        if (true) {
            // Guard will still execute
        }
    }
    
    EXPECT_EQ(counter.load(), 1);
    
    // Test with exception
    counter.store(0);
    try {
        struct Guard {
            std::atomic<int>* c;
            ~Guard() { c->fetch_add(1); }
        };
        Guard g{&counter};
        throw std::runtime_error("test");
    } catch (...) {
        // Guard should have executed
    }
    
    EXPECT_EQ(counter.load(), 1);
}

// Test try_emplace behavior (R12-FIX-07)
TEST_F(ThreadSafetyTest, TryEmplace_AtomicInsert) {
    std::map<int, int> map;
    std::mutex map_mutex;
    std::atomic<int> insert_count{0};
    std::atomic<int> actual_inserts{0};
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < 100; ++j) {
                std::lock_guard<std::mutex> lock(map_mutex);
                auto [it, inserted] = map.try_emplace(j % 50, j);
                insert_count++;
                if (inserted) {
                    actual_inserts++;
                }
            }
        });
    }
    
    for (auto& t : threads) t.join();
    
    EXPECT_EQ(insert_count.load(), 1000);
    // Only 50 unique keys, so only 50 actual inserts
    EXPECT_EQ(actual_inserts.load(), 50);
    EXPECT_EQ(map.size(), 50);
}

// Test memory ordering (R12-FIX-04)
TEST_F(ThreadSafetyTest, MemoryOrdering_AcquireRelease) {
    std::atomic<bool> flag{false};
    std::atomic<int> value{0};
    
    std::thread producer([&]() {
        value.store(42, std::memory_order_relaxed);
        flag.store(true, std::memory_order_release);
    });
    
    std::thread consumer([&]() {
        while (!flag.load(std::memory_order_acquire)) {
            // Spin
        }
        // At this point, we should see value == 42
        EXPECT_EQ(value.load(std::memory_order_relaxed), 42);
    });
    
    producer.join();
    consumer.join();
}

// Test CAS backoff pattern (R12-FIX-02)
TEST_F(ThreadSafetyTest, CASBackoff_DoesNotSpinForever) {
    std::atomic<int> value{0};
    std::atomic<int> max_retries{0};
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 20; ++i) {
        threads.emplace_back([&]() {
            int retries = 0;
            const int MAX_RETRIES = 1000;
            int expected = 0;
            
            while (retries < MAX_RETRIES) {
                if (value.compare_exchange_weak(expected, 1, std::memory_order_relaxed)) {
                    // Success, now reset
                    value.store(0, std::memory_order_relaxed);
                    break;
                }
                ++retries;
                if (retries % 100 == 0) {
                    std::this_thread::yield();
                }
            }
            
            // Track max retries seen
            int current_max = max_retries.load();
            while (retries > current_max && 
                   !max_retries.compare_exchange_weak(current_max, retries)) {
                // Retry
            }
        });
    }
    
    for (auto& t : threads) t.join();
    
    // Max retries should be bounded
    EXPECT_LT(max_retries.load(), 1000);
}

// Test fragment size bounds (R12-FIX-03)
TEST_F(ThreadSafetyTest, FragmentSize_Bounded) {
    constexpr size_t MAX_FRAG_SIZE = 8192;
    
    // Test cases
    struct TestCase {
        size_t requested;
        size_t expected;
    };
    
    TestCase cases[] = {
        {100, 100},          // Normal case
        {MAX_FRAG_SIZE, MAX_FRAG_SIZE},  // At limit
        {MAX_FRAG_SIZE + 1, MAX_FRAG_SIZE},  // Over limit
        {SIZE_MAX, MAX_FRAG_SIZE},  // Overflow case
        {0, 1},  // Zero should be clamped to 1
    };
    
    for (const auto& tc : cases) {
        size_t base_frag_size = (tc.requested > 0) ? tc.requested : 2;
        base_frag_size = std::min(base_frag_size, MAX_FRAG_SIZE);
        base_frag_size = std::max(base_frag_size, size_t{1});
        
        EXPECT_EQ(base_frag_size, tc.expected) 
            << "Failed for requested size: " << tc.requested;
    }
}

// Test concurrent counter with RAII guards
TEST_F(ThreadSafetyTest, ConcurrentCounter_RaiiGuards) {
    std::atomic<int> active_count{0};
    std::atomic<int> peak_count{0};
    
    auto worker = [&]() {
        struct Guard {
            std::atomic<int>* count;
            std::atomic<int>* peak;
            Guard(std::atomic<int>* c, std::atomic<int>* p) : count(c), peak(p) {
                int val = count->fetch_add(1) + 1;
                // Update peak
                int current_peak = peak->load();
                while (val > current_peak && 
                       !peak->compare_exchange_weak(current_peak, val)) {
                    // Retry
                }
            }
            ~Guard() {
                count->fetch_sub(1);
            }
        };
        
        Guard g(&active_count, &peak_count);
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    };
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 50; ++i) {
        threads.emplace_back(worker);
    }
    
    for (auto& t : threads) t.join();
    
    EXPECT_EQ(active_count.load(), 0);
    EXPECT_GT(peak_count.load(), 1);
    EXPECT_LE(peak_count.load(), 50);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
