#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <future>
#include <atomic>
#include <type_traits>
#include <stdexcept>

namespace ncp {

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads = std::thread::hardware_concurrency());
    ~ThreadPool();

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /// Submit task, returns future with result
    template<class F, class... Args>
    auto submit(F&& f, Args&&... args)
        -> std::future<std::invoke_result_t<F, Args...>>;

    /// Graceful shutdown
    void shutdown();

    // Metrics (now marked noexcept for performance)
    size_t pending_tasks() const noexcept;
    size_t active_threads() const noexcept;
    size_t total_threads() const noexcept;
    bool is_running() const noexcept;

private:
    std::vector<std::thread>              workers_;
    std::queue<std::function<void()>>     tasks_;
    mutable std::mutex                    queue_mutex_;
    std::condition_variable               condition_;
    std::atomic<bool>                     stop_{false};
    std::atomic<size_t>                   active_{0};
};

// Template implementation must be in header
template<class F, class... Args>
auto ThreadPool::submit(F&& f, Args&&... args)
    -> std::future<std::invoke_result_t<F, Args...>>
{
    using return_type = std::invoke_result_t<F, Args...>;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );

    // FIXED: Enqueue task BEFORE getting future to ensure exception safety
    // If tasks_.emplace() throws, we haven't created a dangling future yet
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (stop_) {
            throw std::runtime_error("submit on stopped ThreadPool");
        }
        tasks_.emplace([task]() { (*task)(); });
    }

    // Get future only after successful enqueue
    std::future<return_type> result = task->get_future();
    condition_.notify_one();
    return result;
}

} // namespace ncp
