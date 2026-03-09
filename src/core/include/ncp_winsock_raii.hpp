/**
 * @file ncp_winsock_raii.hpp
 * @brief RAII wrapper for Winsock initialization
 *
 * FIXED Issue #17.5: Prevents Winsock resource leaks on exception
 */

#ifndef NCP_WINSOCK_RAII_HPP
#define NCP_WINSOCK_RAII_HPP

#ifdef _WIN32
#include <winsock2.h>
#include <stdexcept>
#include <string>

namespace ncp {

/**
 * @brief RAII wrapper for Winsock initialization
 *
 * Ensures WSACleanup is called even if exceptions occur.
 * Non-copyable, movable.
 */
class WinsockRAII {
public:
    /**
     * @brief Initialize Winsock 2.2
     * @throws std::runtime_error if WSAStartup fails
     */
    WinsockRAII() {
        WSADATA wsa_data;
        int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (result != 0) {
            throw std::runtime_error(
                "Winsock initialization failed with error: " + std::to_string(result)
            );
        }
        initialized_ = true;
    }

    /**
     * @brief Cleanup Winsock on destruction
     */
    ~WinsockRAII() noexcept {
        if (initialized_) {
            WSACleanup();
            initialized_ = false;
        }
    }

    // Non-copyable
    WinsockRAII(const WinsockRAII&) = delete;
    WinsockRAII& operator=(const WinsockRAII&) = delete;

    // Movable
    WinsockRAII(WinsockRAII&& other) noexcept
        : initialized_(other.initialized_)
    {
        other.initialized_ = false;
    }

    WinsockRAII& operator=(WinsockRAII&& other) noexcept {
        if (this != &other) {
            if (initialized_) {
                WSACleanup();
            }
            initialized_ = other.initialized_;
            other.initialized_ = false;
        }
        return *this;
    }

    /**
     * @brief Check if Winsock is initialized
     */
    bool is_initialized() const noexcept {
        return initialized_;
    }

private:
    bool initialized_ = false;
};

} // namespace ncp

#endif // _WIN32
#endif // NCP_WINSOCK_RAII_HPP
