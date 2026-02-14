#ifndef NCP_SECURE_MEMORY_HPP
#define NCP_SECURE_MEMORY_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace ncp {

/**
 * @brief Secure Memory Management with auto-zeroing
 *
 * Uses sodium_memzero for guaranteed secure erasure.
 * Supports mlock/munlock to prevent swapping to disk.
 */
class SecureMemory {
public:
    SecureMemory();
    explicit SecureMemory(size_t size);
    ~SecureMemory();

    // Disable copy - prevent accidental key duplication
    SecureMemory(const SecureMemory&) = delete;
    SecureMemory& operator=(const SecureMemory&) = delete;

    // Allow move
    SecureMemory(SecureMemory&& other) noexcept;
    SecureMemory& operator=(SecureMemory&& other) noexcept;

    uint8_t* data();
    const uint8_t* data() const;
    size_t size() const;
    bool empty() const;

    // Iterator support for range-based for loops
    uint8_t* begin();
    uint8_t* end();
    const uint8_t* begin() const;
    const uint8_t* end() const;

    // Securely zero the memory contents
    void zero();

    // Lock memory to prevent swapping (best-effort)
    bool lock();
    bool unlock();

    // Static utility functions
    static void secure_zero(void* ptr, size_t size);
    static bool lock_memory(void* ptr, size_t size);
    static bool unlock_memory(void* ptr, size_t size);

private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
    bool locked_ = false;
};

/**
 * @brief Secure string with auto-zeroing destructor
 *
 * Suitable for passwords, tokens, and other sensitive string data.
 * Memory is zeroed on destruction and cannot be copied.
 */
class SecureString {
public:
    SecureString();
    explicit SecureString(const std::string& str);
    explicit SecureString(const char* str, size_t len);
    ~SecureString();

    // Disable copy
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    // Allow move
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;

    const char* c_str() const;
    const char* data() const;
    size_t size() const;
    size_t length() const;
    bool empty() const;

    void clear();

private:
    char* data_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;
};

/**
 * @brief Secure cryptographic operations
 *
 * Provides constant-time comparison, CSPRNG, and password hashing.
 */
namespace SecureOps {
    // Constant-time comparison to prevent timing attacks
    bool constant_time_compare(const void* a, const void* b, size_t len);

    // Cryptographically secure random bytes (uses libsodium)
    std::vector<uint8_t> generate_random(size_t size);

    // Password hashing using Argon2id (via libsodium)
    SecureString hash_password(
        const SecureString& password,
        const std::vector<uint8_t>& salt
    );
}

} // namespace ncp

#endif // NCP_SECURE_MEMORY_HPP
