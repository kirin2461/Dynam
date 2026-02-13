#include "ncp_secure_memory.hpp"
#include <sodium.h>
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace ncp {

// ---- SecureMemory ------------------------------------------------------

SecureMemory::SecureMemory() = default;

SecureMemory::SecureMemory(size_t size)
    : size_(size)
{
    if (size > 0) {
        data_ = new uint8_t[size];
        std::memset(data_, 0, size_);
    }
}

SecureMemory::~SecureMemory() {
    if (data_) {
        zero();
        if (locked_) {
            unlock();
        }
        delete[] data_;
        data_ = nullptr;
    }
}

SecureMemory::SecureMemory(SecureMemory&& other) noexcept
    : data_(other.data_), size_(other.size_), locked_(other.locked_)
{
    other.data_ = nullptr;
    other.size_ = 0;
    other.locked_ = false;
}

SecureMemory& SecureMemory::operator=(SecureMemory&& other) noexcept {
    if (this != &other) {
        if (data_) {
            zero();
            if (locked_) unlock();
            delete[] data_;
        }
        data_ = other.data_;
        size_ = other.size_;
        locked_ = other.locked_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.locked_ = false;
    }
    return *this;
}

void SecureMemory::zero() {
    if (data_ && size_ > 0) {
        sodium_memzero(data_, size_);
    }
}

bool SecureMemory::lock() {
#ifdef _WIN32
    if (data_ && size_ > 0 && !locked_) {
        if (VirtualLock(data_, size_)) {
            locked_ = true;
            return true;
        }
    }
    return false;
#else
    if (data_ && size_ > 0 && !locked_) {
        if (mlock(data_, size_) == 0) {
            locked_ = true;
            return true;
        }
    }
    return false;
#endif
}

bool SecureMemory::unlock() {
#ifdef _WIN32
    if (data_ && size_ > 0 && locked_) {
        if (VirtualUnlock(data_, size_)) {
            locked_ = false;
            return true;
        }
    }
    return false;
#else
    if (data_ && size_ > 0 && locked_) {
        if (munlock(data_, size_) == 0) {
            locked_ = false;
            return true;
        }
    }
    return false;
#endif
}

void SecureMemory::secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        sodium_memzero(ptr, size);
    }
}

bool SecureMemory::lock_memory(void* ptr, size_t size) {
#ifdef _WIN32
    return VirtualLock(ptr, size) != 0;
#else
    return mlock(ptr, size) == 0;
#endif
}

bool SecureMemory::unlock_memory(void* ptr, size_t size) {
#ifdef _WIN32
    return VirtualUnlock(ptr, size) != 0;
#else
    return munlock(ptr, size) == 0;
#endif
}

// ---- SecureString ------------------------------------------------------

SecureString::SecureString() = default;

SecureString::SecureString(const std::string& str)
    : size_(str.size()), capacity_(str.size() + 1)
{
    if (capacity_ > 0) {
        data_ = new char[capacity_];
        std::memcpy(data_, str.c_str(), size_);
        data_[size_] = '\0';
    }
}

SecureString::SecureString(const char* str, size_t len)
    : size_(len), capacity_(len + 1)
{
    if (capacity_ > 0 && str) {
        data_ = new char[capacity_];
        std::memcpy(data_, str, size_);
        data_[size_] = '\0';
    }
}

SecureString::~SecureString() {
    clear();
}

SecureString::SecureString(SecureString&& other) noexcept
    : data_(other.data_), size_(other.size_), capacity_(other.capacity_)
{
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = other.data_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    return *this;
}

void SecureString::clear() {
    if (data_) {
        sodium_memzero(data_, capacity_);
        delete[] data_;
        data_ = nullptr;
    }
    size_ = 0;
    capacity_ = 0;
}

// ---- SecureOps ---------------------------------------------------------

namespace SecureOps {

bool constant_time_compare(const void* a, const void* b, size_t len) {
    if (!a || !b || len == 0) return false;
    return sodium_memcmp(a, b, len) == 0;
}

std::vector<uint8_t> generate_random(size_t size) {
    std::vector<uint8_t> result(size);
    if (size > 0) {
        randombytes_buf(result.data(), size);
    }
    return result;
}

SecureString hash_password(
    const SecureString& password,
    const std::vector<uint8_t>& salt)
{
    if (password.empty() || salt.size() < crypto_pwhash_SALTBYTES) {
        return SecureString();
    }

    constexpr size_t hash_len = 32;
    char hash[hash_len];

    if (crypto_pwhash(
            reinterpret_cast<unsigned char*>(hash), hash_len,
            password.c_str(), password.length(),
            salt.data(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return SecureString();
    }

    return SecureString(hash, hash_len);
}

} // namespace SecureOps

} // namespace ncp
