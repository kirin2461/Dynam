#include "ncp_secure_buffer.hpp"
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <iostream>

namespace ncp {

// ==================== SecureDeleter ====================
void SecureBuffer::SecureDeleter::operator()(uint8_t* ptr) const noexcept {
    if (ptr && size_ > 0) {
        // Cryptographic memory wipe - resistant to compiler optimization
        sodium_memzero(ptr, size_);
        delete[] ptr;
    }
}

// ==================== Constructors ====================
SecureBuffer::SecureBuffer(size_t size)
    : data_(nullptr, SecureDeleter{0})
    , size_(size)
    , locked_(false) {
    if (size == 0) {
        return;
    }

    uint8_t* raw = new uint8_t[size];
    sodium_memzero(raw, size);  // Initialize to zero
    data_ = std::unique_ptr<uint8_t[], SecureDeleter>(raw, SecureDeleter{size});

    lock_memory();
}

SecureBuffer::SecureBuffer(const std::vector<uint8_t>& data)
    : data_(nullptr, SecureDeleter{0})
    , size_(data.size())
    , locked_(false) {
    if (data.empty()) {
        return;
    }

    uint8_t* raw = new uint8_t[size_];
    std::memcpy(raw, data.data(), size_);
    data_ = std::unique_ptr<uint8_t[], SecureDeleter>(raw, SecureDeleter{size_});

    lock_memory();
}

// ==================== Destructor ====================
SecureBuffer::~SecureBuffer() noexcept {
    // sodium_memzero is called by SecureDeleter when unique_ptr releases
    // We just need to unlock memory before that
    unlock_memory();
    // data_ destructor will call SecureDeleter::operator()
}

// ==================== Move Operations ====================
SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(std::move(other.data_))
    , size_(other.size_)
    , locked_(other.locked_) {
    other.size_ = 0;
    other.locked_ = false;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        // Wipe current data first
        unlock_memory();
        // data_ destructor handles wiping via SecureDeleter

        data_ = std::move(other.data_);
        size_ = other.size_;
        locked_ = other.locked_;

        other.size_ = 0;
        other.locked_ = false;
    }
    return *this;
}

// ==================== Public Methods ====================
void SecureBuffer::wipe() noexcept {
    if (data_ && size_ > 0) {
        sodium_memzero(data_.get(), size_);
    }
}

void SecureBuffer::resize(size_t new_size) {
    if (new_size == size_) return;

    SecureBuffer new_buf(new_size);

    // Copy existing data (up to min of old and new size)
    if (data_ && new_size > 0 && size_ > 0) {
        size_t copy_size = std::min(size_, new_size);
        std::memcpy(new_buf.data(), data_.get(), copy_size);
    }

    *this = std::move(new_buf);
}

// ==================== Memory Locking ====================
void SecureBuffer::lock_memory() {
    if (!data_ || size_ == 0) return;

#ifdef _WIN32
    // Windows: VirtualLock prevents memory from being paged to disk
    locked_ = (VirtualLock(data_.get(), size_) != 0);
    if (!locked_) {
        // VirtualLock failed - log warning but don't throw
        // Common reason: insufficient working set quota
        std::cerr << "[SecureBuffer] WARNING: VirtualLock failed. "
                  << "Memory may be swapped to disk." << std::endl;
    }
#else
    // Linux/macOS: mlock prevents memory from being swapped
    locked_ = (mlock(data_.get(), size_) == 0);
    if (!locked_) {
        // mlock failed - log warning but don't throw
        // Common reason: RLIMIT_MEMLOCK too low (default 64KB on many distros)
        std::cerr << "[SecureBuffer] WARNING: mlock failed. "
                  << "Memory may be swapped to disk. "
                  << "Consider increasing RLIMIT_MEMLOCK." << std::endl;
    }
#endif
}

void SecureBuffer::unlock_memory() noexcept {
    if (!locked_ || !data_ || size_ == 0) return;

#ifdef _WIN32
    VirtualUnlock(data_.get(), size_);
#else
    munlock(data_.get(), size_);
#endif

    locked_ = false;
}

} // namespace ncp
