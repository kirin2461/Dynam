#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace ncp {

// TODO: Consolidate SecureBuffer and SecureMemory (ncp_secure_memory.hpp) into a single class.
// Both provide identical functionality (sodium_memzero + mlock + RAII + no-copy/move-only).
// SecureBuffer uses unique_ptr<uint8_t[], SecureDeleter>, SecureMemory uses raw pointer.
// Prefer SecureMemory as the primary API; deprecate SecureBuffer in a future release.

/**
 * @brief SecureBuffer - класс для безопасного хранения криптографических данных
 * 
 * Особенности:
 * - Автоматическая очистка памяти через sodium_memzero() в деструкторе
 * - Защита от свопа на диск (mlock на Linux, VirtualLock на Windows)
 * - Запрет копирования, поддержка перемещения (move semantics)
 * - RAII-управление жизненным циклом
 * 
 * Использование:
 *   SecureBuffer key(32);  // 256-bit ключ
 *   // ... работа с key.data()
 *   // Автоматическая очистка при выходе из области видимости
 */
class SecureBuffer {
public:
    /**
     * @brief Конструктор - создает буфер заданного размера
     * @param size Размер буфера в байтах
     * @throws std::bad_alloc при нехватке памяти
     * @throws std::runtime_error если не удалось заблокировать память
     */
    explicit SecureBuffer(size_t size);

    /**
     * @brief Конструктор из вектора (копирование данных)
     * @param data Исходные данные
     */
    explicit SecureBuffer(const std::vector<uint8_t>& data);

    /**
     * @brief Деструктор - затирает память через sodium_memzero
     */
    ~SecureBuffer() noexcept;

    // Запрещаем копирование (безопасность)
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Разрешаем перемещение (move semantics)
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    /**
     * @brief Получить указатель на данные (non-const)
     * @return Указатель на начало буфера
     */
    uint8_t* data() noexcept { return data_.get(); }

    /**
     * @brief Получить указатель на данные (const)
     * @return Константный указатель на начало буфера
     */
    const uint8_t* data() const noexcept { return data_.get(); }

    /**
     * @brief Получить размер буфера
     * @return Размер в байтах
     */
    size_t size() const noexcept { return size_; }

    /**
     * @brief Проверка на пустоту
     * @return true если буфер пустой
     */
    bool empty() const noexcept { return size_ == 0; }

    /**
     * @brief Принудительная очистка памяти (можно вызвать вручную)
     */
    void wipe() noexcept;

    /**
     * @brief Resize буфера (с сохранением данных если возможно)
     * @param new_size Новый размер
     */
    void resize(size_t new_size);

private:
    struct SecureDeleter {
        size_t size_;
        void operator()(uint8_t* ptr) const noexcept;
    };

    std::unique_ptr<uint8_t[], SecureDeleter> data_;
    size_t size_;
    bool locked_;  // Флаг успешной блокировки памяти

    void lock_memory();
    void unlock_memory() noexcept;
};

} // namespace ncp
