#pragma once

/**
 * @file ncp_winsock_init.hpp
 * @brief Shared Winsock2 bootstrap + portable socket-handle type.
 *
 * Winsock requires WSAStartup() before any socket API is used. This header
 * provides a thread-safe, call-once initializer used by all enterprise
 * networking modules (reality / fog / spa / porthop) and the CLI.
 *
 * WSACleanup is intentionally NOT registered via atexit(): Winsock
 * reference-counts WSAStartup calls and the OS reclaims everything at
 * process exit. An atexit handler could fire while detached relay threads
 * (e.g. the reality splice workers) are still inside Winsock calls, which
 * is a use-after-cleanup race with no upside — there is nothing to flush.
 *
 * Include order note: on _WIN32 this header pulls <winsock2.h> and
 * <ws2tcpip.h>. winsock2.h defines _WINSOCKAPI_, so a later <windows.h>
 * in the same translation unit will skip <winsock.h> (the classic
 * winsock.h/winsock2.h conflict). The project also sets
 * WIN32_LEAN_AND_MEAN globally (top-level CMakeLists), which keeps
 * <windows.h> from dragging <winsock.h> in at all.
 */

#include <cstdint>

#ifdef _WIN32
#include <mutex>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace ncp {

#ifdef _WIN32
/// Portable socket handle: Winsock SOCKET (UINT_PTR) on Windows, int fd
/// elsewhere. Public APIs use this type so 64-bit Windows handles are
/// never truncated to int.
using socket_t = SOCKET;
inline constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
inline constexpr socket_t kInvalidSocket = -1;
#endif

/**
 * Ensure Winsock 2.2 is initialized (WSAStartup), exactly once per process,
 * thread-safe. Returns true when the Winsock DLL is usable.
 * On POSIX this is a no-op that always returns true.
 */
inline bool winsock_init() noexcept {
#ifdef _WIN32
    static std::once_flag s_once;
    static bool s_ok = false;
    std::call_once(s_once, [] {
        WSADATA wsa{};
        s_ok = (::WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    });
    return s_ok;
#else
    return true;
#endif
}

} // namespace ncp
