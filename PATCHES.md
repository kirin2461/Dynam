# DPI Bypass Security Fixes - Patch Application Guide

This document provides detailed instructions for applying security fixes for issues #2, #3, and #4.

## Overview

Three critical/medium security issues have been identified and require patching:

- **Issue #2**: Config race condition in proxy threads
- **Issue #3**: Blocking accept() prevents responsive shutdown  
- **Issue #4**: Fake ClientHello easily detectable by DPI systems

## Prerequisites

```bash
# Install required dependencies
sudo apt-get install libsodium-dev libgtest-dev cmake g++ wireshark tshark

# Initialize libsodium
sodium_init()  # in your code
```

---

## Issue #2: Config Race Condition Fix

**File**: `src/core/src/ncp_dpi.cpp`

### Step 1: Modify `handle_proxy_connection()` - Add config snapshot

**Location**: Line ~330

```cpp
void handle_proxy_connection(SOCKET client_sock) {
    // ADD THIS BLOCK AT THE START:
    DPIConfig conn_config;
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        conn_config = config;  // Thread-safe snapshot
    }
    
    // CHANGE THIS LINE:
    // OLD: if (config.target_host.empty()) {
    // NEW:
    if (conn_config.target_host.empty()) {
        log("DPI proxy: target_host is empty, closing client connection");
        CLOSE_SOCKET(client_sock);
        return;
    }
    
    // ... rest of function ...
    
    // CHANGE THESE LINES at end of function:
    // OLD:
    // std::thread t_cs(&Impl::pipe_client_to_server, this, client_sock, server_sock);
    // std::thread t_sc(&Impl::pipe_server_to_client, this, server_sock, client_sock);
    
    // NEW:
    std::thread t_cs(&Impl::pipe_client_to_server, this, client_sock, server_sock, conn_config);
    std::thread t_sc(&Impl::pipe_server_to_client, this, server_sock, client_sock, conn_config);
    
    // ... rest remains same ...
}
```

### Step 2: Update `pipe_client_to_server()` signature

**Location**: Line ~380

```cpp
// CHANGE SIGNATURE FROM:
// void pipe_client_to_server(SOCKET client_sock, SOCKET server_sock) {

// TO:
void pipe_client_to_server(SOCKET client_sock, SOCKET server_sock, const DPIConfig& conn_config) {
    // ... function body ...
    
    // UPDATE THIS CALL:
    send_with_fragmentation(
        server_sock,
        buffer.data(),
        static_cast<size_t>(received),
        is_client_hello,
        conn_config  // ADD THIS PARAMETER
    );
}
```

### Step 3: Update `pipe_server_to_client()` signature

**Location**: Line ~410

```cpp
// CHANGE SIGNATURE FROM:
// void pipe_server_to_client(SOCKET server_sock, SOCKET client_sock) {

// TO:
void pipe_server_to_client(SOCKET server_sock, SOCKET client_sock, const DPIConfig& conn_config) {
    // ... function body ...
    
    send_with_fragmentation(
        client_sock,
        buffer.data(),
        static_cast<size_t>(received),
        false,
        conn_config  // ADD THIS PARAMETER
    );
}
```

### Step 4: Update `send_with_fragmentation()` signature and body

**Location**: Line ~430

```cpp
// CHANGE SIGNATURE FROM:
// void send_with_fragmentation(
//     SOCKET sock,
//     const uint8_t* data,
//     size_t len,
//     bool is_client_hello
// ) {

// TO:
void send_with_fragmentation(
    SOCKET sock,
    const uint8_t* data,
    size_t len,
    bool is_client_hello,
    const DPIConfig& conn_config  // ADD THIS PARAMETER
) {
    // REPLACE ALL `config.xxx` with `conn_config.xxx` throughout function:
    // - config.enable_noise -> conn_config.enable_noise
    // - config.fake_host -> conn_config.fake_host
    // - config.noise_size -> conn_config.noise_size
    // - config.enable_fake_packet -> conn_config.enable_fake_packet
    // - config.fake_ttl -> conn_config.fake_ttl
    // - config.disorder_delay_ms -> conn_config.disorder_delay_ms
    // - config.enable_tcp_split -> conn_config.enable_tcp_split
    // - config.split_at_sni -> conn_config.split_at_sni
    // - config.split_position -> conn_config.split_position
    // - config.fragment_size -> conn_config.fragment_size
    // - config.enable_disorder -> conn_config.enable_disorder
    
    // Use find-and-replace: config. -> conn_config.
}
```

**Result**: Config snapshot eliminates data race. Each connection gets immutable copy.

---

## Issue #3: Blocking accept() Fix

**File**: `src/core/src/ncp_dpi.cpp`

### Step 1: Add accept() timeout after listen()

**Location**: Line ~307 (after `listen(listen_sock, SOMAXCONN)`)

```cpp
if (listen(listen_sock, SOMAXCONN) < 0) {
    // ... error handling ...
}

// ADD THIS BLOCK:
#ifdef _WIN32
    // Windows will use select() before accept() in loop
#else
    // Linux/Unix: set socket receive timeout
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000; // 500ms
    if (setsockopt(listen_sock, SOL_SOCKET, SO_RCVTIMEO, 
                   &timeout, sizeof(timeout)) < 0) {
        log("Warning: Failed to set SO_RCVTIMEO on listen socket");
    }
#endif

// ... continue with thread pool init ...
```

### Step 2: Add select() for Windows and timeout handling

**Location**: Line ~320 (beginning of `while (running)` loop)

```cpp
while (running) {
// ADD THIS BLOCK AT START OF LOOP:
#ifdef _WIN32
    // Windows: use select() to check for incoming connections with timeout
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(listen_sock, &read_fds);
    
    struct timeval select_timeout;
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 500000; // 500ms
    
    int sel_result = select(0, &read_fds, nullptr, nullptr, &select_timeout);
    if (sel_result == 0) {
        // Timeout - check running flag
        continue;
    }
    if (sel_result < 0) {
        if (!running) break;
        continue;
    }
#endif

    sockaddr_in client_addr{};
#ifdef _WIN32
    int addr_len = static_cast<int>(sizeof(client_addr));
#else
    socklen_t addr_len = static_cast<socklen_t>(sizeof(client_addr));
#endif

    SOCKET client_sock = accept(listen_sock,
                                reinterpret_cast<sockaddr*>(&client_addr),
                                &addr_len);
    if (client_sock == INVALID_SOCKET) {
// ADD THIS BLOCK:
#ifndef _WIN32
        // On Linux with SO_RCVTIMEO, errno == EAGAIN/EWOULDBLOCK on timeout
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Timeout occurred - check running flag and retry
            continue;
        }
#endif
        if (!running) break;
        continue;
    }
    
    // ... rest of loop (connections_handled++, thread_pool_->submit) ...
}
```

**Result**: accept() now times out every 500ms, allowing responsive shutdown.

---

## Issue #4: Fake ClientHello Detection Fix

**File**: `src/core/src/dpi_advanced.cpp`

### Replace entire `create_fake_client_hello()` function

**Location**: Line ~271

See full implementation in [Issue #16 comment](https://github.com/kirin2461/Dynam/issues/16#issuecomment-3913742509) or apply from `tests/integration/test_dpi_fixes.cpp` reference.

**Key changes**:
1. Add 17 cipher suites (15 real + GREASE)
2. Add 32-byte random session ID
3. Add extensions: SNI, supported_versions, supported_groups, signature_algorithms, key_share
4. Add GREASE values in cipher suites and extensions

---

## Testing

### Build and run integration tests:

```bash
cd tests/integration
mkdir -p build && cd build
cmake ..
make
./test_dpi_fixes
```

### Expected output:
```
[ RUN      ] DPIBypassIntegration.ConfigRaceCondition_NoDataRace
✓ Config race test: 1500+ updates completed without data race
[       OK ] (2000 ms)

[ RUN      ] DPIBypassIntegration.ResponsiveShutdown_Under500ms
✓ Shutdown test: completed in 234ms
[       OK ] (350 ms)

[ RUN      ] TLSManipulatorIntegration.FakeClientHello_HasRequiredFields
✓ Fake ClientHello size: 312 bytes
[       OK ]

[ RUN      ] TLSManipulatorIntegration.FakeClientHello_HasMultipleCipherSuites
✓ Fake ClientHello has 17 cipher suites
[       OK ]

[ RUN      ] TLSManipulatorIntegration.FakeClientHello_HasCriticalExtensions
✓ Fake ClientHello has all critical extensions
[       OK ]
```

### Run Wireshark comparison:

```bash
cd tests/scripts
chmod +x compare_clienthello.sh
./compare_clienthello.sh
```

### Run with ThreadSanitizer:

```bash
export TSAN_OPTIONS="detect_deadlocks=1"
./test_dpi_fixes --gtest_filter="*ConfigRace*"
```

### Run with Helgrind (Valgrind):

```bash
valgrind --tool=helgrind --error-exitcode=1 ./test_dpi_fixes
```

---

## Verification Checklist

- [ ] Config race test passes with 100+ concurrent updates
- [ ] Shutdown completes in <500ms on all 5 start/stop cycles
- [ ] Fake ClientHello has 15+ cipher suites
- [ ] Fake ClientHello has 32-byte session ID (not empty)
- [ ] Fake ClientHello has all 5 critical extensions
- [ ] No data races detected by ThreadSanitizer
- [ ] No deadlocks detected by Helgrind
- [ ] Config snapshot overhead <1μs per call

---

## Troubleshooting

**Issue**: Tests fail with "port already in use"
```bash
# Kill existing processes
sudo lsof -ti:18080-18083 | xargs kill -9
```

**Issue**: ThreadSanitizer reports false positives
```bash
# Add suppressions file
export TSAN_OPTIONS="suppressions=tsan_suppressions.txt"
```

**Issue**: Can't capture Chrome ClientHello
```bash
# Run tshark with sudo
sudo tshark -i any -f "tcp port 443" -Y "tls.handshake.type == 1"
# Then open Chrome and visit https://www.example.com
```

---

## References

- Issue #2: [Config race condition](https://github.com/kirin2461/Dynam/issues/16#2)
- Issue #3: [Blocking accept()](https://github.com/kirin2461/Dynam/issues/16#3)
- Issue #4: [Fake ClientHello](https://github.com/kirin2461/Dynam/issues/16#4)
- Full implementation guide: [Issue #16 comment](https://github.com/kirin2461/Dynam/issues/16#issuecomment-3913742509)

---

## Statistics

- **Files modified**: 2 (ncp_dpi.cpp, dpi_advanced.cpp)
- **Lines added**: ~150
- **Lines modified**: ~50
- **Functions changed**: 4 signatures
- **Tests added**: 7 integration tests
- **Expected test duration**: ~5 seconds

---

For questions or issues, please comment on [Issue #16](https://github.com/kirin2461/Dynam/issues/16).
