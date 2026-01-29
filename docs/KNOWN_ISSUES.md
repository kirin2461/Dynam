# Known Issues and Improvement Recommendations

## 🔴 Critical Issues

### 1. Incomplete ECH (Encrypted Client Hello) Implementation
**Location**: `src/core/src/dpi_advanced.cpp` (lines 613-650)

**Current Status**:
- ECH implementation is a simplified stub
- Only adds extension header without proper HPKE encryption
- Wrapped in `#ifdef HAVE_OPENSSL` but lacks actual ECH logic
- Missing ECHConfig parsing (RFC 9180)

**Code Location**:
```cpp
std::vector<uint8_t> DPIEvasion::apply_ech(
    const std::vector<uint8_t>& client_hello,
    const std::vector<uint8_t>& ech_config
) {
    // ...
    // ECH uses HPKE for encryption
    // For now, we add the ECH extension with encrypted payload
    // ...
}
```

**Required Implementation**:
1. **HPKE Integration**: Implement RFC 9180 HPKE (Hybrid Public Key Encryption)
   - Use BoringSSL or OpenSSL 3.2+ with ECH support
   - Implement key encapsulation and AEAD encryption

2. **ECHConfig Parsing**: Parse and validate ECH configuration
   - Parse ECHConfigList from DNS records
   - Extract public key and cipher suite parameters
   - Validate key versions and compatibility

3. **ClientHello Encryption**:
   - Encrypt sensitive extensions (SNI, ALPN)
   - Generate outer ClientHello with public name
   - Properly calculate message authentication codes

**Dependencies**:
```cmake
# CMakeLists.txt additions needed:
find_package(OpenSSL 3.2 REQUIRED)
# OR
find_package(BoringSSL REQUIRED)
```

**References**:
- RFC 9180: HPKE
- RFC 8446: TLS 1.3
- Draft: TLS Encrypted Client Hello

---

### 2. Global Variables in CLI (Code Smell)
**Location**: `src/cli/main.cpp` (lines 18-20)

**Current Code**:
```cpp
std::atomic<bool> g_running(false);
NetworkSpoofer* g_spoofer = nullptr;
DPI::DPIBypass* g_dpi_bypass = nullptr;
```

**Problems**:
- Thread-unsafe raw pointers
- Difficult to test
- Poor encapsulation
- Signal handler dependencies

**Recommended Solution**:
Create `Application` class with RAII:

```cpp
class Application {
private:
    std::atomic<bool> running_{false};
    std::unique_ptr<NetworkSpoofer> spoofer_;
    std::unique_ptr<DPI::DPIBypass> dpi_bypass_;
    
    static Application* instance_; // For signal handler
    
public:
    static Application& get_instance();
    void handle_signal(int signal);
    bool run(const std::vector<std::string>& args);
    void stop();
};
```

---

## ⚠️ Security Concerns

### 3. Domain Fronting - Simplified Implementation
**Location**: `src/core/src/dpi_advanced.cpp` (lines 652-695)

**Current Issues**:
- Simple SNI replacement without CDN verification
- May not work with modern CDN routing (Cloudflare, Fastly)
- Lacks HTTP/2 :authority header manipulation
- No TLS session ticket handling

**Modern CDN Protections**:
- Cloudflare: Validates SNI against TLS certificate
- Fastly: Enforces strict origin routing
- Akamai: Uses proprietary routing logic

**Improvements Needed**:
1. Verify CDN compatibility before fronting
2. Add HTTP/2 pseudo-header support
3. Implement TLS 1.3 session resumption
4. Add fallback mechanisms

---

### 4. SNI Parsing - Edge Cases
**Location**: `src/core/src/dpi_advanced.cpp` (TLSManipulator::find_sni_split_points)

**Missing Edge Cases**:
- Malformed TLS records (truncated, overlength)
- Multiple SNI extensions (invalid but possible)
- Missing extensions length field
- Session resumption without full handshake
- TLS 1.2 vs 1.3 differences

**Required Validations**:
```cpp
// Add bounds checking:
if (pos + ext_data_len > ext_end) {
    return points; // Truncated extension
}

// Validate SNI structure:
if (sni_list_len + 5 > ext_data_len) {
    return points; // Malformed SNI
}
```

---

## 📝 Code Quality Issues

### 5. Error Handling - Silent Failures
**Location**: Multiple files

**Problem**: Methods return empty results without logging:
```cpp
std::vector<size_t> TLSManipulator::find_sni_split_points(
    const uint8_t* data,
    size_t len
) {
    std::vector<size_t> points;
    if (!data || len < 43) return points; // Silent failure
    // ...
}
```

**Solution**: Add logging callback:
```cpp
std::optional<std::vector<size_t>> TLSManipulator::find_sni_split_points(
    const uint8_t* data,
    size_t len,
    ErrorCallback error_cb
) {
    if (!data || len < 43) {
        error_cb("Invalid TLS ClientHello: too short");
        return std::nullopt;
    }
    // ...
}
```

---

## 🔧 Infrastructure Issues

### 6. CI/CD Improvements
**Status**: ✅ **FIXED** (commit c240c00)

**Previously Missing**:
- ❌ Windows builds
- ❌ AddressSanitizer
- ❌ ThreadSanitizer
- ❌ UndefinedBehaviorSanitizer

**Now Implemented**:
- ✅ Multi-platform matrix (Ubuntu + Windows)
- ✅ Separate sanitizer job (ASan/TSan/UBSan)
- ✅ Windows MSVC support
- ✅ Npcap installation for Windows

---

### 7. Missing Fuzzing
**Priority**: High

**Targets**:
- TLS ClientHello parser
- DNS query parser
- HTTP header parser
- TCP segment splitter

**Recommended Setup**:
```cmake
# Add to CMakeLists.txt:
option(ENABLE_FUZZING "Enable fuzzing targets" OFF)

if(ENABLE_FUZZING)
    add_executable(fuzz_tls_parser fuzzing/fuzz_tls.cpp)
    target_link_libraries(fuzz_tls_parser PRIVATE -fsanitize=fuzzer)
endif()
```

---

## 📊 Technical Debt

### 8. Missing Code Coverage
**Action**: Add coverage reporting to CI

```yaml
# .github/workflows/ci.yml addition:
- name: Generate coverage
  run: |
    cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_COVERAGE=ON
    cmake --build .
    ctest
    lcov --capture --directory . --output-file coverage.info
    
- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.info
```

---

### 9. Unified Logging System
**Current**: Mix of `std::cout`, `std::cerr`, callbacks

**Recommended**: Integrate spdlog
```cpp
#include <spdlog/spdlog.h>

class Logger {
public:
    static void init(spdlog::level::level_enum level) {
        spdlog::set_level(level);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    }
};
```

---

### 10. Configuration Management
**Current**: Hardcoded values throughout

**Solution**: YAML/JSON configuration
```yaml
# config.yml
dpi:
  techniques:
    - tcp_segmentation
    - sni_split
    - grease_injection
  obfuscation: chacha20
  
network:
  interfaces:
    - eth0
  dns_servers:
    - 1.1.1.1
    - 8.8.8.8
```

---

## 🔬 Testing Requirements

### Priority Test Cases:
1. **ECH**: Mock HPKE encryption/decryption
2. **Domain Fronting**: Test CDN compatibility
3. **SNI Parsing**: Malformed packet handling
4. **Memory Safety**: Valgrind/ASan full runs
5. **Thread Safety**: TSan with concurrent operations

---

## 📚 Documentation Gaps

### Missing Documentation:
1. ❌ API reference (Doxygen)
2. ❌ ECH implementation notes
3. ❌ DPI evasion technique details
4. ❌ Performance benchmarks
5. ❌ Security considerations

**Action**: Generate Doxygen documentation
```bash
doxygen Doxyfile
```

---

## 🎯 Roadmap

### Phase 1: Critical Fixes (High Priority)
- [ ] Complete ECH implementation with HPKE
- [ ] Refactor global variables in CLI
- [ ] Add comprehensive error logging

### Phase 2: Security Hardening (Medium Priority)
- [ ] Improve Domain Fronting for modern CDNs
- [ ] Add SNI parsing edge case handling
- [ ] Implement fuzzing targets

### Phase 3: Code Quality (Low Priority)
- [ ] Add code coverage reporting
- [ ] Integrate spdlog for logging
- [ ] Implement YAML configuration
- [ ] Generate Doxygen documentation

---

## 📞 Contact

For questions about these issues, please open a GitHub issue with the `question` label.
