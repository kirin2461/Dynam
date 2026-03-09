# ECH (Encrypted Client Hello) Implementation

## Overview

This implementation provides **production-ready Encrypted Client Hello (ECH)** using HPKE (Hybrid Public Key Encryption) as specified in RFC 9180 and draft-ietf-tls-esni.

## Features

✅ **Real HPKE encryption** (not a stub)
✅ **Multiple cipher suites** (X25519, P-256, AES-GCM, ChaCha20-Poly1305)
✅ **DNS-over-HTTPS** ECHConfig fetching
✅ **AAD binding** for tamper protection
✅ **Comprehensive unit tests**
✅ **OpenSSL 3.2+ integration**
✅ **Graceful fallback** when OpenSSL is unavailable

## Quick Start

### 1. Fetch ECHConfig and Encrypt ClientHello

```cpp
#include "ncp_ech.hpp"
#include "ncp_ech_fetch.hpp"

using namespace ncp::DPI::ECH;

// Fetch ECHConfig via DoH
auto config = fetch_ech_config_simple("cloudflare.com");

if (config) {
    // Apply ECH to ClientHello
    std::vector<uint8_t> client_hello = /* ... */;
    auto encrypted = apply_ech(client_hello, config.value());
    
    // Send encrypted ClientHello to server
}
```

### 2. Manual Encryption/Decryption

```cpp
// Generate test config
std::vector<uint8_t> private_key;
HPKECipherSuite suite(
    HPKEKem::DHKEM_X25519_HKDF_SHA256,
    HPKEKDF::HKDF_SHA256,
    HPKEAEAD::AES_128_GCM
);
auto config = create_test_ech_config("example.com", suite, private_key);

// Client: Encrypt
ECHClientContext client;
client.init(config);

std::vector<uint8_t> enc, encrypted;
client.encrypt(inner_hello, outer_aad, enc, encrypted);

// Server: Decrypt (pass config for HPKE info vector)
ECHServerContext server;
server.init(private_key, suite, config);

std::vector<uint8_t> decrypted;
server.decrypt(enc, encrypted, outer_aad, decrypted);
```

## Architecture

### Components

1. **ncp_ech.hpp/cpp** - Core HPKE implementation
   - `ECHClientContext` - Client-side encryption
   - `ECHServerContext` - Server-side decryption
   - `ECHConfig` - Configuration structure

2. **ncp_ech_fetch.hpp/cpp** - DoH-based config fetching
   - `ECHConfigFetcher` - DNS-over-HTTPS resolver
   - Parses HTTPS resource records
   - Extracts ECH parameters

3. **test_ech.cpp** - Comprehensive unit tests
   - Round-trip encryption/decryption
   - Multiple cipher suites
   - AAD tampering detection
   - Large payload handling

## Supported Cipher Suites

| KEM | KDF | AEAD |
|-----|-----|------|
| DHKEM-X25519-HKDF-SHA256 ✅ | HKDF-SHA256 | AES-128-GCM |
| DHKEM-P256-HKDF-SHA256 | HKDF-SHA256 | AES-256-GCM |
| DHKEM-P384-HKDF-SHA384 | HKDF-SHA384 | ChaCha20-Poly1305 |
| DHKEM-X448-HKDF-SHA512 | HKDF-SHA512 | - |

✅ = Default

## Requirements

- **OpenSSL 3.2+** for HPKE API support
- **libsodium** for random number generation
- **C++17** or later

## Building

```bash
mkdir build && cd build
cmake .. -DENABLE_TESTS=ON
make

# Run ECH tests
./bin/test_ech

# Run example
./bin/ech_example
```

## Testing

```bash
# Run all ECH tests
ctest -R test_ech -V

# Test DoH fetching
./bin/ech_example
```

## How It Works

### HPKE Encryption Flow

1. **Setup**: Client obtains server's ECHConfig (via DoH)
2. **Encapsulation**: Client generates ephemeral key pair
3. **Key Agreement**: ECDH with server's public key
4. **Encryption**: AEAD encryption of ClientHelloInner
5. **Transmission**: Send enc + encrypted payload in ECH extension

### DNS-over-HTTPS Flow

1. Query HTTPS RR for target domain
2. Extract ECH SvcParam (key = 5)
3. Parse ECHConfigList
4. Validate and return ECHConfig

## Security Properties

✅ **Confidentiality**: SNI and extensions hidden
✅ **Integrity**: AEAD authentication
✅ **Forward Secrecy**: Ephemeral keys
✅ **Tamper Protection**: AAD binding

## Limitations

- Requires OpenSSL 3.2+ (falls back gracefully)
- ClientHelloInner construction simplified (TODO: full implementation)
- Single ECHConfig per domain (multi-config support planned)

## References

- [RFC 9180: HPKE](https://datatracker.ietf.org/doc/html/rfc9180)
- [draft-ietf-tls-esni: ECH](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
- [OpenSSL HPKE API](https://docs.openssl.org/3.2/man3/OSSL_HPKE_CTX_new/)

## License

Same as parent project.
