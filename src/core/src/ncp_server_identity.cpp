/**
 * @file ncp_server_identity.cpp
 * @brief Long-term server identity + client-side pin store — implementation.
 *
 * See ncp_server_identity.hpp for the threat model and wire format.
 */

#include "ncp_server_identity.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>

#include <sodium.h>

#ifdef _WIN32
#  include <direct.h>
#  include <io.h>
#  include <sys/stat.h>
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>
#endif

namespace ncp {

namespace {

constexpr char kDomainTag[] = "ncp-server-identity-v1";

bool ensure_library_initialized() {
    // sodium_init() is idempotent and thread-safe since libsodium 1.0.11.
    return sodium_init() >= 0;
}

bool parse_hex_exact(const std::string& hex, size_t expected_bytes,
                     std::vector<uint8_t>& out) {
    if (hex.size() != expected_bytes * 2) return false;
    out.resize(expected_bytes);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < expected_bytes; ++i) {
        const int hi = nib(hex[i * 2]);
        const int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

/// base64 without line breaks (libsodium's encoder).
std::string b64_encode(const std::vector<uint8_t>& in) {
    const size_t n = sodium_base64_encoded_len(in.size(),
                                               sodium_base64_VARIANT_ORIGINAL);
    std::string out(n, '\0');
    sodium_bin2base64(&out[0], n, in.data(), in.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    // sodium_bin2base64 NUL-terminates; drop it.
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

bool b64_decode(const std::string& text, size_t expected_bytes,
                std::vector<uint8_t>& out) {
    out.assign(expected_bytes + 8, 0);
    size_t written = 0;
    if (sodium_base642bin(out.data(), out.size(),
                          text.c_str(), text.size(),
                          nullptr, &written, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        out.clear();
        return false;
    }
    out.resize(written);
    return written == expected_bytes;
}

bool mkdir_one(const std::string& dir) {
    if (dir.empty()) return true;
#ifdef _WIN32
    if (_mkdir(dir.c_str()) == 0) return true;
#else
    if (mkdir(dir.c_str(), 0700) == 0) return true;
#endif
    // Already exists is success; anything else is a real failure.
    return errno == EEXIST;
}

std::string dir_of(const std::string& path) {
    const size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) return {};
    return path.substr(0, slash);
}

int64_t to_unix(std::chrono::system_clock::time_point tp) {
    return static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            tp.time_since_epoch()).count());
}

std::chrono::system_clock::time_point from_unix(int64_t v) {
    return std::chrono::system_clock::time_point(std::chrono::seconds(v));
}

const char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

} // namespace

// ============================================================================
// Fingerprints
// ============================================================================

std::string fingerprint_to_text(const IdentityFingerprint& fp) {
    // 256 bits -> 52 base32 chars (32 bytes = 51.2 chars, padded with a
    // partial final character). We emit 52 characters as 13 groups of 4.
    std::string raw;
    raw.reserve(52);
    uint32_t buffer = 0;
    int bits = 0;
    for (uint8_t byte : fp) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            raw.push_back(kBase32Alphabet[(buffer >> bits) & 0x1F]);
        }
    }
    if (bits > 0) {
        raw.push_back(kBase32Alphabet[(buffer << (5 - bits)) & 0x1F]);
    }

    std::string out;
    out.reserve(raw.size() + raw.size() / 4);
    for (size_t i = 0; i < raw.size(); ++i) {
        if (i > 0 && i % 4 == 0) out.push_back('-');
        out.push_back(raw[i]);
    }
    return out;
}

bool fingerprint_from_text(const std::string& text, IdentityFingerprint& out) {
    std::string compact;
    compact.reserve(text.size());
    for (char c : text) {
        if (c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        compact.push_back(c);
    }
    if (compact.size() != 52) return false;

    uint32_t buffer = 0;
    int bits = 0;
    size_t produced = 0;
    IdentityFingerprint tmp{};
    for (char c : compact) {
        const char* pos = std::strchr(kBase32Alphabet, c);
        if (!pos || c == '\0') return false;
        buffer = (buffer << 5) | static_cast<uint32_t>(pos - kBase32Alphabet);
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (produced >= tmp.size()) return false;
            tmp[produced++] = static_cast<uint8_t>((buffer >> bits) & 0xFF);
        }
    }
    if (produced != tmp.size()) return false;
    out = tmp;
    return true;
}

bool fingerprint_of_public_key(const std::vector<uint8_t>& public_key,
                               IdentityFingerprint& out) {
    if (public_key.size() != ServerIdentity::kPublicKeyBytes) return false;
    uint8_t digest[32];
    crypto_generichash(digest, sizeof(digest),
                       public_key.data(), public_key.size(),
                       nullptr, 0);
    std::memcpy(out.data(), digest, sizeof(digest));
    return true;
}

bool fingerprint_equal(const IdentityFingerprint& a,
                       const IdentityFingerprint& b) noexcept {
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool handshake_binding_digest(const uint8_t request_hash[32],
                              const std::vector<uint8_t>& response_public_key,
                              uint8_t out[32]) {
    if (!request_hash || !out) return false;
    // Any length is acceptable here: X25519 keys are 32 bytes, P-256 is
    // 65, X448 is 56, Kyber1024 is 1568. The request hash is a fixed
    // 32 bytes, so the concatenation boundary is unambiguous regardless
    // of the key length — no length prefix is needed to avoid collisions.
    if (response_public_key.empty()) return false;

    std::vector<uint8_t> buf;
    buf.reserve(32 + response_public_key.size());
    buf.insert(buf.end(), request_hash, request_hash + 32);
    buf.insert(buf.end(), response_public_key.begin(), response_public_key.end());
    crypto_generichash(out, 32, buf.data(), buf.size(), nullptr, 0);
    return true;
}

// ============================================================================
// ServerIdentity
// ============================================================================

ServerIdentity::ServerIdentity() {
    ensure_library_initialized();
}

ServerIdentity::~ServerIdentity() {
    if (!secret_key_.empty()) sodium_memzero(secret_key_.data(), secret_key_.size());
}

bool ServerIdentity::generate() {
    if (!ensure_library_initialized()) return false;
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
    if (crypto_sign_keypair(pk.data(), sk.data()) != 0) return false;
    secret_key_ = std::move(sk);
    public_key_ = std::move(pk);
    return true;
}

bool ServerIdentity::load_keyfile(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    std::getline(in, line);
    // Tolerate trailing whitespace / CRLF from a Windows-authored file.
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\n')) {
        line.pop_back();
    }
    if (line.empty()) return false;

    std::vector<uint8_t> blob;
    // 96 bytes = 64-byte secret || 32-byte public (same as SpaClient).
    if (!b64_decode(line, 96, blob)) return false;

    std::vector<uint8_t> sk(blob.begin(), blob.begin() + 64);
    std::vector<uint8_t> declared_pk(blob.begin() + 64, blob.begin() + 96);

    // The stored public key must actually belong to the stored secret key.
    // A hand-edited or partially-copied file must fail here rather than
    // produce signatures that never verify.
    std::vector<uint8_t> derived_pk(crypto_sign_PUBLICKEYBYTES);
    if (crypto_sign_ed25519_sk_to_pk(derived_pk.data(), sk.data()) != 0 ||
        sodium_memcmp(derived_pk.data(), declared_pk.data(),
                      crypto_sign_PUBLICKEYBYTES) != 0) {
        sodium_memzero(sk.data(), sk.size());
        return false;
    }

    if (!secret_key_.empty()) sodium_memzero(secret_key_.data(), secret_key_.size());
    secret_key_ = std::move(sk);
    public_key_ = std::move(derived_pk);
    return true;
}

bool ServerIdentity::save_keyfile(const std::string& path) const {
    if (!has_key()) return false;

    const std::string dir = dir_of(path);
    if (!dir.empty() && !mkdir_one(dir)) return false;

    std::vector<uint8_t> blob;
    blob.reserve(96);
    blob.insert(blob.end(), secret_key_.begin(), secret_key_.end());
    blob.insert(blob.end(), public_key_.begin(), public_key_.end());

    // Write-then-rename, for two reasons:
    //  - a crash or power loss mid-write must not truncate the long-term
    //    identity (recovering it means re-pinning every client);
    //  - the secret must never exist in a group/world readable file, not
    //    even for the instant between fopen() and chmod().
    const std::string tmp = path + ".tmp";
    const std::string line = b64_encode(blob) + "\n";
    bool wrote = false;
#ifndef _WIN32
    // O_CREAT with mode 0600 sets the mode at creation, so there is no
    // interval in which the key is readable by anyone else.
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        size_t done = 0;
        while (done < line.size()) {
            const ssize_t n = ::write(fd, line.data() + done, line.size() - done);
            if (n <= 0) break;
            done += static_cast<size_t>(n);
        }
        wrote = (done == line.size()) && ::fsync(fd) == 0;
        ::close(fd);
    }
#else
    // The CRT's "wb" creates the file with the parent directory's inherited
    // ACL, which is the per-user profile here. _chmod can only toggle the
    // read-only bit, so this just clears it after a copy that carried it;
    // the real boundary is that default_identity_path() lives under the
    // user's own profile.
    FILE* f = std::fopen(tmp.c_str(), "wb");
    if (f) {
        _chmod(tmp.c_str(), _S_IREAD | _S_IWRITE);
        const size_t written = std::fwrite(line.data(), 1, line.size(), f);
        const bool flushed = std::fflush(f) == 0;
        wrote = (written == line.size()) && flushed && _commit(_fileno(f)) == 0;
        std::fclose(f);
    }
#endif
    sodium_memzero(blob.data(), blob.size());
    if (!wrote) {
        std::remove(tmp.c_str());
        return false;
    }
    // Plain ::rename() is POSIX-atomic but fails on Windows when the
    // destination exists, so use MoveFileEx there (same as the pin store).
#ifdef _WIN32
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::remove(tmp.c_str());
        return false;
    }
#else
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        return false;
    }
#endif
    return true;
}

bool ServerIdentity::has_key() const noexcept {
    return secret_key_.size() == crypto_sign_SECRETKEYBYTES &&
           public_key_.size() == crypto_sign_PUBLICKEYBYTES;
}

std::shared_ptr<ServerIdentity> load_or_create_identity(const std::string& path,
                                                        std::string* err) {
    if (path.empty()) {
        if (err) *err = "identity path must not be empty";
        return nullptr;
    }
    auto id = std::make_shared<ServerIdentity>();
    if (std::ifstream(path)) {
        if (id->load_keyfile(path)) return id;
        // Never regenerate over an existing file: that would silently
        // rotate the identity and every pinned client would see Changed.
        if (err) *err = "cannot load identity from " + path +
                        " (corrupt or not an identity key; refusing to overwrite)";
        return nullptr;
    }
    if (!id->generate()) {
        if (err) *err = "identity key generation failed";
        return nullptr;
    }
    if (!id->save_keyfile(path)) {
        if (err) *err = "cannot write identity to " + path;
        return nullptr;
    }
    return id;
}

std::string default_identity_path() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata && *appdata) return std::string(appdata) + "\\ncp\\identity.key";
    return "identity.key";
#else
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.ncp/identity.key";
    return "identity.key";
#endif
}

std::vector<uint8_t> ServerIdentity::public_key() const {
    return public_key_;
}

IdentityFingerprint ServerIdentity::fingerprint() const {
    IdentityFingerprint fp{};
    fingerprint_of_public_key(public_key_, fp);
    return fp;
}

std::string ServerIdentity::fingerprint_text() const {
    if (public_key_.size() != kPublicKeyBytes) return {};
    return fingerprint_to_text(fingerprint());
}

std::vector<uint8_t> ServerIdentity::sign_transcript(
    const uint8_t binding[32]) const {
    if (!has_key() || !binding) return {};

    // Domain-separated message. Built on the stack so the bytes are not
    // copied into a resizable buffer; the binding is public, so no
    // zeroing is required here.
    uint8_t msg[sizeof(kDomainTag) - 1 + 32 + kPublicKeyBytes];
    size_t off = 0;
    std::memcpy(msg + off, kDomainTag, sizeof(kDomainTag) - 1);
    off += sizeof(kDomainTag) - 1;
    std::memcpy(msg + off, binding, 32);
    off += 32;
    std::memcpy(msg + off, public_key_.data(), kPublicKeyBytes);
    off += kPublicKeyBytes;

    std::vector<uint8_t> sig(crypto_sign_BYTES);
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len, msg, off,
                             secret_key_.data()) != 0 ||
        sig_len != crypto_sign_BYTES) {
        return {};
    }
    return sig;
}

bool ServerIdentity::verify_transcript(
    const uint8_t binding[32],
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& signature) noexcept {
    if (!binding) return false;
    if (public_key.size() != kPublicKeyBytes) return false;
    if (signature.size() != kSignatureBytes) return false;

    uint8_t msg[sizeof(kDomainTag) - 1 + 32 + kPublicKeyBytes];
    size_t off = 0;
    std::memcpy(msg + off, kDomainTag, sizeof(kDomainTag) - 1);
    off += sizeof(kDomainTag) - 1;
    std::memcpy(msg + off, binding, 32);
    off += 32;
    std::memcpy(msg + off, public_key.data(), kPublicKeyBytes);
    off += kPublicKeyBytes;

    return crypto_sign_verify_detached(signature.data(), msg, off,
                                       public_key.data()) == 0;
}

// ============================================================================
// PinnedServerStore
// ============================================================================

const char* pin_verdict_to_string(PinVerdict v) noexcept {
    switch (v) {
        case PinVerdict::Unpinned: return "UNPINNED";
        case PinVerdict::Match:    return "MATCH";
        case PinVerdict::Changed:  return "CHANGED";
        case PinVerdict::Invalid:  return "INVALID";
    }
    return "INVALID";
}

struct PinnedServerStore::Impl {
    mutable std::mutex mutex;
    std::vector<PinEntry> entries;
    size_t parse_errors = 0;
    /// In-memory state has bookkeeping (last_seen / connections) that has
    /// not reached the file yet.
    bool dirty = false;
    /// When the file was last rewritten, for the debounce window.
    std::chrono::steady_clock::time_point last_persist{};
    /// Completed writes; see persist_count().
    size_t persist_count = 0;

    static constexpr auto kDebounce = std::chrono::seconds(30);

    PinEntry* find(const std::string& host) {
        for (auto& e : entries) {
            if (e.host == host) return &e;
        }
        return nullptr;
    }
    const PinEntry* find(const std::string& host) const {
        for (const auto& e : entries) {
            if (e.host == host) return &e;
        }
        return nullptr;
    }
};

PinnedServerStore::PinnedServerStore()
    : impl_(new Impl()) {
    ensure_library_initialized();
}

PinnedServerStore::~PinnedServerStore() {
    // Flush debounced bookkeeping: the process is going away and the file
    // should not silently lag behind what the operator was shown.
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->dirty) (void)persist_locked_();
}

PinCheckResult PinnedServerStore::check(const std::string& host,
                                        const std::vector<uint8_t>& public_key,
                                        bool trust_on_first_use) {
    PinCheckResult r;
    r.host = host;

    IdentityFingerprint presented{};
    if (public_key.size() != ServerIdentity::kPublicKeyBytes ||
        !fingerprint_of_public_key(public_key, presented)) {
        r.verdict = PinVerdict::Invalid;
        return r;
    }
    r.presented = presented;

    std::lock_guard<std::mutex> lock(impl_->mutex);
    PinEntry* entry = impl_->find(host);
    const auto now = std::chrono::system_clock::now();

    if (!entry) {
        r.verdict = PinVerdict::Unpinned;
        if (trust_on_first_use) {
            PinEntry e;
            e.host = host;
            e.fingerprint = presented;
            e.public_key = public_key;
            e.first_seen = now;
            e.last_seen = now;
            e.connections = 1;
            impl_->entries.push_back(std::move(e));
            r.recorded = true;
            // A new pin is genuinely new durable state: write it now. If the
            // debounce window had been allowed to cover this, a crash between
            // the handshake and the flush would lose the only record of this
            // server's key.
            (void)persist_locked_();
        }
        return r;
    }

    if (fingerprint_equal(entry->fingerprint, presented)) {
        entry->last_seen = now;
        entry->connections += 1;
        r.verdict = PinVerdict::Match;
        r.pinned = entry->fingerprint;
        // Bookkeeping only — the pin itself is unchanged. Rewriting (and
        // fsync-replacing) the whole file for every TLS connection put a
        // full store rewrite on the handshake path.
        impl_->dirty = true;
        flush_if_due_locked_();
        return r;
    }

    // Key change: report both sides and leave the pin untouched. Silently
    // re-trusting here is precisely the failure mode pinning exists to
    // prevent, so the operator has to act deliberately.
    r.verdict = PinVerdict::Changed;
    r.pinned = entry->fingerprint;
    entry->last_seen = now;
    // Persist the observation promptly: this is the record an operator
    // investigating a key change needs, and it is rare unless someone is
    // actually swapping keys.
    (void)persist_locked_();
    return r;
}

bool PinnedServerStore::add_pin(const std::string& host,
                                const std::vector<uint8_t>& public_key,
                                std::string* err) {
    IdentityFingerprint fp{};
    if (host.empty()) {
        if (err) *err = "host must not be empty";
        return false;
    }
    if (!fingerprint_of_public_key(public_key, fp)) {
        if (err) *err = "public key must be exactly 32 bytes (Ed25519)";
        return false;
    }

    std::lock_guard<std::mutex> lock(impl_->mutex);
    const auto now = std::chrono::system_clock::now();
    PinEntry* entry = impl_->find(host);
    if (entry) {
        entry->fingerprint = fp;
        entry->public_key = public_key;
        entry->last_seen = now;
    } else {
        PinEntry e;
        e.host = host;
        e.fingerprint = fp;
        e.public_key = public_key;
        e.first_seen = now;
        e.last_seen = now;
        e.connections = 0;
        impl_->entries.push_back(std::move(e));
    }
    return persist_locked_();
}

bool PinnedServerStore::remove_pin(const std::string& host) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const auto it = std::find_if(impl_->entries.begin(), impl_->entries.end(),
                                 [&](const PinEntry& e) { return e.host == host; });
    if (it == impl_->entries.end()) return false;
    impl_->entries.erase(it);
    (void)persist_locked_();
    return true;
}

bool PinnedServerStore::has_pin(const std::string& host) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->find(host) != nullptr;
}

bool PinnedServerStore::get_pin(const std::string& host, PinEntry& out) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const PinEntry* e = impl_->find(host);
    if (!e) return false;
    out = *e;
    return true;
}

std::vector<PinEntry> PinnedServerStore::list() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::vector<PinEntry> out = impl_->entries;
    std::sort(out.begin(), out.end(),
              [](const PinEntry& a, const PinEntry& b) { return a.host < b.host; });
    return out;
}

size_t PinnedServerStore::size() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->entries.size();
}

size_t PinnedServerStore::parse_errors() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->parse_errors;
}

bool PinnedServerStore::load(const std::string& path, std::string* err) {
    std::ifstream in(path);
    if (!in) {
        if (err) *err = "cannot open " + path;
        return false;
    }

    std::vector<PinEntry> parsed;
    size_t errors = 0;
    std::string line;
    size_t line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        // host \t first_seen \t last_seen \t connections \t key_hex
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, '\t')) fields.push_back(field);
        if (fields.size() != 5) { ++errors; continue; }

        PinEntry e;
        e.host = fields[0];
        std::vector<uint8_t> key;
        // Ed25519 public keys are 32 bytes -> 64 hex characters.
        if (e.host.empty() || !parse_hex_exact(fields[4], 32, key)) {
            ++errors;
            continue;
        }
        char* end = nullptr;
        const long long first = std::strtoll(fields[1].c_str(), &end, 10);
        if (!end || *end != '\0') { ++errors; continue; }
        const long long last = std::strtoll(fields[2].c_str(), &end, 10);
        if (!end || *end != '\0') { ++errors; continue; }
        const long long conns = std::strtoll(fields[3].c_str(), &end, 10);
        if (!end || *end != '\0' || conns < 0) { ++errors; continue; }

        e.public_key = std::move(key);
        // Derive the fingerprint from the key so a hand-edited file cannot
        // desync the two representations.
        if (!fingerprint_of_public_key(e.public_key, e.fingerprint)) {
            ++errors;
            continue;
        }
        e.first_seen = from_unix(first);
        e.last_seen = from_unix(last);
        e.connections = static_cast<uint64_t>(conns);
        parsed.push_back(std::move(e));
    }

    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->entries = std::move(parsed);
    impl_->parse_errors = errors;
    impl_->dirty = false;
    path_ = path;
    return true;
}

bool PinnedServerStore::save(const std::string& path, std::string* err) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return save_unlocked_(path, err);
}

size_t PinnedServerStore::persist_count() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->persist_count;
}

bool PinnedServerStore::save_unlocked_(const std::string& path,
                                       std::string* err) const {
    const std::string dir = dir_of(path);
    if (!dir.empty() && !mkdir_one(dir)) {
        if (err) *err = "cannot create directory " + dir;
        return false;
    }

    std::ostringstream out;
    out << "# Dynam known_servers — do not edit by hand.\n"
        << "# host\tfirst_seen\tlast_seen\tconnections\tpublic_key_hex\n";
    {
        // No lock here: both callers (save / persist_locked_) already hold
        // impl_->mutex, and it is non-recursive.
        for (const auto& e : impl_->entries) {
            std::vector<uint8_t> key = e.public_key;
            std::string hex;
            static const char* kHex = "0123456789abcdef";
            hex.reserve(key.size() * 2);
            for (uint8_t b : key) {
                hex.push_back(kHex[(b >> 4) & 0x0F]);
                hex.push_back(kHex[b & 0x0F]);
            }
            out << e.host << '\t'
                << to_unix(e.first_seen) << '\t'
                << to_unix(e.last_seen) << '\t'
                << e.connections << '\t'
                << hex << '\n';
        }
    }

    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            if (err) *err = "cannot write " + tmp;
            return false;
        }
        f << out.str();
        if (!f.good()) {
            if (err) *err = "write failed for " + tmp;
            return false;
        }
    }
    // Replace atomically so an interrupted save cannot truncate the store
    // and silently unpin every server. Plain ::rename() is POSIX-atomic
    // but fails outright on Windows when the destination exists, so use
    // MoveFileEx there.
#ifdef _WIN32
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::remove(tmp.c_str());
        if (err) *err = "cannot replace " + path;
        return false;
    }
#else
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        if (err) *err = "cannot replace " + path;
        return false;
    }
#endif
    ++impl_->persist_count;
    // A copy written elsewhere does not bring the auto-persist file up to date.
    if (path == path_) {
        impl_->dirty = false;
        impl_->last_persist = std::chrono::steady_clock::now();
    }
    return true;
}

bool PinnedServerStore::persist_locked_() const {
    if (path_.empty()) return true;  // memory-only store
    return save_unlocked_(path_, nullptr);
}

void PinnedServerStore::flush_if_due_locked_() const {
    if (path_.empty() || !impl_->dirty) return;  // nothing to write
    const auto now = std::chrono::steady_clock::now();
    if (impl_->last_persist != std::chrono::steady_clock::time_point{} &&
        now - impl_->last_persist < Impl::kDebounce) {
        return;  // still inside the window; the destructor flushes later
    }
    (void)persist_locked_();
}

std::string PinnedServerStore::default_path() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata && *appdata) return std::string(appdata) + "\\ncp\\known_servers";
    return "known_servers";
#else
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.ncp/known_servers";
    return "known_servers";
#endif
}

bool PinnedServerStore::load_default(std::string* err) {
    const std::string path = default_path();
    std::ifstream probe(path);
    if (!probe) {
        // A missing file is a legitimate empty store on first run.
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->entries.clear();
        impl_->parse_errors = 0;
        impl_->dirty = false;
        path_ = path;
        return true;
    }
    probe.close();
    return load(path, err);
}

bool PinnedServerStore::save_default(std::string* err) const {
    return save(default_path(), err);
}

} // namespace ncp
