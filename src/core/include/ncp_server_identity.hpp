#pragma once

/**
 * @file ncp_server_identity.hpp
 * @brief Long-term server identity + client-side pin store.
 *
 * Threat closed here: before this module the E2E key exchange
 * (ncp_e2e.hpp) proved only that a peer knew *a* private key. Nothing
 * bound that key to an identity, so anyone able to answer PortHop
 * datagrams could complete the handshake with their own keypair and
 * relay to the real server — a silent MITM inside a cryptographically
 * sound AEAD layer. See docs/SERVER_IDENTITY.md for the full analysis.
 *
 * Two halves:
 *
 *  1. ServerIdentity (server side) — a long-term Ed25519 key, created
 *     on first start by load_or_create_identity() at
 *     %APPDATA%\ncp\identity.key (or ~/.ncp/identity.key) unless an
 *     explicit path is given. The server signs the handshake transcript
 *     with it; the signature and the public key ride in the key-exchange
 *     response. An existing but unreadable file is an error, never a
 *     silent regeneration: rotating the key would unpin every client.
 *
 *  2. PinnedServerStore (client side) — an SSH-style known_hosts file.
 *     First connection records the fingerprint (TOFU); a later change is
 *     a hard failure that reports both fingerprints, not a silent
 *     re-trust. Set E2EConfig::pin_store + pin_host to enforce this
 *     inside the handshake; a Changed key fails complete_key_exchange().
 *
 * The fingerprint is BLAKE2b-256 over the raw 32-byte public key,
 * rendered as 52 uppercase base32 characters grouped 4-4-4-4-4-4-4-4-
 * 4-4-4-4-4 — 64 characters with the dashes, e.g.
 *   EJWT-6EUI-BCZ3-4U2O-DY6U-PQZ5-ZPWT-JQS5-TDFY-DPGL-MAK3-UMXC-GCUA
 * (the same shape as an SSH host-key fingerprint, so it is comparable
 * by eye over a voice channel).
 *
 * Trust boundary this does NOT cover: TOFU cannot distinguish a fresh
 * genuine server from a fresh fake one. The first fingerprint must be
 * compared out of band (`ncp identity show` on the server, read over a
 * channel the attacker does not control) or obtained from a signed
 * bundle. That is why ServerIdentity::fingerprint_text() exists.
 */

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ncp {

/// 32-byte BLAKE2b-256 digest of an Ed25519 public key, and its
/// human-comparable rendering.
using IdentityFingerprint = std::array<uint8_t, 32>;

/// Uppercase base32: 52 characters (256 bits, unpadded) grouped by 4
/// with '-', i.e. 13 groups and 64 characters in total. Deterministic.
std::string fingerprint_to_text(const IdentityFingerprint& fp);

/// Parse a fingerprint printed by fingerprint_to_text(). Accepts any
/// case and ignores '-' / whitespace separators. Fails on bad length or
/// non-base32 characters rather than returning a wrong value.
bool fingerprint_from_text(const std::string& text, IdentityFingerprint& out);

/// BLAKE2b-256 over the raw public key bytes. false if the key is not
/// exactly 32 bytes.
bool fingerprint_of_public_key(const std::vector<uint8_t>& public_key,
                               IdentityFingerprint& out);

/// Constant-time comparison of two fingerprints.
bool fingerprint_equal(const IdentityFingerprint& a,
                       const IdentityFingerprint& b) noexcept;

/**
 * @brief Digest the handshake is signed over.
 *
 *   binding = BLAKE2b-256( request_hash(32) || response_public_key(32) )
 *
 * request_hash binds the initiator's ephemeral key. response_public_key
 * binds the responder's. Signing only the request hash would leave a
 * hole: an on-path attacker could keep the (valid) signature while
 * swapping the responder's ephemeral key for their own, and the client
 * would derive a shared secret the attacker knows. Both peers compute
 * this same value, so neither side has to trust the other's arithmetic.
 *
 * @param request_hash         BLAKE2b-256 of the key-exchange request.
 * @param response_public_key  The responder's ephemeral DH public key.
 * @param out                  32-byte digest.
 */
bool handshake_binding_digest(const uint8_t request_hash[32],
                              const std::vector<uint8_t>& response_public_key,
                              uint8_t out[32]);

// ============================================================================
// Server side
// ============================================================================

/**
 * @brief Long-term Ed25519 server identity.
 *
 * Key file format matches SpaClient (`ncp spa keygen`): one base64 line
 * of the 96-byte blob [64-byte libsodium secret key || 32-byte pubkey].
 * Reusing the format means an operator can back up / transfer the
 * identity with the tooling they already have.
 */
class ServerIdentity {
public:
    ServerIdentity();
    ~ServerIdentity();
    ServerIdentity(const ServerIdentity&) = delete;
    ServerIdentity& operator=(const ServerIdentity&) = delete;

    /// Generate a fresh keypair, replacing any loaded one.
    bool generate();

    bool load_keyfile(const std::string& path);
    /// Writes mode 0600 on POSIX. Atomically replaces an existing file
    /// (temp file + fsync + rename), so a failed save leaves the previous
    /// identity intact. Fails if no key has been generated.
    bool save_keyfile(const std::string& path) const;

    bool has_key() const noexcept;

    /// Raw 32-byte public key. Empty when no key is loaded.
    std::vector<uint8_t> public_key() const;

    /// Fingerprint of the loaded public key. Zero-filled when no key.
    IdentityFingerprint fingerprint() const;

    /// The string an operator reads aloud / writes down. Empty when no key.
    std::string fingerprint_text() const;

    /**
     * @brief Sign a handshake binding digest.
     *
     * Signs the domain-separated message
     *   "ncp-server-identity-v1" || binding(32) || public_key(32)
     *
     * Domain separation matters: the same key must never produce a bare
     * signature over attacker-chosen bytes that could be replayed in
     * another protocol context (SPA, reality tokens and license keys all
     * live in this codebase). Build the digest with
     * handshake_binding_digest(), not ad hoc.
     *
     * @return 64-byte signature, or empty on failure / no key.
     */
    std::vector<uint8_t> sign_transcript(const uint8_t binding[32]) const;

    /**
     * @brief Verify a signature produced by sign_transcript().
     *
     * Both the public key and the signature are wire-supplied: this
     * rejects wrong-sized input before touching libsodium and never
     * throws.
     */
    static bool verify_transcript(const uint8_t binding[32],
                                  const std::vector<uint8_t>& public_key,
                                  const std::vector<uint8_t>& signature) noexcept;

    /// Length of the wire signature (64). Exposed for frame sizing.
    static constexpr size_t kSignatureBytes = 64;
    /// Length of an Ed25519 public key (32).
    static constexpr size_t kPublicKeyBytes = 32;

private:
    std::vector<uint8_t> secret_key_;  // 64 bytes
    std::vector<uint8_t> public_key_;  // 32 bytes
};

/**
 * @brief Load the server identity at `path`, generating and saving it on
 *        first use.
 *
 * This is the single entry point a server should use: the identity is
 * long-term, so "no file yet" must mean "create one once", while "file
 * exists but does not load" must NOT be silently replaced — regenerating
 * a corrupted identity would change every client's pin and is exactly the
 * hard failure the pin store reports as Changed.
 *
 * @param err  Set on failure; may be null.
 * @return The identity, or nullptr on failure.
 */
std::shared_ptr<ServerIdentity> load_or_create_identity(const std::string& path,
                                                        std::string* err);

/// Default key file location: %APPDATA%\ncp\identity.key on Windows,
/// ~/.ncp/identity.key elsewhere.
std::string default_identity_path();

// ============================================================================
// Client side
// ============================================================================

/// Outcome of checking a server key against the pin store.
enum class PinVerdict {
    Unpinned,   ///< never seen; caller decides whether to record it
    Match,      ///< pinned key confirmed
    Changed,    ///< pinned, but the server presented a different key
    Invalid     ///< server key was not a well-formed 32-byte Ed25519 key
};

const char* pin_verdict_to_string(PinVerdict v) noexcept;

struct PinEntry {
    std::string host;                  ///< "host:port" as the client dialed it
    IdentityFingerprint fingerprint{}; ///< BLAKE2b-256 of the server public key
    std::vector<uint8_t> public_key;   ///< full key, so the entry can be audited
    std::chrono::system_clock::time_point first_seen{};
    std::chrono::system_clock::time_point last_seen{};
    uint64_t connections = 0;
};

struct PinCheckResult {
    PinVerdict verdict = PinVerdict::Invalid;
    std::string host;
    /// Fingerprint the store holds (zero-filled when Unpinned).
    IdentityFingerprint pinned{};
    /// Fingerprint the server actually presented.
    IdentityFingerprint presented{};
    /// True when the store had no entry and it was created by this call.
    bool recorded = false;
};

/**
 * @brief SSH-style known_hosts for Dynam servers.
 *
 * File format is one line per host, tab-separated:
 *   host:port \t first_seen_unix \t last_seen_unix \t connections \t key_hex
 *
 * The fingerprint is derived from key_hex on load, so a hand-edited
 * file cannot desync the two. Lines that fail to parse are skipped and
 * counted in parse_errors() rather than aborting the load — a corrupt
 * entry must not lock the operator out of every other server.
 *
 * Thread safety: all public methods lock; the store may be shared
 * between the CLI, GUI and web control panel.
 */
class PinnedServerStore {
public:
    PinnedServerStore();
    ~PinnedServerStore();
    PinnedServerStore(const PinnedServerStore&) = delete;
    PinnedServerStore& operator=(const PinnedServerStore&) = delete;

    /**
     * @brief Verify a server key and, when trust_on_first_use is set,
     *        record an Unpinned key.
     *
     * @param host      Dial string, e.g. "vpn.example:443".
     * @param public_key Raw 32-byte Ed25519 key from the handshake.
     * @param trust_on_first_use
     *        true  -> an unknown host is recorded and reported as Unpinned
     *                 with recorded=true (the caller should surface the
     *                 fingerprint to the user).
     *        false -> an unknown host is reported Unpinned and NOT
     *                 recorded; the caller refuses the connection until
     *                 the operator adds the pin explicitly.
     *
     * A Changed verdict NEVER overwrites the old pin. Re-trusting on key
     * change is exactly the behaviour that makes pinning worthless, so
     * the operator must call remove_pin() explicitly.
     *
     * Persistence: a new pin (and a key change) is written immediately.
     * The bookkeeping on a Match — last_seen, connections — is debounced
     * and flushed at most once per 30 s, or by save()/save_default()/the
     * destructor, so a busy client does not rewrite the whole file on
     * every handshake. persist_count() reports completed writes.
     */
    PinCheckResult check(const std::string& host,
                         const std::vector<uint8_t>& public_key,
                         bool trust_on_first_use);

    /// Record or overwrite a pin deliberately (out-of-band verified).
    bool add_pin(const std::string& host, const std::vector<uint8_t>& public_key,
                 std::string* err = nullptr);

    bool remove_pin(const std::string& host);

    bool has_pin(const std::string& host) const;
    bool get_pin(const std::string& host, PinEntry& out) const;

    /// All pins, sorted by host. Safe to display.
    std::vector<PinEntry> list() const;

    size_t size() const;
    size_t parse_errors() const;

    /**
     * @brief How many times the store has been written to disk.
     *
     * Bookkeeping from check() (last_seen, connections) is debounced, so
     * repeated checks of the same host must NOT grow this. Exposed so tests
     * can prove that without depending on file timestamps.
     */
    size_t persist_count() const;

    bool load(const std::string& path, std::string* err = nullptr);
    bool save(const std::string& path, std::string* err = nullptr) const;

    /**
     * @brief Default location: %APPDATA%\ncp\known_servers on Windows,
     *        ~/.ncp/known_servers elsewhere. Creates the parent directory.
     */
    static std::string default_path();

    /// Load default_path(); missing file is success (empty store).
    bool load_default(std::string* err = nullptr);
    bool save_default(std::string* err = nullptr) const;

private:
    /// Caller must NOT hold the mutex.
    bool persist_locked_() const;
    /// Caller MUST hold the mutex. A dirty store is written only once per
    /// debounce window, so per-connection bookkeeping does not rewrite the
    /// file on every handshake.
    void flush_if_due_locked_() const;
    /// Caller MUST already hold the mutex. Exists so mutating methods can
    /// persist without re-entering the non-recursive lock.
    bool save_unlocked_(const std::string& path, std::string* err) const;

    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string path_;  ///< last loaded/saved path; used by auto-persist
};

// ============================================================================
// Wire format for the signed key-exchange response (v1)
// ============================================================================

/**
 * The key-exchange response gains a trailer after the existing 32-byte
 * transcript hash:
 *
 *   offset            size  field
 *   ...                     (existing body, unchanged)
 *   [4 + pk_len]       32   request_hash        (existing)
 *   +32                 1   sig_present flag    (0x01 = signed)
 *   +33                32   server_public_key   (Ed25519)
 *   +65                64   signature
 *
 * The signature covers handshake_binding_digest() — request_hash plus
 * the responder's ephemeral key — which is what stops an on-path
 * attacker from keeping a valid signature while substituting their own
 * ephemeral key.
 *
 * A response without the flag byte is a legacy/anonymous response. E2E
 * rejects it when the responder has no identity configured; a client
 * that requires authentication must reject it too. There is no silent
 * downgrade to an anonymous handshake.
 *
 * The name strings below are the single source of truth for lengths so
 * the CLI, tests and the E2E parser cannot drift apart.
 */
namespace server_identity_wire {
constexpr uint8_t kSignedResponseFlag = 0x01;
constexpr size_t  kPublicKeyBytes     = 32;
constexpr size_t  kSignatureBytes     = 64;
constexpr size_t  kTrailerBytes       = 1 + kPublicKeyBytes + kSignatureBytes;  // 97
} // namespace server_identity_wire

} // namespace ncp
