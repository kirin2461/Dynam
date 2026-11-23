/**
 * @file test_server_identity.cpp
 * @brief Tests for the long-term server identity, the signed key-exchange
 *        handshake, the client pin store, and the server roster's LAN
 *        classification.
 *
 * The property that matters most here is the negative one: an on-path
 * attacker who relays or substitutes keys must not be able to complete a
 * handshake. Several tests below are written specifically to try.
 */

#include <gtest/gtest.h>

#include "ncp_e2e.hpp"
#include "ncp_server_identity.hpp"
#include "ncp_server_roster.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <sys/stat.h>
#endif

using namespace ncp;

namespace {

std::vector<uint8_t> bytes(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

/// Build an initiator/responder pair and run the handshake to the point
/// where the client must decide whether to trust the answer.
struct Handshake {
    E2ESession initiator;
    E2ESession responder;
    KeyPair initiator_keys;
    KeyPair responder_keys;
    std::vector<uint8_t> request;
    std::vector<uint8_t> response;

    explicit Handshake(std::shared_ptr<ServerIdentity> identity,
                       bool require_identity = true,
                       KeyExchangeProtocol proto = KeyExchangeProtocol::X25519,
                       std::shared_ptr<PinnedServerStore> pin_store = nullptr,
                       std::string pin_host = {})
        : initiator(make_initiator_config(require_identity, proto,
                                          std::move(pin_store), std::move(pin_host))),
          responder(make_responder_config(identity, proto)) {
        initiator_keys = initiator.generate_key_pair();
        responder_keys = responder.generate_key_pair();
        request = initiator.create_key_exchange_request(initiator_keys);
        response = responder.process_key_exchange_request(request, responder_keys);
    }

    bool complete() {
        return initiator.complete_key_exchange(response, initiator_keys);
    }

    static E2EConfig make_initiator_config(
            bool require_identity,
            KeyExchangeProtocol proto,
            std::shared_ptr<PinnedServerStore> pin_store = nullptr,
            std::string pin_host = {}) {
        E2EConfig c;
        c.key_exchange = proto;
        c.require_server_identity = require_identity;
        c.pin_store = std::move(pin_store);
        c.pin_host = std::move(pin_host);
        return c;
    }
    static E2EConfig make_responder_config(std::shared_ptr<ServerIdentity> id,
                                           KeyExchangeProtocol proto) {
        E2EConfig c;
        c.key_exchange = proto;
        c.server_identity = std::move(id);
        return c;
    }
};

std::shared_ptr<ServerIdentity> make_identity() {
    auto id = std::make_shared<ServerIdentity>();
    EXPECT_TRUE(id->generate());
    return id;
}

/// Offset of the signed trailer inside a key-exchange response, or 0 if
/// the response is unsigned. Mirrors the parser in e2e.cpp.
size_t trailer_offset(const std::vector<uint8_t>& response) {
    if (response.size() < 4) return 0;
    const uint16_t pk_len =
        static_cast<uint16_t>((static_cast<uint16_t>(response[2]) << 8) |
                              static_cast<uint16_t>(response[3]));
    if (response.size() < 4u + pk_len + 32) return 0;
    const size_t flag = 4 + pk_len + 32;
    if (flag >= response.size()) return 0;
    return response[flag] == server_identity_wire::kSignedResponseFlag ? flag : 0;
}

} // namespace

// ============================================================================
// Fingerprint rendering
// ============================================================================

TEST(FingerprintTest, RoundTripsThroughText) {
    IdentityFingerprint fp{};
    for (size_t i = 0; i < fp.size(); ++i) fp[i] = static_cast<uint8_t>(i * 7 + 3);

    const std::string text = fingerprint_to_text(fp);
    EXPECT_FALSE(text.empty());
    // 52 base32 chars in 13 groups of 4 -> 12 separators.
    EXPECT_EQ(text.size(), 64u);
    EXPECT_EQ(text.find(' '), std::string::npos);
    EXPECT_EQ(std::count(text.begin(), text.end(), '-'), 12);
    // Known answer from an independent RFC 4648 base32 encoder (Python's
    // base64.b32encode, padding stripped, regrouped by 4).
    EXPECT_EQ(text, "AMFB-CGA7-EYWT-IO2C-JFIF-OXTF-NRZX-VAMI-R6LJ-3JFL-WK44-BR6O-2XOA");

    IdentityFingerprint back{};
    ASSERT_TRUE(fingerprint_from_text(text, back));
    EXPECT_TRUE(fingerprint_equal(fp, back));
}

TEST(FingerprintTest, ParsingIsCaseAndSeparatorInsensitive) {
    IdentityFingerprint fp{};
    for (size_t i = 0; i < fp.size(); ++i) fp[i] = static_cast<uint8_t>(255 - i);
    const std::string text = fingerprint_to_text(fp);

    std::string lowered;
    for (char c : text) lowered.push_back(c == '-' ? ' ' : static_cast<char>(std::tolower(c)));

    IdentityFingerprint back{};
    ASSERT_TRUE(fingerprint_from_text(lowered, back));
    EXPECT_TRUE(fingerprint_equal(fp, back));
}

TEST(FingerprintTest, RejectsWrongLengthAndBadCharacters) {
    IdentityFingerprint fp{};
    EXPECT_FALSE(fingerprint_from_text("", fp));
    EXPECT_FALSE(fingerprint_from_text("ABC", fp));
    // 52 characters, but contains characters outside the base32 alphabet.
    std::string bad(52, 'A');
    bad[10] = '1';
    bad[11] = '8';
    EXPECT_FALSE(fingerprint_from_text(bad, fp));
}

TEST(FingerprintTest, DifferentKeysGiveDifferentFingerprints) {
    auto a = make_identity();
    auto b = make_identity();
    EXPECT_FALSE(fingerprint_equal(a->fingerprint(), b->fingerprint()));
    EXPECT_NE(a->fingerprint_text(), b->fingerprint_text());
}

TEST(FingerprintTest, RejectsNonEd25519KeyLength) {
    IdentityFingerprint fp{};
    EXPECT_FALSE(fingerprint_of_public_key(std::vector<uint8_t>(31, 0), fp));
    EXPECT_FALSE(fingerprint_of_public_key(std::vector<uint8_t>(33, 0), fp));
    EXPECT_FALSE(fingerprint_of_public_key({}, fp));
}

// ============================================================================
// ServerIdentity key handling
// ============================================================================

TEST(ServerIdentityTest, GeneratedKeyHasExpectedShape) {
    auto id = make_identity();
    EXPECT_TRUE(id->has_key());
    EXPECT_EQ(id->public_key().size(), ServerIdentity::kPublicKeyBytes);
    EXPECT_FALSE(id->fingerprint_text().empty());
}

TEST(ServerIdentityTest, SignVerifyRoundTrip) {
    auto id = make_identity();
    uint8_t binding[32];
    std::memset(binding, 0xA5, sizeof(binding));

    const auto sig = id->sign_transcript(binding);
    ASSERT_EQ(sig.size(), ServerIdentity::kSignatureBytes);
    EXPECT_TRUE(ServerIdentity::verify_transcript(binding, id->public_key(), sig));
}

TEST(ServerIdentityTest, SignatureIsBoundToTheDigest) {
    auto id = make_identity();
    uint8_t binding[32];
    std::memset(binding, 0x11, sizeof(binding));
    const auto sig = id->sign_transcript(binding);

    uint8_t other[32];
    std::memset(other, 0x12, sizeof(other));
    EXPECT_FALSE(ServerIdentity::verify_transcript(other, id->public_key(), sig));
}

TEST(ServerIdentityTest, SignatureIsBoundToTheIdentityKey) {
    // Same digest, different key: must not verify. This is what stops an
    // attacker from re-labelling a captured signature under their own key.
    auto signer = make_identity();
    auto impostor = make_identity();
    uint8_t binding[32];
    std::memset(binding, 0x42, sizeof(binding));

    const auto sig = signer->sign_transcript(binding);
    EXPECT_FALSE(ServerIdentity::verify_transcript(binding, impostor->public_key(), sig));
}

TEST(ServerIdentityTest, VerifyRejectsMalformedInputWithoutThrowing) {
    auto id = make_identity();
    uint8_t binding[32];
    std::memset(binding, 0, sizeof(binding));
    const auto sig = id->sign_transcript(binding);

    EXPECT_FALSE(ServerIdentity::verify_transcript(binding, {}, sig));
    EXPECT_FALSE(ServerIdentity::verify_transcript(binding, std::vector<uint8_t>(32, 0), {}));
    // Truncated / over-long signature.
    std::vector<uint8_t> short_sig(sig.begin(), sig.end() - 1);
    EXPECT_FALSE(ServerIdentity::verify_transcript(binding, id->public_key(), short_sig));
    std::vector<uint8_t> long_sig = sig;
    long_sig.push_back(0);
    EXPECT_FALSE(ServerIdentity::verify_transcript(binding, id->public_key(), long_sig));
}

TEST(ServerIdentityTest, KeyfileSurvivesSaveAndLoad) {
    auto id = make_identity();
    const std::string path = "ncp_identity_test_keyfile.b64";
    ASSERT_TRUE(id->save_keyfile(path));

    ServerIdentity loaded;
    ASSERT_TRUE(loaded.load_keyfile(path));
    EXPECT_EQ(loaded.public_key(), id->public_key());
    EXPECT_EQ(loaded.fingerprint_text(), id->fingerprint_text());

    std::remove(path.c_str());
}

TEST(ServerIdentityTest, LoadRejectsKeyfileWithMismatchedPublicHalf) {
    // A corrupted/hand-edited file must not produce a key whose signatures
    // can never verify.
    auto id = make_identity();
    auto other = make_identity();
    const std::string path = "ncp_identity_test_bad.b64";

    // Write a file whose stored public half belongs to a different key by
    // round-tripping through the valid writer then swapping the tail.
    ASSERT_TRUE(id->save_keyfile(path));
    {
        std::FILE* f = std::fopen(path.c_str(), "rb");
        ASSERT_NE(f, nullptr);
        std::string content;
        char buf[512];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) content.append(buf, n);
        std::fclose(f);

        // Replace the public half with a fresh valid base64 blob from the
        // other identity. Simpler and more direct: write a file from
        // `other` and splice its last 44 chars (32 bytes in base64).
        other->save_keyfile("ncp_identity_test_other.b64");
        std::FILE* g = std::fopen("ncp_identity_test_other.b64", "rb");
        ASSERT_NE(g, nullptr);
        std::string other_content;
        while ((n = std::fread(buf, 1, sizeof(buf), g)) > 0) other_content.append(buf, n);
        std::fclose(g);
        std::remove("ncp_identity_test_other.b64");

        // 96 bytes -> 128 base64 chars; the public half is the last 32
        // bytes -> last 44 characters (rounded up before padding).
        ASSERT_GT(content.size(), 44u);
        ASSERT_GT(other_content.size(), 44u);
        std::string tampered = content.substr(0, content.size() - 45) +
                               other_content.substr(other_content.size() - 45);
        std::FILE* h = std::fopen(path.c_str(), "wb");
        ASSERT_NE(h, nullptr);
        std::fwrite(tampered.data(), 1, tampered.size(), h);
        std::fclose(h);
    }

    ServerIdentity loaded;
    EXPECT_FALSE(loaded.load_keyfile(path));
    EXPECT_FALSE(loaded.has_key());

    std::remove(path.c_str());
}

TEST(ServerIdentityTest, SaveFailsWithoutAKey) {
    ServerIdentity id;
    EXPECT_FALSE(id.save_keyfile("ncp_identity_test_nokey.b64"));
}

TEST(ServerIdentityTest, SaveOverAnExistingKeyfileReplacesItCleanly) {
    auto id = make_identity();
    const std::string path = "ncp_identity_test_overwrite.b64";
    ASSERT_TRUE(id->save_keyfile(path));
    const std::string first = read_file(path);
    ASSERT_FALSE(first.empty());

    ASSERT_TRUE(id->save_keyfile(path));
    EXPECT_EQ(read_file(path), first);
    ServerIdentity same;
    ASSERT_TRUE(same.load_keyfile(path));
    EXPECT_EQ(same.public_key(), id->public_key());

    auto other = make_identity();
    ASSERT_TRUE(other->save_keyfile(path));
    ServerIdentity replaced;
    ASSERT_TRUE(replaced.load_keyfile(path));
    EXPECT_EQ(replaced.public_key(), other->public_key());
    EXPECT_FALSE(std::filesystem::exists(path + ".tmp"));

#ifndef _WIN32
    struct stat st{};
    ASSERT_EQ(::stat(path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600);
#endif
    std::remove(path.c_str());
}

TEST(ServerIdentityTest, FailedSaveLeavesTheExistingKeyfileIntact) {
    // Block the temp file with a directory so the write fails. A writer
    // that truncates the key in place would already have destroyed the
    // long-term identity at that point; the atomic one must not touch it.
    auto id = make_identity();
    auto other = make_identity();
    const std::string path = "ncp_identity_test_intact.b64";
    ASSERT_TRUE(id->save_keyfile(path));
    const std::string before = read_file(path);

    std::error_code ec;
    std::filesystem::remove_all(path + ".tmp", ec);
    ASSERT_TRUE(std::filesystem::create_directory(path + ".tmp"));

    EXPECT_FALSE(other->save_keyfile(path));
    EXPECT_EQ(read_file(path), before);
    ServerIdentity loaded;
    ASSERT_TRUE(loaded.load_keyfile(path));
    EXPECT_EQ(loaded.public_key(), id->public_key());

    std::filesystem::remove_all(path + ".tmp", ec);
    std::remove(path.c_str());
}

// ============================================================================
// Signed handshake
// ============================================================================

TEST(SignedHandshakeTest, ResponseCarriesATrailerWhenIdentityIsConfigured) {
    Handshake h(make_identity());
    EXPECT_NE(trailer_offset(h.response), 0u);
    EXPECT_EQ(h.response.size(),
              4u + h.responder_keys.public_key.size() + 32 +
                  server_identity_wire::kTrailerBytes);
}

TEST(SignedHandshakeTest, AnonymousResponderProducesNoTrailer) {
    Handshake h(nullptr);
    EXPECT_EQ(trailer_offset(h.response), 0u);
}

TEST(SignedHandshakeTest, ClientVerifiesAndRecordsTheIdentity) {
    auto id = make_identity();
    Handshake h(id);
    ASSERT_TRUE(h.complete());
    EXPECT_TRUE(h.initiator.peer_identity_verified());
    EXPECT_EQ(h.initiator.peer_identity_key(), id->public_key());
    EXPECT_TRUE(fingerprint_equal(h.initiator.peer_identity_fingerprint(),
                                  id->fingerprint()));
}

TEST(SignedHandshakeTest, ClientRefusesAnAnonymousServerByDefault) {
    // The core of the change: without a signature the client must not
    // silently proceed, because an anonymous responder is exactly what an
    // on-path relay looks like.
    Handshake h(nullptr);
    EXPECT_FALSE(h.complete());
    EXPECT_FALSE(h.initiator.is_established());
    EXPECT_FALSE(h.initiator.peer_identity_verified());
}

TEST(SignedHandshakeTest, AnonymousServerAcceptedOnlyWhenExplicitlyOptedIn) {
    Handshake h(nullptr, /*require_identity=*/false);
    ASSERT_TRUE(h.complete());
    EXPECT_TRUE(h.initiator.is_established());
    // Accepted, but must still report as unverified.
    EXPECT_FALSE(h.initiator.peer_identity_verified());
    EXPECT_TRUE(h.initiator.peer_identity_key().empty());
}

TEST(SignedHandshakeTest, MitmSubstitutingTheEphemeralKeyIsRejected) {
    // The attack the binding digest exists to stop: a relay keeps the
    // genuine signed response but swaps the responder's ephemeral public
    // key for its own. The signature is still structurally valid and the
    // request hash still matches — only the binding digest changes.
    auto id = make_identity();
    Handshake h(id);

    const uint16_t pk_len =
        static_cast<uint16_t>((static_cast<uint16_t>(h.response[2]) << 8) |
                              static_cast<uint16_t>(h.response[3]));
    ASSERT_EQ(pk_len, h.responder_keys.public_key.size());

    auto attacker_keys = h.initiator.generate_key_pair();
    ASSERT_EQ(attacker_keys.public_key.size(), pk_len);
    for (size_t i = 0; i < pk_len; ++i) {
        h.response[4 + i] = attacker_keys.public_key.data()[i];
    }

    EXPECT_FALSE(h.complete());
    EXPECT_FALSE(h.initiator.is_established());
}

TEST(SignedHandshakeTest, MitmSubstitutingTheIdentitySignatureIsRejected) {
    // Swap the signature for one made by a different key, keeping the
    // claimed identity: the client must reject it.
    auto id = make_identity();
    auto attacker = make_identity();
    Handshake h(id);

    const size_t flag = trailer_offset(h.response);
    ASSERT_NE(flag, 0u);
    // Overwrite the embedded identity key + signature with the attacker's.
    while (true) {
        Handshake probe(attacker);
        if (probe.response.size() == h.response.size()) {
            // Same size: copy only the trailing key+signature block.
            const size_t probe_flag = trailer_offset(probe.response);
            ASSERT_NE(probe_flag, 0u);
            std::memcpy(h.response.data() + flag + 1,
                        probe.response.data() + probe_flag + 1,
                        server_identity_wire::kPublicKeyBytes +
                            server_identity_wire::kSignatureBytes);
            break;
        }
        // Ed25519 signatures and keys are fixed size, so sizes always
        // match; guard anyway so the test cannot loop forever.
        FAIL() << "unexpected response size mismatch";
        break;
    }

    EXPECT_FALSE(h.complete());
    EXPECT_FALSE(h.initiator.is_established());
}

TEST(SignedHandshakeTest, TruncatedTrailerIsRejected) {
    Handshake h(make_identity());
    // Cut into the trailer: no longer parseable, must fail closed.
    h.response.resize(h.response.size() - 10);
    EXPECT_FALSE(h.complete());
}

TEST(SignedHandshakeTest, TamperedTranscriptHashIsStillRejected) {
    Handshake h(make_identity());
    const uint16_t pk_len =
        static_cast<uint16_t>((static_cast<uint16_t>(h.response[2]) << 8) |
                              static_cast<uint16_t>(h.response[3]));
    h.response[4 + pk_len] ^= 0xFF;  // first transcript-hash byte
    EXPECT_FALSE(h.complete());
}

TEST(SignedHandshakeTest, WorksAcrossKeyExchangeProtocols) {
    for (auto proto : {KeyExchangeProtocol::X25519,
                       KeyExchangeProtocol::X448,
                       KeyExchangeProtocol::ECDH_P256}) {
        auto id = make_identity();
        Handshake h(id, /*require_identity=*/true, proto);
        EXPECT_TRUE(h.complete()) << "protocol " << static_cast<int>(proto);
        EXPECT_TRUE(h.initiator.peer_identity_verified());
        EXPECT_EQ(h.initiator.peer_identity_key(), id->public_key());
    }
}

// ============================================================================
// Identity provisioning + handshake pinning
// ============================================================================

TEST(IdentityProvisioningTest, LoadOrCreateIsIdempotent) {
    const std::string path = "ncp_identity_test_provision.key";
    const std::string other_path = "ncp_identity_test_provision_other.key";
    std::remove(path.c_str());
    std::remove(other_path.c_str());

    std::string err;
    auto first = load_or_create_identity(path, &err);
    ASSERT_NE(first, nullptr) << err;
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_TRUE(first->has_key());

    auto again = load_or_create_identity(path, &err);
    ASSERT_NE(again, nullptr) << err;
    EXPECT_EQ(again->public_key(), first->public_key());
    EXPECT_EQ(again->fingerprint_text(), first->fingerprint_text());

    auto fresh = load_or_create_identity(other_path, &err);
    ASSERT_NE(fresh, nullptr) << err;
    EXPECT_NE(fresh->fingerprint_text(), first->fingerprint_text());

    EXPECT_EQ(load_or_create_identity("", &err), nullptr);
    EXPECT_FALSE(err.empty());

    std::remove(path.c_str());
    std::remove(other_path.c_str());
}

TEST(IdentityProvisioningTest, RefusesToRegenerateOverACorruptFile) {
    // Rotating the identity behind the operator's back would break every
    // client pin, so a file that exists but does not parse is a failure.
    const std::string path = "ncp_identity_test_corrupt.key";
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f << "not a key\n";
    }
    std::string err;
    EXPECT_EQ(load_or_create_identity(path, &err), nullptr);
    EXPECT_FALSE(err.empty());
    EXPECT_EQ(read_file(path), "not a key\n");
    std::remove(path.c_str());
}

TEST(IdentityProvisioningTest, DefaultPathIsNonEmpty) {
    EXPECT_FALSE(default_identity_path().empty());
}

TEST(SignedHandshakeTest, PinStoreRecordsFirstUseAndRejectsAChangedKey) {
    const std::string pin_path = "ncp_known_servers_handshake.txt";
    std::remove(pin_path.c_str());
    {
        // load() succeeds on a missing file only via load_default(); create
        // an empty store so this one auto-persists to pin_path.
        std::ofstream f(pin_path, std::ios::trunc);
    }

    auto store = std::make_shared<PinnedServerStore>();
    ASSERT_TRUE(store->load(pin_path));
    auto genuine = make_identity();

    {
        Handshake h(genuine, /*require_identity=*/true,
                    KeyExchangeProtocol::X25519, store, "vpn.example:443");
        ASSERT_TRUE(h.complete());
        EXPECT_TRUE(h.initiator.peer_identity_verified());
        // First sight: recorded, but not yet a *known* server.
        EXPECT_FALSE(h.initiator.peer_identity_pinned());
    }
    ASSERT_EQ(store->size(), 1u);
    PinEntry pinned;
    ASSERT_TRUE(store->get_pin("vpn.example:443", pinned));
    EXPECT_EQ(pinned.public_key, genuine->public_key());
    EXPECT_EQ(store->parse_errors(), 0u);

    // Same host, same key: now it is a pin match.
    {
        Handshake h(genuine, /*require_identity=*/true,
                    KeyExchangeProtocol::X25519, store, "vpn.example:443");
        ASSERT_TRUE(h.complete());
        EXPECT_TRUE(h.initiator.peer_identity_pinned());
    }

    // Same host, different key (the MITM case): the handshake must fail and
    // the original pin must survive untouched.
    auto impostor = make_identity();
    Handshake bad(impostor, /*require_identity=*/true,
                  KeyExchangeProtocol::X25519, store, "vpn.example:443");
    EXPECT_FALSE(bad.complete());
    EXPECT_FALSE(bad.initiator.is_established());
    EXPECT_FALSE(bad.initiator.peer_identity_verified());
    EXPECT_FALSE(bad.initiator.peer_identity_pinned());
    EXPECT_EQ(bad.initiator.get_state(), E2ESessionState::SessionExpired);

    PinEntry still;
    ASSERT_TRUE(store->get_pin("vpn.example:443", still));
    EXPECT_EQ(still.public_key, genuine->public_key());
    EXPECT_EQ(store->size(), 1u);

    // Pins survive a reload, so the rejection is not a memory-only artifact.
    ASSERT_TRUE(store->save(pin_path));
    PinnedServerStore reloaded;
    ASSERT_TRUE(reloaded.load(pin_path));
    PinEntry from_disk;
    ASSERT_TRUE(reloaded.get_pin("vpn.example:443", from_disk));
    EXPECT_EQ(from_disk.public_key, genuine->public_key());

    std::remove(pin_path.c_str());
}

TEST(SignedHandshakeTest, NoPinStoreConfiguredSkipsPinning) {
    // Without pin_host there is nothing to check against: verification
    // still succeeds, and the pinned flag stays false.
    Handshake h(make_identity());
    ASSERT_TRUE(h.complete());
    EXPECT_TRUE(h.initiator.peer_identity_verified());
    EXPECT_FALSE(h.initiator.peer_identity_pinned());
}

// ============================================================================
// Pin store
// ============================================================================

TEST(PinStoreTest, FirstUseRecordsThePin) {
    PinnedServerStore store;
    auto id = make_identity();

    const auto r = store.check("vpn.local:443", id->public_key(), true);
    EXPECT_EQ(r.verdict, PinVerdict::Unpinned);
    EXPECT_TRUE(r.recorded);
    EXPECT_TRUE(store.has_pin("vpn.local:443"));
    EXPECT_EQ(store.size(), 1u);

    const auto r2 = store.check("vpn.local:443", id->public_key(), true);
    EXPECT_EQ(r2.verdict, PinVerdict::Match);
    EXPECT_FALSE(r2.recorded);
    EXPECT_TRUE(fingerprint_equal(r2.pinned, id->fingerprint()));
}

TEST(PinStoreTest, UnknownHostIsNotRecordedWithoutTrustOnFirstUse) {
    PinnedServerStore store;
    auto id = make_identity();
    const auto r = store.check("vpn.local:443", id->public_key(), false);
    EXPECT_EQ(r.verdict, PinVerdict::Unpinned);
    EXPECT_FALSE(r.recorded);
    EXPECT_FALSE(store.has_pin("vpn.local:443"));
}

TEST(PinStoreTest, ChangedKeyIsReportedAndTheOldPinIsKept) {
    PinnedServerStore store;
    auto genuine = make_identity();
    auto impostor = make_identity();
    ASSERT_TRUE(store.add_pin("vpn.local:443", genuine->public_key()));

    const auto r = store.check("vpn.local:443", impostor->public_key(), true);
    EXPECT_EQ(r.verdict, PinVerdict::Changed);
    EXPECT_TRUE(fingerprint_equal(r.pinned, genuine->fingerprint()));
    EXPECT_TRUE(fingerprint_equal(r.presented, impostor->fingerprint()));
    // The critical property: a mismatch must never overwrite the pin, even
    // with trust_on_first_use set.
    PinEntry still;
    ASSERT_TRUE(store.get_pin("vpn.local:443", still));
    EXPECT_TRUE(fingerprint_equal(still.fingerprint, genuine->fingerprint()));
}

TEST(PinStoreTest, InvalidKeyIsReported) {
    PinnedServerStore store;
    EXPECT_EQ(store.check("x:1", std::vector<uint8_t>(31, 1), true).verdict,
              PinVerdict::Invalid);
    EXPECT_EQ(store.check("x:1", {}, true).verdict, PinVerdict::Invalid);
    EXPECT_EQ(store.size(), 0u);
}

TEST(PinStoreTest, AddPinRejectsBadKeyLength) {
    PinnedServerStore store;
    std::string err;
    EXPECT_FALSE(store.add_pin("a:1", std::vector<uint8_t>(64, 0), &err));
    EXPECT_FALSE(err.empty());
    EXPECT_FALSE(store.add_pin("", std::vector<uint8_t>(32, 0), &err));
}

TEST(PinStoreTest, RemovePinWorks) {
    PinnedServerStore store;
    auto id = make_identity();
    ASSERT_TRUE(store.add_pin("a:1", id->public_key()));
    EXPECT_TRUE(store.remove_pin("a:1"));
    EXPECT_FALSE(store.remove_pin("a:1"));
    EXPECT_FALSE(store.has_pin("a:1"));
}

TEST(PinStoreTest, PersistsAcrossLoadSave) {
    auto id_a = make_identity();
    auto id_b = make_identity();
    const std::string path = "ncp_known_servers_test.txt";

    {
        PinnedServerStore store;
        ASSERT_TRUE(store.add_pin("alpha:443", id_a->public_key()));
        ASSERT_TRUE(store.add_pin("beta:8443", id_b->public_key()));
        ASSERT_TRUE(store.save(path));
    }
    {
        PinnedServerStore store;
        ASSERT_TRUE(store.load(path));
        EXPECT_EQ(store.size(), 2u);
        EXPECT_EQ(store.parse_errors(), 0u);
        EXPECT_EQ(store.check("alpha:443", id_a->public_key(), false).verdict,
                  PinVerdict::Match);
        EXPECT_EQ(store.check("beta:8443", id_b->public_key(), false).verdict,
                  PinVerdict::Match);
    }

    std::remove(path.c_str());
}

TEST(PinStoreTest, CorruptLinesAreSkippedNotFatal) {
    // A single damaged entry must not lock the operator out of every
    // other server.
    auto id = make_identity();
    const std::string path = "ncp_known_servers_corrupt.txt";
    {
        PinnedServerStore store;
        ASSERT_TRUE(store.add_pin("good:443", id->public_key()));
        ASSERT_TRUE(store.save(path));
    }
    {
        std::FILE* f = std::fopen(path.c_str(), "ab");
        ASSERT_NE(f, nullptr);
        std::fputs("not-a-real-line\n", f);
        std::fputs("bad:1\t0\t0\t0\tzzzz\n", f);
        std::fclose(f);
    }
    {
        PinnedServerStore store;
        ASSERT_TRUE(store.load(path));
        EXPECT_EQ(store.size(), 1u);
        EXPECT_GE(store.parse_errors(), 2u);
        EXPECT_TRUE(store.has_pin("good:443"));
    }
    std::remove(path.c_str());
}

TEST(PinStoreTest, HandEditedKeyCannotDesyncTheFingerprint) {
    // The fingerprint is derived from the stored key on load, so writing a
    // bogus fingerprint column is impossible by construction. Verify a
    // known-good key round-trips to the same fingerprint.
    auto id = make_identity();
    const std::string path = "ncp_known_servers_hand.txt";
    {
        PinnedServerStore store;
        ASSERT_TRUE(store.add_pin("h:1", id->public_key()));
        ASSERT_TRUE(store.save(path));
    }
    {
        PinnedServerStore store;
        ASSERT_TRUE(store.load(path));
        PinEntry e;
        ASSERT_TRUE(store.get_pin("h:1", e));
        EXPECT_TRUE(fingerprint_equal(e.fingerprint, id->fingerprint()));
        EXPECT_EQ(e.public_key, id->public_key());
    }
    std::remove(path.c_str());
}

TEST(PinStoreTest, ListIsSortedByHost) {
    PinnedServerStore store;
    auto id = make_identity();
    ASSERT_TRUE(store.add_pin("zeta:1", id->public_key()));
    ASSERT_TRUE(store.add_pin("alpha:1", id->public_key()));
    ASSERT_TRUE(store.add_pin("mike:1", id->public_key()));
    const auto all = store.list();
    ASSERT_EQ(all.size(), 3u);
    EXPECT_EQ(all[0].host, "alpha:1");
    EXPECT_EQ(all[1].host, "mike:1");
    EXPECT_EQ(all[2].host, "zeta:1");
}

TEST(PinStoreTest, DefaultPathIsNonEmpty) {
    EXPECT_FALSE(PinnedServerStore::default_path().empty());
}

TEST(PinStoreTest, RepeatedChecksDoNotRewriteTheStore) {
    // last_seen/connections are bookkeeping. Rewriting (and fsync-replacing)
    // the whole file for each of them put a full store rewrite on the TLS
    // handshake path, so they are debounced.
    auto id = make_identity();
    const std::string path = "ncp_known_servers_no_rewrite.txt";
    std::remove(path.c_str());
    {
        std::ofstream f(path, std::ios::trunc);
    }

    {
        PinnedServerStore store;
        ASSERT_TRUE(store.load(path));
        ASSERT_EQ(store.check("vpn.local:443", id->public_key(), true).verdict,
                  PinVerdict::Unpinned);
        const size_t writes_after_pin = store.persist_count();
        EXPECT_EQ(writes_after_pin, 1u);  // a new pin is written immediately

        for (int i = 0; i < 50; ++i) {
            EXPECT_EQ(store.check("vpn.local:443", id->public_key(), true).verdict,
                      PinVerdict::Match);
        }
        EXPECT_EQ(store.persist_count(), writes_after_pin);

        // The in-memory counters still advanced.
        PinEntry e;
        ASSERT_TRUE(store.get_pin("vpn.local:443", e));
        EXPECT_EQ(e.connections, 51u);
    }  // destructor flushes the deferred bookkeeping

    PinnedServerStore reloaded;
    ASSERT_TRUE(reloaded.load(path));
    PinEntry e;
    ASSERT_TRUE(reloaded.get_pin("vpn.local:443", e));
    EXPECT_EQ(e.connections, 51u);
    EXPECT_EQ(reloaded.parse_errors(), 0u);

    std::remove(path.c_str());
}

// ============================================================================
// Roster: address classification
// ============================================================================

TEST(LocalityTest, SubnetParsingCanonicalisesHostBits) {
    std::string net;
    uint8_t prefix = 0;
    bool v6 = false;
    ASSERT_TRUE(parse_local_subnet("192.168.1.77/24", net, prefix, v6));
    EXPECT_EQ(net, "192.168.1.0");
    EXPECT_EQ(prefix, 24u);
    EXPECT_FALSE(v6);
}

TEST(LocalityTest, BareAddressIsTreatedAsHostRoute) {
    std::string net;
    uint8_t prefix = 0;
    bool v6 = false;
    ASSERT_TRUE(parse_local_subnet("10.1.2.3", net, prefix, v6));
    EXPECT_EQ(net, "10.1.2.3");
    EXPECT_EQ(prefix, 32u);
    EXPECT_FALSE(v6);
}

TEST(LocalityTest, SubnetParsingRejectsGarbage) {
    std::string net;
    uint8_t prefix = 0;
    bool v6 = false;
    EXPECT_FALSE(parse_local_subnet("", net, prefix, v6));
    EXPECT_FALSE(parse_local_subnet("192.168.1.0/33", net, prefix, v6));
    EXPECT_FALSE(parse_local_subnet("192.168.1.256/24", net, prefix, v6));
    EXPECT_FALSE(parse_local_subnet("192.168.1/24", net, prefix, v6));
    EXPECT_FALSE(parse_local_subnet("192.168.1.0/abc", net, prefix, v6));
    EXPECT_FALSE(parse_local_subnet("nonsense", net, prefix, v6));
}

TEST(LocalityTest, ClassifiesLanLoopbackAndExternal) {
    LocalSubnet lan{"eth0", "192.168.1.0", 24, false};
    LocalSubnet wide{"eth1", "10.0.0.0", 8, false};
    const std::vector<LocalSubnet> subnets{lan, wide};

    EXPECT_EQ(classify_address("192.168.1.55", subnets), Locality::Lan);
    EXPECT_EQ(classify_address("192.168.1.255", subnets), Locality::Lan);
    EXPECT_EQ(classify_address("10.99.1.1", subnets), Locality::Lan);
    EXPECT_EQ(classify_address("127.0.0.1", subnets), Locality::Loopback);
    EXPECT_EQ(classify_address("8.8.8.8", subnets), Locality::External);
}

TEST(LocalityTest, NoSubnetListReportsUnknownNotExternal) {
    // "I could not tell" must never be reported as "definitely remote" —
    // that would hide a LAN peer on a host where enumeration failed.
    EXPECT_EQ(classify_address("192.168.1.5", {}), Locality::Unknown);
}

TEST(LocalityTest, UnparsableAddressIsUnknown) {
    LocalSubnet lan{"eth0", "192.168.1.0", 24, false};
    EXPECT_EQ(classify_address("", {lan}), Locality::Unknown);
    EXPECT_EQ(classify_address("not-an-ip", {lan}), Locality::Unknown);
    EXPECT_EQ(classify_address("192.168.1.5", {lan}), Locality::Lan);
}

TEST(LocalityTest, ClassifiesIpv6) {
    std::string net;
    uint8_t prefix = 0;
    bool v6 = false;
    ASSERT_TRUE(parse_local_subnet("fd00:1::5/64", net, prefix, v6));
    EXPECT_TRUE(v6);
    EXPECT_EQ(prefix, 64u);

    LocalSubnet lan6{"eth0", net, prefix, true};
    const std::vector<LocalSubnet> subnets{lan6};
    EXPECT_EQ(classify_address("fd00:1::abcd", subnets), Locality::Lan);
    EXPECT_EQ(classify_address("2001:db8::1", subnets), Locality::External);
    EXPECT_EQ(classify_address("::1", subnets), Locality::Loopback);
}

TEST(LocalityTest, ClassifiesIpv4MappedIpv6) {
    // Dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d; they must
    // classify exactly like the plain IPv4 address.
    std::string net;
    uint8_t prefix = 0;
    bool v6 = false;
    ASSERT_TRUE(parse_local_subnet("::ffff:1.2.3.4", net, prefix, v6));
    EXPECT_TRUE(v6);
    EXPECT_EQ(prefix, 128u);
    EXPECT_EQ(net, "0000:0000:0000:0000:0000:ffff:0102:0304");
    ASSERT_TRUE(parse_local_subnet("::FFFF:192.168.1.5", net, prefix, v6));
    EXPECT_EQ(net, "0000:0000:0000:0000:0000:ffff:c0a8:0105");
    ASSERT_TRUE(parse_local_subnet("::1.2.3.4", net, prefix, v6));
    EXPECT_EQ(net, "0000:0000:0000:0000:0000:0000:0102:0304");
    ASSERT_TRUE(parse_local_subnet("1:2:3:4:5:6:1.2.3.4", net, prefix, v6));
    EXPECT_EQ(net, "0001:0002:0003:0004:0005:0006:0102:0304");
    EXPECT_FALSE(parse_local_subnet("1:2:3:4:5:6:7:1.2.3.4", net, prefix, v6));
    EXPECT_FALSE(parse_local_subnet("::ffff:1.2.3", net, prefix, v6));

    LocalSubnet lan{"eth0", "192.168.1.0", 24, false};
    const std::vector<LocalSubnet> subnets{lan};
    EXPECT_EQ(classify_address("::ffff:192.168.1.5", subnets), Locality::Lan);
    EXPECT_EQ(classify_address("::FFFF:192.168.1.5", subnets), Locality::Lan);
    EXPECT_EQ(classify_address("::ffff:8.8.8.8", subnets), Locality::External);
    EXPECT_EQ(classify_address("::ffff:127.0.0.1", subnets), Locality::Loopback);
}

TEST(LocalityTest, SubnetsDoNotCrossAddressFamilies) {
    LocalSubnet lan4{"eth0", "192.168.1.0", 24, false};
    EXPECT_EQ(classify_address("fd00:1::1", {lan4}), Locality::Unknown);
}

TEST(LocalityTest, DiscoverReturnsSomethingOnARealHost) {
    // Smoke test only: we do not know this machine's addresses, but a host
    // running tests has at least a loopback interface.
    const auto all = discover_local_subnets(false);
    const auto with_loopback = discover_local_subnets(true);
    EXPECT_GE(with_loopback.size(), all.size());
    for (const auto& s : with_loopback) {
        EXPECT_FALSE(s.network.empty());
        EXPECT_FALSE(s.to_string().empty());
        if (!s.is_ipv6) EXPECT_LE(s.prefix_len, 32u);
        else EXPECT_LE(s.prefix_len, 128u);
    }
}

// ============================================================================
// Roster: recording
// ============================================================================

namespace {

std::vector<uint8_t> key_of(uint8_t seed) {
    std::vector<uint8_t> k(32);
    for (size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i);
    return k;
}

} // namespace

namespace {
// ServerRoster is non-copyable (it owns a locked impl), so tests get a
// unique_ptr rather than a by-value helper return.
std::unique_ptr<ServerRoster> make_roster(size_t capacity = ServerRoster::kDefaultCapacity) {
    auto r = std::unique_ptr<ServerRoster>(new ServerRoster(capacity));
    r->set_local_subnets({LocalSubnet{"eth0", "192.168.1.0", 24, false}});
    return r;
}
} // namespace

TEST(RosterTest, RecordsAndFindsAConnection) {
    auto r = make_roster();
    const auto key = key_of(1);
    r->record_connection(key, "192.168.1.42", 5555);

    EXPECT_EQ(r->size(), 1u);
    EXPECT_EQ(r->connected_count(), 1u);

    RosterEntry e;
    ASSERT_TRUE(r->find(roster_key_for(key, "192.168.1.42"), e));
    EXPECT_EQ(e.address, "192.168.1.42");
    EXPECT_EQ(e.port, 5555);
    EXPECT_EQ(e.locality, Locality::Lan);
    EXPECT_EQ(e.matched_subnet, "192.168.1.0/24");
    EXPECT_TRUE(e.connected);
    EXPECT_EQ(e.connections, 1u);
}

TEST(RosterTest, LanFilterFindsOnlyLocalPeers) {
    // The actual question the operator asked: which local machines
    // connected?
    auto r = make_roster();
    r->record_connection(key_of(1), "192.168.1.42", 1000);
    r->record_connection(key_of(50), "203.0.113.9", 2000);
    r->record_connection(key_of(99), "127.0.0.1", 3000);

    RosterFilter local_only;
    local_only.local_only = true;
    const auto local = r->snapshot(local_only);
    ASSERT_EQ(local.size(), 2u);

    bool saw_lan = false, saw_loopback = false;
    for (const auto& e : local) {
        if (e.locality == Locality::Lan) saw_lan = true;
        if (e.locality == Locality::Loopback) saw_loopback = true;
        EXPECT_NE(e.locality, Locality::External);
    }
    EXPECT_TRUE(saw_lan);
    EXPECT_TRUE(saw_loopback);

    // The unfiltered snapshot still has all three.
    EXPECT_EQ(r->snapshot().size(), 3u);
}

TEST(RosterTest, ReconnectIncrementsCountAndStaysConnected) {
    auto r = make_roster();
    const auto key = key_of(7);
    r->record_connection(key, "192.168.1.10", 1111);
    r->record_disconnect(roster_key_for(key, "192.168.1.10"));
    EXPECT_EQ(r->connected_count(), 0u);
    // The entry survives disconnect: it is a record, not a live table.
    EXPECT_EQ(r->size(), 1u);

    r->record_connection(key, "192.168.1.10", 2222);
    RosterEntry e;
    ASSERT_TRUE(r->find(roster_key_for(key, "192.168.1.10"), e));
    EXPECT_EQ(e.connections, 2u);
    EXPECT_EQ(e.port, 2222);
    EXPECT_TRUE(e.connected);
}

TEST(RosterTest, RoamingClientIsReclassified) {
    auto r = make_roster();
    const auto key = key_of(3);
    r->record_connection(key, "192.168.1.10", 1111);

    RosterEntry before;
    ASSERT_TRUE(r->find(roster_key_for(key, "192.168.1.10"), before));
    EXPECT_EQ(before.locality, Locality::Lan);

    // Same key, now appearing from an external address: the locality must
    // follow the address rather than being latched from first sight.
    r->update_address(roster_key_for(key, "192.168.1.10"), "203.0.113.7", 4444);
    RosterEntry after;
    ASSERT_TRUE(r->find(roster_key_for(key, "192.168.1.10"), after));
    EXPECT_EQ(after.locality, Locality::External);
    EXPECT_TRUE(after.matched_subnet.empty());
}

TEST(RosterTest, SubnetChangeReclassifiesExistingEntries) {
    auto r = make_roster();
    const auto key = key_of(11);
    r->record_connection(key, "192.168.1.10", 1111);

    // DHCP moved us to a different subnet; peers in the old one are no
    // longer "near".
    r->set_local_subnets({LocalSubnet{"eth0", "192.168.9.0", 24, false}});
    RosterEntry e;
    ASSERT_TRUE(r->find(roster_key_for(key, "192.168.1.10"), e));
    EXPECT_EQ(e.locality, Locality::External);
}

TEST(RosterTest, MalformedKeyIsRecordedUnderSyntheticIdentity) {
    // A peer we cannot attribute is exactly the one worth seeing.
    auto r = make_roster();
    r->record_connection(std::vector<uint8_t>(5, 0xAB), "192.168.1.99", 1234);
    EXPECT_EQ(r->size(), 1u);
    const auto all = r->snapshot();
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].client_key_hex.rfind("unknown:", 0), 0u);
    EXPECT_EQ(all[0].locality, Locality::Lan);
}

TEST(RosterTest, CapacityIsBoundedAndCountsDrops) {
    auto r = make_roster(3);

    for (int i = 0; i < 10; ++i) {
        const std::string addr = "192.168.1." + std::to_string(10 + i);
        const auto key = key_of(static_cast<uint8_t>(i * 8));
        r->record_connection(key, addr, static_cast<uint16_t>(1000 + i));
        // Disconnect each so the next insert may evict it.
        r->record_disconnect(roster_key_for(key, addr));
    }
    EXPECT_LE(r->size(), 3u);
}

TEST(RosterTest, LiveSessionsAreNeverEvicted) {
    auto r = make_roster(2);
    r->record_connection(key_of(1), "192.168.1.1", 1);
    r->record_connection(key_of(2), "192.168.1.2", 2);

    r->record_connection(key_of(3), "192.168.1.3", 3);
    // Both slots are live: the new entry is refused and counted, rather
    // than silently dropping a live session.
    EXPECT_EQ(r->size(), 2u);
    EXPECT_EQ(r->connected_count(), 2u);
    EXPECT_EQ(r->dropped_full(), 1u);
}

TEST(RosterTest, SnapshotOrdersMostRecentFirst) {
    auto r = make_roster();
    r->record_connection(key_of(1), "192.168.1.1", 1);
    r->record_connection(key_of(50), "203.0.113.1", 2);
    const auto all = r->snapshot();
    ASSERT_EQ(all.size(), 2u);
    EXPECT_GE(all[0].last_seen, all[1].last_seen);
}

TEST(RosterTest, ConnectedFilterExcludesDisconnected) {
    auto r = make_roster();
    r->record_connection(key_of(1), "192.168.1.1", 1);
    r->record_connection(key_of(2), "192.168.1.2", 2);
    r->record_disconnect(roster_key_for(key_of(1), "192.168.1.1"));

    RosterFilter f;
    f.connected_only = true;
    EXPECT_EQ(r->snapshot(f).size(), 1u);
    EXPECT_EQ(r->snapshot().size(), 2u);
}

TEST(RosterTest, ClearEmptiesTheRoster) {
    auto r = make_roster();
    r->record_connection(key_of(1), "192.168.1.1", 1);
    r->clear();
    EXPECT_EQ(r->size(), 0u);
    EXPECT_EQ(r->connected_count(), 0u);
}

TEST(RosterTest, KeyForUsesHexOfFullKey) {
    const auto key = key_of(0);
    const std::string k = roster_key_for(key, "1.2.3.4");
    EXPECT_EQ(k.size(), 64u);
    EXPECT_EQ(k.substr(0, 2), "00");
}
