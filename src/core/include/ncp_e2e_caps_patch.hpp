#ifndef NCP_E2E_CAPS_PATCH_HPP
#define NCP_E2E_CAPS_PATCH_HPP

// ======================================================================
//  Patch for e2e.cpp — Capabilities Exchange Integration
// ======================================================================
//
//  This file documents the exact changes needed in e2e.cpp and ncp_e2e.hpp.
//
//  ---- ncp_e2e.hpp CHANGES ----
//
//  1. Add to E2ESession::Impl:
//     bool is_initiator_ = false;  // Set during handshake
//
//  2. In process_key_exchange_request() (responder):
//     pImpl_->is_initiator_ = false;
//
//  3. In complete_key_exchange() (initiator):
//     pImpl_->is_initiator_ = true;
//
//  4. Add public methods to E2ESession:
//     bool is_initiator() const;
//     // Capabilities exchange hook — called after ratchet init
//     void set_capabilities_handler(CapabilitiesHandler handler);
//
//  ---- e2e.cpp CHANGES ----
//
//  After init_ratchet_keys() in BOTH complete_key_exchange() and
//  process_key_exchange_request(), insert capabilities exchange.
//  Both sides send immediately, both sides receive.
//  Order doesn't matter — encrypt()/decrypt() work bidirectionally
//  after ratchet init.
//
//  The exchange is asynchronous: the actual send/receive happens
//  through a callback provided by the transport layer. The E2E
//  session doesn't own the socket.
//
//  ---- INTEGRATION PATTERN ----
//
//  Rather than modifying e2e.cpp directly (which would couple E2E
//  to capabilities), the recommended pattern is:
//
//  1. Transport layer detects SessionEstablished
//  2. Transport calls capabilities exchange protocol
//  3. Result applied to Orchestrator
//
//  This keeps E2E layer clean and capabilities as an optional layer.

#include "ncp_capabilities.hpp"
#include "ncp_e2e.hpp"
#include <sodium.h>
#include <functional>
#include <chrono>

namespace ncp {

// ======================================================================
//  Capabilities Exchange Controller
// ======================================================================
//
//  Sits between E2ESession and ProtocolOrchestrator.
//  Coordinates the 2-RTT capabilities exchange after E2E handshake.
//
//  Usage:
//    auto session = e2e_manager.get_session(peer_id);
//    CapabilitiesController ctrl(session, is_initiator);
//    ctrl.set_local_capabilities(my_caps);
//    ctrl.set_send_callback([&](auto& msg) { transport.send(msg); });
//
//    // After SessionEstablished:
//    ctrl.start_exchange();
//
//    // When receiving a message, check type first:
//    auto decrypted = session->decrypt(incoming);
//    auto type = CapabilitiesExchange::peek_type(*decrypted);
//    if (type == E2EMessageType::CAPABILITIES ||
//        type == E2EMessageType::CAPS_CONFIRM) {
//        ctrl.on_message_received(*decrypted);
//    } else {
//        // Normal application data
//        handle_data(CapabilitiesExchange::unwrap(*decrypted));
//    }
//
//    // When exchange completes:
//    if (ctrl.is_complete()) {
//        auto config = ctrl.get_negotiated_config();
//        orchestrator.apply_negotiated_config(config);
//    }

class CapabilitiesController {
public:
    enum class State {
        IDLE,               // Not started
        CAPS_SENT,          // Sent our capabilities, waiting for peer's
        CAPS_RECEIVED,      // Received peer's, computing negotiation
        CONFIRM_SENT,       // Sent HMAC confirmation
        CONFIRM_RECEIVED,   // Received peer's HMAC
        COMPLETE,           // Both confirmed, negotiation done
        FAILED,             // Exchange failed (timeout, HMAC mismatch, etc.)
        FALLBACK            // Timed out, using local-only config
    };

    using SendCallback = std::function<void(const EncryptedMessage&)>;

    CapabilitiesController(
        std::shared_ptr<E2ESession> session,
        bool is_initiator)
        : session_(std::move(session))
        , is_initiator_(is_initiator) {}

    void set_local_capabilities(const NCPCapabilities& caps) {
        local_caps_ = caps;
        // Fill morph seed with CSPRNG if empty
        bool all_zero = true;
        for (auto b : local_caps_.morph_seed) {
            if (b != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            randombytes_buf(local_caps_.morph_seed.data(),
                           NCP_MORPH_SEED_SIZE);
        }
    }

    void set_send_callback(SendCallback cb) {
        send_cb_ = std::move(cb);
    }

    /// Start the capabilities exchange.
    /// Encrypts and sends local capabilities via the E2E session.
    /// Returns false if session is not established.
    bool start_exchange() {
        if (!session_ || !session_->is_established()) return false;
        if (!send_cb_) return false;

        // Wrap capabilities with type tag
        auto msg = CapabilitiesExchange::wrap_capabilities(local_caps_);

        // Encrypt through E2E session (Double Ratchet)
        auto encrypted = session_->encrypt(msg);

        // Send via transport
        send_cb_(encrypted);

        state_ = State::CAPS_SENT;
        exchange_start_ = std::chrono::steady_clock::now();
        return true;
    }

    /// Handle an incoming decrypted message (already decrypted by E2E).
    /// Returns true if the message was consumed (capabilities/confirm).
    bool on_message_received(const std::vector<uint8_t>& decrypted) {
        if (decrypted.empty()) return false;

        auto type = CapabilitiesExchange::peek_type(decrypted);

        switch (type) {
            case E2EMessageType::CAPABILITIES:
                return handle_capabilities(decrypted);

            case E2EMessageType::CAPS_CONFIRM:
                return handle_confirm(decrypted);

            case E2EMessageType::DATA:
            default:
                return false;  // Not ours, pass to application
        }
    }

    /// Check if exchange has timed out.
    bool check_timeout() {
        if (state_ == State::COMPLETE || state_ == State::FAILED ||
            state_ == State::FALLBACK || state_ == State::IDLE) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - exchange_start_).count();

        if (elapsed >= CapabilitiesExchange::EXCHANGE_TIMEOUT_MS) {
            // Timeout — fallback to local-only config
            negotiated_ = negotiate_local_only(local_caps_);
            state_ = State::FALLBACK;
            return true;
        }
        return false;
    }

    State get_state() const { return state_; }
    bool is_complete() const {
        return state_ == State::COMPLETE || state_ == State::FALLBACK;
    }

    const NegotiatedConfig& get_negotiated_config() const {
        return negotiated_;
    }

    const NCPCapabilities& get_peer_capabilities() const {
        return peer_caps_;
    }

    bool is_initiator() const { return is_initiator_; }

private:
    bool handle_capabilities(const std::vector<uint8_t>& decrypted) {
        auto caps = CapabilitiesExchange::parse_capabilities(decrypted);
        if (!caps) {
            state_ = State::FAILED;
            return true;
        }

        peer_caps_ = *caps;

        // Negotiate
        negotiated_ = negotiate(local_caps_, peer_caps_);

        // Derive shared morph seed via HKDF
        // NOTE: This requires access to the shared secret from E2ESession.
        // The actual HKDF call happens in the transport layer integration,
        // using E2EUtils::derive_key() with the morph salt.
        // Here we just store the raw seeds for the caller to derive.
        //
        // The caller should do:
        //   auto salt = MorphSeedDerivation::build_salt(
        //       local_caps_.morph_seed, peer_caps_.morph_seed, is_initiator_);
        //   auto info = MorphSeedDerivation::info();
        //   negotiated_.morph_seed = hkdf(shared_secret, salt, info, 32);

        // Send confirmation HMAC
        // NOTE: HMAC computation requires session key access.
        // The confirmation is computed as:
        //   hmac = HMAC-SHA256(session_derived_key, negotiated.serialize_for_hmac())
        // For now, send the serialized negotiated config as the confirm payload.
        // The caller should replace this with actual HMAC.
        auto confirm_data = negotiated_.serialize_for_hmac();
        auto confirm_msg = CapabilitiesExchange::wrap_confirm(confirm_data);
        auto encrypted = session_->encrypt(confirm_msg);
        send_cb_(encrypted);

        state_ = (state_ == State::CAPS_SENT)
            ? State::CONFIRM_SENT  // We sent caps + confirm, waiting for peer's confirm
            : State::CONFIRM_SENT; // We received caps first, sent confirm

        return true;
    }

    bool handle_confirm(const std::vector<uint8_t>& decrypted) {
        auto payload = CapabilitiesExchange::unwrap(decrypted);

        // Verify: peer's negotiated config matches ours
        auto our_hmac = negotiated_.serialize_for_hmac();

        if (payload.size() != our_hmac.size()) {
            state_ = State::FAILED;
            return true;
        }

        // Constant-time comparison to prevent timing attacks
        if (sodium_memcmp(payload.data(), our_hmac.data(),
                          our_hmac.size()) != 0) {
            // HMAC mismatch — possible MITM selective capability stripping
            state_ = State::FAILED;
            return true;
        }

        state_ = State::COMPLETE;
        return true;
    }

    std::shared_ptr<E2ESession> session_;
    bool is_initiator_;
    SendCallback send_cb_;

    NCPCapabilities local_caps_;
    NCPCapabilities peer_caps_;
    NegotiatedConfig negotiated_;

    State state_ = State::IDLE;
    std::chrono::steady_clock::time_point exchange_start_;
};

} // namespace ncp

#endif // NCP_E2E_CAPS_PATCH_HPP
