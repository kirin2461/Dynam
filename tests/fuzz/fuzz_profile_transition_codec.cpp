#include "ncp_profile_transition.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

// Do not use assert(): the project's RelWithDebInfo flags define NDEBUG.
// Fuzz oracles must remain executable in every build configuration.
void require(bool condition) {
    if (!condition) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> wire(data, data + size);
    const auto decoded = ncp::ProfileTransitionCodec::decode(wire);
    if (!decoded) return 0;

    // A decoder success must always belong to the encoder's valid domain and
    // remain decodable after canonical re-encoding. No parser state is global,
    // so every fuzz input is independent of all preceding inputs.
    const auto encoded = ncp::ProfileTransitionCodec::encode(*decoded);
    require(encoded.has_value());
    // The accepted wire language is canonical: every accepted field, including
    // counters/direction/reason/grace, must survive byte-exactly. This also
    // rejects any hidden normalization or trailing-byte acceptance.
    require(*encoded == wire);
    const auto roundtrip = ncp::ProfileTransitionCodec::decode(*encoded);
    require(roundtrip.has_value());
    require(roundtrip->type == decoded->type);
    require(roundtrip->session_id == decoded->session_id);
    require(roundtrip->transition_id == decoded->transition_id);
    require(roundtrip->profile_epoch == decoded->profile_epoch);
    require(roundtrip->effective_counter == decoded->effective_counter);
    require(roundtrip->crypto_epoch == decoded->crypto_epoch);
    require(roundtrip->direction == decoded->direction);
    require(roundtrip->reason == decoded->reason);
    require(roundtrip->grace_ms == decoded->grace_ms);
    require(roundtrip->target == decoded->target);
    return 0;
}
