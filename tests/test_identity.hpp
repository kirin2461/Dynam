// Shared responder identity for handshake tests.
//
// Production handshakes are identity-signed and E2EConfig::require_server_identity
// defaults to true, so a client rejects an anonymous responder with
// "handshake did not complete". Any fixture that builds a session Config by hand
// must wire an identity or its handshake never establishes. One process-wide key
// keeps every fixture in a test binary agreeing on the same public key.
#pragma once

#include "ncp_server_identity.hpp"

#include <memory>

inline const std::shared_ptr<ncp::ServerIdentity>& test_server_identity() {
    static const std::shared_ptr<ncp::ServerIdentity> identity = [] {
        auto p = std::make_shared<ncp::ServerIdentity>();
        p->generate();
        return p;
    }();
    return identity;
}
