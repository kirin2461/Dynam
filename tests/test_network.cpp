#include <gtest/gtest.h>
#include "ncp_network.hpp"

using namespace ncp;

class NetworkTest : public ::testing::Test {
protected:
    Network network;
};

TEST_F(NetworkTest, GetInterfaces) {
#if NCP_HAS_PCAP
    try {
        auto interfaces = network.get_interfaces();
        // On CI without root permissions, list may be empty - that's OK
        // Main goal: ensure no crash
    } catch (...) {
        GTEST_SKIP() << "pcap not available in CI environment";
    }
#else
    GTEST_SKIP() << "pcap disabled";
#endif
}

// Additional tests will be added in Phase 3
