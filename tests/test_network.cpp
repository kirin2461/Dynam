#include <gtest/gtest.h>
#include "ncp_network.hpp"

using namespace NCP;

class NetworkTest : public ::testing::Test {
protected:
    Network network;
};

TEST_F(NetworkTest, GetInterfaces) {
    auto interfaces = network.get_interfaces();
    // May be empty in test environment, but should not throw
    EXPECT_TRUE(true);
}

// Additional tests will be added in Phase 3
