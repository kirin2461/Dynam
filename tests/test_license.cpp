#include <gtest/gtest.h>
#include "ncp_license.hpp"

using namespace NCP;

class LicenseTest : public ::testing::Test {
protected:
    License license;
};

TEST_F(LicenseTest, GetHWID) {
    std::string hwid = license.get_hwid();
    EXPECT_FALSE(hwid.empty());
}

TEST_F(LicenseTest, IsExpired) {
    auto now = std::chrono::system_clock::now();
    auto future = now + std::chrono::hours(24);
    auto past = now - std::chrono::hours(24);
    
    EXPECT_FALSE(license.is_expired(future));
    EXPECT_TRUE(license.is_expired(past));
}

// Additional tests will be added in Phase 2
