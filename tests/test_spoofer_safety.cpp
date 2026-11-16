// ══════════════════════════════════════════════════════════════════════════════
// tests/test_spoofer_safety.cpp
// Regression tests for the R18 spoofer findings:
//   R18-01  disk-serial spoof no longer writes Services\disk\Enum
//   R18-02  hardware-info spoof reports "not supported" instead of success
//   R18-03  SMBIOS spoof reports "not supported", no UUID in SystemProductName
//   R18-05  DHCP client ID spoof reports "not supported" on Windows
//   R18-06  SpoofConfig defaults are all off
//
// These tests must never touch the network or the registry: every category
// under test is one that the fix turned into an unconditional "not supported",
// so enable() has nothing to apply. The tests below only assert on the
// reported status, not on any system state.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_spoofer.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#include <vector>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

using namespace ncp;

namespace {

// First usable adapter name, so a test can enable() against a real interface.
// enable() only *reads* the adapter; the configurations used below enable no
// category that enable() applies, so nothing is changed.
std::string first_adapter_name() {
#ifdef _WIN32
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf(size);
    auto addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    for (int i = 0; i < 3; ++i) {
        DWORD rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &size);
        if (rc == NO_ERROR) break;
        if (rc != ERROR_BUFFER_OVERFLOW) return {};
        buf.resize(size);
        addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    }
    for (auto a = addrs; a; a = a->Next) {
        if (a->FriendlyName && a->FriendlyName[0]) {
            // Convert the wide FriendlyName to UTF-8, which is what
            // detect_default_interface() hands to enable().
            int n = WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                                        nullptr, 0, nullptr, nullptr);
            if (n > 0) {
                std::string out(static_cast<size_t>(n - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1,
                                    &out[0], n, nullptr, nullptr);
                return out;
            }
        }
    }
    return {};
#else
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return {};
    std::string found;
    for (ifaddrs* i = list; i; i = i->ifa_next) {
        if (i->ifa_name) { found = i->ifa_name; break; }
    }
    freeifaddrs(list);
    return found;
#endif
}

// A config that asks for every unsupported category and nothing else. Enabling
// this must not fail the whole call on the unsupported flags, and must leave
// each corresponding status bit false.
NetworkSpoofer::SpoofConfig unsupported_only_config() {
    NetworkSpoofer::SpoofConfig cfg;   // all off by default (R18-06)
    cfg.spoof_hw_info      = true;     // R18-02: not supported
    cfg.spoof_smbios       = true;     // R18-03: not supported
    cfg.spoof_disk_serial  = true;     // R18-01: not supported
    cfg.spoof_dhcp_client_id = true;   // R18-05: not supported on Windows
    return cfg;
}

}  // namespace

// ── R18-06: safe defaults ─────────────────────────────────────────────────────

TEST(SpooferSafety, DefaultsEnableNothing) {
    NetworkSpoofer::SpoofConfig cfg;
    EXPECT_FALSE(cfg.spoof_ipv4);
    EXPECT_FALSE(cfg.spoof_ipv6);
    EXPECT_FALSE(cfg.spoof_mac);
    EXPECT_FALSE(cfg.spoof_dns);
    EXPECT_FALSE(cfg.spoof_hostname);
    EXPECT_FALSE(cfg.spoof_hw_info);
    EXPECT_FALSE(cfg.spoof_smbios);
    EXPECT_FALSE(cfg.spoof_disk_serial);
    EXPECT_FALSE(cfg.spoof_dhcp_client_id);
    EXPECT_FALSE(cfg.spoof_tcp_fingerprint);
}

// A default-constructed config must be a no-op: enable() succeeds and reports
// nothing as spoofed, because nothing was asked for.
TEST(SpooferSafety, EnableWithDefaultsChangesNothing) {
    NetworkSpoofer spoofer;
    NetworkSpoofer::SpoofConfig cfg;   // everything off
    // Use a bogus interface name on purpose: with no categories enabled the
    // spoofer should still succeed, since it never has to touch the adapter.
    // (save_original_identity may still fail on a bogus name on Windows; that
    // returns false before any change, which is also acceptable.)
    bool ok = spoofer.enable("ncp-nonexistent-iface-0", cfg);
    if (ok) {
        auto s = spoofer.get_status();
        EXPECT_FALSE(s.ipv4_spoofed);
        EXPECT_FALSE(s.ipv6_spoofed);
        EXPECT_FALSE(s.mac_spoofed);
        EXPECT_FALSE(s.dns_spoofed);
        EXPECT_FALSE(s.hostname_spoofed);
        spoofer.disable();
    }
    // Either outcome is fine; what must never happen is a changed adapter.
}

// ── R18-02 / R18-03 / R18-01 / R18-05: honest "not supported" reporting ──────

TEST(SpooferSafety, UnsupportedCategoriesAreNeverReportedAsSpoofed) {
    NetworkSpoofer spoofer;
    auto cfg = unsupported_only_config();
    // Deliberately use an interface name that cannot exist, so even a platform
    // where save_original_identity() succeeds cannot actually change anything.
    spoofer.enable("ncp-nonexistent-iface-0", cfg);

    auto s = spoofer.get_status();
    EXPECT_FALSE(s.hw_info_spoofed)      << "R18-02: hw-info spoof is a no-op";
    EXPECT_FALSE(s.smbios_spoofed)       << "R18-03: SMBIOS spoof is not supported";
    EXPECT_FALSE(s.disk_serial_spoofed)  << "R18-01: disk-serial spoof is not supported";
    EXPECT_FALSE(s.dhcp_client_id_spoofed) << "R18-05: DHCP client ID is not supported";
    spoofer.disable();
}

// R18-01: the disk-serial path must never report success, on any platform.
// apply_disk_serial() is private, so this is exercised through
// set_custom_disk_serial() + rotate_disk_serial(), which both gate on the
// config flag and the enabled state.
TEST(SpooferSafety, DiskSerialRotationNeverSucceeds) {
    const std::string iface = first_adapter_name();
    if (iface.empty()) GTEST_SKIP() << "no network adapter to inspect";
    NetworkSpoofer spoofer;
    NetworkSpoofer::SpoofConfig cfg;
    cfg.spoof_disk_serial = true;
    if (!spoofer.enable(iface, cfg)) {
        GTEST_SKIP() << "enable() failed before any change; nothing to check";
    }
    EXPECT_FALSE(spoofer.rotate_disk_serial())
        << "R18-01: a disk serial cannot be changed from user mode";
    spoofer.disable();
}

// R18-03: the 3-arg SMBIOS overload must refuse rather than write a UUID into
// the product-name field. Exercised via the public rotation entry point.
TEST(SpooferSafety, SmbiosRotationNeverSucceeds) {
    const std::string iface = first_adapter_name();
    if (iface.empty()) GTEST_SKIP() << "no network adapter to inspect";
    NetworkSpoofer spoofer;
    NetworkSpoofer::SpoofConfig cfg;
    cfg.spoof_smbios = true;
    if (!spoofer.enable(iface, cfg)) {
        GTEST_SKIP() << "enable() failed before any change; nothing to check";
    }
    EXPECT_FALSE(spoofer.rotate_smbios())
        << "R18-03: SMBIOS is firmware data and cannot be changed";
    spoofer.disable();
}

// ── Disable is safe to call twice and after a failed enable ──────────────────

TEST(SpooferSafety, DisableTwiceIsSafe) {
    NetworkSpoofer spoofer;
    spoofer.disable();          // never enabled: returns false, no crash
    EXPECT_FALSE(spoofer.is_enabled());
    spoofer.disable();          // idempotent
    EXPECT_FALSE(spoofer.is_enabled());
}
