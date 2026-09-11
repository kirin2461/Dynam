// test_xdp.cpp — unit tests for ncp_xdp (XdpManager).
// Environment-dependent tests SKIP gracefully (no clang / no root / no BPF).

#include <gtest/gtest.h>
#include "ncp_xdp.hpp"

#ifdef _WIN32

// XDP/eBPF is a Linux kernel feature; XdpManager is a linkable stub on
// Windows (run_cmd reports failure like a missing binary would), so only
// the clean-failure contract is meaningful here.
TEST(XdpTest, AttachFailsCleanlyOnWindows) {
    std::string err;
    EXPECT_FALSE(ncp::XdpManager::attach_generic("any", "/nonexistent.o",
                                                 "xdp", err));
    EXPECT_FALSE(err.empty());
}

#else  // Linux/POSIX — full test suite

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace ncp;

namespace {

const char* kTestSrc = "/tmp/test_xdp_prog.c";
const char* kTestObj = "/tmp/test_xdp_prog.o";

// TSan: fork()+execvp() in compile_program is not instrumentable — a forked
// child of an instrumented process can deadlock on TSan's internal mutexes.
// The compile path is exercised by the unsanitized Linux CI jobs instead.
#if defined(__SANITIZE_THREAD__)
constexpr bool kUnderTsan = true;
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
constexpr bool kUnderTsan = true;
#else
constexpr bool kUnderTsan = false;
#endif
#else
constexpr bool kUnderTsan = false;
#endif

bool have_clang() {
    return ::system("which clang >/dev/null 2>&1") == 0;
}

bool write_test_source() {
    std::ofstream f(kTestSrc);
    f << "typedef unsigned int __u32;\n"
         "#define SEC(N) __attribute__((section(N), used))\n"
         "struct xdp_md { __u32 data; __u32 data_end; __u32 data_meta;"
         " __u32 ingress_ifindex; __u32 rx_queue_index; __u32 egress_ifindex; };\n"
         "SEC(\"xdp\") int prog(struct xdp_md *ctx) { return 2; }\n"
         "char _license[] SEC(\"license\") = \"GPL\";\n";
    return f.good();
}

// Probe whether the installed clang actually has the BPF backend: some
// distro/CI clang builds are compiled without it and fail with
// "error: unsupported target 'bpf'" even though the binary exists.
bool have_bpf_backend() {
    const char* probe_src = "/tmp/test_xdp_probe.c";
    const char* probe_obj = "/tmp/test_xdp_probe.o";
    {
        std::ofstream f(probe_src);
        f << "int ncp_probe(void) { return 0; }\n";
        if (!f.good()) return false;
    }
    std::string err;
    const bool ok = XdpManager::compile_program(probe_src, probe_obj, err);
    std::remove(probe_src);
    std::remove(probe_obj);
    return ok;
}

} // namespace

TEST(XdpTest, CompileProgramProducesElf) {
    if (kUnderTsan) GTEST_SKIP() << "fork+exec under TSan is unsupported";
    if (!have_clang()) GTEST_SKIP() << "clang not installed";
    if (!have_bpf_backend()) GTEST_SKIP() << "clang lacks BPF target support";
    ASSERT_TRUE(write_test_source());
    std::string err;
    ASSERT_TRUE(XdpManager::compile_program(kTestSrc, kTestObj, err)) << err;
    std::ifstream obj(kTestObj, std::ios::binary);
    char magic[4] = {0,0,0,0};
    obj.read(magic, 4);
    EXPECT_EQ(magic[0], 0x7F);
    EXPECT_EQ(magic[1], 'E');
    EXPECT_EQ(magic[2], 'L');
    EXPECT_EQ(magic[3], 'F');
    std::remove(kTestSrc);
    std::remove(kTestObj);
}

TEST(XdpTest, CompileFailsOnBadSource) {
    if (kUnderTsan) GTEST_SKIP() << "fork+exec under TSan is unsupported";
    if (!have_clang()) GTEST_SKIP() << "clang not installed";
    if (!have_bpf_backend()) GTEST_SKIP() << "clang lacks BPF target support";
    std::ofstream f("/tmp/test_xdp_bad.c");
    f << "this is not C code {{{\n";
    f.close();
    std::string err;
    EXPECT_FALSE(XdpManager::compile_program("/tmp/test_xdp_bad.c",
                                             "/tmp/test_xdp_bad.o", err));
    EXPECT_FALSE(err.empty());
    std::remove("/tmp/test_xdp_bad.c");
}

TEST(XdpTest, AttachFailsOnMissingIface) {
    // Even without root, attaching to a nonexistent interface must fail cleanly.
    std::string err;
    bool ok = XdpManager::attach_generic("no_such_iface_zzz", "/nonexistent.o",
                                         "xdp", err);
    EXPECT_FALSE(ok);
    EXPECT_FALSE(err.empty());
}

TEST(XdpTest, KernelBpfProbeConsistent) {
    // Must not crash; result depends on privileges, both are acceptable.
    bool supported = XdpManager::kernel_supports_bpf();
    SUCCEED() << "kernel_supports_bpf=" << supported;
}

TEST(XdpTest, MapOpsOnMissingPinFailCleanly) {
    uint32_t key = 0;
    uint64_t val = 0;
    EXPECT_FALSE(XdpManager::map_lookup_pinned("/nonexistent/pin/path",
                                               &key, sizeof(key),
                                               &val, sizeof(val)));
    EXPECT_FALSE(XdpManager::map_update_pinned("/nonexistent/pin/path",
                                               &key, sizeof(key),
                                               &val, sizeof(val)));
}

TEST(XdpTest, MapFindMissingFailsCleanly) {
    // Without privileges returns -1 (EPERM on GET_NEXT_ID); with privileges
    // returns -1 for a structure/name that does not exist. No crash either way.
    EXPECT_EQ(XdpManager::map_find("ncp_no_such_map_xyz", 1, 4, 8, 65535), -1);
}

// NOTE: stats/drop behavior against a live attached program is verified by
// the lab integration test (netns + veth), not here — unit environment may
// or may not have an attached program.

// Full attach/detach/counter flow is exercised by the Docker lab integration
// test (needs NET_ADMIN + writable /sys/fs/bpf); kept out of unit tests.

#endif  // _WIN32
