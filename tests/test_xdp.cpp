// test_xdp.cpp — unit tests for ncp_xdp (XdpManager).
// Environment-dependent tests SKIP gracefully (no clang / no root / no BPF).

#include <gtest/gtest.h>
#include "ncp_xdp.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace ncp;

namespace {

const char* kTestSrc = "/tmp/test_xdp_prog.c";
const char* kTestObj = "/tmp/test_xdp_prog.o";

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

} // namespace

TEST(XdpTest, CompileProgramProducesElf) {
    if (!have_clang()) GTEST_SKIP() << "clang not installed";
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
    if (!have_clang()) GTEST_SKIP() << "clang not installed";
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
