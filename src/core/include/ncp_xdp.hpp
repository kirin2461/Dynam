#pragma once

/**
 * @file ncp_xdp.hpp
 * @brief eBPF/XDP kernel-level packet processing (Enterprise layer).
 *
 * Zero-copy / near-zero-copy packet handling at the earliest possible point
 * in the Linux networking stack. This module manages the lifecycle of NCP's
 * XDP programs without requiring libbpf:
 *
 *   - compile_program():  clang -target bpf  (C source -> ELF object)
 *   - attach_generic():   iproute2 built-in ELF loader (xdpgeneric mode,
 *                         works on any driver incl. veth — used in the lab)
 *   - detach_generic():   ip xdpgeneric off
 *   - pinned-map I/O:     raw bpf(2) syscalls (BPF_OBJ_GET / BPF_MAP_*)
 *                         against maps pinned by the program under
 *                         /sys/fs/bpf/tc/globals/
 *
 * The reference program (bpf/xdp_udpmon_kern.c) counts UDP packets/bytes per
 * destination port and can selectively drop a configured port — the building
 * block for kernel-level AEMM multipath / phantom-splicing follow-ups.
 *
 * Thread safety: all methods are stateless/re-entrant.
 */

#include <cstdint>
#include <cstddef>
#include <string>

namespace ncp {

struct XdpStats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

class XdpManager {
public:
    /// Compile BPF C source into an ELF object via clang -target bpf.
    /// Returns false and fills err on failure (clang missing, compile error).
    static bool compile_program(const std::string& src_path,
                                const std::string& obj_path,
                                std::string& err,
                                const std::string& clang_bin = "clang");

    /// Attach an XDP program in generic (SKB) mode via iproute2.
    /// Generic mode works on any interface (incl. veth in containers).
    static bool attach_generic(const std::string& iface,
                               const std::string& obj_path,
                               const std::string& section,
                               std::string& err,
                               const std::string& ip_bin = "ip");

    /// Detach any generic-mode XDP program from the interface.
    static bool detach_generic(const std::string& iface,
                               std::string& err,
                               const std::string& ip_bin = "ip");

    /// True if a generic XDP program is currently attached to iface.
    static bool is_attached_generic(const std::string& iface,
                                    const std::string& ip_bin = "ip");

    /// Look up a value in a pinned BPF map via raw bpf(2) syscalls.
    /// pin_path: e.g. /sys/fs/bpf/tc/globals/udp_stats_map
    static bool map_lookup_pinned(const std::string& pin_path,
                                  const void* key, size_t key_len,
                                  void* value, size_t value_len);

    /// Update a value in a pinned BPF map via raw bpf(2) syscalls.
    static bool map_update_pinned(const std::string& pin_path,
                                  const void* key, size_t key_len,
                                  const void* value, size_t value_len);

    /// Convenience: read per-port UDP counters from the pinned stats map of
    /// bpf/xdp_udpmon_kern.c.
    static bool read_udp_stats(uint32_t dport, XdpStats& out,
                               const std::string& pin_path =
                                   "/sys/fs/bpf/tc/globals/udp_stats_map");

    /// Convenience: set/clear the selective-drop port (0 = disable).
    static bool set_drop_port(uint32_t dport,
                              const std::string& pin_path =
                                  "/sys/fs/bpf/tc/globals/xdp_config_map");

    /// Probe: does the kernel accept a minimal BPF_PROG_LOAD? (root needed)
    static bool kernel_supports_bpf();
};

} // namespace ncp
