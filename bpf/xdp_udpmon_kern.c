/* xdp_udpmon_kern.c — NCP XDP UDP monitor / selective drop (lab-verifiable).
 *
 * Legacy map-definition style (struct bpf_map_def) so the program can be
 * loaded by iproute2's built-in ELF loader without libbpf:
 *     ip link set dev <if> xdpgeneric obj xdp_udpmon_kern.o sec xdp
 *
 * Maps are pinned (PIN_GLOBAL_NS) so user space can read counters via
 * bpf(BPF_OBJ_GET)/bpf(BPF_MAP_LOOKUP_ELEM) after attach.
 *
 * Behaviour:
 *   - every UDP datagram is counted per destination port (packets+bytes)
 *   - if config.drop_port != 0 and dport == drop_port -> XDP_DROP
 *     (otherwise XDP_PASS)
 *
 * No kernel headers required — all structs/constants defined locally so a
 * bare `clang -target bpf` is enough.
 */

typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))

/* ---- minimal XDP / BPF definitions ---- */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2

#define ETH_P_IP   0x0800
#define IPPROTO_UDP 17

/* legacy map def for iproute2 loader */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
    __u32 inner_map_idx;
    __u32 numa_node;
    __u32 pinning;   /* 2 = PIN_GLOBAL_NS -> /sys/fs/bpf/tc/globals/<name> */
};

#define BPF_MAP_TYPE_HASH  1
#define BPF_MAP_TYPE_ARRAY 2
#define PIN_GLOBAL_NS 2

struct udp_stats {
    __u64 packets;
    __u64 bytes;
};

struct bpf_map_def SEC("maps") udp_stats_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct udp_stats),
    .max_entries = 1024,
    .pinning = PIN_GLOBAL_NS,
};

struct bpf_map_def SEC("maps") xdp_config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),  /* drop_port, 0 = disabled */
    .max_entries = 1,
    .pinning = PIN_GLOBAL_NS,
};

/* BPF helper */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

/* ---- packet headers (packed, no kernel headers) ---- */
struct eth_hdr {
    __u8 dst[6];
    __u8 src[6];
    __u16 proto;   /* big endian */
} __attribute__((packed));

struct ip_hdr {
    __u8 ihl_version;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct udp_hdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} __attribute__((packed));

static __inline __u16 bpf_ntohs_local(__u16 v) {
    return (v >> 8) | (v << 8);
}

SEC("xdp")
int xdp_udpmon(struct xdp_md *ctx) {
    /* void* arithmetic on raw context pointers (BPF style) */
    __u64 data = ctx->data;
    __u64 data_end = ctx->data_end;

    struct eth_hdr *eth = (struct eth_hdr *)data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    if (bpf_ntohs_local(eth->proto) != ETH_P_IP)
        return XDP_PASS;

    struct ip_hdr *ip = (struct ip_hdr *)(data + sizeof(*eth));
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ihl = (ip->ihl_version & 0x0F) * 4;
    struct udp_hdr *udp = (struct udp_hdr *)((__u8 *)ip + ihl);
    if ((__u64)(__u8 *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    __u32 dport = bpf_ntohs_local(udp->dest);

    /* stats */
    struct udp_stats *st = bpf_map_lookup_elem(&udp_stats_map, &dport);
    if (st) {
        st->packets += 1;
        st->bytes += (data_end - data);
    }

    /* selective drop */
    __u32 zero = 0;
    __u32 *drop_port = bpf_map_lookup_elem(&xdp_config_map, &zero);
    if (drop_port && *drop_port != 0 && *drop_port == dport)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
