#include "../include/ncp_l3_stealth.hpp"
#include <cstring>
#include <algorithm>
#include <unordered_map>
#include <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

namespace ncp {

// ==================== IP/TCP Header Structs ====================

#pragma pack(push, 1)
struct IPv4Header {
    uint8_t  ihl_ver;       // version (4 bits) + IHL (4 bits)
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;            // IPID — target for randomization
    uint16_t frag_off;      // flags (3 bits) + fragment offset (13 bits)
    uint8_t  ttl;           // TTL — target for normalization
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct IPv6Header {
    uint32_t ver_tc_flow;   // version(4) + traffic class(8) + flow label(20)
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;     // Hop Limit — target for normalization
    uint8_t  saddr[16];
    uint8_t  daddr[16];
};

struct TCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  res_doff;      // data offset (4 bits) + reserved (4 bits)
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct PseudoHeaderV4 {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_length;
};

struct PseudoHeaderV6 {
    uint8_t  saddr[16];
    uint8_t  daddr[16];
    uint32_t tcp_length;
    uint8_t  zeros[3];
    uint8_t  next_header;
};
#pragma pack(pop)

// TCP option kinds
static constexpr uint8_t TCP_OPT_END   = 0;
static constexpr uint8_t TCP_OPT_NOP   = 1;
static constexpr uint8_t TCP_OPT_MSS   = 2;
static constexpr uint8_t TCP_OPT_TS    = 8;

// TCP flags
static constexpr uint8_t TCP_FLAG_SYN = 0x02;

// DF bit mask in frag_off field (network byte order depends on platform)
static constexpr uint16_t IP_FLAG_DF = 0x4000;
static constexpr uint16_t IP_FLAG_MF = 0x2000;
static constexpr uint16_t IP_OFFSET_MASK = 0x1FFF;

// Flow label cache eviction constants
static constexpr size_t FLOW_LABEL_CACHE_MAX = 10000;
static constexpr auto FLOW_LABEL_TTL = std::chrono::minutes(5);

// ==================== L3Stealth Implementation ====================

L3Stealth::L3Stealth() = default;
L3Stealth::~L3Stealth() = default;

bool L3Stealth::initialize(const Config& config) {
    // FIX #28: Properly handle sodium_init() failure.
    // sodium_init() returns 0 on success, 1 if already initialized, -1 on failure.
    if (sodium_init() < 0) {
        log("FATAL: sodium_init() failed — libsodium cannot be initialized");
        initialized_ = false;
        return false;
    }

    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;

    // Apply OS profile defaults if AUTO
    if (config_.os_profile == OSProfile::AUTO) {
        config_.os_profile = detect_os_profile();
    }
    if (config_.ttl_profile == OSProfile::AUTO) {
        config_.ttl_profile = config_.os_profile;
    }

    // FIX #26: Use atomic store for thread-safe initialization of IPID counter
    global_ipid_counter_.store(
        static_cast<uint16_t>(randombytes_uniform(65536)),
        std::memory_order_relaxed);

    // Initialize timestamp offset
    if (config_.randomize_timestamp_offset) {
        timestamp_offset_ = randombytes_random();
    }
    timestamp_epoch_ = std::chrono::steady_clock::now();

    stats_.reset();
    initialized_ = true;
    log("L3Stealth initialized, profile=" + std::to_string(static_cast<int>(config_.os_profile)));
    return true;
}

bool L3Stealth::update_config(const Config& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    if (config_.os_profile == OSProfile::AUTO) {
        config_.os_profile = detect_os_profile();
    }
    if (config_.ttl_profile == OSProfile::AUTO) {
        config_.ttl_profile = config_.os_profile;
    }
    return true;
}

L3Stealth::Config L3Stealth::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

// ==================== Packet Processing ====================

bool L3Stealth::process_ipv4_packet(std::vector<uint8_t>& packet) {
    if (!initialized_) return false;
    if (packet.size() < sizeof(IPv4Header)) return false;

    auto* ip = reinterpret_cast<IPv4Header*>(packet.data());
    uint8_t ihl = (ip->ihl_ver & 0x0F) * 4;
    if (packet.size() < ihl) return false;

    bool modified = false;
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    stats_.packets_processed++;

    // 1. IPID randomization
    if (cfg.enable_ipid_randomization) {
        if (rewrite_ipid(packet.data(), packet.size())) {
            modified = true;
            stats_.ipid_rewritten++;
        }
    }

    // 2. TTL normalization
    if (cfg.enable_ttl_normalization) {
        if (normalize_ttl(packet.data(), packet.size())) {
            modified = true;
            stats_.ttl_normalized++;
        }
    }

    // 3. DF bit normalization
    if (cfg.enable_df_normalization) {
        if (normalize_df(packet.data(), packet.size())) {
            modified = true;
            stats_.df_bits_modified++;
        }
    }

    // 4. TCP-specific: MSS clamping + timestamp normalization
    if (ip->protocol == 6 /* IPPROTO_TCP */) {
        size_t tcp_offset = ihl;
        if (packet.size() >= tcp_offset + sizeof(TCPHeader)) {
            auto* tcp = reinterpret_cast<TCPHeader*>(packet.data() + tcp_offset);
            size_t tcp_total_len = packet.size() - tcp_offset;
            uint8_t tcp_doff = (tcp->res_doff >> 4) * 4;

            // MSS clamping (SYN packets only if configured)
            if (cfg.enable_mss_clamping) {
                bool is_syn = (tcp->flags & TCP_FLAG_SYN) != 0;
                if (!cfg.clamp_only_syn || is_syn) {
                    if (tcp_doff > sizeof(TCPHeader) && packet.size() >= tcp_offset + tcp_doff) {
                        if (clamp_mss_ipv4(packet.data() + tcp_offset, tcp_doff)) {
                            modified = true;
                            stats_.mss_clamped++;
                        }
                    }
                }
            }

            // TCP timestamp normalization
            if (cfg.enable_tcp_timestamp_normalization) {
                if (tcp_doff > sizeof(TCPHeader) && packet.size() >= tcp_offset + tcp_doff) {
                    if (normalize_tcp_timestamps(packet.data() + tcp_offset, tcp_doff)) {
                        modified = true;
                        stats_.timestamps_normalized++;
                    }
                }
            }

            // Recalculate TCP checksum if modified
            if (modified) {
                recalculate_tcp_checksum_ipv4(packet.data(), packet.data() + tcp_offset, tcp_total_len);
            }
        }
    }

    // Recalculate IP checksum if any IP header fields changed
    if (modified) {
        recalculate_ip_checksum(packet.data());
    }

    return modified;
}

bool L3Stealth::process_ipv6_packet(std::vector<uint8_t>& packet) {
    if (!initialized_) return false;
    if (packet.size() < sizeof(IPv6Header)) return false;

    auto* ip6 = reinterpret_cast<IPv6Header*>(packet.data());
    bool modified = false;
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    stats_.packets_processed++;

    // 1. Flow Label randomization
    if (cfg.enable_flow_label_randomization) {
        // Compute 5-tuple hash for per-flow labels
        uint64_t flow_hash = 0;
        if (cfg.per_flow_label && ip6->next_header == 6 /* TCP */) {
            size_t tcp_off = sizeof(IPv6Header);
            if (packet.size() >= tcp_off + sizeof(TCPHeader)) {
                auto* tcp = reinterpret_cast<TCPHeader*>(packet.data() + tcp_off);
                // Simple hash: XOR src/dst addr chunks + ports + proto
                uint64_t h = 0;
                for (int i = 0; i < 16; i += 4) {
                    uint32_t sa, da;
                    std::memcpy(&sa, ip6->saddr + i, 4);
                    std::memcpy(&da, ip6->daddr + i, 4);
                    h ^= static_cast<uint64_t>(sa) << 32 | da;
                }
                h ^= (static_cast<uint64_t>(tcp->source) << 16) | tcp->dest;
                h ^= ip6->next_header;
                flow_hash = h;
            }
        }
        if (rewrite_ipv6_flow_label(packet.data(), packet.size(), flow_hash)) {
            modified = true;
            stats_.flow_labels_randomized++;
        }
    }

    // 2. Hop Limit normalization
    if (cfg.enable_ttl_normalization) {
        if (normalize_hop_limit(packet.data(), packet.size())) {
            modified = true;
            stats_.ttl_normalized++;
        }
    }

    // 3. TCP-specific for IPv6
    if (ip6->next_header == 6 /* TCP */) {
        size_t tcp_offset = sizeof(IPv6Header);
        if (packet.size() >= tcp_offset + sizeof(TCPHeader)) {
            auto* tcp = reinterpret_cast<TCPHeader*>(packet.data() + tcp_offset);
            size_t tcp_total_len = packet.size() - tcp_offset;
            uint8_t tcp_doff = (tcp->res_doff >> 4) * 4;

            if (cfg.enable_mss_clamping) {
                bool is_syn = (tcp->flags & TCP_FLAG_SYN) != 0;
                if (!cfg.clamp_only_syn || is_syn) {
                    if (tcp_doff > sizeof(TCPHeader) && packet.size() >= tcp_offset + tcp_doff) {
                        if (clamp_mss_ipv6(packet.data() + tcp_offset, tcp_doff)) {
                            modified = true;
                            stats_.mss_clamped++;
                        }
                    }
                }
            }

            if (cfg.enable_tcp_timestamp_normalization) {
                if (tcp_doff > sizeof(TCPHeader) && packet.size() >= tcp_offset + tcp_doff) {
                    if (normalize_tcp_timestamps(packet.data() + tcp_offset, tcp_doff)) {
                        modified = true;
                        stats_.timestamps_normalized++;
                    }
                }
            }

            if (modified) {
                recalculate_tcp_checksum_ipv6(packet.data(), packet.data() + tcp_offset, tcp_total_len);
            }
        }
    }

    return modified;
}

// ==================== IP Fragmentation ====================

std::vector<std::vector<uint8_t>> L3Stealth::fragment_ipv4(
    const std::vector<uint8_t>& packet, uint16_t mtu)
{
    std::vector<std::vector<uint8_t>> fragments;

    if (packet.size() < sizeof(IPv4Header)) {
        fragments.push_back(packet);
        return fragments;
    }

    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    if (mtu == 0) mtu = cfg.enforce_mtu;
    if (mtu == 0) mtu = 1500;

    // If packet fits in MTU, no fragmentation needed
    if (packet.size() <= mtu) {
        fragments.push_back(packet);
        return fragments;
    }

    auto* ip = reinterpret_cast<const IPv4Header*>(packet.data());
    uint8_t ihl = (ip->ihl_ver & 0x0F) * 4;
    uint16_t total_len = ntohs(ip->tot_len);

    if (total_len > packet.size()) {
        fragments.push_back(packet);
        return fragments;
    }

    // Check DF bit — if set and we need to fragment, clear it if configured
    uint16_t frag_off_host = ntohs(ip->frag_off);
    bool df_set = (frag_off_host & IP_FLAG_DF) != 0;
    if (df_set && !cfg.clear_df_for_tunneled) {
        // DF set and not allowed to clear — return as-is
        fragments.push_back(packet);
        return fragments;
    }

    // Payload = everything after IP header
    const uint8_t* payload = packet.data() + ihl;
    size_t payload_len = total_len - ihl;

    // Max payload per fragment (must be multiple of 8)
    uint16_t max_frag_payload = ((mtu - ihl) / 8) * 8;
    if (max_frag_payload == 0) {
        fragments.push_back(packet);
        return fragments;
    }

    size_t offset = 0;
    while (offset < payload_len) {
        size_t chunk_size = std::min(static_cast<size_t>(max_frag_payload), payload_len - offset);
        bool more_fragments = (offset + chunk_size < payload_len);

        std::vector<uint8_t> frag(ihl + chunk_size);

        // Copy IP header
        std::memcpy(frag.data(), packet.data(), ihl);

        // Copy payload chunk
        std::memcpy(frag.data() + ihl, payload + offset, chunk_size);

        // Update IP header for fragment
        auto* frag_ip = reinterpret_cast<IPv4Header*>(frag.data());
        frag_ip->tot_len = htons(static_cast<uint16_t>(ihl + chunk_size));

        uint16_t frag_offset_val = static_cast<uint16_t>(offset / 8);
        uint16_t flags = 0;
        if (more_fragments) flags |= IP_FLAG_MF;
        // Clear DF for fragments
        frag_ip->frag_off = htons(flags | (frag_offset_val & IP_OFFSET_MASK));

        // Recalculate IP checksum
        frag_ip->check = 0;
        recalculate_ip_checksum(frag.data());

        fragments.push_back(std::move(frag));
        offset += chunk_size;
    }

    stats_.packets_fragmented += fragments.size();
    log("Fragmented packet into " + std::to_string(fragments.size()) + " parts");
    return fragments;
}

// ==================== IPID Generation ====================

uint16_t L3Stealth::generate_ipid(uint32_t dest_ip) {
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    switch (cfg.ipid_strategy) {
        case IPIDStrategy::CSPRNG:
            return static_cast<uint16_t>(randombytes_uniform(65536));

        case IPIDStrategy::INCREMENTAL_RANDOM: {
            // FIX #26: Use atomic fetch_add to prevent data race.
            // Multiple threads can call generate_ipid() concurrently from
            // packet processing; plain += on non-atomic was undefined behavior.
            uint16_t inc = static_cast<uint16_t>(1 + randombytes_uniform(64));
            return global_ipid_counter_.fetch_add(inc, std::memory_order_relaxed) + inc;
        }

        case IPIDStrategy::ZERO:
            return 0;

        case IPIDStrategy::PER_DESTINATION: {
            std::lock_guard<std::mutex> lock(dest_ipid_mutex_);
            auto it = dest_ipid_map_.find(dest_ip);
            if (it == dest_ipid_map_.end()) {
                uint16_t start = static_cast<uint16_t>(randombytes_uniform(65536));
                dest_ipid_map_[dest_ip] = {start, std::chrono::steady_clock::now()};
                return start;
            }
            // Increment by random small value
            uint16_t inc = static_cast<uint16_t>(1 + randombytes_uniform(8));
            it->second.current_id += inc;
            it->second.last_used = std::chrono::steady_clock::now();
            return it->second.current_id;
        }

        case IPIDStrategy::GLOBAL_COUNTER:
            // FIX #26: Use atomic fetch_add instead of non-atomic ++.
            return global_ipid_counter_.fetch_add(1, std::memory_order_relaxed) + 1;

        default:
            return static_cast<uint16_t>(randombytes_uniform(65536));
    }
}

// ==================== Flow Label Generation ====================

uint32_t L3Stealth::generate_flow_label(uint64_t flow_hash) {
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    if (cfg.custom_flow_label != 0) {
        return cfg.custom_flow_label & 0xFFFFF; // 20 bits max
    }

    if (cfg.per_flow_label && flow_hash != 0) {
        std::lock_guard<std::mutex> lock(flow_label_mutex_);
        auto it = flow_label_cache_.find(flow_hash);
        if (it != flow_label_cache_.end()) {
            // Update last_used timestamp on access
            it->second.last_used = std::chrono::steady_clock::now();
            return it->second.label;
        }
        uint32_t label = randombytes_uniform(0xFFFFF + 1); // 0 to 0xFFFFF
        if (label == 0) label = 1; // Avoid 0 as it means "no label"

        flow_label_cache_[flow_hash] = {label, std::chrono::steady_clock::now()};

        // FIX #27: Age-based eviction instead of arbitrary half-erase.
        // unordered_map iteration order is non-deterministic, so erasing
        // [begin, mid) would delete arbitrary entries — potentially fresh ones.
        // Now we evict entries older than FLOW_LABEL_TTL first, then if still
        // over the limit, find and erase the oldest entries.
        if (flow_label_cache_.size() > FLOW_LABEL_CACHE_MAX) {
            auto now = std::chrono::steady_clock::now();
            auto cutoff = now - FLOW_LABEL_TTL;

            // Phase 1: Remove entries older than TTL
            for (auto iter = flow_label_cache_.begin(); iter != flow_label_cache_.end(); ) {
                if (iter->second.last_used < cutoff) {
                    iter = flow_label_cache_.erase(iter);
                } else {
                    ++iter;
                }
            }

            // Phase 2: If still over limit, remove oldest entries until at 75% capacity.
            // FIX: Use partial_sort via a sorted vector of iterators to achieve O(n log k)
            // instead of O(n²) from repeated full scans. k = entries to remove.
            if (flow_label_cache_.size() > FLOW_LABEL_CACHE_MAX) {
                size_t target_size = FLOW_LABEL_CACHE_MAX * 3 / 4;
                size_t to_remove = flow_label_cache_.size() - target_size;

                // Collect all iterators
                std::vector<decltype(flow_label_cache_)::iterator> entries;
                entries.reserve(flow_label_cache_.size());
                for (auto it = flow_label_cache_.begin(); it != flow_label_cache_.end(); ++it) {
                    entries.push_back(it);
                }

                // Partial sort: move the `to_remove` oldest entries to the front — O(n log k)
                std::partial_sort(entries.begin(), entries.begin() + static_cast<ptrdiff_t>(to_remove),
                                  entries.end(),
                                  [](const auto& a, const auto& b) {
                                      return a->second.last_used < b->second.last_used;
                                  });

                // Erase the oldest entries
                for (size_t i = 0; i < to_remove; ++i) {
                    flow_label_cache_.erase(entries[i]);
                }
            }
        }
        return label;
    }

    // Fully random per-packet
    uint32_t label = randombytes_uniform(0xFFFFF + 1);
    return (label == 0) ? 1 : label;
}

// ==================== TTL/MSS helpers ====================

uint8_t L3Stealth::get_profile_ttl() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    if (config_.ttl_profile == OSProfile::CUSTOM) {
        return config_.custom_ttl;
    }
    return default_ttl_for_profile(config_.ttl_profile);
}

uint16_t L3Stealth::get_target_mss() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_.target_mss;
}

// ==================== Internal Rewriters ====================

bool L3Stealth::rewrite_ipid(uint8_t* ip_header, size_t len) {
    if (len < sizeof(IPv4Header)) return false;
    auto* ip = reinterpret_cast<IPv4Header*>(ip_header);
    uint16_t new_id = generate_ipid(ip->daddr);
    if (ip->id == htons(new_id)) return false;
    ip->id = htons(new_id);
    return true;
}

bool L3Stealth::normalize_ttl(uint8_t* ip_header, size_t len) {
    if (len < sizeof(IPv4Header)) return false;
    auto* ip = reinterpret_cast<IPv4Header*>(ip_header);

    uint8_t target_ttl = get_profile_ttl();

    // Add jitter if configured
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    if (cfg.randomize_ttl_jitter && target_ttl > 1) {
        int jitter = static_cast<int>(randombytes_uniform(3)) - 1; // -1, 0, or +1
        int new_ttl = static_cast<int>(target_ttl) + jitter;
        if (new_ttl < 1) new_ttl = 1;
        if (new_ttl > 255) new_ttl = 255;
        target_ttl = static_cast<uint8_t>(new_ttl);
    }

    if (ip->ttl == target_ttl) return false;
    ip->ttl = target_ttl;
    return true;
}

bool L3Stealth::normalize_df(uint8_t* ip_header, size_t len) {
    if (len < sizeof(IPv4Header)) return false;
    auto* ip = reinterpret_cast<IPv4Header*>(ip_header);

    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    uint16_t frag_host = ntohs(ip->frag_off);
    bool current_df = (frag_host & IP_FLAG_DF) != 0;

    if (current_df == cfg.force_df) return false;

    if (cfg.force_df) {
        frag_host |= IP_FLAG_DF;
    } else {
        frag_host &= ~IP_FLAG_DF;
    }
    ip->frag_off = htons(frag_host);
    return true;
}

bool L3Stealth::normalize_hop_limit(uint8_t* ipv6_header, size_t len) {
    if (len < sizeof(IPv6Header)) return false;
    auto* ip6 = reinterpret_cast<IPv6Header*>(ipv6_header);

    uint8_t target = get_profile_ttl(); // Same values for IPv6 hop limit
    if (ip6->hop_limit == target) return false;
    ip6->hop_limit = target;
    return true;
}

bool L3Stealth::rewrite_ipv6_flow_label(uint8_t* ipv6_header, size_t len, uint64_t flow_hash) {
    if (len < sizeof(IPv6Header)) return false;
    auto* ip6 = reinterpret_cast<IPv6Header*>(ipv6_header);

    uint32_t new_label = generate_flow_label(flow_hash);

    // ver_tc_flow: bits [31:28]=version, [27:20]=TC, [19:0]=flow label
    uint32_t vtf = ntohl(ip6->ver_tc_flow);
    uint32_t old_label = vtf & 0xFFFFF;
    if (old_label == new_label) return false;

    vtf = (vtf & 0xFFF00000) | (new_label & 0xFFFFF);
    ip6->ver_tc_flow = htonl(vtf);
    return true;
}

// ==================== TCP Options Manipulation ====================

int L3Stealth::find_mss_option_offset(const uint8_t* tcp_header, size_t tcp_header_len) {
    // TCP options start after the fixed 20-byte header
    size_t offset = sizeof(TCPHeader);
    while (offset < tcp_header_len) {
        uint8_t kind = tcp_header[offset];
        if (kind == TCP_OPT_END) break;
        if (kind == TCP_OPT_NOP) { offset++; continue; }
        if (offset + 1 >= tcp_header_len) break;
        uint8_t opt_len = tcp_header[offset + 1];
        if (opt_len < 2 || offset + opt_len > tcp_header_len) break;
        if (kind == TCP_OPT_MSS && opt_len == 4) {
            return static_cast<int>(offset);
        }
        offset += opt_len;
    }
    return -1;
}

int L3Stealth::find_timestamp_option_offset(const uint8_t* tcp_header, size_t tcp_header_len) {
    size_t offset = sizeof(TCPHeader);
    while (offset < tcp_header_len) {
        uint8_t kind = tcp_header[offset];
        if (kind == TCP_OPT_END) break;
        if (kind == TCP_OPT_NOP) { offset++; continue; }
        if (offset + 1 >= tcp_header_len) break;
        uint8_t opt_len = tcp_header[offset + 1];
        if (opt_len < 2 || offset + opt_len > tcp_header_len) break;
        if (kind == TCP_OPT_TS && opt_len == 10) {
            return static_cast<int>(offset);
        }
        offset += opt_len;
    }
    return -1;
}

bool L3Stealth::clamp_mss_ipv4(uint8_t* tcp_header, size_t tcp_len) {
    int mss_off = find_mss_option_offset(tcp_header, tcp_len);
    if (mss_off < 0) return false;

    // MSS option: [kind=2][len=4][MSS value (2 bytes, network order)]
    uint16_t current_mss;
    std::memcpy(&current_mss, tcp_header + mss_off + 2, 2);
    current_mss = ntohs(current_mss);

    uint16_t target = get_target_mss();
    if (current_mss <= target) return false; // Only clamp down

    uint16_t new_mss = htons(target);
    std::memcpy(tcp_header + mss_off + 2, &new_mss, 2);
    return true;
}

bool L3Stealth::clamp_mss_ipv6(uint8_t* tcp_header, size_t tcp_len) {
    // Same logic as IPv4 MSS clamping — MSS option is protocol-agnostic
    // But IPv6 target MSS = MTU - 60 (40 IPv6 header + 20 TCP header)
    int mss_off = find_mss_option_offset(tcp_header, tcp_len);
    if (mss_off < 0) return false;

    uint16_t current_mss;
    std::memcpy(&current_mss, tcp_header + mss_off + 2, 2);
    current_mss = ntohs(current_mss);

    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    // IPv6 MSS = target_mss - 20 (since IPv6 header is 40, not 20)
    // Actually: MSS = MTU - IPv6_header(40) - TCP_header(20) = MTU - 60
    // If target_mss is 1460 (based on IPv4 MTU 1500), for IPv6: 1500 - 60 = 1440
    uint16_t ipv6_mss = (cfg.target_mss > 20) ? (cfg.target_mss - 20) : cfg.target_mss;
    if (current_mss <= ipv6_mss) return false;

    uint16_t new_mss = htons(ipv6_mss);
    std::memcpy(tcp_header + mss_off + 2, &new_mss, 2);
    return true;
}

bool L3Stealth::normalize_tcp_timestamps(uint8_t* tcp_header, size_t tcp_len) {
    int ts_off = find_timestamp_option_offset(tcp_header, tcp_len);
    if (ts_off < 0) return false;

    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }

    // TS option: [kind=8][len=10][TSval(4)][TSecr(4)]
    // Rewrite TSval to our normalized clock
    auto now = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - timestamp_epoch_).count();

    // Convert to target tick rate
    uint32_t normalized_ts;
    if (cfg.timestamp_hz == 1000) {
        normalized_ts = static_cast<uint32_t>(elapsed_ms);
    } else if (cfg.timestamp_hz == 100) {
        normalized_ts = static_cast<uint32_t>(elapsed_ms / 10);
    } else {
        normalized_ts = static_cast<uint32_t>(
            elapsed_ms * cfg.timestamp_hz / 1000);
    }
    normalized_ts += timestamp_offset_;

    uint32_t net_ts = htonl(normalized_ts);
    std::memcpy(tcp_header + ts_off + 2, &net_ts, 4);
    // TSecr (echo reply) left unchanged — it echoes the peer's value

    return true;
}

// ==================== Checksum ====================

uint16_t L3Stealth::calculate_checksum(const void* data, int len) {
    const uint16_t* buf = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(buf);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

void L3Stealth::recalculate_ip_checksum(uint8_t* ip_header) {
    auto* ip = reinterpret_cast<IPv4Header*>(ip_header);
    uint8_t ihl = (ip->ihl_ver & 0x0F) * 4;
    ip->check = 0;
    ip->check = calculate_checksum(ip_header, ihl);
}

void L3Stealth::recalculate_tcp_checksum_ipv4(
    uint8_t* ip_header, uint8_t* tcp_header, size_t tcp_total_len)
{
    auto* ip = reinterpret_cast<IPv4Header*>(ip_header);
    auto* tcp = reinterpret_cast<TCPHeader*>(tcp_header);

    tcp->check = 0;

    PseudoHeaderV4 psh{};
    psh.saddr = ip->saddr;
    psh.daddr = ip->daddr;
    psh.zero = 0;
    psh.protocol = ip->protocol;
    psh.tcp_length = htons(static_cast<uint16_t>(tcp_total_len));

    size_t psh_total = sizeof(PseudoHeaderV4) + tcp_total_len;
    std::vector<uint8_t> buf(psh_total);
    std::memcpy(buf.data(), &psh, sizeof(PseudoHeaderV4));
    std::memcpy(buf.data() + sizeof(PseudoHeaderV4), tcp_header, tcp_total_len);

    tcp->check = calculate_checksum(buf.data(), static_cast<int>(psh_total));
}

void L3Stealth::recalculate_tcp_checksum_ipv6(
    uint8_t* ipv6_header, uint8_t* tcp_header, size_t tcp_total_len)
{
    auto* ip6 = reinterpret_cast<IPv6Header*>(ipv6_header);
    auto* tcp = reinterpret_cast<TCPHeader*>(tcp_header);

    tcp->check = 0;

    PseudoHeaderV6 psh{};
    std::memcpy(psh.saddr, ip6->saddr, 16);
    std::memcpy(psh.daddr, ip6->daddr, 16);
    psh.tcp_length = htonl(static_cast<uint32_t>(tcp_total_len));
    std::memset(psh.zeros, 0, 3);
    psh.next_header = 6; // TCP

    size_t psh_total = sizeof(PseudoHeaderV6) + tcp_total_len;
    std::vector<uint8_t> buf(psh_total);
    std::memcpy(buf.data(), &psh, sizeof(PseudoHeaderV6));
    std::memcpy(buf.data() + sizeof(PseudoHeaderV6), tcp_header, tcp_total_len);

    tcp->check = calculate_checksum(buf.data(), static_cast<int>(psh_total));
}

// ==================== Stats ====================

L3Stealth::Stats L3Stealth::get_stats() const {
    return Stats(stats_);
}

void L3Stealth::reset_stats() {
    stats_.reset();
}

// ==================== Logging ====================

void L3Stealth::set_log_callback(LogCallback cb) {
    log_cb_ = cb;
}

void L3Stealth::log(const std::string& msg) {
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    if (cfg.enable_logging && log_cb_) {
        log_cb_("[L3Stealth] " + msg);
    }
}

// ==================== Static Helpers ====================

L3Stealth::OSProfile L3Stealth::detect_os_profile() {
#ifdef _WIN32
    return OSProfile::WINDOWS_10;
#elif defined(__APPLE__)
    return OSProfile::MACOS_14;
#elif defined(__ANDROID__)
    return OSProfile::ANDROID_14;
#elif defined(__FreeBSD__)
    return OSProfile::FREEBSD_14;
#else
    return OSProfile::LINUX_6X;
#endif
}

uint8_t L3Stealth::default_ttl_for_profile(OSProfile profile) {
    switch (profile) {
        case OSProfile::WINDOWS_10:
        case OSProfile::WINDOWS_11:
            return 128;
        case OSProfile::LINUX_5X:
        case OSProfile::LINUX_6X:
        case OSProfile::MACOS_14:
        case OSProfile::FREEBSD_14:
        case OSProfile::ANDROID_14:
        case OSProfile::IOS_17:
            return 64;
        case OSProfile::AUTO:
            return default_ttl_for_profile(detect_os_profile());
        case OSProfile::CUSTOM:
            return 128; // Fallback
        default:
            return 64;
    }
}

} // namespace ncp
