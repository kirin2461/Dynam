#ifndef NCP_DATAGRAM_PATH_HPP
#define NCP_DATAGRAM_PATH_HPP

#include <cstddef>
#include <cstdint>

namespace ncp {

/** Network-layer version used by the current UDP path. */
enum class PathIpVersion : uint8_t { Unknown = 0, IPv4 = 4, IPv6 = 6 };

/** Encapsulation outside the Dynam/PortHop datagram. */
enum class OuterTransportKind : uint8_t {
    Direct = 0,
    TurnChannelData = 1,
    TurnSendData = 2,  // bootstrap only; established application flow is invalid
};

/** PH policy in force for this path. Real QUIC uses Disabled. */
enum class PathHopPolicy : uint8_t { Disabled = 0, LegacyPortHop = 1 };

/**
 * Authoritative path-sizing inputs. effective_mtu is the IP MTU (including
 * IP and UDP headers), not merely the UDP payload. Zero means unknown and
 * fails safe to the IPv6 minimum MTU basis (1280 bytes).
 *
 * porthop_padding_headroom is the configured content-padding maximum plus
 * its one-byte length encoding. It is charged in addition to the 20-byte PH
 * header. TURN ChannelData padding adds the RFC-required 0..3 alignment
 * bytes; turn_send_data_bootstrap must be false for application traffic.
 */
struct PathState {
    uint32_t effective_mtu = 0;
    PathIpVersion ip_version = PathIpVersion::Unknown;
    OuterTransportKind outer_transport = OuterTransportKind::Direct;
    PathHopPolicy hop_policy = PathHopPolicy::LegacyPortHop;
    uint32_t porthop_padding_headroom = 0;
    bool turn_channeldata_padding = false;
    bool turn_send_data_bootstrap = false;
};

inline constexpr uint32_t kUnknownPathMtuBasis = 1280;
inline constexpr uint32_t kUdpHeaderBytes = 8;
inline constexpr uint32_t kPortHopHeaderBytes = 20;
inline constexpr uint32_t kTurnChannelDataHeaderBytes = 4;

}  // namespace ncp

#endif  // NCP_DATAGRAM_PATH_HPP
