#ifndef NCP_I2P_HPP
#define NCP_I2P_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>
#include <chrono>

namespace ncp {

class I2PManager {
public:
    enum class TunnelType {
        CLIENT,
        SERVER,
        BIDIRECTIONAL
    };

    enum class EncryptionLayer {
        GARLIC_ROUTING,     // End-to-end encryption through multiple hops
        ELGAMAL_AES,        // ElGamal/AES+SessionTag encryption
        NTCP2,              // Transport layer encryption
        SSU2                // UDP-based encrypted transport
    };

    struct Config {
        bool enabled = false;
        std::string sam_host = "127.0.0.1";
        uint16_t sam_port = 7656;
        std::string proxy_host = "127.0.0.1";
        uint16_t proxy_port = 4444;
        bool use_http_proxy = true;
        
        // Advanced I2P features
        bool enable_garlic_routing = true;
        int tunnel_length = 3;           // Hops per tunnel (default 3)
        int tunnel_quantity = 2;         // Number of parallel tunnels
        int tunnel_backup_quantity = 1;  // Backup tunnels
        bool enable_multihoming = true;  // Multiple transport protocols
        bool enable_floodfill = false;   // Act as network database node
        
        // Encryption preferences
        EncryptionLayer primary_encryption = EncryptionLayer::GARLIC_ROUTING;
        bool enable_ntcp2 = true;
        bool enable_ssu2 = true;
        
        // Anonymity enhancements
        bool random_tunnel_selection = true;
        bool obfuscate_tunnel_messages = true;
        int mix_delay_ms = 50;           // Message mixing delay
        bool enable_dummy_traffic = true; // Padding/dummy messages
        
        // Network database protection
        bool enable_encrypted_leaseset = true;
        bool enable_blinded_destinations = true;
        int destination_expiration_hours = 24;
    };

    struct TunnelInfo {
        std::string tunnel_id;
        TunnelType type;
        std::string local_dest;
        std::string remote_dest;
        std::vector<std::string> hops;   // List of router hashes in tunnel
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point expires;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        bool is_backup = false;
    };

    struct GarlicClove {
        std::string destination;
        std::vector<uint8_t> payload;
        uint32_t clove_id;
        std::chrono::system_clock::time_point expiration;
    };

    I2PManager();
    ~I2PManager();

    bool initialize(const Config& config);
    bool is_active() const;
    void set_enabled(bool enabled);

    // Destination management
    std::string get_destination() const;
    std::string create_ephemeral_destination();
    bool import_destination(const std::string& private_keys);
    std::string export_destination() const;
    
    // Advanced tunnel creation
    bool create_tunnel(const std::string& name, uint16_t local_port, 
                      const std::string& remote_dest, TunnelType type = TunnelType::CLIENT);
    bool create_server_tunnel(const std::string& name, uint16_t local_port);
    std::vector<TunnelInfo> get_active_tunnels() const;
    bool destroy_tunnel(const std::string& tunnel_id);
    
    // Garlic routing (end-to-end encryption)
    std::vector<uint8_t> create_garlic_message(const std::vector<GarlicClove>& cloves,
                                                const std::string& dest_public_key);
    bool send_garlic_message(const std::string& destination, 
                            const std::vector<uint8_t>& message);
    
    // Network database operations
    std::string lookup_destination(const std::string& hostname);
    bool publish_leaseset(bool encrypted = true, bool blinded = false);
    std::vector<std::string> get_floodfill_routers() const;
    
    // Traffic obfuscation
    void enable_traffic_mixing(bool enable, int delay_ms = 50);
    void send_dummy_traffic(size_t bytes_per_second);
    std::vector<uint8_t> pad_message(const std::vector<uint8_t>& msg, size_t target_size);
    
    // Tunnel management and rotation
    void rotate_tunnels();
    void set_tunnel_build_rate(int tunnels_per_minute);
    bool use_exploratory_tunnels() const;
    
    // Statistics and monitoring (anonymized)
    struct Statistics {
        uint64_t total_sent = 0;
        uint64_t total_received = 0;
        size_t active_tunnels = 0;
        size_t known_routers = 0;
        double tunnel_success_rate = 0.0;
        std::chrono::milliseconds avg_tunnel_latency{0};
    };
    Statistics get_statistics() const;
    
    // Multihoming support (NTCP2 + SSU2)
    bool enable_transport(EncryptionLayer transport);
    std::vector<EncryptionLayer> get_active_transports() const;
    
    // Advanced anonymity features
    void set_profile_mode(const std::string& mode); // "high_security", "balanced", "performance"
    bool enable_path_selection_randomization(bool enable);
    void set_cover_traffic_rate(size_t bytes_per_minute);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    Config config_;
    bool is_initialized_ = false;
    std::string current_dest_;
    std::map<std::string, TunnelInfo> tunnels_;
    
    // Internal tunnel operations
    std::vector<std::string> select_tunnel_hops(int length);
    bool build_tunnel(const std::vector<std::string>& hops, TunnelType type);
    void maintain_tunnel_pool();
    
    // Encryption helpers
    std::vector<uint8_t> encrypt_garlic_layer(const std::vector<uint8_t>& data,
                                              const std::string& hop_pubkey);
    std::vector<uint8_t> create_session_tag();
    
    // Network database cache
    std::map<std::string, std::string> netdb_cache_;
    std::chrono::system_clock::time_point last_netdb_update_;
    
    void schedule_tunnel_rotation();
    void inject_dummy_message();
};

} // namespace ncp

#endif // NCP_I2P_HPP
