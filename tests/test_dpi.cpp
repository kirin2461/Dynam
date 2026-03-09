#include <gtest/gtest.h>
#include "ncp_dpi.hpp"
#include <vector>
#include <string>

using namespace ncp::DPI;

// Forward declaration of internal helper for SNI parsing tests
namespace ncp::DPI {
int find_sni_hostname_offset(const uint8_t* data, size_t len);
}

TEST(DPIConfigTest, DefaultsAreReasonable) {
    DPIConfig cfg;
    EXPECT_EQ(cfg.mode, DPIMode::DRIVER);
    EXPECT_TRUE(cfg.enable_tcp_split);
    EXPECT_TRUE(cfg.enable_fake_packet);
    EXPECT_TRUE(cfg.enable_disorder);
    EXPECT_EQ(cfg.listen_port, 8080);
}

TEST(DPIPresetTest, RunetSoftPresetAppliesExpectedFlags) {
    DPIConfig cfg;
    cfg.listen_port = 3128;
    cfg.target_host = "example.com";
    cfg.target_port = 443;

    apply_preset(DPIPreset::RUNET_SOFT, cfg);

    EXPECT_EQ(cfg.mode, DPIMode::PROXY);
    EXPECT_TRUE(cfg.enable_tcp_split);
    EXPECT_TRUE(cfg.split_at_sni);
    EXPECT_GE(cfg.fragment_size, 1);
    EXPECT_FALSE(cfg.enable_fake_packet);
    EXPECT_FALSE(cfg.enable_disorder);
}

TEST(DPIPresetTest, RunetStrongPresetIsMoreAggressive) {
    DPIConfig cfg_soft;
    DPIConfig cfg_strong;

    apply_preset(DPIPreset::RUNET_SOFT, cfg_soft);
    apply_preset(DPIPreset::RUNET_STRONG, cfg_strong);

    EXPECT_EQ(cfg_soft.mode, DPIMode::PROXY);
    EXPECT_EQ(cfg_strong.mode, DPIMode::PROXY);

    EXPECT_LE(cfg_strong.fragment_size, cfg_soft.fragment_size);
    EXPECT_TRUE(cfg_strong.enable_fake_packet);
    EXPECT_TRUE(cfg_strong.enable_disorder);
}

TEST(DPIPresetTest, StringMappingIsCaseInsensitive) {
    EXPECT_EQ(preset_from_string("runet-soft"), DPIPreset::RUNET_SOFT);
    EXPECT_EQ(preset_from_string("RuNet-Strong"), DPIPreset::RUNET_STRONG);
    EXPECT_EQ(preset_from_string("RUNET_STRONG"), DPIPreset::RUNET_STRONG);
    EXPECT_EQ(preset_from_string("unknown-profile"), DPIPreset::NONE);
}

TEST(DPISniParserTest, ReturnsMinusOneOnInvalidRecords) {
    const uint8_t not_tls[] = {0x15, 0x03, 0x03, 0x00, 0x00};
    EXPECT_EQ(find_sni_hostname_offset(not_tls, sizeof(not_tls)), -1);

    const uint8_t short_record[] = {0x16, 0x03, 0x03};
    EXPECT_EQ(find_sni_hostname_offset(short_record, sizeof(short_record)), -1);
}

TEST(DPISniParserTest, ParsesSimpleClientHelloWithSni) {
    std::vector<uint8_t> buf;
    // TLS record header: type(1) + version(2) + length(2)
    buf.push_back(0x16); // Handshake
    buf.push_back(0x03);
    buf.push_back(0x03);
    buf.push_back(0x00); // length placeholder
    buf.push_back(0x00);

    const size_t hs_start = buf.size();

    // Handshake header: ClientHello (1) + length (3)
    buf.push_back(0x01); // ClientHello
    buf.push_back(0x00);
    buf.push_back(0x00);
    buf.push_back(0x00); // handshake length placeholder

    // client_version
    buf.push_back(0x03);
    buf.push_back(0x03);
    // random (32 bytes)
    for (int i = 0; i < 32; ++i) buf.push_back(0x00);
    // session_id
    buf.push_back(0x00); // length 0
    // cipher_suites (len=2, one suite)
    buf.push_back(0x00);
    buf.push_back(0x02);
    buf.push_back(0x00);
    buf.push_back(0x2f); // TLS_RSA_WITH_AES_128_CBC_SHA (arbitrary)
    // compression_methods (len=1, null)
    buf.push_back(0x01);
    buf.push_back(0x00);

    // extensions length placeholder
    const size_t ext_len_pos = buf.size();
    buf.push_back(0x00);
    buf.push_back(0x00);

    // ---- SNI extension ----
    const size_t ext_start = buf.size();
    // Extension type: server_name (0x0000)
    buf.push_back(0x00);
    buf.push_back(0x00);
    // Extension data length placeholder
        (void)ext_start;  // Suppress unused variable warning
    const size_t ext_data_len_pos = buf.size();
    buf.push_back(0x00);
    buf.push_back(0x00);

    // server_name_list length
    const std::string host = "example.com";
    const uint16_t host_len = static_cast<uint16_t>(host.size());
    const uint16_t list_len = static_cast<uint16_t>(1 + 2 + host_len);
    buf.push_back(static_cast<uint8_t>(list_len >> 8));
    buf.push_back(static_cast<uint8_t>(list_len & 0xff));
    // name_type
    buf.push_back(0x00); // host_name
    // host_name length
    buf.push_back(static_cast<uint8_t>(host_len >> 8));
    buf.push_back(static_cast<uint8_t>(host_len & 0xff));
    // host_name bytes
    for (char c : host) {
        buf.push_back(static_cast<uint8_t>(c));
    }

    const size_t end = buf.size();

    // Fill extension data length
    const uint16_t ext_data_len =
        static_cast<uint16_t>(end - (ext_data_len_pos + 2));
    buf[ext_data_len_pos]     = static_cast<uint8_t>(ext_data_len >> 8);
    buf[ext_data_len_pos + 1] = static_cast<uint8_t>(ext_data_len & 0xff);

    // Fill extensions length
    const uint16_t exts_len =
        static_cast<uint16_t>(end - (ext_len_pos + 2));
    buf[ext_len_pos]     = static_cast<uint8_t>(exts_len >> 8);
    buf[ext_len_pos + 1] = static_cast<uint8_t>(exts_len & 0xff);

    // Fill handshake length (bytes after handshake header)
    const uint32_t hs_len =
        static_cast<uint32_t>(end - (hs_start + 4));
    buf[hs_start + 1] = static_cast<uint8_t>((hs_len >> 16) & 0xff);
    buf[hs_start + 2] = static_cast<uint8_t>((hs_len >> 8) & 0xff);
    buf[hs_start + 3] = static_cast<uint8_t>(hs_len & 0xff);

    // Fill record length (bytes after record header)
    const uint16_t rec_len =
        static_cast<uint16_t>(end - 5);
    buf[3] = static_cast<uint8_t>(rec_len >> 8);
    buf[4] = static_cast<uint8_t>(rec_len & 0xff);

    int offset = find_sni_hostname_offset(buf.data(), buf.size());
    ASSERT_GT(offset, 0);
    ASSERT_LE(static_cast<size_t>(offset) + host.size(), buf.size());

    std::string parsed_host(
        reinterpret_cast<const char*>(buf.data() + offset),
        host.size());
    EXPECT_EQ(parsed_host, host);
}

