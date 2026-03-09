#include <gtest/gtest.h>
#include "ncp_license.hpp"
#include <fstream>
#include <cstring>
#include <chrono>
#include <thread>

using namespace ncp;

class LicenseTest : public ::testing::Test {
protected:
    License license;
};

// ═══════════════════════════════════════════════════════════════════════════════
// HWID & Hardware Fingerprinting
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, GetHWID) {
    std::string hwid = license.get_hwid();
    EXPECT_FALSE(hwid.empty());
    // HWID is SHA-256 hex => 64 chars
    EXPECT_EQ(hwid.size(), 64u);
}

TEST_F(LicenseTest, HWIDDeterministic) {
    std::string hwid1 = license.get_hwid();
    std::string hwid2 = license.get_hwid();
    EXPECT_EQ(hwid1, hwid2) << "HWID must be deterministic across calls";
}

TEST_F(LicenseTest, GetHardwareProfile) {
    auto profile = license.get_hardware_profile();
    // At least some fields should be non-empty on any real system
    // (total_ram is always > 0)
    EXPECT_GT(profile.total_ram, 0u);
}

TEST_F(LicenseTest, ComputeCompositeHWID) {
    auto profile = license.get_hardware_profile();
    std::string composite = license.compute_composite_hwid(profile);
    EXPECT_FALSE(composite.empty());
    // BLAKE2b 32-byte hash => 64 hex chars
    EXPECT_EQ(composite.size(), 64u);
}

TEST_F(LicenseTest, GenerateMachineFingerprint) {
    std::string fp = license.generate_machine_fingerprint();
    EXPECT_FALSE(fp.empty());
    EXPECT_EQ(fp.size(), 64u);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Expiry
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, IsExpired) {
    auto now = std::chrono::system_clock::now();
    auto future = now + std::chrono::hours(24);
    auto past = now - std::chrono::hours(24);

    EXPECT_FALSE(license.is_expired(future));
    EXPECT_TRUE(license.is_expired(past));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keypair Persistence (FIX #28)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, ExportPublicKeyHex) {
    std::string pk_hex = license.export_public_key_hex();
    EXPECT_FALSE(pk_hex.empty());
    // Ed25519 public key = 32 bytes = 64 hex chars
    EXPECT_EQ(pk_hex.size(), 64u);
}

TEST_F(LicenseTest, ExportSecretKeyHex) {
    std::string sk_hex = license.export_secret_key_hex();
    EXPECT_FALSE(sk_hex.empty());
    // Ed25519 secret key (libsodium) = 64 bytes = 128 hex chars
    EXPECT_EQ(sk_hex.size(), 128u);
}

TEST_F(LicenseTest, ImportKeypairRoundtrip) {
    std::string sk_hex = license.export_secret_key_hex();

    License restored(sk_hex);
    EXPECT_EQ(restored.export_public_key_hex(), license.export_public_key_hex());
    EXPECT_EQ(restored.export_secret_key_hex(), license.export_secret_key_hex());
}

TEST_F(LicenseTest, ImportKeypairInvalid) {
    EXPECT_FALSE(license.import_keypair("not_valid_hex"));
    EXPECT_FALSE(license.import_keypair(""));
    EXPECT_FALSE(license.import_keypair(std::string(128, 'z'))); // invalid hex
}

// ═══════════════════════════════════════════════════════════════════════════════
// License File Generation & Offline Validation
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, GenerateAndValidateLicenseFile) {
    std::string hwid = license.get_hwid();
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24 * 30);
    std::string tmpfile = "test_license_gen.key";

    bool ok = license.generate_license_file(hwid, "TEST-1234-ABCD-5678", expiry, tmpfile);
    EXPECT_TRUE(ok);

    auto result = license.validate_offline(hwid, tmpfile);
    EXPECT_EQ(result, License::ValidationResult::VALID);

    // Cleanup
    std::remove(tmpfile.c_str());
}

TEST_F(LicenseTest, ValidateOffline_HWIDMismatch) {
    std::string hwid = license.get_hwid();
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24 * 30);
    std::string tmpfile = "test_license_mismatch.key";

    license.generate_license_file(hwid, "TEST-0000-0000-0000", expiry, tmpfile);
    auto result = license.validate_offline("wrong_hwid_00000000", tmpfile);
    EXPECT_EQ(result, License::ValidationResult::HWID_MISMATCH);

    std::remove(tmpfile.c_str());
}

TEST_F(LicenseTest, ValidateOffline_Expired) {
    std::string hwid = license.get_hwid();
    auto past = std::chrono::system_clock::now() - std::chrono::hours(24);
    std::string tmpfile = "test_license_expired.key";

    license.generate_license_file(hwid, "TEST-0000-0000-0000", past, tmpfile);
    auto result = license.validate_offline(hwid, tmpfile);
    EXPECT_EQ(result, License::ValidationResult::EXPIRED);

    std::remove(tmpfile.c_str());
}

TEST_F(LicenseTest, ValidateOffline_FileNotFound) {
    auto result = license.validate_offline("anything", "nonexistent_file_xyz.key");
    EXPECT_EQ(result, License::ValidationResult::FILE_NOT_FOUND);
}

TEST_F(LicenseTest, ValidateOffline_InvalidFormat) {
    std::string tmpfile = "test_license_bad.key";
    {
        std::ofstream f(tmpfile);
        f << "garbage data with no pipes";
    }
    auto result = license.validate_offline("any", tmpfile);
    EXPECT_EQ(result, License::ValidationResult::INVALID_FORMAT);
    std::remove(tmpfile.c_str());
}

TEST_F(LicenseTest, ValidateOfflineWithExternalPublicKey) {
    std::string hwid = license.get_hwid();
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24 * 365);
    std::string tmpfile = "test_license_extpk.key";

    license.generate_license_file(hwid, "KEY1-KEY2-KEY3-KEY4", expiry, tmpfile);

    // Validate with the correct public key
    std::string pk_hex = license.export_public_key_hex();
    auto result = license.validate_offline(hwid, tmpfile, pk_hex);
    EXPECT_EQ(result, License::ValidationResult::VALID);

    // Validate with a wrong public key (fresh keypair)
    License other_signer;
    std::string wrong_pk = other_signer.export_public_key_hex();
    auto result2 = license.validate_offline(hwid, tmpfile, wrong_pk);
    EXPECT_EQ(result2, License::ValidationResult::INVALID_SIGNATURE);

    std::remove(tmpfile.c_str());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Online Validation (without server — expects SERVER_ERROR or VALID format check)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, ValidateOnline_EmptyKey) {
    auto r = license.validate_online("hwid", "", "http://localhost:1234");
    EXPECT_EQ(r, License::ValidationResult::INVALID_KEY);
}

TEST_F(LicenseTest, ValidateOnline_EmptyServer) {
    auto r = license.validate_online("hwid", "AAAA-BBBB-CCCC-DDDD", "");
    EXPECT_EQ(r, License::ValidationResult::SERVER_ERROR);
}

TEST_F(LicenseTest, ValidateOnline_BadKeyFormat) {
    auto r = license.validate_online("hwid", "not-a-key", "http://localhost:1234");
    EXPECT_EQ(r, License::ValidationResult::INVALID_KEY);
}

// ═══════════════════════════════════════════════════════════════════════════════
// License Info
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, GetLicenseInfo_ValidFile) {
    std::string hwid = license.get_hwid();
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24 * 90);
    std::string tmpfile = "test_license_info.key";

    license.generate_license_file(hwid, "KEY1-KEY2-KEY3-KEY4", expiry, tmpfile);

    auto info = license.get_license_info(tmpfile);
    EXPECT_TRUE(info.is_valid);
    EXPECT_EQ(info.hwid, hwid);
    EXPECT_GT(info.days_remaining, 80);
    EXPECT_LT(info.days_remaining, 92);

    std::remove(tmpfile.c_str());
}

TEST_F(LicenseTest, GetLicenseInfo_NonExistentFile) {
    auto info = license.get_license_info("no_such_file_xyz.key");
    EXPECT_FALSE(info.is_valid);
    EXPECT_EQ(info.days_remaining, 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Anti-Debug & Anti-Tamper
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, EnableAntiTamper) {
    EXPECT_NO_THROW(license.enable_anti_tamper(
        static_cast<uint8_t>(License::AntiTamperFlag::CHECK_DEBUGGER) |
        static_cast<uint8_t>(License::AntiTamperFlag::CHECK_VM)));
}

TEST_F(LicenseTest, CheckAntiDebug) {
    auto info = license.check_anti_debug();
    // In a test runner environment, debugger_present may or may not be true.
    // Just check the struct is populated.
    (void)info.debugger_present;
    (void)info.vm_detected;
    (void)info.sandbox_detected;
    (void)info.memory_tampering;
}

TEST_F(LicenseTest, DetectDebugger) {
    // Should not throw regardless of environment
    bool result = license.detect_debugger();
    (void)result;
}

TEST_F(LicenseTest, DetectVM) {
    // Just ensure it runs without crash
    bool result = license.detect_vm();
    (void)result;
}

TEST_F(LicenseTest, DetectSandbox) {
    bool result = license.detect_sandbox();
    (void)result;
}

TEST_F(LicenseTest, CheckCodeIntegrity) {
    bool ok = license.check_code_integrity();
    (void)ok;
}

TEST_F(LicenseTest, CheckMemoryIntegrity) {
    bool ok = license.check_memory_integrity();
    (void)ok;
}

TEST_F(LicenseTest, ObfuscateLicenseData) {
    EXPECT_NO_THROW(license.obfuscate_license_data());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Encrypt / Decrypt License Data
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, EncryptDecryptRoundtrip) {
    std::string original = "test-license-payload-data-12345";
    std::string encrypted = license.encrypt_license_data(original);
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, original);

    std::string decrypted = license.decrypt_license_data(encrypted);
    EXPECT_EQ(decrypted, original);
}

TEST_F(LicenseTest, DecryptBadData) {
    std::string bad = license.decrypt_license_data("not_valid_hex_data");
    EXPECT_TRUE(bad.empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Verify Signature
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, VerifyLicenseSignature) {
    std::string data = "some license payload";

    // Create signature using the private sign helper indirectly
    // We'll generate a license file and extract its parts
    std::string hwid = license.get_hwid();
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24);
    std::string tmpfile = "test_verify_sig.key";
    license.generate_license_file(hwid, "ABCD-EFGH-IJKL-MNOP", expiry, tmpfile);

    std::ifstream f(tmpfile);
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    f.close();

    // content = "HWID|DATE|SIGNATURE_HEX"
    auto last_pipe = content.rfind('|');
    ASSERT_NE(last_pipe, std::string::npos);
    std::string signed_data = content.substr(0, last_pipe);
    std::string sig_hex = content.substr(last_pipe + 1);

    EXPECT_TRUE(license.verify_license_signature(signed_data, sig_hex));
    EXPECT_FALSE(license.verify_license_signature("tampered_data", sig_hex));

    std::remove(tmpfile.c_str());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Blacklist & Rate Limiting
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, BlacklistOperations) {
    EXPECT_FALSE(license.is_hwid_blacklisted("test_hwid_123"));

    license.update_blacklist({"test_hwid_123", "test_hwid_456"});
    EXPECT_TRUE(license.is_hwid_blacklisted("test_hwid_123"));
    EXPECT_TRUE(license.is_hwid_blacklisted("test_hwid_456"));
    EXPECT_FALSE(license.is_hwid_blacklisted("test_hwid_789"));
}

TEST_F(LicenseTest, RateLimiting) {
    std::string ip = "192.168.1.100";
    // First call should not be rate limited
    EXPECT_FALSE(license.is_ip_rate_limited(ip));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Trial Management
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, CreateTrialLicense) {
    std::string tmpfile = "test_trial.key";
    EXPECT_TRUE(license.create_trial_license(14, tmpfile));

    EXPECT_FALSE(license.is_trial_expired());
    EXPECT_LE(license.get_trial_days_remaining(), 14);
    EXPECT_GE(license.get_trial_days_remaining(), 13);
    EXPECT_TRUE(license.has_trial_been_used());

    // Validate the generated trial file
    std::string hwid = license.get_hwid();
    auto result = license.validate_offline(hwid, tmpfile);
    EXPECT_EQ(result, License::ValidationResult::VALID);

    std::remove(tmpfile.c_str());
}

TEST_F(LicenseTest, TrialNotUsedBeforeCreation) {
    License fresh_license;
    EXPECT_FALSE(fresh_license.has_trial_been_used());
    EXPECT_EQ(fresh_license.get_trial_days_remaining(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Feature Flags
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, FeatureFlags) {
    EXPECT_FALSE(license.is_feature_enabled("dpi_bypass"));
    EXPECT_TRUE(license.get_enabled_features().empty());

    license.set_feature_flag("dpi_bypass", true);
    license.set_feature_flag("tor_proxy", true);
    license.set_feature_flag("ech", false);

    EXPECT_TRUE(license.is_feature_enabled("dpi_bypass"));
    EXPECT_TRUE(license.is_feature_enabled("tor_proxy"));
    EXPECT_FALSE(license.is_feature_enabled("ech"));

    auto enabled = license.get_enabled_features();
    EXPECT_EQ(enabled.size(), 2u);

    license.set_feature_flag("dpi_bypass", false);
    EXPECT_FALSE(license.is_feature_enabled("dpi_bypass"));
    enabled = license.get_enabled_features();
    EXPECT_EQ(enabled.size(), 1u);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Telemetry
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, Telemetry) {
    auto td = license.get_telemetry();
    EXPECT_EQ(td.validation_attempts, 0u);
    EXPECT_EQ(td.failed_attempts, 0u);
}

TEST_F(LicenseTest, SendTelemetry_EmptyUrl) {
    EXPECT_NO_THROW(license.send_telemetry(""));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Security Callbacks
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, SetCallbacks) {
    bool tamper_called = false;
    bool expiry_called = false;

    license.set_tamper_callback([&](const std::string&) { tamper_called = true; });
    license.set_expiry_callback([&](const std::string&) { expiry_called = true; });

    // Callbacks are set but not invoked here — just ensure no crash
    EXPECT_FALSE(tamper_called);
    EXPECT_FALSE(expiry_called);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Periodic Validation — just ensure start/stop don't crash
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, PeriodicValidation_StartStop) {
    EXPECT_NO_THROW(license.start_periodic_validation(1));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_NO_THROW(license.stop_periodic_validation());
}

TEST_F(LicenseTest, PeriodicValidation_DoubleStop) {
    license.start_periodic_validation(1);
    license.stop_periodic_validation();
    EXPECT_NO_THROW(license.stop_periodic_validation());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Secure Storage
// ═══════════════════════════════════════════════════════════════════════════════

TEST_F(LicenseTest, EncryptDecryptLicenseDataEmpty) {
    std::string enc = license.encrypt_license_data("");
    // Empty input should return empty or handle gracefully
    // (depends on implementation)
    if (!enc.empty()) {
        std::string dec = license.decrypt_license_data(enc);
        EXPECT_EQ(dec, "");
    }
}
