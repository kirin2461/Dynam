#ifndef NCP_LICENSE_HPP
#define NCP_LICENSE_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <memory>

namespace NCP {

class Crypto;  // Forward declaration

class License {
public:
    enum class ValidationResult {
        VALID,
        INVALID_HWID,
        HWID_MISMATCH,
        EXPIRED,
        INVALID_SIGNATURE,
        INVALID_KEY,
        INVALID_FORMAT,
        FILE_NOT_FOUND,
        SERVER_ERROR,
        CORRUPTED
    };

    struct LicenseInfo {
        std::string hwid;
        std::chrono::system_clock::time_point expiry_date;
        std::string plan;
        int days_remaining;
        bool is_valid;
        bool is_trial;
    };

    License();
    ~License();

    std::string get_hwid();

    bool is_expired(const std::chrono::system_clock::time_point& expiry_date);
    ValidationResult validate_offline(
        const std::string& hwid,
        const std::string& license_file
    );

    ValidationResult validate_online(
        const std::string& hwid,
        const std::string& license_key,
        const std::string& server_url
    );

    bool generate_license_file(
        const std::string& hwid,
        const std::string& license_key,
        const std::chrono::system_clock::time_point& expiration_date,
        const std::string& output_file
    );

    LicenseInfo get_license_info(const std::string& license_file);

private:
    std::unique_ptr<Crypto> crypto_;

    std::string get_mac_address();
    std::string get_cpu_id();
    std::string get_os_uuid();
};

} // namespace NCP

#endif // NCP_LICENSE_HPP
