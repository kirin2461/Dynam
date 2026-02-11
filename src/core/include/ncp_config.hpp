#pragma once

#include <string>
#include <cstdint>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <mutex>

namespace NCP {

/**
 * @brief Runtime configuration manager for NCP
 * 
 * Manages all configurable parameters: network interfaces,
 * DPI evasion settings, crypto keys, logging levels, etc.
 * Thread-safe singleton pattern.
 */
class Config {
public:
    static Config& instance() {
        static Config cfg;
        return cfg;
    }

    // Prevent copying
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    // ==================== Getters ====================
    std::string get(const std::string& key, const std::string& default_val = "") const {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = values_.find(key);
        return (it != values_.end()) ? it->second : default_val;
    }

    int getInt(const std::string& key, int default_val = 0) const {
        std::string v = get(key);
        if (v.empty()) return default_val;
        try { return std::stoi(v); }
        catch (...) { return default_val; }
    }

    bool getBool(const std::string& key, bool default_val = false) const {
        std::string v = get(key);
        if (v.empty()) return default_val;
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        return (v == "true" || v == "1" || v == "yes" || v == "on");
    }

    // ==================== Setters ====================
    void set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mtx_);
        values_[key] = value;
    }

    void setInt(const std::string& key, int value) {
        set(key, std::to_string(value));
    }

    void setBool(const std::string& key, bool value) {
        set(key, value ? "true" : "false");
    }

    // ==================== File I/O ====================
    bool loadFromFile(const std::string& path) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::ifstream file(path);
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            auto pos = line.find('=');
            if (pos == std::string::npos) continue;

            std::string key = line.substr(0, pos);
            std::string val = line.substr(pos + 1);
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            values_[key] = val;
        }
        return true;
    }

    bool saveToFile(const std::string& path) const {
        std::lock_guard<std::mutex> lock(mtx_);
        std::ofstream file(path);
        if (!file.is_open()) return false;

        file << "# NCP Configuration File\n";
        file << "# Auto-generated\n\n";
        for (const auto& [k, v] : values_) {
            file << k << " = " << v << "\n";
        }
        return true;
    }

    // ==================== Defaults ====================
    void loadDefaults() {
        std::lock_guard<std::mutex> lock(mtx_);
        values_["log.level"] = "info";
        values_["log.file"] = "ncp.log";
        values_["log.console"] = "true";
        values_["network.interface"] = "auto";
        values_["network.timeout_ms"] = "5000";
        values_["dpi.evasion_enabled"] = "true";
        values_["dpi.fragmentation"] = "true";
        values_["dpi.tls_fingerprint"] = "chrome";
        values_["crypto.algorithm"] = "xchacha20-poly1305";
        values_["crypto.kdf"] = "argon2id";
        values_["dns.provider"] = "cloudflare";
        values_["dns.doh_enabled"] = "true";
        values_["security.memory_lock"] = "true";
        values_["security.secure_delete"] = "true";
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mtx_);
        values_.clear();
    }

private:
    Config() { loadDefaults(); }

    mutable std::mutex mtx_;
    std::map<std::string, std::string> values_;
};

} // namespace NCP
