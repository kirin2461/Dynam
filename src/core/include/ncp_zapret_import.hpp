#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP zapret import — parse zapret command-line arguments into ZapretProfile
//
// Accepts the same flags as zapret's nfqws/winws, e.g.:
//   --filter-tcp=443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=2
//   --dpi-desync-ttl=4 --dpi-desync-fooling=badsum --new --filter-udp=443 ...
//
// Unknown / unsupported flags are collected into `warnings` and skipped.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_dpi_zapret.hpp"

#include <string>
#include <vector>

namespace ncp {
namespace DPI {

struct ZapretImportResult {
    ZapretProfile profile;
    std::vector<std::string> warnings;   // unsupported/unknown flags
    std::vector<std::string> errors;     // malformed values
    bool ok() const { return errors.empty() && !profile.chains.empty(); }
};

// Parse a zapret argument vector (already tokenized).
ZapretImportResult parse_zapret_argv(const std::vector<std::string>& args);

// Parse a zapret command line string (shell-style tokenization with
// support for single/double quotes and backslash escapes).
ZapretImportResult parse_zapret_cmdline(const std::string& cmdline);

// Tokenize shell-style command line (exposed for tests).
std::vector<std::string> zapret_tokenize(const std::string& cmdline);

// Serialize imported profile to JSON (for GUI preview / profile files).
std::string zapret_profile_to_json(const ZapretImportResult& result);

} // namespace DPI
} // namespace ncp
