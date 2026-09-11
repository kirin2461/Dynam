#pragma once

/**
 * @file ncp_test_temp.hpp
 * @brief Portable temp-file path helper for tests.
 *
 * Hard-coded "/tmp/..." does not exist on Windows (MSVC maps it to
 * "<current-drive>:\\tmp", which is absent on CI runners, so every file
 * creation fails). std::filesystem::temp_directory_path() resolves %TEMP%
 * on Windows and $TMPDIR//tmp on POSIX.
 */

#include <filesystem>
#include <string>

namespace ncp_test {

inline std::string temp_path(const std::string& name) {
    return (std::filesystem::temp_directory_path() / name).string();
}

} // namespace ncp_test
