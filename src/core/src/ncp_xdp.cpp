/**
 * @file ncp_xdp.cpp
 * @brief eBPF/XDP lifecycle management without libbpf (see header).
 */

#include "ncp_xdp.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ncp {
namespace {

// Run a program, capture combined stdout+stderr, return exit status.
int run_cmd(const std::vector<std::string>& argv, std::string& output) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;

    pid_t pid = fork();
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        std::vector<char*> cargv;
        for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        _exit(127);
    }
    close(pipefd[1]);
    char buf[512];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        output.append(buf, static_cast<size_t>(n));
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool file_exists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

// ---- raw bpf(2) — Linux only; stubs below keep the API linkable elsewhere ----

#if defined(__linux__)

union bpf_attr_min {
    struct { __attribute__((aligned(8))) char pathname[8]; uint32_t bpf_fd; uint32_t file_flags; } obj;
    struct {
        uint32_t map_fd;
        uint64_t key;
        uint64_t value_or_next;
        uint64_t flags;
    } map;
    char _pad[128];
};

int bpf_obj_get(const char* pathname) {
    // struct bpf_attr { __aligned_u64 pathname; __u32 bpf_fd; __u32 file_flags; }
    struct {
        uint64_t pathname;
        uint32_t bpf_fd;
        uint32_t file_flags;
    } attr{};
    attr.pathname = reinterpret_cast<uint64_t>(pathname);
    return static_cast<int>(::syscall(SYS_bpf, 7 /*BPF_OBJ_GET*/, &attr, sizeof(attr)));
}

int bpf_map_lookup(int map_fd, const void* key, void* value) {
    struct {
        uint32_t map_fd;
        uint64_t key;
        uint64_t value;
        uint64_t flags;
    } attr{};
    attr.map_fd = static_cast<uint32_t>(map_fd);
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.value = reinterpret_cast<uint64_t>(value);
    return static_cast<int>(::syscall(SYS_bpf, 1 /*BPF_MAP_LOOKUP_ELEM*/, &attr, sizeof(attr)));
}

int bpf_map_update(int map_fd, const void* key, const void* value, uint64_t flags) {
    struct {
        uint32_t map_fd;
        uint64_t key;
        uint64_t value;
        uint64_t flags;
    } attr{};
    attr.map_fd = static_cast<uint32_t>(map_fd);
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.value = reinterpret_cast<uint64_t>(value);
    attr.flags = flags;
    return static_cast<int>(::syscall(SYS_bpf, 2 /*BPF_MAP_UPDATE_ELEM*/, &attr, sizeof(attr)));
}

#else  // !__linux__ — no bpf(2) syscall on this platform

int bpf_obj_get(const char*)                      { errno = ENOSYS; return -1; }
int bpf_map_lookup(int, const void*, void*)       { errno = ENOSYS; return -1; }
int bpf_map_update(int, const void*, const void*, uint64_t)
                                                  { errno = ENOSYS; return -1; }

#endif  // __linux__

} // namespace

bool XdpManager::compile_program(const std::string& src_path,
                                 const std::string& obj_path,
                                 std::string& err,
                                 const std::string& clang_bin) {
    std::string out;
    int rc = run_cmd({clang_bin, "-O2", "-g0", "-target", "bpf",
                      "-c", src_path, "-o", obj_path}, out);
    if (rc != 0) {
        err = "clang failed (" + std::to_string(rc) + "): " + out;
        return false;
    }
    if (!file_exists(obj_path)) {
        err = "clang reported success but object file missing";
        return false;
    }
    // sanity: ELF magic
    int fd = ::open(obj_path.c_str(), O_RDONLY);
    if (fd < 0) { err = "cannot open object"; return false; }
    unsigned char magic[4] = {0,0,0,0};
    ssize_t n = ::read(fd, magic, 4);
    ::close(fd);
    if (n != 4 || magic[0] != 0x7F || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        err = "object is not an ELF file";
        return false;
    }
    return true;
}

bool XdpManager::attach_generic(const std::string& iface,
                                const std::string& obj_path,
                                const std::string& section,
                                std::string& err,
                                const std::string& ip_bin) {
    std::string out;
    int rc = run_cmd({ip_bin, "link", "set", "dev", iface,
                      "xdpgeneric", "obj", obj_path, "sec", section}, out);
    if (rc != 0) {
        err = "ip xdpgeneric attach failed (" + std::to_string(rc) + "): " + out;
        return false;
    }
    return true;
}

bool XdpManager::detach_generic(const std::string& iface,
                                std::string& err,
                                const std::string& ip_bin) {
    std::string out;
    int rc = run_cmd({ip_bin, "link", "set", "dev", iface, "xdpgeneric", "off"}, out);
    if (rc != 0) {
        err = "ip xdpgeneric off failed (" + std::to_string(rc) + "): " + out;
        return false;
    }
    return true;
}

bool XdpManager::is_attached_generic(const std::string& iface,
                                     const std::string& ip_bin) {
    std::string out;
    int rc = run_cmd({ip_bin, "link", "show", "dev", iface}, out);
    if (rc != 0) return false;
    // iproute2 prints "xdpgeneric" (and prog id) when a generic program is attached
    return out.find("xdpgeneric") != std::string::npos &&
           out.find("prog/xdp") != std::string::npos;
}

bool XdpManager::map_lookup_pinned(const std::string& pin_path,
                                   const void* key, size_t key_len,
                                   void* value, size_t value_len) {
    (void)key_len; (void)value_len; // sizes are defined by the map itself
    int fd = bpf_obj_get(pin_path.c_str());
    if (fd < 0) return false;
    int rc = bpf_map_lookup(fd, key, value);
    ::close(fd);
    return rc == 0;
}

bool XdpManager::map_update_pinned(const std::string& pin_path,
                                   const void* key, size_t key_len,
                                   const void* value, size_t value_len) {
    (void)key_len; (void)value_len;
    int fd = bpf_obj_get(pin_path.c_str());
    if (fd < 0) return false;
    int rc = bpf_map_update(fd, key, value, 0 /*BPF_ANY*/);
    ::close(fd);
    return rc == 0;
}

int XdpManager::map_find(const std::string& name, uint32_t type,
                         uint32_t key_size, uint32_t value_size,
                         uint32_t max_entries) {
#if !defined(__linux__)
    (void)name; (void)type; (void)key_size; (void)value_size; (void)max_entries;
    errno = ENOSYS;
    return -1;
#else
    // BPF_MAP_GET_NEXT_ID = 12, BPF_OBJ_GET_INFO_BY_FD = 15
    uint32_t id = 0;
    for (int guard = 0; guard < 4096; ++guard) {
        struct { uint32_t start_id; uint32_t next_id; uint32_t open_flags; } attr{};
        attr.start_id = id;
        long rc = ::syscall(SYS_bpf, 12, &attr, sizeof(attr));
        if (rc != 0) return -1;  // no more maps or EPERM
        id = attr.next_id;

        struct { uint32_t map_id; uint64_t next_id; } fdattr{};
        fdattr.map_id = id;
        int fd = static_cast<int>(::syscall(SYS_bpf, 14 /*BPF_MAP_GET_FD_BY_ID*/,
                                            &fdattr, sizeof(fdattr)));
        if (fd < 0) continue;

        // struct bpf_map_info: name at offset 24, 16 bytes (BPF_OBJ_NAME_LEN)
        struct {
            uint32_t type;
            uint32_t id;
            uint32_t key_size;
            uint32_t value_size;
            uint32_t max_entries;
            uint32_t map_flags;
            char name[16];
            char _rest[216];
        } info{};
        struct { uint32_t bpf_fd; uint32_t info_len; uint64_t info; } iattr{};
        iattr.bpf_fd = static_cast<uint32_t>(fd);
        iattr.info_len = sizeof(info);
        iattr.info = reinterpret_cast<uint64_t>(&info);
        long irc = ::syscall(SYS_bpf, 15, &iattr, sizeof(iattr));
        if (irc == 0) {
            bool match;
            if (info.name[0] != '\0') {
                match = (name == info.name);
            } else {
                // legacy loader: no name — match structurally
                match = (info.type == type && info.key_size == key_size &&
                         info.value_size == value_size &&
                         info.max_entries == max_entries);
            }
            if (match) return fd;  // caller owns fd
        }
        ::close(fd);
    }
    return -1;
#endif  // __linux__
}

bool XdpManager::read_udp_stats(uint32_t dport, XdpStats& out,
                                const std::string& pin_path) {
    if (!pin_path.empty() &&
        map_lookup_pinned(pin_path, &dport, sizeof(dport), &out, sizeof(out)))
        return true;
    int fd = map_find("udp_stats_map", 1 /*HASH*/, 4, 16, 1024);
    if (fd < 0) return false;
    int rc = bpf_map_lookup(fd, &dport, &out);
    int saved = errno;
    ::close(fd);
    if (rc != 0 && saved == ENOENT) {
        // Map reachable, no packets counted for this port yet.
        out = XdpStats{};
        return true;
    }
    return rc == 0;
}

bool XdpManager::set_drop_port(uint32_t dport, const std::string& pin_path) {
    uint32_t zero = 0;
    if (!pin_path.empty() &&
        map_update_pinned(pin_path, &zero, sizeof(zero), &dport, sizeof(dport)))
        return true;
    int fd = map_find("xdp_config_map", 2 /*ARRAY*/, 4, 4, 1);
    if (fd < 0) return false;
    int rc = bpf_map_update(fd, &zero, &dport, 0 /*BPF_ANY*/);
    ::close(fd);
    return rc == 0;
}

bool XdpManager::kernel_supports_bpf() {
#if !defined(__linux__)
    return false;  // bpf(2) is a Linux syscall
#else
    // Minimal probe: an intentionally invalid-but-parseable program load.
    // EPERM/EINVAL => syscall exists; ENOSYS => no BPF support.
    uint64_t insns[2] = {
        0x00000000000000b7ULL, // mov64 r0, 0
        0x0000000000000095ULL, // exit
    };
    struct {
        uint32_t prog_type;
        uint32_t insn_cnt;
        uint64_t insns;
        uint64_t license;
        uint32_t log_level;
        uint32_t log_size;
        uint64_t log_buf;
        uint32_t kern_version;
        uint32_t prog_flags;
        char _pad[64];
    } attr{};
    attr.prog_type = 6;  // BPF_PROG_TYPE_XDP
    attr.insn_cnt = 2;
    attr.insns = reinterpret_cast<uint64_t>(&insns);
    attr.license = reinterpret_cast<uint64_t>("GPL");
    attr.kern_version = 0;
    int rc = static_cast<int>(::syscall(SYS_bpf, 5 /*BPF_PROG_LOAD*/, &attr, sizeof(attr)));
    if (rc >= 0) { ::close(rc); return true; }
    return errno != ENOSYS;
#endif  // __linux__
}

} // namespace ncp
