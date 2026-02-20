/**
 * @file smbios_hook.cpp
 * @brief LD_PRELOAD library for SMBIOS/DMI spoofing on Linux
 *
 * Compile: gcc -shared -fPIC -o libncp_smbios_hook.so smbios_hook.cpp -ldl
 * Usage:   LD_PRELOAD=./libncp_smbios_hook.so <program>
 *
 * Set fake values via environment:
 *   NCP_BOARD_SERIAL, NCP_PRODUCT_SERIAL, NCP_PRODUCT_UUID,
 *   NCP_BIOS_VENDOR, NCP_BIOS_VERSION, NCP_DISK_SERIAL
 */

#ifndef _WIN32

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>

// DMI sysfs paths we intercept
static const char* DMI_BOARD_SERIAL   = "/sys/class/dmi/id/board_serial";
static const char* DMI_PRODUCT_SERIAL = "/sys/class/dmi/id/product_serial";
static const char* DMI_PRODUCT_UUID   = "/sys/class/dmi/id/product_uuid";
static const char* DMI_BIOS_VENDOR    = "/sys/class/dmi/id/bios_vendor";
static const char* DMI_BIOS_VERSION   = "/sys/class/dmi/id/bios_version";
static const char* DMI_BOARD_VENDOR   = "/sys/class/dmi/id/board_vendor";
static const char* DMI_BOARD_NAME     = "/sys/class/dmi/id/board_name";
static const char* DMI_SYS_VENDOR     = "/sys/class/dmi/id/sys_vendor";
static const char* DMI_PRODUCT_NAME   = "/sys/class/dmi/id/product_name";

// Default fake values (overridden by env vars)
static const char* DEFAULT_BOARD_SERIAL   = "PF2K4B9N01";
static const char* DEFAULT_PRODUCT_SERIAL = "VMW7ABCD1234";
static const char* DEFAULT_PRODUCT_UUID   = "a1b2c3d4-e5f6-4789-abcd-ef0123456789";
static const char* DEFAULT_BIOS_VENDOR    = "American Megatrends Inc.";
static const char* DEFAULT_BIOS_VERSION   = "F20a";

static const char* get_fake_value(const char* env_name, const char* default_val) {
    const char* val = getenv(env_name);
    return (val && val[0]) ? val : default_val;
}

static int create_fake_fd(const char* content) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return -1;

    size_t len = strlen(content);
    ssize_t written = write(pipefd[1], content, len);
    (void)written;
    // Write trailing newline like real sysfs
    write(pipefd[1], "\n", 1);
    close(pipefd[1]);

    return pipefd[0];
}

static const char* match_dmi_path(const char* pathname) {
    if (!pathname) return NULL;

    if (strcmp(pathname, DMI_BOARD_SERIAL) == 0)
        return get_fake_value("NCP_BOARD_SERIAL", DEFAULT_BOARD_SERIAL);
    if (strcmp(pathname, DMI_PRODUCT_SERIAL) == 0)
        return get_fake_value("NCP_PRODUCT_SERIAL", DEFAULT_PRODUCT_SERIAL);
    if (strcmp(pathname, DMI_PRODUCT_UUID) == 0)
        return get_fake_value("NCP_PRODUCT_UUID", DEFAULT_PRODUCT_UUID);
    if (strcmp(pathname, DMI_BIOS_VENDOR) == 0)
        return get_fake_value("NCP_BIOS_VENDOR", DEFAULT_BIOS_VENDOR);
    if (strcmp(pathname, DMI_BIOS_VERSION) == 0)
        return get_fake_value("NCP_BIOS_VERSION", DEFAULT_BIOS_VERSION);
    if (strcmp(pathname, DMI_BOARD_VENDOR) == 0)
        return get_fake_value("NCP_BOARD_VENDOR", "ASUSTeK Computer INC.");
    if (strcmp(pathname, DMI_BOARD_NAME) == 0)
        return get_fake_value("NCP_BOARD_NAME", "PRIME Z490-A");
    if (strcmp(pathname, DMI_SYS_VENDOR) == 0)
        return get_fake_value("NCP_SYS_VENDOR", "ASUS");
    if (strcmp(pathname, DMI_PRODUCT_NAME) == 0)
        return get_fake_value("NCP_PRODUCT_NAME", "System Product Name");

    return NULL;
}

// ==================== Hooked Functions ====================

typedef int (*orig_open_t)(const char*, int, ...);
typedef FILE* (*orig_fopen_t)(const char*, const char*);

extern "C" {

int open(const char* pathname, int flags, ...) {
    static orig_open_t orig_open = NULL;
    if (!orig_open) {
        orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
    }

    const char* fake = match_dmi_path(pathname);
    if (fake) {
        return create_fake_fd(fake);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        return orig_open(pathname, flags, mode);
    }

    return orig_open(pathname, flags);
}

int open64(const char* pathname, int flags, ...) {
    static orig_open_t orig_open64 = NULL;
    if (!orig_open64) {
        orig_open64 = (orig_open_t)dlsym(RTLD_NEXT, "open64");
    }

    const char* fake = match_dmi_path(pathname);
    if (fake) {
        return create_fake_fd(fake);
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = (mode_t)va_arg(args, int);
        va_end(args);
        return orig_open64(pathname, flags, mode);
    }

    return orig_open64(pathname, flags);
}

FILE* fopen(const char* pathname, const char* mode) {
    static orig_fopen_t orig_fopen = NULL;
    if (!orig_fopen) {
        orig_fopen = (orig_fopen_t)dlsym(RTLD_NEXT, "fopen");
    }

    const char* fake = match_dmi_path(pathname);
    if (fake) {
        int fd = create_fake_fd(fake);
        if (fd >= 0) {
            return fdopen(fd, "r");
        }
    }

    return orig_fopen(pathname, mode);
}

FILE* fopen64(const char* pathname, const char* mode) {
    static orig_fopen_t orig_fopen64 = NULL;
    if (!orig_fopen64) {
        orig_fopen64 = (orig_fopen_t)dlsym(RTLD_NEXT, "fopen64");
    }

    const char* fake = match_dmi_path(pathname);
    if (fake) {
        int fd = create_fake_fd(fake);
        if (fd >= 0) {
            return fdopen(fd, "r");
        }
    }

    return orig_fopen64(pathname, mode);
}

} // extern "C"

#endif // !_WIN32
