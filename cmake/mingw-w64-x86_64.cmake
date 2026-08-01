# CMake toolchain: Linux -> Windows x86_64 cross-compile via mingw-w64
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc-posix)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++-posix)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

set(WIN_DEPS /opt/win-deps)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32 ${WIN_DEPS})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(OPENSSL_ROOT_DIR ${WIN_DEPS})
set(SODIUM_ROOT_DIR ${WIN_DEPS})
set(CMAKE_PREFIX_PATH ${WIN_DEPS})

# Static libstdc++/libgcc/winpthread so ncp.exe runs without mingw DLLs
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc -static-libstdc++")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-static-libgcc -static-libstdc++")
