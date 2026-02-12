@echo off
setlocal enabledelayedexpansion

:: NCP Windows Launcher & Dependencies Setup
echo [NCP] Initializing Network Control Protocol...

:: Check for CMake
where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] CMake not found. Please install CMake and add it to PATH.
    pause
    exit /b 1
)

:: Check for Visual Studio or MSVC
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] MSVC Compiler not found. Ensure "Desktop development with C++" is installed.
    pause
    exit /b 1
)

:: Build NCP if not already built
if not exist "build\bin\ncp.exe" (
    echo [*] Building NCP project...
    if not exist build mkdir build
    cd build
    cmake .. -G "Visual Studio 17 2022" -DCMAKE_BUILD_TYPE=Release -DENABLE_CLI=ON -DENABLE_GUI=OFF -DENABLE_TESTS=OFF
    cmake --build . --config Release
    cd ..
)

:: CLI Commands Interface
:MENU
echo.
echo ============================================================
echo   NCP - Network Control Protocol (Windows CLI)
echo ============================================================
echo   Commands:
echo   run       - Launch PARANOID Mode (all 8 protection layers)
echo     status   - View current protection status
echo     help     - Show list of all available commands
echo     exit     - Close application
echo ============================================================
echo.

set /p CMD="Enter command: "

if /i "%CMD%"=="run" (
    echo [*] Activating PARANOID Mode (all 8 protection layers)...
        :: 'run' command now auto-enables PARANOID mode with all protection layers
    build\bin\Release\ncp.exe run
    goto MENU
)
    

if /i "%CMD%"=="status" (
    build\bin\Release\ncp.exe status
    goto MENU
)

if /i "%CMD%"=="help" (
    build\bin\Release\ncp.exe help
    goto MENU
)

if /i "%CMD%"=="exit" (
    exit /b 0
)

:: For any other command, pass it directly to the binary
build\bin\Release\ncp.exe %CMD%
goto MENU
