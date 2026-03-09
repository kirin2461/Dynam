@echo off
REM ============================================
REM NCP-CPP Build Script using VCPKG
REM For Visual Studio 2022/2026 and newer
REM ============================================
setlocal enabledelayedexpansion

set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "CYAN=[96m"
set "NC=[0m"

echo %GREEN%========================================%NC%
echo %GREEN%  NCP-CPP Build Script (VCPKG)%NC%
echo %GREEN%========================================%NC%
echo.

set "PROJECT_ROOT=%~dp0.."
set "VCPKG_ROOT=%PROJECT_ROOT%\vcpkg"

REM Check CMake
echo %YELLOW%[1/5] Checking prerequisites...%NC%
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: CMake not found%NC%
    goto :error
)
echo   - CMake found

REM Check Git
where git >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: Git not found. Please install Git%NC%
    goto :error
)
echo   - Git found
echo.

REM Install/Update VCPKG
echo %YELLOW%[2/5] Setting up VCPKG...%NC%
if not exist "%VCPKG_ROOT%" (
    echo   Cloning vcpkg...
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_ROOT%"
    if %ERRORLEVEL% NEQ 0 (
        echo %RED%ERROR: Failed to clone vcpkg%NC%
        goto :error
    )
)

if not exist "%VCPKG_ROOT%\vcpkg.exe" (
    echo   Bootstrapping vcpkg...
    call "%VCPKG_ROOT%\bootstrap-vcpkg.bat" -disableMetrics
    if %ERRORLEVEL% NEQ 0 (
        echo %RED%ERROR: Failed to bootstrap vcpkg%NC%
        goto :error
    )
)
echo   - VCPKG ready
echo.

REM Install dependencies
echo %YELLOW%[3/5] Installing dependencies via VCPKG...%NC%
echo   This may take a while on first run...
"%VCPKG_ROOT%\vcpkg.exe" install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: Failed to install dependencies%NC%
    goto :error
)
echo   - Dependencies installed
echo.

REM Create build directory
echo %YELLOW%[4/5] Configuring with CMake...%NC%
cd /d "%PROJECT_ROOT%"
if exist "build" rmdir /s /q build
mkdir build
cd build

cmake .. -DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release -DENABLE_GUI=OFF -DENABLE_CLI=ON -DENABLE_TESTS=ON
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: CMake configuration failed%NC%
    goto :error
)
echo   - CMake configuration complete
echo.

REM Build
echo %YELLOW%[5/5] Building project...%NC%
cmake --build . --config Release --parallel %NUMBER_OF_PROCESSORS%
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: Build failed%NC%
    goto :error
)
echo   - Build complete
echo.

echo %GREEN%========================================%NC%
echo %GREEN%  Build completed successfully!%NC%
echo %GREEN%========================================%NC%
echo.
echo Executable: %PROJECT_ROOT%\build\Release\ncp_cli.exe
echo.

set /p RUN="Run CLI app? (y/n): "
if /i "%RUN%"=="y" (
    "%PROJECT_ROOT%\build\Release\ncp_cli.exe" help
)
goto :end

:error
echo.
echo %RED%Build failed!%NC%
pause
exit /b 1

:end
cd /d "%~dp0"
pause
exit /b 0
