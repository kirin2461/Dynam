@echo off
REM ============================================
REM NCP-CPP Build Script for Windows (No Qt6 required)
REM ============================================

set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "CYAN=[96m"
set "NC=[0m"

echo %GREEN%============================================%NC%
echo %GREEN%  NCP-CPP Build Script for Windows%NC%
echo %GREEN%  Core + CLI only (no Qt6 required)%NC%
echo %GREEN%============================================%NC%
echo.

REM Get the script directory and go to project root
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%.."
set "PROJECT_ROOT=%CD%"
echo Working directory: %PROJECT_ROOT%
echo.

REM Verify CMakeLists.txt exists
if not exist CMakeLists.txt (
    echo %RED%ERROR: CMakeLists.txt not found in %PROJECT_ROOT%%NC%
    echo Please run this script from the scripts folder inside the project.
    goto :error
)

REM Check for CMake
echo %YELLOW%[1/4] Checking prerequisites...%NC%
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: CMake not found. Please install CMake 3.20+%NC%
    echo Download from: https://cmake.org/download/
    goto :error
)
echo   - CMake found

REM Find Visual Studio
set VCVARS=

REM VS 2022 BuildTools in Program Files (x86)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2022 Build Tools found
    goto :vs_found
)

REM VS 2022 BuildTools in Program Files
if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2022 Build Tools found
    goto :vs_found
)

REM VS 2022 Community
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2022 Community found
    goto :vs_found
)

REM VS 2022 Professional
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2022 Professional found
    goto :vs_found
)

REM VS 2022 Enterprise
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2022 Enterprise found
    goto :vs_found
)

REM VS 2019 BuildTools
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2019 Build Tools found
    goto :vs_found
)

REM VS 2019 Community
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    echo   - Visual Studio 2019 Community found
    goto :vs_found
)

REM Visual Studio not found
echo %RED%ERROR: Visual Studio not found.%NC%
echo Please install Visual Studio 2022 or 2019 with C++ workload
echo Download from: https://visualstudio.microsoft.com/downloads/
goto :error

:vs_found

REM Setup VS environment
echo.
echo %YELLOW%[2/4] Setting up Visual Studio environment...%NC%
call "%VCVARS%"
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: Failed to setup Visual Studio environment%NC%
    goto :error
)
echo   - Environment configured

REM Create build directory
echo.
echo %YELLOW%[3/4] Configuring CMake...%NC%
if not exist build mkdir build
cd build

REM Configure with CMake
cmake "%PROJECT_ROOT%" -G "Visual Studio 17 2022" -A x64 -DENABLE_GUI=OFF -DENABLE_CLI=ON -DENABLE_TESTS=OFF 2>nul
if %ERRORLEVEL% NEQ 0 (
    cmake "%PROJECT_ROOT%" -G "Visual Studio 16 2019" -A x64 -DENABLE_GUI=OFF -DENABLE_CLI=ON -DENABLE_TESTS=OFF 2>nul
    if %ERRORLEVEL% NEQ 0 (
        cmake "%PROJECT_ROOT%" -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DENABLE_GUI=OFF -DENABLE_CLI=ON -DENABLE_TESTS=OFF 2>nul
        if %ERRORLEVEL% NEQ 0 (
            cmake "%PROJECT_ROOT%" -DENABLE_GUI=OFF -DENABLE_CLI=ON -DENABLE_TESTS=OFF
            if %ERRORLEVEL% NEQ 0 (
                echo %RED%ERROR: CMake configuration failed%NC%
                cd "%PROJECT_ROOT%"
                goto :error
            )
        )
    )
)
echo   - Configuration complete

REM Build
echo.
echo %YELLOW%[4/4] Building project...%NC%
cmake --build . --config Release
if %ERRORLEVEL% NEQ 0 (
    echo %RED%ERROR: Build failed%NC%
    cd "%PROJECT_ROOT%"
    goto :error
)

echo.
echo %GREEN%============================================%NC%
echo %GREEN%  Build completed successfully!%NC%
echo %GREEN%============================================%NC%
echo.
echo Output files are in: %PROJECT_ROOT%\build\bin\Release\
echo.

if exist bin\Release\ncp.exe (
    echo %CYAN%Running CLI tool...%NC%
    echo.
    bin\Release\ncp.exe --help
)

cd "%PROJECT_ROOT%"
goto :end

:error
echo.
echo %RED%Build failed. Check the errors above.%NC%
exit /b 1

:end
echo.
pause
