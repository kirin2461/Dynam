@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

title Dynam (NCP) - Build Script
color 0A

echo ============================================
echo   Dynam (NCP C++) - Автоматическая сборка
echo ============================================
echo.

:: ==========================================
:: Настройки (можно менять)
:: ==========================================
set "BUILD_TYPE=Release"
set "VCPKG_DIR=%USERPROFILE%\vcpkg"
set "REPO_URL=https://github.com/kirin2461/Dynam.git"
set "PROJECT_DIR=%~dp0"

:: ==========================================
:: 1. Проверка Git
:: ==========================================
echo [1/6] Проверка Git...
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Git не найден. Скачиваю Git...
    echo     Скачивание Git для Windows...
    powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.2/Git-2.47.1.2-64-bit.exe' -OutFile '%TEMP%\git-installer.exe' }"
    if exist "%TEMP%\git-installer.exe" (
        echo     Устанавливаю Git тихо...
        "%TEMP%\git-installer.exe" /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
        set "PATH=%PATH%;C:\Program Files\Git\cmd"
        del "%TEMP%\git-installer.exe" >nul 2>&1
    ) else (
        echo [ОШИБКА] Не удалось скачать Git. Установите вручную: https://git-scm.com
        goto :error
    )
)
for /f "tokens=3" %%v in ('git --version') do echo     Git %%v - OK
echo.

:: ==========================================
:: 2. Проверка CMake
:: ==========================================
echo [2/6] Проверка CMake...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] CMake не найден. Скачиваю CMake...
    powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/Kitware/CMake/releases/download/v3.31.4/cmake-3.31.4-windows-x86_64.msi' -OutFile '%TEMP%\cmake-installer.msi' }"
    if exist "%TEMP%\cmake-installer.msi" (
        echo     Устанавливаю CMake тихо...
        msiexec /i "%TEMP%\cmake-installer.msi" /quiet /norestart ADD_CMAKE_TO_PATH=System
        set "PATH=%PATH%;C:\Program Files\CMake\bin"
        del "%TEMP%\cmake-installer.msi" >nul 2>&1
    ) else (
        echo [ОШИБКА] Не удалось скачать CMake. Установите вручную: https://cmake.org
        goto :error
    )
)
for /f "tokens=3" %%v in ('cmake --version 2^>^&1') do (
    echo     CMake %%v - OK
    goto :cmake_ok
)
:cmake_ok
echo.

:: ==========================================
:: 3. Проверка Visual Studio / MSVC
:: ==========================================
echo [3/6] Проверка Visual Studio...
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VS_FOUND=0"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
        set "VS_PATH=%%i"
        set "VS_FOUND=1"
    )
)

if "!VS_FOUND!"=="0" (
    echo [!] Visual Studio с C++ не найдена.
    echo     Скачиваю Visual Studio Build Tools...
    powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile '%TEMP%\vs_buildtools.exe' }"
    if exist "%TEMP%\vs_buildtools.exe" (
        echo     Устанавливаю Build Tools (это займет 5-15 минут)...
        "%TEMP%\vs_buildtools.exe" --quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended
        del "%TEMP%\vs_buildtools.exe" >nul 2>&1
        echo     Visual Studio Build Tools установлены.
    ) else (
        echo [ОШИБКА] Не удалось скачать VS Build Tools.
        echo     Установите вручную: https://visualstudio.microsoft.com/visual-cpp-build-tools/
        goto :error
    )
) else (
    echo     Visual Studio найдена: !VS_PATH!
)
echo.

:: ==========================================
:: 4. Установка vcpkg и libsodium
:: ==========================================
echo [4/6] Настройка vcpkg и зависимостей...

if not exist "%VCPKG_DIR%\vcpkg.exe" (
    echo     Клонирую vcpkg...
    if exist "%VCPKG_DIR%" rmdir /s /q "%VCPKG_DIR%"
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_DIR%"
    if %errorlevel% neq 0 (
        echo [ОШИБКА] Не удалось клонировать vcpkg.
        goto :error
    )
    echo     Собираю vcpkg...
    call "%VCPKG_DIR%\bootstrap-vcpkg.bat" -disableMetrics
    if %errorlevel% neq 0 (
        echo [ОШИБКА] Не удалось собрать vcpkg.
        goto :error
    )
) else (
    echo     vcpkg найден: %VCPKG_DIR%
)

echo     Устанавливаю libsodium (x64-windows)...
"%VCPKG_DIR%\vcpkg.exe" install libsodium:x64-windows
if %errorlevel% neq 0 (
    echo [ОШИБКА] Не удалось установить libsodium.
    goto :error
)
echo     libsodium - OK
echo.

:: ==========================================
:: 5. Конфигурация CMake
:: ==========================================
echo [5/6] Конфигурация CMake...

if exist "%PROJECT_DIR%build" rmdir /s /q "%PROJECT_DIR%build"

cmake -B "%PROJECT_DIR%build" -S "%PROJECT_DIR%." ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_TOOLCHAIN_FILE="%VCPKG_DIR%/scripts/buildsystems/vcpkg.cmake" ^
    -DENABLE_TESTS=ON ^
    -DENABLE_CLI=ON ^
    -DENABLE_GUI=OFF ^
    -DENABLE_LIBOQS=OFF ^
    -DENABLE_WEBSOCKETS=OFF ^
    -DENABLE_TOR_PROXY=OFF

if %errorlevel% neq 0 (
    echo [ОШИБКА] CMake конфигурация провалилась.
    goto :error
)
echo     Конфигурация - OK
echo.

:: ==========================================
:: 6. Сборка
:: ==========================================
echo [6/6] Сборка проекта...

cmake --build "%PROJECT_DIR%build" --config %BUILD_TYPE% -j %NUMBER_OF_PROCESSORS%

if %errorlevel% neq 0 (
    echo [ОШИБКА] Сборка провалилась.
    goto :error
)

echo.
echo ============================================
echo   СБОРКА УСПЕШНА!
echo ============================================
echo.
echo Бинарники находятся в: %PROJECT_DIR%build\bin\%BUILD_TYPE%
echo.

if exist "%PROJECT_DIR%build\bin\%BUILD_TYPE%\ncp-cli.exe" (
    echo Найден ncp-cli.exe - запускаю...
    echo.
    "%PROJECT_DIR%build\bin\%BUILD_TYPE%\ncp-cli.exe" --help
) else (
    echo Исполняемые файлы в build\bin\:
    dir /b "%PROJECT_DIR%build\bin\%BUILD_TYPE%\*.exe" 2>nul
    if %errorlevel% neq 0 (
        dir /b "%PROJECT_DIR%build\bin\*.exe" 2>nul
    )
)

echo.
echo Нажмите любую клавишу для выхода...
pause >nul
exit /b 0

:error
echo.
echo [ОШИБКА] Сборка завершилась с ошибкой.
echo Нажмите любую клавишу для выхода...
pause >nul
exit /b 1
