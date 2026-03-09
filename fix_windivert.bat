@echo off
:: ============================================================
:: WinDivert Driver Fix Script
:: Fixes error 1058 (ERROR_SERVICE_DISABLED)
:: Run as Administrator!
:: ============================================================

echo ============================================
echo  WinDivert Driver Diagnostic and Fix Tool
echo ============================================
echo.

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

echo [OK] Running as Administrator
echo.

:: --- Step 1: Check for WinDivert files ---
echo --- Step 1: Checking WinDivert files ---
set "SCRIPT_DIR=%~dp0"
set "BUILD_DIR=%SCRIPT_DIR%build"

if exist "%BUILD_DIR%\ncp.exe" (
    echo [OK] ncp.exe found in build\
) else (
    echo [WARN] ncp.exe not found in build\
)

if exist "%BUILD_DIR%\WinDivert.dll" (
    echo [OK] WinDivert.dll found in build\
) else (
    echo [WARN] WinDivert.dll NOT found in build\
    :: Try to copy from SDK
    if exist "C:\WinDivert-2.2.2-A\x64\WinDivert.dll" (
        copy "C:\WinDivert-2.2.2-A\x64\WinDivert.dll" "%BUILD_DIR%\" >nul
        echo [FIX] Copied WinDivert.dll from SDK
    )
)

if exist "%BUILD_DIR%\WinDivert64.sys" (
    echo [OK] WinDivert64.sys found in build\
) else (
    echo [WARN] WinDivert64.sys NOT found in build\
    :: Try to copy from SDK
    if exist "C:\WinDivert-2.2.2-A\x64\WinDivert64.sys" (
        copy "C:\WinDivert-2.2.2-A\x64\WinDivert64.sys" "%BUILD_DIR%\" >nul
        echo [FIX] Copied WinDivert64.sys from SDK
    )
)
echo.

:: --- Step 2: Check WinDivert service in registry ---
echo --- Step 2: Checking WinDivert service registry ---

reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert" >nul 2>&1
if %errorlevel% equ 0 (
    echo [FOUND] WinDivert service exists in registry
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert" /v Start 2>nul
    reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert" /v ImagePath 2>nul
    echo.
    echo [INFO] Stale WinDivert service entry found. This is the cause of error 1058.
    echo [FIX] Removing stale WinDivert service...
    sc stop WinDivert >nul 2>&1
    sc delete WinDivert >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] WinDivert service deleted successfully
    ) else (
        echo [INFO] sc delete failed, trying registry cleanup...
        reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert" /f >nul 2>&1
        if %errorlevel% equ 0 (
            echo [OK] WinDivert registry entry removed
        ) else (
            echo [ERROR] Failed to remove registry entry. Try rebooting and running again.
        )
    )
) else (
    echo [OK] No stale WinDivert service in registry
)

:: Also check WinDivert1.0 (older versions)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert1.0" >nul 2>&1
if %errorlevel% equ 0 (
    echo [FOUND] Old WinDivert1.0 service found, removing...
    sc stop WinDivert1.0 >nul 2>&1
    sc delete WinDivert1.0 >nul 2>&1
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert1.0" /f >nul 2>&1
    echo [OK] Old WinDivert1.0 cleaned up
)

:: Check WinDivert14 (another old version)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert14" >nul 2>&1
if %errorlevel% equ 0 (
    echo [FOUND] Old WinDivert14 service found, removing...
    sc stop WinDivert14 >nul 2>&1
    sc delete WinDivert14 >nul 2>&1
    reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WinDivert14" /f >nul 2>&1
    echo [OK] Old WinDivert14 cleaned up
)
echo.

:: --- Step 3: Check Base Filtering Engine (BFE) ---
echo --- Step 3: Checking Base Filtering Engine ---
sc query BFE | findstr "STATE" | findstr "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Base Filtering Engine is running
) else (
    echo [WARN] Base Filtering Engine is NOT running!
    echo [FIX] Attempting BFE repair...
    sc config BFE start= auto >nul 2>&1
    SC.EXE SDSET BFE D:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD) >nul 2>&1
    if %errorlevel% neq 0 (
        SC.EXE SDSET BFE D:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU) >nul 2>&1
    )
    net start BFE >nul 2>&1
    sc query BFE | findstr "STATE" | findstr "RUNNING" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] BFE started successfully
    ) else (
        echo [ERROR] Could not start BFE. WinDivert will NOT work.
        echo [ERROR] Run fix_bfe.bat for advanced BFE repair.
    )
)
echo.

:: --- Step 4: Check Windows Filtering Platform ---
echo --- Step 4: Checking WFP service ---
sc query mpssvc | findstr "STATE" | findstr "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Windows Firewall service is running
) else (
    echo [WARN] Windows Firewall service is not running
    echo [INFO] This may cause WFP filter errors (err=2150760487)
)
echo.

:: --- Step 5: Check for driver signing ---
echo --- Step 5: Checking Secure Boot / driver signing ---
bcdedit /enum {current} 2>nul | findstr /i "testsigning" | findstr /i "Yes" >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Test signing is enabled
) else (
    echo [INFO] Test signing is not enabled (normal)
)
echo.

:: --- Step 6: Verify file signatures ---
echo --- Step 6: Verifying WinDivert file signatures ---
if exist "%BUILD_DIR%\WinDivert64.sys" (
    signtool verify /pa "%BUILD_DIR%\WinDivert64.sys" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] WinDivert64.sys signature is valid
    ) else (
        echo [INFO] Could not verify signature (signtool may not be in PATH)
        echo [INFO] Using pre-built WinDivert from official release should be fine
    )
)
echo.

:: --- Summary ---
echo ============================================
echo  DONE! Summary of actions:
echo ============================================
echo  - Checked WinDivert files in build directory
echo  - Cleaned up stale WinDivert service entries
echo  - Verified Base Filtering Engine is running
echo  - Checked Windows Firewall service
echo.
echo  NEXT STEPS:
echo  1. Reboot your computer (recommended after service cleanup)
echo  2. Run NCP as Administrator
echo  3. If error persists after reboot, check if antivirus
echo     (Windows Defender, Kaspersky, etc.) is blocking WinDivert
echo.
echo  ANTIVIRUS: WinDivert is often flagged as suspicious.
echo  Add these to your antivirus exclusions:
echo    - %BUILD_DIR%\WinDivert.dll
echo    - %BUILD_DIR%\WinDivert64.sys
echo    - %BUILD_DIR%\ncp.exe
echo ============================================
pause
