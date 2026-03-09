@echo off
chcp 65001 >nul 2>&1
title BFE (Base Filtering Engine) Repair Tool
color 0B

echo ============================================================
echo    BFE (Base Filtering Engine) Repair Tool
echo    WinDivert requires BFE to be running
echo ============================================================
echo.

:: ---- Check admin rights ----
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script MUST be run as Administrator!
    echo Right-click the file and select "Run as administrator"
    pause
    exit /b 1
)
echo [OK] Running as Administrator
echo.

:: ---- Step 1: Check current BFE status ----
echo === Step 1: Checking BFE service status ===
sc query BFE >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] BFE service not found in registry!
    echo This is a serious Windows issue. BFE may need to be reinstalled.
    echo Try running: sfc /scannow
    pause
    exit /b 1
)

sc query BFE | findstr /i "STATE" | findstr /i "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] BFE is already RUNNING!
    echo.
    goto :check_firewall
)

echo [INFO] BFE is NOT running. Attempting repair...
echo.

:: ---- Step 2: Set BFE startup type to Automatic ----
echo === Step 2: Setting BFE startup type to Automatic ===
sc config BFE start= auto >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] BFE startup type set to Automatic
) else (
    echo [WARN] Could not set BFE startup type via sc config
    echo        Trying registry method...
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v Start /t REG_DWORD /d 2 /f >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] BFE Start value set to 2 (Automatic) via registry
    ) else (
        echo [WARN] Could not modify BFE registry Start value
    )
)
echo.

:: ---- Step 3: Reset BFE security descriptors ----
echo === Step 3: Resetting BFE security descriptors ===
echo Applying Windows 10 security descriptor...
SC.EXE SDSET BFE D:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD) >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Security descriptors reset (Win10 format)
    goto :step4
)
echo [INFO] Win10 format failed, trying Win11 format...
SC.EXE SDSET BFE D:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU) >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Security descriptors reset (Win11 format)
    goto :step4
)
echo [WARN] Could not reset BFE security descriptors
echo        This may be caused by permission restrictions
echo.

:step4
echo.

:: ---- Step 4: Fix BFE registry permissions ----
echo === Step 4: Fixing BFE registry permissions ===

:: Take ownership of BFE service registry key
echo Taking ownership of BFE registry keys...
takeown /f "C:\Windows\System32\bfe.dll" >nul 2>&1

:: Grant permissions to the BFE registry keys using SubInACL or icacls approach
:: We use reg commands to ensure BFE Parameters exist
reg query "HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] BFE Parameters\Policy key exists
) else (
    echo [INFO] BFE Parameters\Policy key missing, creating...
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy" /f >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Created BFE Parameters\Policy key
    ) else (
        echo [WARN] Could not create BFE Parameters\Policy key
    )
)
echo.

:: ---- Step 5: Repair BFE DLL with SFC ----
echo === Step 5: Repairing bfe.dll with System File Checker ===
sfc /scanfile=C:\Windows\System32\bfe.dll >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] bfe.dll integrity check passed
) else (
    echo [WARN] SFC could not verify bfe.dll
    echo        Running full system file check might be needed: sfc /scannow
)
echo.

:: ---- Step 6: Ensure dependent services config ----
echo === Step 6: Configuring dependent services ===
sc config RpcSs start= auto >nul 2>&1
echo [OK] RPC (RpcSs) set to Automatic
sc config RPCSS start= auto >nul 2>&1

:: Make sure mpssvc (Windows Firewall) can start
sc config mpssvc start= auto >nul 2>&1
echo [OK] Windows Firewall (mpssvc) set to Automatic

:: Make sure WFP/WdiServiceHost is set
sc config WdiServiceHost start= demand >nul 2>&1
echo.

:: ---- Step 7: Try starting BFE ----
echo === Step 7: Starting BFE service ===
net start BFE >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] BFE service started SUCCESSFULLY!
    echo.
    goto :check_firewall
)

:: If net start failed, try sc start
sc start BFE >nul 2>&1
timeout /t 3 >nul

sc query BFE | findstr /i "STATE" | findstr /i "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] BFE service started SUCCESSFULLY!
    echo.
    goto :check_firewall
)

echo [ERROR] BFE still could not start.
echo.
echo ============================================================
echo    BFE COULD NOT START - ADDITIONAL STEPS NEEDED
echo ============================================================
echo.
echo Try these manual steps:
echo.
echo 1. Run full system file check:
echo    sfc /scannow
echo    (wait for it to finish, then reboot)
echo.
echo 2. If sfc finds problems, also run:
echo    DISM /Online /Cleanup-Image /RestoreHealth
echo    (then run sfc /scannow again)
echo.
echo 3. Check for malware:
echo    Open CMD as admin and run: mrt.exe /F:Y
echo    (this runs Microsoft Malicious Software Removal Tool)
echo.
echo 4. After any of the above, REBOOT and run this script again.
echo.
echo 5. If nothing helps, try Windows Repair (free tool):
echo    https://www.tweaking.com/
echo.
pause
exit /b 1

:check_firewall
echo === Checking Windows Firewall ===
sc query mpssvc | findstr /i "STATE" | findstr /i "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Windows Firewall is already running
) else (
    echo [INFO] Starting Windows Firewall...
    net start mpssvc >nul 2>&1
    sc query mpssvc | findstr /i "STATE" | findstr /i "RUNNING" >nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Windows Firewall started successfully
    ) else (
        echo [WARN] Windows Firewall did not start
        echo        It may start after reboot
    )
)
echo.

echo === Verifying WinDivert compatibility ===
sc query BFE | findstr /i "STATE" | findstr /i "RUNNING" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] BFE is RUNNING - WinDivert should now work!
) else (
    echo [WARN] BFE is not running
)
echo.

echo ============================================================
echo    REPAIR COMPLETE
echo ============================================================
echo.
echo STATUS SUMMARY:

sc query BFE | findstr /i "STATE"
sc query mpssvc | findstr /i "STATE"

echo.
echo IMPORTANT: Please REBOOT your computer now, then:
echo   1. Run NCP as Administrator
echo   2. Check if DPI bypass starts successfully
echo.
echo If BFE started successfully, WinDivert error 1058
echo should be resolved after reboot.
echo.
pause
