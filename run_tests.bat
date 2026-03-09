@echo off
title NCP - Tests
echo.
echo  Running NCP tests...
echo.
cd /d "%~dp0build"
ctest --build-config Release --output-on-failure --parallel %NUMBER_OF_PROCESSORS%
echo.
pause
