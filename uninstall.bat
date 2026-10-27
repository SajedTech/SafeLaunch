@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  SafeLaunch / VirusTotal Inspector - Uninstaller
echo =====================================================================
echo:

REM Terminate any running instances before cleaning up
taskkill /F /IM vt_checker.exe >nul 2>nul

set "KEY_FILES=HKCU\Software\Classes\*\shell\ScanWithVirusTotal"
set "KEY_DIR=HKCU\Software\Classes\Directory\shell\ScanWithVirusTotal"
set "KEY_BG=HKCU\Software\Classes\Directory\Background\shell\ScanWithVirusTotal"

echo Removing context menu registry entries...

REM 1. Remove Files key
reg query "%KEY_FILES%" >nul 2>nul
if %errorlevel% equ 0 (
    reg delete "%KEY_FILES%" /f >nul
    echo [SUCCESS] Removed File context menu entry.
) else (
    echo [INFO] File entry not found [already removed].
)

REM 2. Remove Directory key
reg query "%KEY_DIR%" >nul 2>nul
if %errorlevel% equ 0 (
    reg delete "%KEY_DIR%" /f >nul
    echo [SUCCESS] Removed Folder context menu entry.
) else (
    echo [INFO] Folder entry not found [already removed].
)

REM 3. Remove Directory Background key
reg query "%KEY_BG%" >nul 2>nul
if %errorlevel% equ 0 (
    reg delete "%KEY_BG%" /f >nul
    echo [SUCCESS] Removed Folder Background entry.
) else (
    echo [INFO] Folder Background entry not found [already removed].
)

REM 4. Cleanup Local AppData binary while preserving config.json if desired
set "INSTALL_DIR=%LOCALAPPDATA%\VirusTotalChecker"
if exist "%INSTALL_DIR%" (
    echo:
    echo Cleaning up executable files from: "%INSTALL_DIR%"
    if exist "%INSTALL_DIR%\vt_checker.exe" del /f /q "%INSTALL_DIR%\vt_checker.exe" >nul 2>nul
    if exist "%INSTALL_DIR%\vt_icon.ico" del /f /q "%INSTALL_DIR%\vt_icon.ico" >nul 2>nul
    echo [SUCCESS] Application binaries removed.
    echo [NOTE] If you stored an API key, config.json is preserved in %INSTALL_DIR%.
)

echo:
echo =====================================================================
echo  Uninstallation Complete!
echo  "Scan with VirusTotal" has been removed from all Context Menus.
echo =====================================================================
echo:
pause
