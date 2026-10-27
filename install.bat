@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  SafeLaunch / VirusTotal Inspector - Installer
echo =====================================================================
echo:

set "SCRIPT_DIR=%~dp0"
set "SOURCE_EXE="

REM Find compiled executable
if exist "%SCRIPT_DIR%dist\vt_checker.exe" (
    set "SOURCE_EXE=%SCRIPT_DIR%dist\vt_checker.exe"
) else if exist "%SCRIPT_DIR%vt_checker.exe" (
    set "SOURCE_EXE=%SCRIPT_DIR%vt_checker.exe"
)

if not defined SOURCE_EXE (
    echo [ERROR] vt_checker.exe was not found!
    echo Please compile the executable first by running "build.bat".
    echo:
    pause
    exit /b 1
)

echo Found executable: "%SOURCE_EXE%"

REM Target installation folder in %LOCALAPPDATA%\VirusTotalChecker
set "INSTALL_DIR=%LOCALAPPDATA%\VirusTotalChecker"
set "TARGET_EXE=%INSTALL_DIR%\vt_checker.exe"

REM Close any running instances before updating binary
taskkill /F /IM vt_checker.exe >nul 2>nul

echo:
echo Installing binary to: "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /y "%SOURCE_EXE%" "%TARGET_EXE%" >nul
if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy executable to %INSTALL_DIR%.
    pause
    exit /b 1
)

REM Copy icon if present
if exist "%SCRIPT_DIR%vt_icon.ico" (
    copy /y "%SCRIPT_DIR%vt_icon.ico" "%INSTALL_DIR%\vt_icon.ico" >nul
)

echo:
echo Registering Windows Context Menu (Right-Click) entries...

REM 1. Register for All Files (*)
echo [1/3] Registering for All Files [*]...
set "KEY_FILES=HKCU\Software\Classes\*\shell\ScanWithVirusTotal"
reg add "%KEY_FILES%" /ve /d "Scan with VirusTotal" /f >nul
reg add "%KEY_FILES%" /v "Icon" /d "\"%TARGET_EXE%\"" /f >nul
reg add "%KEY_FILES%\command" /ve /d "\"%TARGET_EXE%\" \"%%1\"" /f >nul
if %errorlevel% neq 0 (
    echo [ERROR] Failed to register context menu for files.
    pause
    exit /b 1
)

REM 2. Register for Folders (Directory)
echo [2/3] Registering for Folders [Directory]...
set "KEY_DIR=HKCU\Software\Classes\Directory\shell\ScanWithVirusTotal"
reg add "%KEY_DIR%" /ve /d "Scan with VirusTotal" /f >nul
reg add "%KEY_DIR%" /v "Icon" /d "\"%TARGET_EXE%\"" /f >nul
reg add "%KEY_DIR%\command" /ve /d "\"%TARGET_EXE%\" \"%%1\"" /f >nul
if %errorlevel% neq 0 (
    echo [ERROR] Failed to register context menu for folders.
    pause
    exit /b 1
)

REM 3. Register for Folder Background (Directory\Background)
echo [3/3] Registering for Folder Background [Directory\Background]...
set "KEY_BG=HKCU\Software\Classes\Directory\Background\shell\ScanWithVirusTotal"
reg add "%KEY_BG%" /ve /d "Scan with VirusTotal" /f >nul
reg add "%KEY_BG%" /v "Icon" /d "\"%TARGET_EXE%\"" /f >nul
reg add "%KEY_BG%\command" /ve /d "\"%TARGET_EXE%\" \"%%V\"" /f >nul

echo:
echo =====================================================================
echo  [SUCCESS] Installation Completed Successfully!
echo =====================================================================
echo:
echo "Scan with VirusTotal" is now available in Windows Context Menu:
echo   - Right-click any FILE to inspect it directly.
echo   - Right-click any FOLDER to scan all root *.exe and *.dll binaries!
echo   - Right-click inside any FOLDER BACKGROUND to inspect its binaries!
echo:
echo Note for Windows 11:
echo   Choose 'Show more options' or press Shift+F10 / Shift+Right Click.
echo:
echo To uninstall at any time, run "uninstall.bat".
echo =====================================================================
echo:
pause
