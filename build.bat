@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  VirusTotal Context Menu Checker - PyInstaller Build Script
echo =====================================================================
echo.

REM Verify Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python was not found in your PATH.
    echo Please install Python 3.8+ and ensure "Add to PATH" is checked.
    pause
    exit /b 1
)

REM Verify PyInstaller is installed
where pyinstaller >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] PyInstaller is not installed in the current environment.
    echo Attempting to install PyInstaller via pip...
    python -m pip install --upgrade pyinstaller
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install PyInstaller. Please run: pip install pyinstaller
        pause
        exit /b 1
    )
)

echo [1/3] Cleaning previous build artifacts...
if exist "build" rmdir /s /q "build"
if exist "dist\vt_checker.exe" del /f /q "dist\vt_checker.exe"
if exist "vt_checker.spec" del /f /q "vt_checker.spec"

echo [2/3] Compiling standalone windowless executable...
echo Target: vt_checker.py
echo Flags:  --noconsole --onefile --clean

if exist "vt_icon.ico" (
    echo Icon:   vt_icon.ico detected, embedding icon...
    pyinstaller --noconsole --onefile --clean --icon="vt_icon.ico" --name="vt_checker" vt_checker.py
) else (
    pyinstaller --noconsole --onefile --clean --name="vt_checker" vt_checker.py
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] PyInstaller build failed! Please check the output above.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Build Succeeded!
echo Output executable: dist\vt_checker.exe
echo.
echo =====================================================================
echo  NEXT STEPS:
echo  1. Run "install.bat" to add "Scan with VirusTotal" to right-click menu.
echo  2. Right-click any file in Windows Explorer to test!
echo =====================================================================
echo.
pause
