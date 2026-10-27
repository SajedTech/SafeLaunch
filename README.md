# SafeLaunch / VirusTotal Inspector for Windows
![SafeLaunch Preview](Securityphoto.png)
A fast, lightweight Windows utility that integrates with the Windows Explorer Context Menu (Right-Click menu) for **both Files and Folders** to inspect suspicious binaries on **VirusTotal** using a **Consolidated Summary GUI** and **Headless API Lookups**.

---

## Key Features & Highlights

- 📂 **Folder & File Context Menu Integration**: Right-click any file, folder, or folder background to instantly inspect root executable binaries (`*.exe`, `*.dll`).
- ⚡ **Headless VirusTotal v3 API Lookups**: Queries `GET /api/v3/files/{hash}` directly in the background. Fetches detection scores (`malicious / total engines`, type, status) silently without flooding your browser with tabs.
- 🚀 **Smooth Auto-Scan on Open**:
  - Scanning begins immediately when a folder or file is opened (via context menu, drag & drop, Open File, or Open Folder).
- ⏹ **Instant Stop / Cancel Scan Mechanism**:
  - Powered by responsive `threading.Event()` synchronization instead of blocking sleeps.
  - Dynamically transforms the `[ ▶ Rescan All ]` button into a prominent red **`[ ⏹ Stop Scan (Esc) ]`** button while scanning.
  - Pressing **<kbd>Escape</kbd>** or clicking Stop **instantly terminates the queue and cancels the cooldown timer in 0 milliseconds**, allowing you to inspect specific files with `[ ⚡ Scan Selected ]`.
- 🎯 **Selective API Scanning (`[ ⚡ Scan Selected ]`)**:
  - Scan only the specific files you have selected (or any remaining unscanned ones).
  - Conserves your API quota and avoids unnecessary rate-limiting pauses on known files.
- 📋 **Target Path Quick Copy**:
  - Located directly beside the Target label in the header: **`[ 📋 Copy Path ]`**.
  - Copies the loaded folder or file absolute path straight to the clipboard with one click.
- 🖱 **Multi-Row Selection & Bulk Operations**:
  - Extended selection enabled: use <kbd>Ctrl</kbd>+Click or <kbd>Shift</kbd>+Click to select multiple rows.
  - **`[ 🌐 Open Report ]`**: Opens VirusTotal analysis pages for **all selected files simultaneously** in new browser tabs.
  - **`[ 📋 Copy Hash ]`**: Copies SHA-256 hashes of **all selected files** (one per line) directly to the clipboard.
- 🗑 **Delete / Remove Items from Table**:
  - Remove items using the **<kbd>Delete</kbd>** or **<kbd>Backspace</kbd>** keys, the right-click menu (**"🗑 Remove from List"**), or the toolbar button (**`[ 🗑 Remove Selected ]`**).
  - Automatically recalculates and updates the top summary cards (Total, Clean, Malicious, Unknown) in real time.
- ⏱ **Sleek Progress Bar & Rate-Limit Cooldown**:
  - Seamlessly tracks the free tier limit (4 requests/minute).
  - During cooldown, displays an eye-catching inline pill badge: **`⏳ Cooldown: 12s (API Quota)`** alongside clear status text.
  - Automatically catches and retries HTTP 429 quota events.
- 🛡 **Accurate Status Bar (Zero False Sense of Security)**:
  - Dynamically reports the actual state of files (`"Waiting for API Key or user action"`, `"Inspecting file X of Y..."`, `"Completed: X clean, Y suspicious"`).
  - Never displays "all clean" when files are unverified or skipped.
- ⌨ **Layout-Independent Keyboard Pasting**:
  - Direct **`[ 📋 Paste ]`** button beside the API key field.
  - Intercepts virtual key codes (<kbd>Ctrl</kbd>+<kbd>V</kbd>) across all Windows keyboard layouts (Arabic, Cyrillic, Hebrew, Latin, etc.).
  - Right-click mouse context menu with Cut / Copy / Paste / Select All.
- 🖥 **Wide SHA-256 Display & Scrollbars**:
  - Full 520px column width displays the complete 64-hex SHA-256 hash without truncation.
  - Both horizontal and vertical scrollbars included.

---

## File Structure

```
SafeLaunch/
├── vt_checker.py             # Complete Python utility & Tkinter GUI
├── context_menu_manager.py   # Registry manager using standard library 'winreg'
├── vt_icon.ico               # High-res security shield icon
├── build.bat                 # PyInstaller compilation script
├── install.bat               # Installs context menu for Files and Folders
├── uninstall.bat             # Clean uninstaller script
└── dist/
    └── vt_checker.exe        # Standalone windowless executable
```

---

## Quick Setup & Compilation

### 1. Build Standalone Executable
Double-click `build.bat` or run:
```cmd
build.bat
```
*PyInstaller command:*
```cmd
pyinstaller --noconsole --onefile --clean --icon="vt_icon.ico" --name="vt_checker" vt_checker.py
```
This produces `dist\vt_checker.exe` (windowless, standalone, zero-console flicker).

### 2. Install Context Menu Integration
Double-click `install.bat`:
```cmd
install.bat
```
*What this registers (in `HKEY_CURRENT_USER` - no admin rights needed):*
1. **`HKCU\Software\Classes\*\shell\ScanWithVirusTotal`** (All files)
2. **`HKCU\Software\Classes\Directory\shell\ScanWithVirusTotal`** (Folders)
3. **`HKCU\Software\Classes\Directory\Background\shell\ScanWithVirusTotal`** (Inside folder background)

---

## How to Use

### 1. Inspecting a Folder
1. Right-click any folder in Windows Explorer.
   *(On Windows 11: select "Show more options" or press <kbd>Shift</kbd> + <kbd>F10</kbd>).*
2. Select **"Scan with VirusTotal"**.
3. SafeLaunch automatically scans the folder root for `*.exe` and `*.dll` binaries and begins scanning.
4. Hit **`[ ⏹ Stop Scan ]`** (or press <kbd>Esc</kbd>) at any time to halt the queue and inspect specific files with **`[ ⚡ Scan Selected ]`**.

### 2. Inspecting a Single File
- Right-click any single file and select **"Scan with VirusTotal"**.
- Displays detection statistics, computes hash, and copies SHA-256 to clipboard.

### 3. Standalone Mode
- Run `vt_checker.exe` directly to open the GUI.
- Use **"Open File..."** or **"Open Folder..."** to inspect targets on demand.

---

## Uninstallation

To cleanly remove Context Menu entries:
```cmd
uninstall.bat
```
Or via Python:
```bash
python context_menu_manager.py --uninstall
```
This removes all registry keys and cleans up `%LOCALAPPDATA%\VirusTotalChecker`.

---

## Prerequisites & Compatibility

- **OS**: Windows 10 / Windows 11 (64-bit).
- **Standalone Mode**: No external dependencies or Python installation required if using the precompiled `vt_checker.exe`.
- **Building from Source**: Requires Python 3.8+ and `pyinstaller` (`pip install pyinstaller`).

---

## ⚠️ Security & Educational Disclaimer

This software is developed strictly for **educational, defensive, and security research purposes**. 

- **False Positives Note**: Game modifications, emulators, and cracked binaries frequently trigger high detection ratios on VirusTotal due to code-obfuscation (packers/cryptors), memory modification hooks, and DRM-bypass techniques. A high score does not always guarantee an active Trojan, nor does a `0/70` guarantee absolute safety against brand-new or zero-day threats.
- **Liability**: The author assumes no responsibility for any misuse, system damage, or security breaches resulting from opening or executing untrusted files analyzed by this tool.

---

## License

Distributed under the **MIT License**. See the [LICENSE](LICENSE) file for more information.