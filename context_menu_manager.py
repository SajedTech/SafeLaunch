"""
Context Menu Manager for SafeLaunch / VirusTotal Checker (context_menu_manager.py)
----------------------------------------------------------------------------------
Automates registration and removal of "Scan with VirusTotal" Windows
Context Menu entries for both Files (*) and Folders (Directory) using Python's
standard library `winreg` module.
Does not require Administrator rights (operates in HKEY_CURRENT_USER).
"""

import sys
import os
import shutil
import winreg
import argparse
from typing import Optional, Tuple, List

MENU_NAME = "Scan with VirusTotal"
APP_DIR_NAME = "VirusTotalChecker"

REG_KEYS = [
    (r"Software\Classes\*\shell\ScanWithVirusTotal", "%1"),
    (r"Software\Classes\Directory\shell\ScanWithVirusTotal", "%1"),
    (r"Software\Classes\Directory\Background\shell\ScanWithVirusTotal", "%V")
]


def get_install_target_dir() -> str:
    """Returns %LOCALAPPDATA%\\VirusTotalChecker."""
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
    return os.path.join(local_app_data, APP_DIR_NAME)


def locate_executable() -> Optional[str]:
    """Finds vt_checker.exe in dist/ or current directory or AppData."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "dist", "vt_checker.exe"),
        os.path.join(base_dir, "vt_checker.exe"),
        os.path.join(get_install_target_dir(), "vt_checker.exe")
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def get_status() -> List[Tuple[str, bool, Optional[str]]]:
    """Checks whether the context menu keys exist and returns their status."""
    results = []
    for subkey, _ in REG_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey + r"\command") as key:
                cmd, _ = winreg.QueryValueEx(key, "")
                results.append((subkey, True, cmd))
        except FileNotFoundError:
            results.append((subkey, False, None))
        except Exception as e:
            results.append((subkey, False, str(e)))
    return results


def install(inplace: bool = False, dev_mode: bool = False) -> bool:
    """
    Registers the context menu items in HKEY_CURRENT_USER for files and folders.
    - inplace: if False, copies the executable to %LOCALAPPDATA%\\VirusTotalChecker
    - dev_mode: registers pythonw.exe running vt_checker.py directly
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(base_dir, "vt_checker.py")
    icon_path = os.path.join(base_dir, "vt_icon.ico")

    if dev_mode:
        pythonw_exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.isfile(pythonw_exe):
            pythonw_exe = sys.executable
        target_bin = pythonw_exe
        icon_target = icon_path if os.path.isfile(icon_path) else pythonw_exe
        print(f"[*] Dev Mode: Using {pythonw_exe}")
    else:
        exe_src = locate_executable()
        if not exe_src:
            print("[ERROR] vt_checker.exe not found!")
            print("Please compile first by running: build.bat")
            print("Or install in development mode using: python context_menu_manager.py --install --dev")
            return False

        if inplace:
            target_bin = exe_src
            icon_target = icon_path if os.path.isfile(icon_path) else target_bin
            print(f"[*] In-Place Mode: Linking directly to {target_bin}")
        else:
            target_dir = get_install_target_dir()
            os.makedirs(target_dir, exist_ok=True)
            target_bin = os.path.join(target_dir, "vt_checker.exe")
            print(f"[*] Copying executable to: {target_dir}")
            shutil.copy2(exe_src, target_bin)

            if os.path.isfile(icon_path):
                target_icon = os.path.join(target_dir, "vt_icon.ico")
                shutil.copy2(icon_path, target_icon)
                icon_target = target_icon
            else:
                icon_target = target_bin

    # Register each entry
    success_all = True
    for subkey, arg_spec in REG_KEYS:
        if dev_mode:
            command_str = f'"{target_bin}" "{script_path}" "{arg_spec}"'
        else:
            command_str = f'"{target_bin}" "{arg_spec}"'

        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey) as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, MENU_NAME)
                if icon_target and os.path.isfile(icon_target):
                    winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon_target)

            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey + r"\command") as cmd_key:
                winreg.SetValueEx(cmd_key, "", 0, winreg.REG_SZ, command_str)

            print(f"[SUCCESS] Registered: HKCU\\{subkey}")
        except Exception as e:
            print(f"[ERROR] Failed to write HKCU\\{subkey}: {e}")
            success_all = False

    if success_all:
        print("\nAll Context Menu entries registered successfully!")
        print("  - Right-click any FILE to scan it.")
        print("  - Right-click any FOLDER to scan root *.exe and *.dll binaries in the Summary GUI!")
    return success_all


def uninstall(clean_files: bool = False) -> bool:
    """Removes registry entries for files and folders."""
    any_removed = False
    for subkey, _ in REG_KEYS:
        # Delete command subkey first
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey + r"\command")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[WARNING] Could not delete HKCU\\{subkey}\\command: {e}")

        # Delete main shell key
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
            any_removed = True
            print(f"[SUCCESS] Removed: HKCU\\{subkey}")
        except FileNotFoundError:
            print(f"[INFO] Not found: HKCU\\{subkey}")
        except Exception as e:
            print(f"[WARNING] Could not delete HKCU\\{subkey}: {e}")

    if clean_files:
        target_dir = get_install_target_dir()
        if os.path.isdir(target_dir):
            try:
                # Remove binaries but preserve config.json if present
                for f in ["vt_checker.exe", "vt_icon.ico"]:
                    fp = os.path.join(target_dir, f)
                    if os.path.isfile(fp):
                        os.remove(fp)
                print(f"[SUCCESS] Cleaned binary files from {target_dir}")
            except Exception as e:
                print(f"[NOTE] Could not clean files: {e}")

    return any_removed


def main():
    parser = argparse.ArgumentParser(
        description="SafeLaunch Context Menu Manager for VirusTotal Checker"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--install",
        action="store_true",
        help="Register context menu for Files and Folders (default)"
    )
    group.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove context menu entries"
    )
    group.add_argument(
        "--status",
        action="store_true",
        help="Check current context menu registration status"
    )

    parser.add_argument(
        "--inplace",
        action="store_true",
        help="Link directly to local binary without copying to AppData"
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Development mode: run pythonw.exe vt_checker.py directly"
    )

    args = parser.parse_args()

    if args.uninstall:
        uninstall(clean_files=True)
    elif args.status:
        statuses = get_status()
        print("\n=== SafeLaunch Context Menu Status ===")
        for subkey, installed, cmd in statuses:
            state = "INSTALLED" if installed else "NOT INSTALLED"
            print(f"[{state}] {subkey}")
            if installed and cmd:
                print(f"  Command: {cmd}")
    else:
        install(inplace=args.inplace, dev_mode=args.dev)


if __name__ == "__main__":
    main()
