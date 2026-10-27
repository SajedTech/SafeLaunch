"""
VirusTotal Context Menu Checker & SafeLaunch Inspector (vt_checker.py)
-----------------------------------------------------------------------
A lightweight Windows utility that integrates with the Windows Context Menu
for both Files (*) and Folders (Directory).

Features:
1. Rock-solid Win32 Drag & Drop support using windnd (zero crash on 64-bit Windows).
2. Append Mode: Dragging or pasting new files/folders appends to the current list
   without wiping existing items, automatically skipping duplicates.
3. Paste Target (Ctrl+V & button) supporting CF_HDROP (Explorer copied files) & text paths.
4. Auto-Scan on open/drop/paste with instant Stop / Cancel mechanism using threading.Event.
5. Prominent dynamic [ ⏹ Stop Scan ] button with global <Escape> hotkey.
6. Headless VirusTotal v3 API lookups without opening multiple browser tabs.
7. Clean Tkinter Consolidated Summary GUI with detection stats and color coding.
8. Robust rate limiting (free tier 4 req/min) with sleek cooldown badge and status.
9. Multi-row selection (extended mode) with bulk browser opening and hash copying.
10. Delete/Remove items from table with Delete key, context menu, and auto-recalculation.
11. Selective API Scanning ("Scan Selected") to save quota and avoid rate limit delays.
12. Target Path Copy button in header with direct clipboard integration.
13. Accurate status bar reporting (no false sense of security for unverified files).
14. Full clipboard paste support in API dialog across all keyboard language layouts.
15. Generous column widths for complete 64-char SHA-256 hash display.
"""

import sys
import os
import json
import time
import math
import hashlib
import webbrowser
import threading
import urllib.request
import urllib.error
import ctypes
from ctypes import wintypes
from typing import Optional, List, Dict, Any, Tuple

# Tkinter imports (Python Standard Library)
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Pure-Python Windows Drag & Drop library
import windnd
HAS_WINDND = True


# Win32 Constants
MB_OK = 0x00000000
MB_ICONINFORMATION = 0x00000040
MB_ICONERROR = 0x00000010
MB_TOPMOST = 0x00040000
MB_SETFOREGROUND = 0x00010000

CF_UNICODETEXT = 13
CF_HDROP = 15

GMEM_MOVEABLE = 0x0002
GMEM_ZEROINIT = 0x0040
GHND = GMEM_MOVEABLE | GMEM_ZEROINIT

APP_DIR_NAME = "VirusTotalChecker"
CONFIG_FILE_NAME = "config.json"
FREE_TIER_RATE_LIMIT_DELAY = 15  # 4 requests/minute = 15s delay between requests
FREE_TIER_BURST_MAX = 4          # Up to 4 queries before rate limiting cooldown kicks in
EXECUTABLE_EXTS = ('.exe', '.dll')


# ============================================================================
# Win32 API Configuration
# ============================================================================

def set_win32_prototypes():
    """Configure ctypes prototypes for 64-bit/32-bit Windows API safety."""
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32

    # Memory functions
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]

    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]

    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]

    # Clipboard functions
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.OpenClipboard.argtypes = [wintypes.HWND]

    user32.CloseClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.argtypes = []

    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.argtypes = []

    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]

    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.GetClipboardData.argtypes = [ctypes.c_uint]

    user32.IsClipboardFormatAvailable.restype = wintypes.BOOL
    user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]

    # Shell Drag & Drop functions
    shell32.DragQueryFileW.restype = wintypes.UINT
    shell32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]

    shell32.DragFinish.restype = None
    shell32.DragFinish.argtypes = [wintypes.HANDLE]

    # MessageBox functions
    user32.MessageBoxW.restype = ctypes.c_int
    user32.MessageBoxW.argtypes = [wintypes.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]

    if hasattr(user32, 'MessageBoxTimeoutW'):
        user32.MessageBoxTimeoutW.restype = ctypes.c_int
        user32.MessageBoxTimeoutW.argtypes = [
            wintypes.HWND, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_uint, ctypes.c_ushort, ctypes.c_uint
        ]


set_win32_prototypes()


def copy_to_clipboard(text: str) -> bool:
    """Copies unicode text to Windows Clipboard via native Win32 API."""
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32

    if not user32.OpenClipboard(None):
        return False

    try:
        user32.EmptyClipboard()
        encoded_data = text.encode('utf-16le') + b'\x00\x00'
        h_mem = kernel32.GlobalAlloc(GHND, len(encoded_data))
        if not h_mem:
            return False

        p_mem = kernel32.GlobalLock(h_mem)
        if not p_mem:
            return False

        ctypes.memmove(p_mem, encoded_data, len(encoded_data))
        kernel32.GlobalUnlock(h_mem)

        if not user32.SetClipboardData(CF_UNICODETEXT, h_mem):
            return False

        return True
    except Exception:
        return False
    finally:
        user32.CloseClipboard()


def get_clipboard_text() -> str:
    """
    Retrieves unicode text from Windows clipboard.
    Uses Win32 API directly for bulletproof layout-independent reliability.
    """
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32

    if not user32.OpenClipboard(None):
        return ""

    try:
        h_mem = user32.GetClipboardData(CF_UNICODETEXT)
        if not h_mem:
            return ""
        p_mem = kernel32.GlobalLock(h_mem)
        if not p_mem:
            return ""
        text = ctypes.c_wchar_p(p_mem).value
        kernel32.GlobalUnlock(h_mem)
        return (text or "").strip()
    except Exception:
        return ""
    finally:
        user32.CloseClipboard()


def get_clipboard_hdrop_files() -> List[str]:
    """
    Retrieves file/folder paths if the Windows Clipboard contains
    Explorer-copied file objects (CF_HDROP = 15).
    """
    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32

    if not user32.IsClipboardFormatAvailable(CF_HDROP):
        return []

    if not user32.OpenClipboard(None):
        return []

    try:
        h_drop = user32.GetClipboardData(CF_HDROP)
        if not h_drop:
            return []

        count = shell32.DragQueryFileW(h_drop, 0xFFFFFFFF, None, 0)
        files = []
        buf = ctypes.create_unicode_buffer(1024)
        for i in range(count):
            length = shell32.DragQueryFileW(h_drop, i, buf, 1024)
            if length > 0:
                files.append(buf.value)
        return files
    except Exception:
        return []
    finally:
        user32.CloseClipboard()


def get_target_from_clipboard() -> List[str]:
    """
    Extracts valid target paths from clipboard:
    1. Checks CF_HDROP (copied files from Windows Explorer).
    2. Checks CF_UNICODETEXT for valid file or folder paths.
    """
    # 1. Check CF_HDROP
    hdrop_files = get_clipboard_hdrop_files()
    if hdrop_files:
        valid_hdrop = [f for f in hdrop_files if os.path.exists(f)]
        if valid_hdrop:
            return valid_hdrop

    # 2. Check text clipboard
    raw_text = get_clipboard_text()
    if raw_text:
        lines = [line.strip().strip('\"').strip('\'') for line in raw_text.splitlines() if line.strip()]
        valid_paths = [p for p in lines if os.path.exists(p)]
        if valid_paths:
            return valid_paths

        # Check full raw string without newline splits
        stripped_all = raw_text.strip().strip('\"').strip('\'')
        if os.path.exists(stripped_all):
            return [stripped_all]

    return []


def format_file_size(size_bytes: int) -> str:
    """Formats file size into human-readable units (B, KB, MB, GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    for unit in ['KB', 'MB', 'GB', 'TB']:
        size_bytes /= 1024.0
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
    return f"{size_bytes:.2f} PB"


def show_error_dialog(message: str, title: str = "VirusTotal Checker - Error") -> None:
    flags = MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND
    ctypes.windll.user32.MessageBoxW(None, message, title, flags)


def show_notification(title: str, message: str, timeout_seconds: int = 6) -> None:
    """Displays a non-intrusive notification."""
    try:
        from plyer import notification
        notification.notify(title=title, message=message, app_name="VirusTotal Checker", timeout=timeout_seconds)
        return
    except Exception:
        pass

    try:
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=timeout_seconds, threaded=True)
        return
    except Exception:
        pass

    user32 = ctypes.windll.user32
    flags = MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND
    if hasattr(user32, 'MessageBoxTimeoutW'):
        try:
            user32.MessageBoxTimeoutW(None, message, title, flags, 0, timeout_seconds * 1000)
            return
        except Exception:
            pass

    user32.MessageBoxW(None, message, title, flags)


# ============================================================================
# Configuration & Local Storage
# ============================================================================

def get_app_dir() -> str:
    """Returns %LOCALAPPDATA%\\VirusTotalChecker."""
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
    app_dir = os.path.join(local_app_data, APP_DIR_NAME)
    os.makedirs(app_dir, exist_ok=True)
    return app_dir


def get_config_path() -> str:
    return os.path.join(get_app_dir(), CONFIG_FILE_NAME)


def load_config() -> dict:
    config_file = get_config_path()
    if os.path.isfile(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_config(config: dict) -> bool:
    try:
        with open(get_config_path(), "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def get_api_key() -> str:
    return load_config().get("api_key", "").strip()


def set_api_key(api_key: str) -> None:
    cfg = load_config()
    cfg["api_key"] = api_key.strip()
    save_config(cfg)


# ============================================================================
# File Operations & Hashing
# ============================================================================

def calculate_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Calculates SHA-256 hash using chunked binary reading (memory-efficient)."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def find_high_risk_binaries(folder_path: str) -> List[str]:
    """
    Locates high-risk executable binaries (*.exe, *.dll) in the root of the folder.
    Returns sorted list of absolute file paths.
    """
    binaries = []
    try:
        for entry in os.listdir(folder_path):
            full_path = os.path.join(folder_path, entry)
            if os.path.isfile(full_path) and entry.lower().endswith(EXECUTABLE_EXTS):
                binaries.append(full_path)
    except Exception as e:
        show_error_dialog(f"Error accessing folder contents:\n\n{str(e)}")
        return []

    binaries.sort(key=lambda p: (0 if p.lower().endswith('.exe') else 1, os.path.basename(p).lower()))
    return binaries


def identify_main_executable(folder_path: str, binaries: List[str]) -> Optional[str]:
    """Identifies the primary executable in a folder."""
    if not binaries:
        return None

    folder_name = os.path.basename(os.path.abspath(folder_path)).lower()
    exe_files = [b for b in binaries if b.lower().endswith('.exe')]

    if not exe_files:
        return binaries[0]

    for exe in exe_files:
        stem = os.path.splitext(os.path.basename(exe))[0].lower()
        if stem == folder_name:
            return exe

    common_names = ('main.exe', 'app.exe', 'setup.exe', 'launcher.exe', 'start.exe')
    for exe in exe_files:
        if os.path.basename(exe).lower() in common_names:
            return exe

    try:
        return max(exe_files, key=os.path.getsize)
    except Exception:
        return exe_files[0]


# ============================================================================
# VirusTotal Rate Limiter & v3 API Client
# ============================================================================

class VirusTotalRateLimiter:
    """
    Tracks VirusTotal API request timestamps within a 60-second sliding window.
    Free tier quota: 4 requests per minute.
    Allows bursts up to 4 requests, then enforces cooldown.
    """

    def __init__(self, max_requests: int = FREE_TIER_BURST_MAX, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.timestamps: List[float] = []
        self._lock = threading.Lock()

    def get_wait_seconds(self) -> float:
        """Calculates seconds to wait before sending the next query."""
        with self._lock:
            now = time.time()
            self.timestamps = [t for t in self.timestamps if now - t < self.window_seconds]
            if len(self.timestamps) < self.max_requests:
                return 0.0
            oldest = self.timestamps[0]
            wait = (oldest + self.window_seconds) - now
            return max(0.0, wait)

    def record_request(self):
        """Records a completed request timestamp."""
        with self._lock:
            self.timestamps.append(time.time())

    def reset(self):
        with self._lock:
            self.timestamps.clear()


vt_rate_limiter = VirusTotalRateLimiter()


def query_virustotal_api(sha256_hash: str, api_key: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 API: GET /api/v3/files/{hash}
    Returns dictionary with status and parsed detection metrics.
    """
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "User-Agent": "SafeLaunch-VT-Checker/2.0",
            "Accept": "application/json"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            type_desc = attrs.get("type_description") or "Binary"

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total = malicious + suspicious + undetected + harmless

            if malicious > 0:
                verdict = "MALICIOUS"
            elif suspicious > 0:
                verdict = "SUSPICIOUS"
            elif total > 0:
                verdict = "CLEAN"
            else:
                verdict = "UNKNOWN"

            return {
                "status": "success",
                "verdict": verdict,
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total,
                "detections_str": f"{malicious}/{total}",
                "type_desc": type_desc,
                "last_analysis_date": attrs.get("last_analysis_date")
            }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "status": "not_found",
                "verdict": "NOT_FOUND",
                "malicious": 0,
                "suspicious": 0,
                "total": 0,
                "detections_str": "N/A (Unseen)",
                "type_desc": "Unknown",
                "message": "File not found in VirusTotal database"
            }
        elif e.code == 429:
            return {
                "status": "rate_limited",
                "verdict": "RATE_LIMITED",
                "message": "Rate limit exceeded (Quota exceeded)"
            }
        elif e.code in (401, 403):
            return {
                "status": "auth_error",
                "verdict": "AUTH_ERROR",
                "message": "Invalid or unauthorized API key"
            }
        else:
            return {
                "status": "http_error",
                "verdict": "ERROR",
                "code": e.code,
                "message": f"HTTP Error {e.code}"
            }
    except Exception as e:
        return {
            "status": "network_error",
            "verdict": "ERROR",
            "message": str(e)
        }


def request_reanalysis(sha256_hash: str, api_key: str) -> Tuple[bool, str]:
    """Requests a file reanalysis: POST /api/v3/files/{hash}/analyse."""
    if not api_key:
        return False, "No API key configured."

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}/analyse"
    req = urllib.request.Request(
        url,
        data=b"",
        headers={
            "x-apikey": api_key,
            "User-Agent": "SafeLaunch-VT-Checker/2.0",
            "Accept": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return True, "Reanalysis queued successfully on VirusTotal."
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, "File not present in VirusTotal. Upload required via web interface."
        elif e.code == 429:
            return False, "API Rate limit exceeded. Please wait a moment."
        return False, f"Reanalysis request failed (HTTP {e.code})."
    except Exception as e:
        return False, str(e)


# ============================================================================
# API Key Input Dialog (with Layout-Independent Clipboard Support)
# ============================================================================

class ApiKeyDialog(tk.Toplevel):
    """
    Clean modal dialog prompting the user for their free VirusTotal API key.
    Includes explicit Paste button, context menu, and keyboard handling that
    functions across all Windows keyboard language layouts.
    """

    def __init__(self, parent, current_key=""):
        super().__init__(parent)
        self.title("VirusTotal API Configuration")
        self.geometry("580x320")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.result_action = "cancel"
        self.entered_key = current_key

        self.update_idletasks()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        w = 580
        h = 320
        x = px + max(0, (pw - w) // 2)
        y = py + max(0, (ph - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

        self._build_ui()

    def _build_ui(self):
        container = ttk.Frame(self, padding=20)
        container.pack(fill=tk.BOTH, expand=True)

        lbl_title = ttk.Label(
            container,
            text="VirusTotal API Key Configuration",
            font=("Segoe UI", 12, "bold")
        )
        lbl_title.pack(anchor="w", pady=(0, 6))

        lbl_desc = ttk.Label(
            container,
            text=(
                "A free VirusTotal API key allows SafeLaunch to inspect files silently\n"
                "in the background without opening multiple browser tabs.\n\n"
                "• Get a free API key at: virustotal.com (Sign up -> Profile -> API Key)\n"
                "• Free tier allows 4 queries/minute (SafeLaunch manages rate limiting automatically)\n"
                "• Your key is saved locally in %LOCALAPPDATA%\\VirusTotalChecker"
            ),
            font=("Segoe UI", 9),
            justify="left"
        )
        lbl_desc.pack(anchor="w", pady=(0, 15))

        input_frame = ttk.Frame(container)
        input_frame.pack(fill=tk.X, pady=(0, 15))

        lbl_key = ttk.Label(input_frame, text="API Key:", font=("Segoe UI", 9, "bold"))
        lbl_key.pack(side=tk.LEFT, padx=(0, 8))

        self.var_key = tk.StringVar(value=self.entered_key)
        self.entry_key = ttk.Entry(input_frame, textvariable=self.var_key, width=36, show="*")
        self.entry_key.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.btn_paste = ttk.Button(
            input_frame,
            text="📋 Paste",
            width=8,
            command=self._paste_clipboard
        )
        self.btn_paste.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_toggle = ttk.Button(
            input_frame,
            text="👁 Show",
            width=8,
            command=self._toggle_visibility
        )
        self.btn_toggle.pack(side=tk.LEFT)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Cut", command=self._cut_selection)
        self.context_menu.add_command(label="Copy", command=self._copy_selection)
        self.context_menu.add_command(label="Paste", command=self._paste_clipboard)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=lambda: self.entry_key.select_range(0, tk.END))
        self.context_menu.add_command(label="Clear", command=lambda: self.var_key.set(""))

        self.entry_key.bind("<Button-3>", self._show_entry_context_menu)
        self.entry_key.bind("<KeyPress>", self._on_entry_key)
        self.entry_key.bind("<Control-v>", lambda e: (self._paste_clipboard(), "break")[1])
        self.entry_key.bind("<Control-V>", lambda e: (self._paste_clipboard(), "break")[1])

        btn_frame = ttk.Frame(container)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        btn_save = ttk.Button(btn_frame, text="Save & Use Key", command=self._on_save)
        btn_save.pack(side=tk.RIGHT, padx=(6, 0))

        btn_browser = ttk.Button(
            btn_frame,
            text="Continue Without Key (Browser Mode)",
            command=self._on_browser_mode
        )
        btn_browser.pack(side=tk.RIGHT)

        self.entry_key.focus_set()

    def _show_entry_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)

    def _on_entry_key(self, event):
        if event.state & 0x0004:
            if event.keycode == 86:  # VK_V
                self._paste_clipboard()
                return "break"
            elif event.keycode == 67:  # VK_C
                self._copy_selection()
                return "break"
            elif event.keycode == 88:  # VK_X
                self._cut_selection()
                return "break"
            elif event.keycode == 65:  # VK_A
                self.entry_key.select_range(0, tk.END)
                return "break"

    def _paste_clipboard(self):
        text = get_clipboard_text()
        if not text:
            try:
                text = self.clipboard_get().strip()
            except Exception:
                text = ""

        if text:
            try:
                if self.entry_key.selection_present():
                    self.entry_key.delete(tk.SEL_FIRST, tk.SEL_LAST)
                self.entry_key.insert(tk.INSERT, text)
            except Exception:
                self.var_key.set(text)

    def _copy_selection(self):
        try:
            if self.entry_key.selection_present():
                selected = self.entry_key.selection_get()
                copy_to_clipboard(selected)
        except Exception:
            pass

    def _cut_selection(self):
        try:
            if self.entry_key.selection_present():
                selected = self.entry_key.selection_get()
                copy_to_clipboard(selected)
                self.entry_key.delete(tk.SEL_FIRST, tk.SEL_LAST)
        except Exception:
            pass

    def _toggle_visibility(self):
        if self.entry_key.cget("show") == "*":
            self.entry_key.config(show="")
            self.btn_toggle.config(text="🙈 Hide")
        else:
            self.entry_key.config(show="*")
            self.btn_toggle.config(text="👁 Show")

    def _on_save(self):
        key = self.var_key.get().strip()
        if not key:
            messagebox.showwarning(
                "API Key Required",
                "Please enter an API key or choose 'Continue Without Key'.",
                parent=self
            )
            return
        set_api_key(key)
        self.entered_key = key
        self.result_action = "saved"
        self.destroy()

    def _on_browser_mode(self):
        self.result_action = "browser_mode"
        self.destroy()


# ============================================================================
# Consolidated Summary GUI Window
# ============================================================================

class SafeLaunchGUI(tk.Tk):
    """
    Main Consolidated Summary GUI:
    Displays high-risk binaries, computed SHA-256 hashes, detection statistics,
    and visual status indicators (Clean, Malicious, Suspicious, Unknown).
    Includes Native Drag & Drop and Append Mode for dropped/pasted files.
    """

    def __init__(self, target_path: Optional[str] = None):
        super().__init__()
        self.title("SafeLaunch - VirusTotal Inspector")
        self.geometry("1160x650")
        self.minsize(960, 520)

        # Center on screen
        self._center_window(1160, 650)

        # State
        self.target_path = os.path.abspath(target_path) if target_path else None
        self.is_folder = os.path.isdir(self.target_path) if self.target_path else False
        self.files_to_scan: List[str] = []
        self.file_records: Dict[str, Dict[str, Any]] = {}
        self.is_scanning = False
        self.stop_event = threading.Event()
        self.scan_lock = threading.Lock()
        self.active_scan_queue: List[str] = []
        self.api_key = get_api_key()

        # Set application icon if available
        self._load_icon()

        # Setup styling
        self._setup_styles()

        # Build UI layout
        self._build_header()
        self._build_summary_cards()
        self._build_treeview()
        self._build_action_bar()
        self._build_status_bar()

        # Global Hotkey Bindings
        self.bind_all("<Escape>", lambda event: self._stop_scan())
        self.bind("<Delete>", self._on_global_delete)

        # Global Paste Bindings (<Control-v>, <Control-V>, and VK_V = 86)
        self.bind_all("<Control-v>", self._on_global_paste)
        self.bind_all("<Control-V>", self._on_global_paste)
        self.bind_all("<KeyPress>", self._on_global_key)

        # Setup rock-solid native Drag & Drop via windnd
        self._setup_drag_and_drop()

        # Auto-initialize and start scan on open if target provided
        self.after(100, self._initialize_scan)

    def _center_window(self, width, height):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - width) // 2
        y = (sh - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _load_icon(self):
        """Loads vt_icon.ico if present."""
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "vt_icon.ico"),
            os.path.join(get_app_dir(), "vt_icon.ico")
        ]
        for icon in candidates:
            if os.path.isfile(icon):
                try:
                    self.iconbitmap(icon)
                    break
                except Exception:
                    pass

    def _setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass

        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=26)
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Small.TButton", font=("Segoe UI", 8))

        # Distinctive Red Button style for [ ⏹ Stop Scan ]
        style.configure(
            "Stop.TButton",
            font=("Segoe UI", 9, "bold"),
            foreground="white",
            background="#c62828"
        )
        style.map(
            "Stop.TButton",
            background=[("active", "#b71c1c"), ("pressed", "#8e0000"), ("!disabled", "#c62828")],
            foreground=[("!disabled", "white")]
        )

    # ------------------------------------------------------------------------
    # Native Win32 Drag & Drop Integration (via windnd)
    # ------------------------------------------------------------------------

    def _setup_drag_and_drop(self):
        """
        Enables rock-solid Win32 Drag & Drop using windnd.
        Hooks both the main window (self), Treeview (self.tree), and container frames
        so dropping files anywhere inside the window works instantly and reliably.
        """
        try:
            self.update_idletasks()
            import windnd
            windnd.hook_dropfiles(self, func=self._on_files_dropped)
            windnd.hook_dropfiles(self.tree, func=self._on_files_dropped)

            # Also hook major containers to catch drops anywhere inside the window
            hooked_hwnds = {self.winfo_id(), self.tree.winfo_id()}
            for attr in ['header_frame', 'cards_frame', 'tree_container', 'action_frame', 'status_frame']:
                w = getattr(self, attr, None)
                if w:
                    try:
                        wid = w.winfo_id()
                        if wid not in hooked_hwnds:
                            windnd.hook_dropfiles(w, func=self._on_files_dropped)
                            hooked_hwnds.add(wid)
                    except Exception:
                        pass
        except Exception as e:
            print(f"Could not hook windnd drag & drop: {e}")

    def _on_files_dropped(self, files):
        """
        Callback received when files/folders are dropped onto the window.
        Safely decodes incoming paths with UTF-8 and MBCS fallback for non-ASCII/Arabic paths.
        """
        decoded_paths = []
        for f in files:
            if isinstance(f, bytes):
                try:
                    f = f.decode('utf-8')
                except UnicodeDecodeError:
                    f = f.decode('mbcs', errors='ignore')
            decoded_paths.append(os.path.abspath(f))

        if decoded_paths:
            self._append_targets(decoded_paths)

    # ------------------------------------------------------------------------
    # UI Layout Builders
    # ------------------------------------------------------------------------

    def _build_header(self):
        header_frame = ttk.Frame(self, padding=(16, 12, 16, 8))
        header_frame.pack(fill=tk.X)
        self.header_frame = header_frame

        title_box = ttk.Frame(header_frame)
        title_box.pack(side=tk.LEFT, fill=tk.X, expand=True)

        lbl_app_name = ttk.Label(
            title_box,
            text="🛡 SafeLaunch Inspector",
            font=("Segoe UI", 14, "bold"),
            foreground="#0d47a1"
        )
        lbl_app_name.pack(anchor="w")

        target_row = ttk.Frame(title_box)
        target_row.pack(anchor="w", pady=(3, 0), fill=tk.X)

        target_desc = self.target_path if self.target_path else "No target loaded (Drag & drop or Paste files here)"
        self.lbl_target = ttk.Label(
            target_row,
            text=f"Target: {target_desc}",
            font=("Segoe UI", 9),
            foreground="#444444"
        )
        self.lbl_target.pack(side=tk.LEFT)

        self.btn_copy_target = ttk.Button(
            target_row,
            text="📋 Copy Path",
            command=self._copy_target_path,
            style="Small.TButton"
        )
        self.btn_copy_target.pack(side=tk.LEFT, padx=(8, 0))

        # Top-right action controls
        top_btn_box = ttk.Frame(header_frame)
        top_btn_box.pack(side=tk.RIGHT)

        # 1. Paste Target Button
        self.btn_paste_target = ttk.Button(
            top_btn_box,
            text="📋 Paste Target",
            command=self._paste_target
        )
        self.btn_paste_target.pack(side=tk.LEFT, padx=3)

        self.btn_select_file = ttk.Button(top_btn_box, text="Open File...", command=self._browse_file)
        self.btn_select_file.pack(side=tk.LEFT, padx=3)

        self.btn_select_folder = ttk.Button(top_btn_box, text="Open Folder...", command=self._browse_folder)
        self.btn_select_folder.pack(side=tk.LEFT, padx=3)

        self.btn_api_settings = ttk.Button(top_btn_box, text="🔑 API Key", command=self._open_api_settings)
        self.btn_api_settings.pack(side=tk.LEFT, padx=3)

    def _copy_target_path(self):
        """Copies the full absolute path of currently loaded target to clipboard."""
        if not self.target_path:
            messagebox.showinfo("No Target", "No target file or folder is currently loaded.")
            return

        if copy_to_clipboard(self.target_path):
            self.lbl_status.config(text=f"Path copied to clipboard: {self.target_path}")
            show_notification("Path Copied", f"Copied to clipboard:\n{self.target_path}", timeout_seconds=2)
        else:
            messagebox.showerror("Clipboard Error", "Could not copy target path to Windows clipboard.")

    def _build_summary_cards(self):
        card_frame = ttk.Frame(self, padding=(16, 4, 16, 8))
        card_frame.pack(fill=tk.X)
        self.cards_frame = card_frame

        self.card_total = self._create_card(card_frame, "Total Binaries", "0", "#e0e0e0", "#333333")
        self.card_clean = self._create_card(card_frame, "Clean (VT)", "0", "#c8e6c9", "#1b5e20")
        self.card_suspicious = self._create_card(card_frame, "Suspicious / Malicious", "0", "#ffcdd2", "#b71c1c")
        self.card_unknown = self._create_card(card_frame, "Unverified / Unknown", "0", "#fff9c4", "#f57f17")

    def _create_card(self, parent, label_text, initial_value, bg_color, fg_color):
        frame = tk.Frame(parent, bg=bg_color, padx=12, pady=6, relief=tk.GROOVE, bd=1)
        frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        lbl_title = tk.Label(frame, text=label_text, bg=bg_color, fg=fg_color, font=("Segoe UI", 8))
        lbl_title.pack(anchor="w")

        lbl_val = tk.Label(frame, text=initial_value, bg=bg_color, fg=fg_color, font=("Segoe UI", 13, "bold"))
        lbl_val.pack(anchor="w")
        return lbl_val

    def _build_treeview(self):
        tree_container = ttk.Frame(self, padding=(16, 0, 16, 8))
        tree_container.pack(fill=tk.BOTH, expand=True)
        self.tree_container = tree_container

        columns = ("name", "type_size", "detections", "status", "sha256")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", selectmode="extended")

        self.tree.heading("name", text="File Name")
        self.tree.heading("type_size", text="Type & Size")
        self.tree.heading("detections", text="Detections (VT)")
        self.tree.heading("status", text="Status")
        self.tree.heading("sha256", text="SHA-256 Hash")

        self.tree.column("name", width=220, minwidth=140, anchor="w")
        self.tree.column("type_size", width=110, minwidth=90, anchor="center")
        self.tree.column("detections", width=110, minwidth=90, anchor="center")
        self.tree.column("status", width=160, minwidth=130, anchor="center")
        self.tree.column("sha256", width=520, minwidth=490, anchor="w")

        # Vertical & Horizontal Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        # Style tags for row colors
        self.tree.tag_configure("clean", background="#E8F8F0", foreground="#1B5E20")
        self.tree.tag_configure("malicious", background="#FDE8E8", foreground="#B71C1C")
        self.tree.tag_configure("suspicious", background="#FFF3E0", foreground="#E65100")
        self.tree.tag_configure("unknown", background="#F5F5F5", foreground="#616161")
        self.tree.tag_configure("scanning", background="#E3F2FD", foreground="#0D47A1")

        # Double click opens report
        self.tree.bind("<Double-1>", lambda event: self._open_selected_report())

        # Bind Delete and Backspace keys on tree
        self.tree.bind("<Delete>", lambda event: self._remove_selected())
        self.tree.bind("<BackSpace>", lambda event: self._remove_selected())

        # Select all rows with Ctrl+A
        self.tree.bind("<Control-a>", lambda e: (self.tree.selection_set(self.tree.get_children()), "break")[1])
        self.tree.bind("<Control-A>", lambda e: (self.tree.selection_set(self.tree.get_children()), "break")[1])

        # Context Menu on Right Click
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="⚡ Scan Selected with VT", command=self._scan_selected)
        self.context_menu.add_command(label="🌐 Open VirusTotal Report", command=self._open_selected_report)
        self.context_menu.add_command(label="🔄 Reanalyze File", command=self._reanalyze_selected)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copy SHA-256 Hash", command=self._copy_selected_hash)
        self.context_menu.add_command(label="📂 Locate in File Explorer", command=self._locate_selected_file)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🗑 Remove from List", command=self._remove_selected)

        self.tree.bind("<Button-3>", self._show_context_menu)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            if item not in self.tree.selection():
                self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _on_global_delete(self, event):
        """Catches <Delete> press on window level (unless user is typing in Entry)."""
        if not isinstance(event.widget, (ttk.Entry, tk.Entry)):
            if self.tree.selection():
                self._remove_selected()
                return "break"

    def _on_global_paste(self, event):
        """Catches Ctrl+V on window level (unless user is typing in Entry/Text widget)."""
        if isinstance(event.widget, (ttk.Entry, tk.Entry, tk.Text)):
            return
        self._paste_target()
        return "break"

    def _on_global_key(self, event):
        """Hardware Virtual Key check for layout-independent Ctrl+V."""
        if event.state & 0x0004:
            if event.keycode == 86:  # VK_V
                if not isinstance(event.widget, (ttk.Entry, tk.Entry, tk.Text)):
                    self._paste_target()
                    return "break"

    def _build_action_bar(self):
        action_frame = ttk.Frame(self, padding=(16, 4, 16, 4))
        action_frame.pack(fill=tk.X)
        self.action_frame = action_frame

        # 1. Scan Selected Button
        self.btn_scan_selected = ttk.Button(
            action_frame,
            text="⚡ Scan Selected",
            command=self._scan_selected
        )
        self.btn_scan_selected.pack(side=tk.LEFT, padx=(0, 6))

        # 2. Open Report
        self.btn_open_report = ttk.Button(
            action_frame,
            text="🌐 Open Report",
            command=self._open_selected_report
        )
        self.btn_open_report.pack(side=tk.LEFT, padx=(0, 6))

        # 3. Reanalyze
        self.btn_reanalyze = ttk.Button(
            action_frame,
            text="🔄 Reanalyze",
            command=self._reanalyze_selected
        )
        self.btn_reanalyze.pack(side=tk.LEFT, padx=(0, 6))

        # 4. Copy Hash
        self.btn_copy_hash = ttk.Button(
            action_frame,
            text="📋 Copy Hash",
            command=self._copy_selected_hash
        )
        self.btn_copy_hash.pack(side=tk.LEFT, padx=(0, 6))

        # 5. Locate in Explorer
        self.btn_locate = ttk.Button(
            action_frame,
            text="📂 Locate",
            command=self._locate_selected_file
        )
        self.btn_locate.pack(side=tk.LEFT, padx=(0, 6))

        # 6. Remove Selected
        self.btn_remove = ttk.Button(
            action_frame,
            text="🗑 Remove Selected",
            command=self._remove_selected
        )
        self.btn_remove.pack(side=tk.LEFT)

        # Right side: Dynamic [ ▶ Rescan All ] / [ ⏹ Stop Scan ] button
        self.btn_rescan = ttk.Button(
            action_frame,
            text="▶ Rescan All",
            command=self._restart_scan
        )
        self.btn_rescan.pack(side=tk.RIGHT)

    def _build_status_bar(self):
        """
        Sleek, redesigned modern status container.
        Integrates progress bar with a clean inline cooldown pill badge.
        """
        status_frame = ttk.Frame(self, padding=(16, 6, 16, 10))
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_frame = status_frame

        progress_row = ttk.Frame(status_frame)
        progress_row.pack(fill=tk.X, pady=(0, 4))

        self.progress_bar = ttk.Progressbar(progress_row, orient=tk.HORIZONTAL, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.badge_cooldown = tk.Label(
            progress_row,
            text="",
            bg="#FFF3E0",
            fg="#D84315",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=1,
            relief=tk.SOLID,
            bd=1
        )

        info_box = ttk.Frame(status_frame)
        info_box.pack(fill=tk.X)

        self.lbl_status = ttk.Label(info_box, text="Ready (Drag & drop or Paste files here)", font=("Segoe UI", 9))
        self.lbl_status.pack(side=tk.LEFT)

        self.lbl_quota_hint = ttk.Label(
            info_box,
            text="Free API Quota: 4 req/min",
            font=("Segoe UI", 8),
            foreground="#888888"
        )
        self.lbl_quota_hint.pack(side=tk.RIGHT)

    # ------------------------------------------------------------------------
    # State & Control Flow (Scanning vs Stopped)
    # ------------------------------------------------------------------------

    def _set_ui_scanning_state(self, is_scanning: bool):
        """Dynamically transforms UI controls between scanning and ready states."""
        self.is_scanning = is_scanning
        if is_scanning:
            self.btn_rescan.config(text="⏹ Stop Scan (Esc)", command=self._stop_scan, style="Stop.TButton")
            self.btn_scan_selected.config(state=tk.DISABLED)
        else:
            self.btn_rescan.config(text="▶ Rescan All", command=self._restart_scan, style="TButton")
            self.btn_scan_selected.config(state=tk.NORMAL)

    def _stop_scan(self):
        """Immediately halts background scanning and rate-limit cooldown."""
        if not self.is_scanning:
            return
        self.stop_event.set()
        with self.scan_lock:
            self.active_scan_queue.clear()
        self.lbl_status.config(text="Stopping scan...")

    def _handle_scan_stopped(self):
        """Handles post-stop UI updates and dynamic messaging."""
        self._hide_cooldown_badge()
        self._set_ui_scanning_state(False)
        self.lbl_status.config(
            text="Scan stopped by user. Select files and click 'Scan Selected' to continue."
        )
        self._refresh_summary_cards()

    # ------------------------------------------------------------------------
    # Universal Target Loader & Appender (Append Mode)
    # ------------------------------------------------------------------------

    def _append_targets(self, paths: List[str]):
        """
        Appends dropped or pasted targets to the inspection table:
        - For dropped folders: automatically extract root executable binaries (*.exe, *.dll).
        - For dropped files: add valid files directly.
        - Preserves existing table items (does NOT wipe or reset).
        - Skips duplicate file paths if already present in the list.
        - Automatically recalculates and refreshes the top summary cards (Total, Clean, Suspicious, Unknown).
        - Auto-triggers background scanning for the newly appended items.
        """
        if not paths:
            return

        clean_paths = []
        for p in paths:
            if isinstance(p, str):
                p_clean = os.path.abspath(p.strip().strip('"').strip("'"))
                if os.path.exists(p_clean):
                    clean_paths.append(p_clean)

        if not clean_paths:
            self.lbl_status.config(text="No valid file or folder paths detected.")
            return

        # 1. Extract files from paths
        new_candidates = []
        empty_folders = []

        for p in clean_paths:
            if os.path.isdir(p):
                # Folder: automatically extract root executable binaries (*.exe, *.dll)
                bins = find_high_risk_binaries(p)
                if bins:
                    new_candidates.extend(bins)
                else:
                    empty_folders.append(os.path.basename(p))
            elif os.path.isfile(p):
                # File: add valid files directly
                new_candidates.append(p)

        if not new_candidates:
            if empty_folders:
                self.lbl_status.config(
                    text=f"No *.exe or *.dll binaries found in: {', '.join(empty_folders)}"
                )
            else:
                self.lbl_status.config(text="No valid files detected to inspect.")
            return

        # 2. Skip duplicates if already present in the list
        files_to_add = []
        for f in new_candidates:
            if f not in self.file_records and f not in files_to_add:
                files_to_add.append(f)

        if not files_to_add:
            self.lbl_status.config(text="All dropped/pasted files are already in the list (skipped duplicates).")
            return

        # 3. Append newly added files to self.file_records and self.tree
        for file_path in files_to_add:
            fname = os.path.basename(file_path)
            try:
                fsize = format_file_size(os.path.getsize(file_path))
            except Exception:
                fsize = "Unknown"
            ext = os.path.splitext(fname)[1].upper() or "FILE"

            self.file_records[file_path] = {
                "name": fname,
                "path": file_path,
                "size_str": f"{ext} ({fsize})",
                "sha256": "",
                "detections": "Pending...",
                "status": "⏳ Queued",
                "tag": "unknown",
                "verdict": "PENDING"
            }
            if file_path not in self.files_to_scan:
                self.files_to_scan.append(file_path)

            self.tree.insert(
                "",
                tk.END,
                iid=file_path,
                values=(fname, f"{ext} ({fsize})", "Pending...", "⏳ Queued", "")
            )

        # 4. Update Header Target Label
        total_count = len(self.file_records)
        if len(self.file_records) == len(files_to_add):
            # First load
            if len(clean_paths) == 1:
                self.target_path = clean_paths[0]
                if os.path.isdir(clean_paths[0]):
                    self.lbl_target.config(text=f"Folder: {clean_paths[0]} ({len(files_to_add)} binaries)")
                else:
                    self.lbl_target.config(text=f"File: {clean_paths[0]}")
            else:
                self.target_path = os.path.dirname(clean_paths[0])
                self.lbl_target.config(text=f"Targets: {len(files_to_add)} files loaded")
        else:
            # Appended load
            self.lbl_target.config(text=f"Multiple Targets ({total_count} total files in list)")

        # 5. Automatically recalculate and refresh top summary cards (Total, Clean, Suspicious, Unknown)
        self._refresh_summary_cards()
        self.card_total.config(text=str(total_count))

        # 6. Check API Key
        self.api_key = get_api_key()
        if not self.api_key:
            dlg = ApiKeyDialog(self)
            self.wait_window(dlg)
            self.api_key = get_api_key()

            if not self.api_key and dlg.result_action == "browser_mode":
                self._handle_no_key_fallback(files_to_add)
                return

        # 7. Auto-trigger background scanning for the newly appended items
        if not self.is_scanning:
            self.lbl_status.config(text=f"Added {len(files_to_add)} new file(s). Starting scan...")
            self._start_scan_thread(files_to_add)
        else:
            with self.scan_lock:
                self.active_scan_queue.extend(files_to_add)
            self.progress_bar['maximum'] = self.progress_bar['maximum'] + len(files_to_add)
            self.lbl_status.config(
                text=f"Added {len(files_to_add)} new file(s) to scan queue. Scan in progress..."
            )

    def load_and_scan_targets(self, paths: List[str], append: bool = True):
        """Universal target loader - delegates directly to _append_targets."""
        self._append_targets(paths)

    def _paste_target(self):
        """
        Handler for [ 📋 Paste Target ] button and Ctrl+V hotkey.
        Extracts copied files (CF_HDROP) or path strings from Windows Clipboard.
        """
        paths = get_target_from_clipboard()
        if not paths:
            self.lbl_status.config(text="Clipboard does not contain a valid file or folder path.")
            show_notification(
                "Paste Target",
                "Clipboard does not contain a valid file or folder path.",
                timeout_seconds=2
            )
            return

        self._append_targets(paths)

    def _initialize_scan(self):
        """Initial check on app launch."""
        if self.target_path:
            self._append_targets([self.target_path])

    def _handle_no_key_fallback(self, target_subset: Optional[List[str]] = None):
        """
        Fallback when user opts out of API key:
        Computes SHA-256 for files and opens the main executable in the browser.
        Accurately updates the status bar without claiming files are clean.
        """
        files_to_process = target_subset if target_subset else self.files_to_scan
        if not files_to_process:
            return

        for f in files_to_process:
            try:
                h = calculate_sha256(f)
                self.file_records[f]["sha256"] = h
                fname = self.file_records[f]["name"]
                fsize = self.file_records[f]["size_str"]
                self.tree.item(f, values=(fname, fsize, "N/A", "Ready (No API Key)", h), tags=("unknown",))
            except Exception as e:
                self.file_records[f]["status"] = f"Error: {e}"

        main_exe = files_to_process[0]
        if self.target_path and os.path.isdir(self.target_path):
            identified = identify_main_executable(self.target_path, files_to_process)
            if identified:
                main_exe = identified

        if main_exe and main_exe in self.file_records:
            sha256 = self.file_records[main_exe]["sha256"]
            copy_to_clipboard(sha256)
            url = f"https://www.virustotal.com/gui/file/{sha256}"
            webbrowser.open(url, new=2)

            fname = self.file_records[main_exe]["name"]
            fsize = self.file_records[main_exe]["size_str"]
            self.tree.item(
                main_exe,
                values=(fname, fsize, "Opened in VT", "🌐 Browser Mode", sha256),
                tags=("clean",)
            )

            show_notification(
                "VirusTotal Checker",
                f"Opened {fname} in browser.\nSHA-256 copied to clipboard."
            )

        self.lbl_status.config(
            text="Hashes calculated. Waiting for API Key or user action (files not verified on VT)."
        )
        self._hide_cooldown_badge()
        self._refresh_summary_cards()

    # ------------------------------------------------------------------------
    # Background Scanning & Rate Limiting (4 req/min)
    # ------------------------------------------------------------------------

    def _start_scan_thread(self, target_files: Optional[List[str]] = None):
        """Launches background worker with responsive threading.Event cancellation."""
        if self.is_scanning:
            if target_files:
                with self.scan_lock:
                    self.active_scan_queue.extend(target_files)
                self.progress_bar['maximum'] = self.progress_bar['maximum'] + len(target_files)
            return

        files_to_process = list(target_files) if target_files else list(self.files_to_scan)
        if not files_to_process:
            return

        self.stop_event.clear()
        self._set_ui_scanning_state(True)
        with self.scan_lock:
            self.active_scan_queue = list(files_to_process)
        self.progress_bar['maximum'] = len(self.active_scan_queue)
        self.progress_bar['value'] = 0

        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def _scan_worker(self):
        index = 0
        was_stopped = False

        while True:
            if self.stop_event.is_set():
                was_stopped = True
                break

            with self.scan_lock:
                if not self.active_scan_queue:
                    break
                file_path = self.active_scan_queue.pop(0)

            # Skip if removed by user while queued
            if file_path not in self.file_records:
                continue

            index += 1
            with self.scan_lock:
                total_files = index + len(self.active_scan_queue)
            fname = os.path.basename(file_path)

            # Step 1: Calculate SHA-256
            self.after(0, self._update_row_status, file_path, "⏳ Hashing...", "scanning")
            self.after(0, self._set_status_text, f"Inspecting file {index} of {total_files}: Calculating SHA-256 for {fname}...")

            try:
                sha256 = calculate_sha256(file_path)
                self.file_records[file_path]["sha256"] = sha256
            except Exception as e:
                self.after(
                    0, self._update_row_result, file_path,
                    "Error", f"✖ Read Error: {e}", "malicious", "ERROR", ""
                )
                self.after(0, self._increment_progress)
                continue

            if self.stop_event.is_set():
                was_stopped = True
                break

            # Step 2: Rate Limiting Check before sending API query
            if self.api_key:
                wait_time = vt_rate_limiter.get_wait_seconds()

                if wait_time > 0:
                    completed = self._handle_rate_limit_wait(math.ceil(wait_time), index, total_files)
                    if not completed or self.stop_event.is_set():
                        was_stopped = True
                        break

                if self.stop_event.is_set():
                    was_stopped = True
                    break

                # Query VirusTotal API
                self.after(0, self._update_row_status, file_path, "⏳ Querying VT API...", "scanning")
                self.after(0, self._set_status_text, f"Inspecting file {index} of {total_files}: Querying VirusTotal for {fname}...")

                api_result = query_virustotal_api(sha256, self.api_key)
                vt_rate_limiter.record_request()

                # Handle HTTP 429 automatically if encountered
                if api_result["status"] == "rate_limited":
                    completed = self._handle_rate_limit_wait(FREE_TIER_RATE_LIMIT_DELAY, index, total_files)
                    if not completed or self.stop_event.is_set():
                        was_stopped = True
                        break
                    api_result = query_virustotal_api(sha256, self.api_key)
                    vt_rate_limiter.record_request()

                # Parse verdict
                verdict = api_result["verdict"]
                if verdict == "CLEAN":
                    detections = api_result["detections_str"]
                    status_str = f"✔ Clean ({detections})"
                    tag = "clean"
                elif verdict == "MALICIOUS":
                    detections = api_result["detections_str"]
                    status_str = f"✖ Malicious ({detections})"
                    tag = "malicious"
                elif verdict == "SUSPICIOUS":
                    detections = api_result["detections_str"]
                    status_str = f"⚠ Suspicious ({detections})"
                    tag = "suspicious"
                elif verdict == "NOT_FOUND":
                    detections = "N/A"
                    status_str = "? Unknown (Not in VT)"
                    tag = "unknown"
                elif verdict == "AUTH_ERROR":
                    detections = "Key Error"
                    status_str = "⚠ Invalid API Key"
                    tag = "suspicious"
                else:
                    detections = "Error"
                    status_str = f"Error: {api_result.get('message', 'Failed')}"
                    tag = "unknown"

                self.after(
                    0, self._update_row_result, file_path,
                    detections, status_str, tag, verdict, sha256
                )
            else:
                self.after(
                    0, self._update_row_result, file_path,
                    "N/A", "Ready (No API Key)", "unknown", "UNVERIFIED", sha256
                )

            # Update progress bar
            self.after(0, self._increment_progress)

        self.is_scanning = False
        if was_stopped or self.stop_event.is_set():
            self.after(0, self._handle_scan_stopped)
        else:
            self.after(0, self._finalize_scan)

    def _handle_rate_limit_wait(self, wait_seconds: int, current_file: int, total_files: int) -> bool:
        """
        Coordinates cooldown countdown using threading.Event.wait()
        for INSTANT cancellation (0ms delay) when Stop is requested.
        """
        for remaining in range(wait_seconds, 0, -1):
            if self.stop_event.is_set():
                self.after(0, self._hide_cooldown_badge)
                return False

            self.after(
                0, self._set_status_text,
                f"Waiting for rate limit cooldown (file {current_file} of {total_files}) — Free VT API limit: 4 req/min..."
            )
            self.after(0, self._show_cooldown_badge, f"⏳ Cooldown: {remaining}s (API Quota)")

            if self.stop_event.wait(timeout=1.0):
                self.after(0, self._hide_cooldown_badge)
                return False

        self.after(0, self._hide_cooldown_badge)
        return True

    def _show_cooldown_badge(self, text: str):
        self.badge_cooldown.config(text=text)
        self.badge_cooldown.pack(side=tk.RIGHT, padx=(8, 0))

    def _hide_cooldown_badge(self):
        self.badge_cooldown.pack_forget()

    def _update_row_status(self, file_path, status_text, tag):
        rec = self.file_records.get(file_path, {})
        fname = rec.get("name", os.path.basename(file_path))
        fsize = rec.get("size_str", "")
        self.tree.item(file_path, values=(fname, fsize, "...", status_text, rec.get("sha256", "")), tags=(tag,))

    def _update_row_result(self, file_path, detections, status, tag, verdict, sha256):
        rec = self.file_records.get(file_path, {})
        rec["detections"] = detections
        rec["status"] = status
        rec["tag"] = tag
        rec["verdict"] = verdict
        rec["sha256"] = sha256

        fname = rec.get("name", os.path.basename(file_path))
        fsize = rec.get("size_str", "")

        self.tree.item(
            file_path,
            values=(fname, fsize, detections, status, sha256),
            tags=(tag,)
        )
        self._refresh_summary_cards()

    def _increment_progress(self):
        self.progress_bar['value'] += 1

    def _set_status_text(self, text):
        self.lbl_status.config(text=text)

    def _refresh_summary_cards(self):
        clean_cnt = 0
        suspicious_cnt = 0
        unknown_cnt = 0

        for rec in self.file_records.values():
            verdict = rec.get("verdict")
            if verdict == "CLEAN":
                clean_cnt += 1
            elif verdict in ("MALICIOUS", "SUSPICIOUS"):
                suspicious_cnt += 1
            else:
                unknown_cnt += 1

        self.card_total.config(text=str(len(self.file_records)))
        self.card_clean.config(text=str(clean_cnt))
        self.card_suspicious.config(text=str(suspicious_cnt))
        self.card_unknown.config(text=str(unknown_cnt))

    def _finalize_scan(self):
        """
        Dynamically reports the TRUE state of all files in the status bar.
        Eliminates any false sense of security.
        """
        self._hide_cooldown_badge()
        self._set_ui_scanning_state(False)

        clean_cnt = 0
        threat_cnt = 0
        unverified_cnt = 0

        for rec in self.file_records.values():
            verdict = rec.get("verdict")
            if verdict == "CLEAN":
                clean_cnt += 1
            elif verdict in ("MALICIOUS", "SUSPICIOUS"):
                threat_cnt += 1
            else:
                unverified_cnt += 1

        total = len(self.file_records)

        if total == 0:
            self.lbl_status.config(text="Ready. No files to inspect.")
        elif not self.api_key and clean_cnt == 0 and threat_cnt == 0:
            self.lbl_status.config(
                text="Waiting for API Key or user action (files not verified on VT)."
            )
        elif threat_cnt > 0:
            self.lbl_status.config(
                text=f"Completed: {clean_cnt} clean, ⚠ {threat_cnt} suspicious/malicious, {unverified_cnt} unverified"
            )
        elif unverified_cnt > 0:
            self.lbl_status.config(
                text=f"Completed: {clean_cnt} clean, {unverified_cnt} unverified / not in VT (0 suspicious)"
            )
        else:
            self.lbl_status.config(
                text=f"Completed: All {clean_cnt} inspected files verified clean on VirusTotal."
            )

    # ------------------------------------------------------------------------
    # User Actions (Multi-Select, Scan Selected, Remove, Open, Reanalyze, Copy)
    # ------------------------------------------------------------------------

    def _get_selected_records(self) -> List[Dict[str, Any]]:
        """Returns list of all currently selected file records in Treeview."""
        selected_ids = self.tree.selection()
        if not selected_ids:
            return []
        records = []
        for item_id in selected_ids:
            rec = self.file_records.get(item_id)
            if rec:
                records.append(rec)
        return records

    def _scan_selected(self):
        """
        Queries VirusTotal API ONLY for selected rows (or unscanned ones).
        Saves rate limit quota and avoids long cooldown queues.
        """
        if self.is_scanning:
            messagebox.showinfo("Scan Running", "A scan is already in progress. Please stop it first if you wish to switch targets.")
            return

        selected_ids = list(self.tree.selection())

        if not selected_ids:
            unverified = [
                path for path, rec in self.file_records.items()
                if rec.get("verdict") in ("PENDING", "UNVERIFIED")
            ]
            if not unverified:
                messagebox.showinfo("Scan Selected", "All files have already been verified. Select specific files to rescan.")
                return
            targets = unverified
        else:
            targets = [i for i in selected_ids if i in self.file_records]

        if not self.api_key:
            dlg = ApiKeyDialog(self, current_key=self.api_key)
            self.wait_window(dlg)
            self.api_key = get_api_key()
            if not self.api_key:
                messagebox.showwarning("API Key Needed", "An API key is required for selective headless scanning.")
                return

        self.lbl_status.config(text=f"Starting selective scan for {len(targets)} file(s)...")
        self._start_scan_thread(targets)

    def _remove_selected(self):
        """
        Removes selected item(s) from the Treeview and internal state.
        Recalculates and refreshes the top summary cards automatically.
        """
        selected_ids = list(self.tree.selection())
        if not selected_ids:
            return

        count = len(selected_ids)
        with self.scan_lock:
            self.active_scan_queue = [f for f in self.active_scan_queue if f not in selected_ids]

        for item_id in selected_ids:
            if self.tree.exists(item_id):
                self.tree.delete(item_id)
            if item_id in self.file_records:
                del self.file_records[item_id]
            if item_id in self.files_to_scan:
                self.files_to_scan.remove(item_id)

        self._refresh_summary_cards()
        self.lbl_status.config(text=f"Removed {count} item(s) from list ({len(self.file_records)} remaining).")

    def _open_selected_report(self):
        """Opens VirusTotal browser reports for ALL selected files simultaneously in new tabs."""
        records = self._get_selected_records()
        if not records:
            messagebox.showinfo("Select a File", "Please select one or more files from the list first.")
            return

        urls = []
        for rec in records:
            sha256 = rec.get("sha256")
            if not sha256:
                try:
                    sha256 = calculate_sha256(rec["path"])
                    rec["sha256"] = sha256
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to compute SHA-256 for {rec['name']}:\n{e}")
                    continue
            urls.append(f"https://www.virustotal.com/gui/file/{sha256}")

        if len(records) == 1:
            copy_to_clipboard(records[0]["sha256"])
        else:
            hashes = [r["sha256"] for r in records if r.get("sha256")]
            if hashes:
                copy_to_clipboard("\n".join(hashes))

        for url in urls:
            webbrowser.open(url, new=2)

        count = len(urls)
        if count == 1:
            self.lbl_status.config(text=f"Opened VirusTotal report for {records[0]['name']}")
        else:
            self.lbl_status.config(text=f"Opened {count} VirusTotal reports in browser tabs.")

    def _reanalyze_selected(self):
        """Requests reanalysis for all selected files."""
        records = self._get_selected_records()
        if not records:
            messagebox.showinfo("Select a File", "Please select one or more files from the list first.")
            return

        for rec in records:
            sha256 = rec.get("sha256")
            if not sha256:
                try:
                    sha256 = calculate_sha256(rec["path"])
                    rec["sha256"] = sha256
                except Exception as e:
                    continue

            if not self.api_key:
                vt_url = f"https://www.virustotal.com/gui/file/{sha256}"
                webbrowser.open(vt_url, new=2)
                continue

            success, msg = request_reanalysis(sha256, self.api_key)
            if success:
                self.lbl_status.config(text=f"Reanalysis queued for {rec['name']}")
            else:
                self.lbl_status.config(text=f"Reanalysis note: {msg}")

        if not self.api_key:
            messagebox.showinfo(
                "Web Reanalyze",
                "No API key configured. Opened VirusTotal page(s) in browser where you can click 'Reanalyze'."
            )
        else:
            messagebox.showinfo("Reanalyze Complete", f"Requested reanalysis for {len(records)} selected file(s).")

    def _copy_selected_hash(self):
        """
        Copies SHA-256 hashes of all selected files to clipboard.
        If multiple rows are selected, formats as one hash per line.
        """
        records = self._get_selected_records()
        if not records:
            messagebox.showinfo("Select a File", "Please select one or more files from the list first.")
            return

        hashes = []
        for rec in records:
            sha256 = rec.get("sha256")
            if not sha256:
                try:
                    sha256 = calculate_sha256(rec["path"])
                    rec["sha256"] = sha256
                except Exception as e:
                    continue
            if sha256:
                hashes.append(sha256)

        if not hashes:
            messagebox.showerror("Error", "No SHA-256 hashes available to copy.")
            return

        text_to_copy = "\n".join(hashes)
        if copy_to_clipboard(text_to_copy):
            count = len(hashes)
            if count == 1:
                self.lbl_status.config(text=f"Copied SHA-256 to clipboard: {hashes[0][:16]}...")
                show_notification("Hash Copied", f"SHA-256 for {records[0]['name']} copied to clipboard!", timeout_seconds=3)
            else:
                self.lbl_status.config(text=f"Copied {count} SHA-256 hashes to clipboard (one per line).")
                show_notification("Hashes Copied", f"Copied {count} SHA-256 hashes to clipboard!", timeout_seconds=3)
        else:
            messagebox.showerror("Clipboard Error", "Could not copy hash to Windows clipboard.")

    def _locate_selected_file(self):
        records = self._get_selected_records()
        if not records:
            messagebox.showinfo("Select a File", "Please select a file from the list first.")
            return
        path = records[0].get("path")
        if path and os.path.exists(path):
            os.system(f'explorer /select,"{path}"')

    def _restart_scan(self):
        if self.is_scanning:
            return
        vt_rate_limiter.reset()
        for f in self.files_to_scan:
            if f in self.file_records:
                self.file_records[f]["verdict"] = "PENDING"
                self.file_records[f]["status"] = "⏳ Queued"
                self.tree.item(
                    f,
                    values=(
                        self.file_records[f]["name"],
                        self.file_records[f]["size_str"],
                        "Pending...",
                        "⏳ Queued",
                        self.file_records[f].get("sha256", "")
                    ),
                    tags=("unknown",)
                )
        self._refresh_summary_cards()
        self._start_scan_thread(self.files_to_scan)

    def _browse_file(self):
        file_selected = filedialog.askopenfilename(
            title="Select File to Inspect",
            filetypes=[("Executable & DLL Files", "*.exe;*.dll"), ("All Files", "*.*")]
        )
        if file_selected:
            # Append mode
            self.load_and_scan_targets([file_selected], append=True)

    def _browse_folder(self):
        folder_selected = filedialog.askdirectory(title="Select Folder to Inspect")
        if folder_selected:
            # Append mode
            self.load_and_scan_targets([folder_selected], append=True)

    def _open_api_settings(self):
        dlg = ApiKeyDialog(self, current_key=self.api_key)
        self.wait_window(dlg)
        self.api_key = get_api_key()


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    target_path = sys.argv[1] if len(sys.argv) > 1 else None
    app = SafeLaunchGUI(target_path=target_path)
    app.mainloop()


if __name__ == "__main__":
    main()
