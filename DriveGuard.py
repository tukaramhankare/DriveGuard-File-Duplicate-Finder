#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DriveGuard - Drive & File Integrity Manager
=============================================
Scans a drive, folder, or removable media device; computes SHA-256 for every
file; visualises duplicates and corrupted/changed files; and lets you act on
any file directly at its ORIGINAL location - reveal it, rename it, copy it,
replace it with a hash-verified, auto-backed-up overwrite, or delete it
(single or multi-select) to a recoverable local quarantine folder.

Licensed under the Apache License, Version 2.0
Tukaram Hankare - Farmer, Coder & Web Developer, Solapur, Maharashtra, India

Zero external dependencies - Python standard library only.
"""

import os
import sys
import shutil
import hashlib
import json
import csv
import threading
import queue
import subprocess
import multiprocessing
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog


# --------------------------------------------------------------------------- #
# Frozen-app (PyInstaller) support
# --------------------------------------------------------------------------- #
def resource_path(relative_path):
    """Absolute path to a bundled resource, for dev and PyInstaller onefile."""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


APP_NAME = "DriveGuard"
APP_VERSION = "1.2"

APP_DIR = os.path.join(os.path.expanduser("~"), ".driveguard")
BACKUP_DIR = os.path.join(APP_DIR, "backups")
MANIFEST_DIR = os.path.join(APP_DIR, "manifests")
LOG_PATH = os.path.join(APP_DIR, "operations.log.jsonl")

for _d in (APP_DIR, BACKUP_DIR, MANIFEST_DIR):
    os.makedirs(_d, exist_ok=True)

# --------------------------------------------------------------------------- #
# Theme - dark (original) plus a new light/light-gray option, toggled at
# runtime. Module-level names below stay as the dark defaults so nothing
# that referenced BG/PANEL/etc. directly needs to change; the running app
# tracks self.theme_name and re-applies THEMES[name] via _apply_theme().
# --------------------------------------------------------------------------- #
BG = "#161310"
PANEL = "#1A1A1A"
PANEL_LIGHT = "#232019"
ACCENT = "#D97757"
ACCENT_DARK = "#C96442"
WARN = "#E85C4A"
FG = "#E8E0D8"
FG_DIM = "#8A8378"
FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")
FONT_MONO_SM = ("Consolas", 9)

THEMES = {
    "dark": {
        "bg": BG, "panel": PANEL, "panel_light": PANEL_LIGHT,
        "accent": ACCENT, "accent_dark": ACCENT_DARK, "warn": WARN,
        "fg": FG, "fg_dim": FG_DIM, "accent_text": "#1A1310",
    },
    "light": {
        "bg": "#F4F3F1", "panel": "#EAE9E6", "panel_light": "#DCDAD5",
        "accent": "#C96442", "accent_dark": "#B0532F", "warn": "#C4432E",
        "fg": "#262420", "fg_dim": "#6E685F", "accent_text": "#FFFFFF",
    },
}

CHUNK_SIZE = 1024 * 1024  # 1 MB streaming reads
LONG_PRESS_MS = 550       # touch/trackpad "hold" threshold

# Lightweight file-signature table for corruption / mislabeling detection.
# Not exhaustive by design - flags only confident mismatches, never guesses.
MAGIC_SIGNATURES = {
    b"\xff\xd8\xff": [".jpg", ".jpeg"],
    b"\x89PNG\r\n\x1a\n": [".png"],
    b"%PDF-": [".pdf"],
    b"PK\x03\x04": [".zip", ".docx", ".xlsx", ".pptx", ".apk", ".jar"],
    b"GIF87a": [".gif"],
    b"GIF89a": [".gif"],
    b"ID3": [".mp3"],
    b"RIFF": [".wav", ".avi"],
    b"\x1f\x8b": [".gz"],
    b"7z\xbc\xaf\x27\x1c": [".7z"],
    b"\x42\x4d": [".bmp"],
}
_KNOWN_EXTS = set(ext for exts in MAGIC_SIGNATURES.values() for ext in exts)


# --------------------------------------------------------------------------- #
# Core file utilities
# --------------------------------------------------------------------------- #
def sha256_of_file(path):
    """Return (hex_digest, size_bytes) or raise OSError on unreadable file."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def detect_signature_mismatch(path):
    """Return a warning string if the file's magic bytes don't match its
    extension, when the extension is one we recognise. None if OK/unknown."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in _KNOWN_EXTS:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None
    for sig, exts in MAGIC_SIGNATURES.items():
        if ext in exts and head.startswith(sig):
            return None
    return "content signature does not match extension \"{}\"".format(ext)


def human_size(num_bytes):
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return "{:.1f} {}".format(size, unit) if unit != "B" else "{:.0f} B".format(size)
        size /= 1024.0
    return "{:.1f} PB".format(size)


def reveal_in_file_manager(path):
    """Open the OS file manager with the given file pre-selected/highlighted."""
    path = os.path.normpath(os.path.abspath(path))
    folder = os.path.dirname(path)
    try:
        if sys.platform.startswith("win"):
            # explorer.exe has its own oddball command-line parser for
            # /select,. Passing ["explorer", "/select,{}".format(path)] as a
            # LIST makes Python's subprocess quote the whole argument
            # whenever the path contains a space - producing
            # "/select,C:\Users\John Doe\file.txt" - and explorer fails to
            # recognise /select inside those quotes, silently falling back
            # to a default location (Quick access / This PC) instead of the
            # actual file. The fix is to build the exact command line
            # ourselves, quoting only the path, and pass it as a STRING
            # (not a list) with shell=False so Python does no quoting of
            # its own: explorer /select,"C:\path with spaces\file.txt"
            command = 'explorer /select,"{}"'.format(path)
            subprocess.run(command, shell=False)
            # explorer.exe always exits with code 1 even on success - that
            # is a known quirk, not a failure, so the return code is never
            # checked here.
        elif sys.platform == "darwin":
            subprocess.run(["open", "-R", path])
        else:
            subprocess.run(["xdg-open", folder])
    except Exception as exc:
        raise RuntimeError("could not open file manager: {}".format(exc))


# --------------------------------------------------------------------------- #
# Manifest (baseline hash record) - powers bit-rot / "changed since last
# scan" detection, since a single SHA-256 alone cannot tell you a file is
# corrupted - only that it differs from something.
# --------------------------------------------------------------------------- #
def manifest_path_for(source_root):
    key = hashlib.sha256(os.path.abspath(source_root).encode("utf-8")).hexdigest()[:20]
    return os.path.join(MANIFEST_DIR, key + ".json")


def load_last_manifest(source_root):
    path = manifest_path_for(source_root)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get("files", {})
    except (OSError, json.JSONDecodeError):
        return {}


def save_manifest(source_root, path_hash_map):
    path = manifest_path_for(source_root)
    payload = {
        "source_root": os.path.abspath(source_root),
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "file_count": len(path_hash_map),
        "files": path_hash_map,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)


# --------------------------------------------------------------------------- #
# Operation log (every rename / copy / replace, append-only JSON Lines)
# --------------------------------------------------------------------------- #
def log_operation(action, **details):
    entry = {"time": datetime.now().isoformat(timespec="seconds"), "action": action}
    entry.update(details)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def read_recent_log(n=200):
    if not os.path.isfile(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# --------------------------------------------------------------------------- #
# Background scan worker - never touches Tk from this thread; only pushes
# messages onto a queue the main thread polls via `.after(...)`.
# --------------------------------------------------------------------------- #
class ScanWorker(threading.Thread):
    def __init__(self, source_root, out_queue, cancel_event):
        super().__init__(daemon=True)
        self.source_root = source_root
        self.q = out_queue
        self.cancel_event = cancel_event

    def run(self):
        try:
            last_manifest = load_last_manifest(self.source_root)
            path_hash_map = {}
            count = 0
            total_bytes = 0

            for dirpath, dirnames, filenames in os.walk(self.source_root):
                if self.cancel_event.is_set():
                    self.q.put(("cancelled", None))
                    return
                for name in filenames:
                    if self.cancel_event.is_set():
                        self.q.put(("cancelled", None))
                        return
                    full_path = os.path.join(dirpath, name)
                    count += 1
                    self.q.put(("progress", (count, full_path)))

                    try:
                        if os.path.islink(full_path):
                            continue
                        size_on_disk = os.path.getsize(full_path)
                        if size_on_disk == 0:
                            self.q.put(("file", {
                                "path": full_path, "hash": None, "size": 0,
                                "error": "empty file (0 bytes)",
                                "mismatch": None, "bitrot": False,
                            }))
                            continue

                        digest, size = sha256_of_file(full_path)
                        total_bytes += size
                        mismatch = detect_signature_mismatch(full_path)
                        prev_hash = last_manifest.get(full_path)
                        bitrot = bool(prev_hash and prev_hash != digest)

                        path_hash_map[full_path] = digest
                        self.q.put(("file", {
                            "path": full_path, "hash": digest, "size": size,
                            "error": None, "mismatch": mismatch, "bitrot": bitrot,
                        }))
                    except OSError as exc:
                        self.q.put(("file", {
                            "path": full_path, "hash": None, "size": 0,
                            "error": "unreadable: {}".format(exc.strerror or exc),
                            "mismatch": None, "bitrot": False,
                        }))

            save_manifest(self.source_root, path_hash_map)
            self.q.put(("done", {
                "count": count,
                "total_bytes": total_bytes,
                "path_hash_map": path_hash_map,
            }))
        except Exception as exc:  # last-resort guard so the UI never hangs
            self.q.put(("error", str(exc)))


# --------------------------------------------------------------------------- #
# Main application
# --------------------------------------------------------------------------- #
class DriveGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("{} v{}".format(APP_NAME, APP_VERSION))
        self.root.geometry("1150x720")
        self.root.minsize(860, 560)
        self.root.configure(bg=BG)

        self.theme_name = "dark"
        self.source_root = tk.StringVar(value="")
        self.status_text = tk.StringVar(value="No scan yet.")
        self.q = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker = None
        self._scan_results = []  # last completed scan, kept for Export

        # iid -> absolute path, for every leaf (file) row in the tree
        self.item_paths = {}
        self.item_hashes = {}

        self._press_after_id = None
        self._press_xy = (0, 0)

        self._build_style()
        self._build_layout()
        self._apply_theme(self.theme_name)
        self._refresh_log_panel()

    # ---------------------------------------------------------- styling ---
    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, font=FONT_MONO)
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)

        style.configure("TLabel", background=BG, foreground=FG, font=FONT_MONO)
        style.configure("Dim.TLabel", background=BG, foreground=FG_DIM, font=FONT_MONO_SM)
        style.configure("Header.TLabel", background=BG, foreground=ACCENT, font=FONT_MONO_BOLD)

        style.configure("TButton", background=PANEL_LIGHT, foreground=FG,
                         font=FONT_MONO, borderwidth=0, focusthickness=0, padding=6)
        style.map("TButton", background=[("active", ACCENT_DARK)], foreground=[("active", "#FFFFFF")])

        style.configure("Accent.TButton", background=ACCENT, foreground="#1A1310",
                         font=FONT_MONO_BOLD, borderwidth=0, padding=6)
        style.map("Accent.TButton", background=[("active", ACCENT_DARK)])

        style.configure("TEntry", fieldbackground=PANEL_LIGHT, foreground=FG,
                         insertcolor=FG, borderwidth=1)

        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                         foreground=FG, font=FONT_MONO, rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background=PANEL_LIGHT, foreground=ACCENT,
                         font=FONT_MONO_BOLD, borderwidth=0)
        style.map("Treeview", background=[("selected", ACCENT_DARK)],
                  foreground=[("selected", "#FFFFFF")])

        style.configure("Horizontal.TProgressbar", background=ACCENT,
                         troughcolor=PANEL_LIGHT, borderwidth=0)

    # ------------------------------------------------------------ theme ---
    def _toggle_theme(self):
        self.theme_name = "light" if self.theme_name == "dark" else "dark"
        self._apply_theme(self.theme_name)
        self.theme_btn.configure(text="Dark Theme" if self.theme_name == "light" else "Light Theme")

    def _apply_theme(self, name):
        c = THEMES[name]
        style = ttk.Style()

        style.configure(".", background=c["bg"], foreground=c["fg"], font=FONT_MONO)
        style.configure("TFrame", background=c["bg"])
        style.configure("Panel.TFrame", background=c["panel"])
        style.configure("TLabel", background=c["bg"], foreground=c["fg"], font=FONT_MONO)
        style.configure("Dim.TLabel", background=c["bg"], foreground=c["fg_dim"], font=FONT_MONO_SM)
        style.configure("Header.TLabel", background=c["bg"], foreground=c["accent"], font=FONT_MONO_BOLD)

        style.configure("TButton", background=c["panel_light"], foreground=c["fg"],
                         font=FONT_MONO, borderwidth=0, focusthickness=0, padding=6)
        style.map("TButton", background=[("active", c["accent_dark"])],
                  foreground=[("active", "#FFFFFF")])

        style.configure("Accent.TButton", background=c["accent"], foreground=c["accent_text"],
                         font=FONT_MONO_BOLD, borderwidth=0, padding=6)
        style.map("Accent.TButton", background=[("active", c["accent_dark"])])

        style.configure("TEntry", fieldbackground=c["panel_light"], foreground=c["fg"],
                         insertcolor=c["fg"], borderwidth=1)

        style.configure("Treeview", background=c["panel"], fieldbackground=c["panel"],
                         foreground=c["fg"], font=FONT_MONO, rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background=c["panel_light"], foreground=c["accent"],
                         font=FONT_MONO_BOLD, borderwidth=0)
        style.map("Treeview", background=[("selected", c["accent_dark"])],
                  foreground=[("selected", "#FFFFFF")])

        style.configure("Horizontal.TProgressbar", background=c["accent"],
                         troughcolor=c["panel_light"], borderwidth=0)

        self.root.configure(bg=c["bg"])
        self.tree.tag_configure("dup", foreground=c["accent"])
        self.tree.tag_configure("bad", foreground=c["warn"])
        self.tree.tag_configure("group", foreground=c["fg_dim"], font=FONT_MONO_BOLD)
        self.menu.configure(bg=c["panel_light"], fg=c["fg"],
                             activebackground=c["accent"], activeforeground="#FFFFFF")
        self.log_box.configure(bg=c["panel"], fg=c["fg_dim"])

    # ---------------------------------------------------------- layout ----
    def _build_layout(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(side="top", fill="x")

        ttk.Label(top, text="Source (drive / folder / device):").pack(side="left")
        entry = ttk.Entry(top, textvariable=self.source_root, width=55, font=FONT_MONO)
        entry.pack(side="left", padx=6)
        ttk.Button(top, text="Browse", command=self.browse_source).pack(side="left", padx=2)
        self.scan_btn = ttk.Button(top, text="Scan", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=6)
        self.cancel_btn = ttk.Button(top, text="Cancel", command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(side="left", padx=2)
        ttk.Button(top, text="Export SHA-256", command=self._act_export_hashes).pack(side="left", padx=(12, 2))
        ttk.Button(top, text="Import SHA-256", command=self._act_import_hashes).pack(side="left", padx=2)
        self.theme_btn = ttk.Button(top, text="Light Theme", command=self._toggle_theme)
        self.theme_btn.pack(side="right", padx=2)

        prog_frame = ttk.Frame(self.root, padding=(10, 0))
        prog_frame.pack(side="top", fill="x")
        self.progress = ttk.Progressbar(prog_frame, mode="indeterminate",
                                         style="Horizontal.TProgressbar")
        self.progress.pack(side="top", fill="x", pady=(0, 4))
        ttk.Label(prog_frame, textvariable=self.status_text, style="Dim.TLabel").pack(side="top", anchor="w")

        # Selection status (live count as the user ctrl/shift-clicks rows)
        sel_frame = ttk.Frame(self.root, padding=(10, 0))
        sel_frame.pack(side="top", fill="x")
        self.selection_text = tk.StringVar(value="")
        ttk.Label(sel_frame, textvariable=self.selection_text, style="Header.TLabel").pack(side="left")

        # Results tree
        mid = ttk.Frame(self.root, padding=10)
        mid.pack(side="top", fill="both", expand=True)

        columns = ("size", "hash", "flag")
        self.tree = ttk.Treeview(mid, columns=columns, show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="File / Group")
        self.tree.heading("size", text="Size")
        self.tree.heading("hash", text="SHA-256")
        self.tree.heading("flag", text="Status")
        self.tree.column("#0", width=480, anchor="w")
        self.tree.column("size", width=90, anchor="e")
        self.tree.column("hash", width=210, anchor="w")
        self.tree.column("flag", width=260, anchor="w")

        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="left", fill="y")

        self.tree.tag_configure("dup", foreground=ACCENT)
        self.tree.tag_configure("bad", foreground=WARN)
        self.tree.tag_configure("group", foreground=FG_DIM, font=FONT_MONO_BOLD)

        # Right-click (desktop) and long-press (touch/trackpad) both open
        # the same context menu.
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<ButtonPress-1>", self._on_press_start)
        self.tree.bind("<ButtonRelease-1>", self._on_press_end)
        self.tree.bind("<B1-Motion>", self._on_press_move)
        self.tree.bind("<<TreeviewSelect>>", self._on_selection_change)
        self.tree.bind("<Delete>", lambda event: self._act_delete())

        self.menu = tk.Menu(self.root, tearoff=0, bg=PANEL_LIGHT, fg=FG,
                             activebackground=ACCENT, activeforeground="#FFFFFF",
                             font=FONT_MONO)
        self.menu.add_command(label="Open containing folder", command=self._act_reveal)
        self.menu.add_command(label="Rename here", command=self._act_rename)
        self.menu.add_command(label="Copy / backup to... (bulk-aware)", command=self._act_copy_to)
        self.menu.add_command(label="Replace with... (verified)", command=self._act_replace)
        self.menu.add_separator()
        self.menu.add_command(label="Delete... (bulk-aware)", command=self._act_delete)
        self.menu.add_separator()
        self.menu.add_command(label="Copy full path", command=self._act_copy_path)

        # Log panel
        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.pack(side="top", fill="x")
        log_header = ttk.Frame(bottom)
        log_header.pack(side="top", fill="x")
        ttk.Label(log_header, text="Operation log", style="Header.TLabel").pack(side="left")
        ttk.Button(log_header, text="Clear Log", command=self._act_clear_log).pack(side="right")
        self.log_box = tk.Text(bottom, height=7, bg=PANEL, fg=FG_DIM, font=FONT_MONO_SM,
                                borderwidth=0, wrap="none", state="disabled")
        self.log_box.pack(side="top", fill="x", pady=(2, 6))

        footer = ttk.Label(
            self.root,
            text="DriveGuard v{} - Apache License 2.0 - "
                 "Tukaram Hankare, Farmer, Coder & Web Developer, Solapur, Maharashtra, India".format(APP_VERSION),
            style="Dim.TLabel",
        )
        footer.pack(side="bottom", pady=6)

    # -------------------------------------------------------- scanning ----
    def browse_source(self):
        chosen = filedialog.askdirectory(title="Select drive, folder, or media device root")
        if chosen:
            self.source_root.set(chosen)

    def start_scan(self):
        root_path = self.source_root.get().strip()
        if not root_path or not os.path.isdir(root_path):
            messagebox.showwarning(APP_NAME, "Choose a valid drive or folder first.")
            return
        if self.worker and self.worker.is_alive():
            return

        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.item_paths.clear()
        self.item_hashes.clear()

        self.cancel_event = threading.Event()
        self.q = queue.Queue()
        self.worker = ScanWorker(root_path, self.q, self.cancel_event)

        self._scan_results = []  # list of file result dicts, filled as we go
        self.scan_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.progress.start(12)
        self.status_text.set("Scanning...")
        self.worker.start()
        self.root.after(100, self._poll_queue)

    def cancel_scan(self):
        if self.worker and self.worker.is_alive():
            self.cancel_event.set()
            self.status_text.set("Cancelling...")

    def _poll_queue(self):
        while True:
            kind, payload = self._safe_get()
            if kind is None:
                break
            self._handle_message(kind, payload)

        if (self.worker and self.worker.is_alive()) or not self.q.empty():
            self.root.after(100, self._poll_queue)

    def _safe_get(self):
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None, None

    def _handle_message(self, kind, payload):
        if kind is None:
            return
        if kind == "progress":
            count, path = payload
            self.status_text.set("Scanning ({} files)... {}".format(count, os.path.basename(path)))
        elif kind == "file":
            self._scan_results.append(payload)
        elif kind == "done":
            self.progress.stop()
            self.scan_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self._finish_scan(payload)
        elif kind == "cancelled":
            self.progress.stop()
            self.scan_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.status_text.set("Scan cancelled.")
        elif kind == "error":
            self.progress.stop()
            self.scan_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            self.status_text.set("Scan failed: {}".format(payload))
            messagebox.showerror(APP_NAME, "Scan failed:\n{}".format(payload))

    def _finish_scan(self, done_payload):
        results = self._scan_results
        by_hash = {}
        flagged = []
        bitrot = []

        for r in results:
            if r["hash"]:
                by_hash.setdefault(r["hash"], []).append(r)
            if r["error"] or r["mismatch"]:
                flagged.append(r)
            if r["bitrot"]:
                bitrot.append(r)

        duplicates = {h: rows for h, rows in by_hash.items() if len(rows) > 1}

        dup_group = self.tree.insert("", "end", text="Duplicates ({} groups)".format(len(duplicates)),
                                      tags=("group",), open=True)
        for h, rows in duplicates.items():
            g = self.tree.insert(dup_group, "end",
                                  text="{} identical copies".format(len(rows)),
                                  values=("", h[:16] + "...", ""), tags=("group",), open=False)
            for r in rows:
                iid = self.tree.insert(g, "end", text=r["path"],
                                        values=(human_size(r["size"]), r["hash"][:16] + "...", "duplicate"),
                                        tags=("dup",))
                self.item_paths[iid] = r["path"]
                self.item_hashes[iid] = r["hash"]

        bad_group = self.tree.insert("", "end",
                                      text="Corrupted / Unreadable / Mislabeled ({})".format(len(flagged)),
                                      tags=("group",), open=True)
        for r in flagged:
            reason = r["error"] or r["mismatch"]
            iid = self.tree.insert(bad_group, "end", text=r["path"],
                                    values=(human_size(r["size"]), (r["hash"] or "")[:16], reason),
                                    tags=("bad",))
            self.item_paths[iid] = r["path"]
            self.item_hashes[iid] = r["hash"]

        rot_group = self.tree.insert("", "end",
                                      text="Changed since last scan ({})".format(len(bitrot)),
                                      tags=("group",), open=len(bitrot) > 0)
        for r in bitrot:
            iid = self.tree.insert(rot_group, "end", text=r["path"],
                                    values=(human_size(r["size"]), r["hash"][:16] + "...",
                                            "hash differs from last recorded scan"),
                                    tags=("bad",))
            self.item_paths[iid] = r["path"]
            self.item_hashes[iid] = r["hash"]

        self.status_text.set(
            "Scan complete: {} files, {} total, {} duplicate groups, {} corrupted/mislabeled, "
            "{} changed since last scan.".format(
                done_payload["count"], human_size(done_payload["total_bytes"]),
                len(duplicates), len(flagged), len(bitrot))
        )
        log_operation("scan", source=self.source_root.get(), file_count=done_payload["count"],
                       duplicate_groups=len(duplicates), flagged=len(flagged), bitrot=len(bitrot))
        self._refresh_log_panel()

    # --------------------------------------------------- context actions --
    def _selected_file_items(self):
        """All currently selected rows that are real files (group headers
        and duplicate-count subgroups are silently excluded)."""
        return [(iid, self.item_paths[iid]) for iid in self.tree.selection() if iid in self.item_paths]

    def _on_selection_change(self, event=None):
        items = self._selected_file_items()
        if not items:
            self.selection_text.set("")
            return
        total = 0
        for _, path in items:
            try:
                total += os.path.getsize(path)
            except OSError:
                pass
        self.selection_text.set("{} file{} selected ({})".format(
            len(items), "" if len(items) == 1 else "s", human_size(total)))

    def _remove_all_rows_for_path(self, path):
        """A file can appear in more than one group (e.g. flagged as both a
        duplicate and changed-since-last-scan) - delete every row for it."""
        for iid in [iid for iid, p in self.item_paths.items() if p == path]:
            if self.tree.exists(iid):
                self.tree.delete(iid)
            self.item_paths.pop(iid, None)
            self.item_hashes.pop(iid, None)

    def _update_all_rows_for_path(self, old_path, new_path, new_hash=None):
        for iid in [iid for iid, p in self.item_paths.items() if p == old_path]:
            self.item_paths[iid] = new_path
            if new_hash:
                self.item_hashes[iid] = new_hash
            if self.tree.exists(iid):
                self.tree.item(iid, text=new_path)
                if new_hash:
                    vals = list(self.tree.item(iid, "values"))
                    if len(vals) >= 2:
                        vals[1] = new_hash[:16] + "..."
                        self.tree.item(iid, values=vals)

    @staticmethod
    def _unique_dest_path(dest_dir, filename):
        """A destination path that won't silently overwrite an unrelated
        file of the same name (common with duplicate-named photos/exports)."""
        candidate = os.path.join(dest_dir, filename)
        if not os.path.exists(candidate):
            return candidate
        stem, ext = os.path.splitext(filename)
        n = 2
        while True:
            candidate = os.path.join(dest_dir, "{} ({}){}".format(stem, n, ext))
            if not os.path.exists(candidate):
                return candidate
            n += 1

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid or iid not in self.item_paths:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.menu.tk_popup(event.x_root, event.y_root)

    def _on_press_start(self, event):
        iid = self.tree.identify_row(event.y)
        self._press_xy = (event.x, event.y)
        if iid and iid in self.item_paths:
            self._press_after_id = self.root.after(
                LONG_PRESS_MS, lambda: self._trigger_long_press(iid, event.x_root, event.y_root))

    def _on_press_move(self, event):
        if self._press_after_id and (abs(event.x - self._press_xy[0]) > 6 or abs(event.y - self._press_xy[1]) > 6):
            self.root.after_cancel(self._press_after_id)
            self._press_after_id = None

    def _on_press_end(self, event):
        if self._press_after_id:
            self.root.after_cancel(self._press_after_id)
            self._press_after_id = None

    def _trigger_long_press(self, iid, x_root, y_root):
        self._press_after_id = None
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        self.menu.tk_popup(x_root, y_root)

    def _act_reveal(self):
        items = self._selected_file_items()
        if not items:
            return
        iid, path = items[0]
        if not os.path.exists(path):
            messagebox.showerror(APP_NAME, "File no longer exists at:\n{}".format(path))
            return
        try:
            reveal_in_file_manager(path)
            log_operation("reveal", path=path)
        except RuntimeError as exc:
            messagebox.showerror(APP_NAME, str(exc))
        self._refresh_log_panel()

    def _act_copy_path(self):
        items = self._selected_file_items()
        if not items:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(path for _, path in items))

    def _act_rename(self):
        items = self._selected_file_items()
        if not items:
            return
        if len(items) > 1:
            messagebox.showinfo(APP_NAME, "Rename works on one file at a time - select just one.")
            return
        iid, path = items[0]
        if not os.path.exists(path):
            messagebox.showerror(APP_NAME, "File not found at its original location.")
            return
        folder, old_name = os.path.split(path)
        new_name = simpledialog.askstring(APP_NAME, "Rename \"{}\" to:".format(old_name),
                                           initialvalue=old_name, parent=self.root)
        if not new_name or new_name == old_name:
            return
        new_path = os.path.join(folder, new_name)
        if os.path.exists(new_path):
            messagebox.showerror(APP_NAME, "A file already exists at:\n{}".format(new_path))
            return
        try:
            os.rename(path, new_path)
            log_operation("rename", old_path=path, new_path=new_path)
            self._update_all_rows_for_path(path, new_path)
            self.status_text.set("Renamed to {}".format(new_name))
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Rename failed:\n{}".format(exc))
        self._refresh_log_panel()

    def _act_copy_to(self):
        items = self._selected_file_items()
        if not items:
            return
        existing = [(iid, p) for iid, p in items if os.path.exists(p)]
        missing = len(items) - len(existing)
        if not existing:
            messagebox.showerror(APP_NAME, "Selected file(s) no longer exist at their original location.")
            return

        dest_dir = filedialog.askdirectory(
            title="Copy / backup {} file{} to...".format(len(existing), "" if len(existing) == 1 else "s"))
        if not dest_dir:
            return

        copied, skipped_identical, mismatched, failed = 0, 0, [], []
        for iid, path in existing:
            filename = os.path.basename(path)
            dest_path = os.path.join(dest_dir, filename)
            try:
                src_hash, _ = sha256_of_file(path)
                if os.path.exists(dest_path):
                    existing_hash, _ = sha256_of_file(dest_path)
                    if existing_hash == src_hash:
                        # Already backed up with identical content - nothing to do.
                        skipped_identical += 1
                        copied += 1
                        continue
                    dest_path = self._unique_dest_path(dest_dir, filename)
                shutil.copy2(path, dest_path)
                dst_hash, _ = sha256_of_file(dest_path)
                ok = (src_hash == dst_hash)
                log_operation("copy_to", src=path, dest=dest_path, verified=ok,
                               src_hash=src_hash, dest_hash=dst_hash)
                if ok:
                    copied += 1
                else:
                    mismatched.append(dest_path)
            except OSError as exc:
                failed.append("{} ({})".format(path, exc.strerror or exc))

        summary = "{} of {} file{} copied and SHA-256 verified to:\n{}".format(
            copied, len(existing), "" if len(existing) == 1 else "s", dest_dir)
        if skipped_identical:
            summary += "\n({} already present with matching hash - skipped re-copy)".format(skipped_identical)
        if missing:
            summary += "\n{} selected file(s) were already gone.".format(missing)
        if mismatched:
            summary += "\n\nHash mismatch (possibly corrupt) on {}:\n".format(len(mismatched)) + "\n".join(mismatched[:10])
        if failed:
            summary += "\n\nFailed:\n" + "\n".join(failed[:10])

        if mismatched or failed:
            messagebox.showwarning(APP_NAME, summary)
        else:
            messagebox.showinfo(APP_NAME, summary)
        self.status_text.set("Copied {}/{} file(s) to {}".format(copied, len(existing), dest_dir))
        self._refresh_log_panel()

    def _act_delete(self):
        """Move selected file(s) to a local quarantine folder rather than
        erasing them outright - a dedup cleanup that silently destroys the
        one good copy defeats its own purpose, so deletes stay recoverable."""
        items = self._selected_file_items()
        if not items:
            return
        existing = [(iid, p) for iid, p in items if os.path.exists(p)]
        missing = len(items) - len(existing)
        if not existing:
            messagebox.showerror(APP_NAME, "Selected file(s) no longer exist at their original location.")
            return

        count = len(existing)
        total_size = 0
        preview_lines = []
        for _, p in existing:
            try:
                total_size += os.path.getsize(p)
            except OSError:
                pass
            if len(preview_lines) < 10:
                preview_lines.append(p)
        preview = "\n".join(preview_lines)
        if count > 10:
            preview += "\n...and {} more".format(count - 10)

        body = (
            "Delete {} file{}?\n\nTotal size: {}\n\n{}\n\n"
            "Deleted files move to DriveGuard's local quarantine folder, not "
            "permanent erasure - recoverable from:\n{}".format(
                count, "" if count == 1 else "s", human_size(total_size), preview, BACKUP_DIR)
        )
        if not messagebox.askyesno(APP_NAME, body):
            return

        deleted, failed = 0, []
        for idx, (iid, path) in enumerate(existing):
            try:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                quarantine_name = "{}_{:04d}__DELETED__{}".format(ts, idx, os.path.basename(path))
                quarantine_path = os.path.join(BACKUP_DIR, quarantine_name)
                shutil.move(path, quarantine_path)
                log_operation("delete", original_path=path, quarantine_path=quarantine_path)
                self._remove_all_rows_for_path(path)
                deleted += 1
            except OSError as exc:
                failed.append("{} ({})".format(path, exc.strerror or exc))

        summary = "{} file{} deleted (moved to quarantine).".format(deleted, "" if deleted == 1 else "s")
        if missing:
            summary += "\n{} selected file(s) were already gone.".format(missing)
        if failed:
            summary += "\n\nFailed:\n" + "\n".join(failed[:10])
            messagebox.showwarning(APP_NAME, summary)
        else:
            messagebox.showinfo(APP_NAME, summary)
        self.status_text.set(summary.splitlines()[0])
        self._on_selection_change()
        self._refresh_log_panel()

    def _act_replace(self):
        """Overwrite the file at its ORIGINAL location with a different
        source file, only after backing up the original and verifying the
        write against the replacement's SHA-256."""
        items = self._selected_file_items()
        if not items:
            return
        if len(items) > 1:
            messagebox.showinfo(APP_NAME, "Replace works on one file at a time - select just one.")
            return
        iid, target_path = items[0]
        if not os.path.exists(target_path):
            messagebox.showerror(APP_NAME, "Target no longer exists at:\n{}".format(target_path))
            return

        replacement_path = filedialog.askopenfilename(
            title="Choose replacement file for:\n{}".format(target_path))
        if not replacement_path:
            return

        confirm = messagebox.askyesno(
            APP_NAME,
            "This will REPLACE the file at its original location:\n\n{}\n\n"
            "with the contents of:\n\n{}\n\n"
            "The current file will be backed up first, and the write will be "
            "verified by SHA-256. Continue?".format(target_path, replacement_path))
        if not confirm:
            return

        try:
            replacement_hash, _ = sha256_of_file(replacement_path)
            old_hash, _ = sha256_of_file(target_path)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            backup_name = "{}__{}".format(ts, os.path.basename(target_path))
            backup_path = os.path.join(BACKUP_DIR, backup_name)
            shutil.copy2(target_path, backup_path)

            shutil.copy2(replacement_path, target_path)
            written_hash, _ = sha256_of_file(target_path)

            if written_hash == replacement_hash:
                log_operation("replace", target=target_path, replacement_source=replacement_path,
                               old_hash=old_hash, new_hash=written_hash, backup_path=backup_path,
                               verified=True)
                self._update_all_rows_for_path(target_path, target_path, new_hash=written_hash)
                messagebox.showinfo(
                    APP_NAME,
                    "Replace verified (SHA-256 match).\nPrevious version backed up to:\n{}".format(backup_path))
            else:
                # Verification failed - restore the original immediately.
                shutil.copy2(backup_path, target_path)
                log_operation("replace_failed_reverted", target=target_path,
                               replacement_source=replacement_path, backup_path=backup_path,
                               expected_hash=replacement_hash, written_hash=written_hash)
                messagebox.showerror(
                    APP_NAME,
                    "Verification FAILED after write - the original file has been "
                    "restored automatically from backup. No data was lost.")
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Replace failed:\n{}".format(exc))
        self._refresh_log_panel()

    # ------------------------------------------------------ export/import -
    def _act_export_hashes(self):
        """Export the last completed scan's SHA-256 records to a portable
        CSV - covers whatever the Scan option was last pointed at (a single
        folder, a whole drive letter, or any directory the user chose)."""
        if not self._scan_results:
            messagebox.showinfo(APP_NAME, "Run a scan first - there's nothing to export yet.")
            return
        default_name = "DriveGuard_SHA256_{}.csv".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
        export_path = filedialog.asksaveasfilename(
            title="Export SHA-256 list", defaultextension=".csv",
            initialfile=default_name, filetypes=[("CSV file", "*.csv"), ("All files", "*.*")])
        if not export_path:
            return
        try:
            with open(export_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["sha256", "size_bytes", "path", "status", "signature_check"])
                for r in self._scan_results:
                    writer.writerow([r["hash"] or "", r["size"], r["path"],
                                      r["error"] or "", r["mismatch"] or ""])
            log_operation("export_hashes", path=export_path, count=len(self._scan_results))
            messagebox.showinfo(APP_NAME, "Exported {} file record(s) to:\n{}".format(
                len(self._scan_results), export_path))
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Export failed:\n{}".format(exc))
        self._refresh_log_panel()

    def _act_import_hashes(self):
        """Import a previously exported SHA-256 CSV and re-check it against
        what's actually on disk now, using the SAME hashing and duplicate-
        grouping logic a normal Scan uses - not a separate detection path."""
        import_path = filedialog.askopenfilename(
            title="Import SHA-256 list (DriveGuard CSV export)",
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")])
        if not import_path:
            return
        try:
            with open(import_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                fieldnames = reader.fieldnames or []
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Could not read import file:\n{}".format(exc))
            return

        if not rows or "sha256" not in fieldnames or "path" not in fieldnames:
            messagebox.showerror(
                APP_NAME,
                "That file doesn't look like a DriveGuard SHA-256 export - "
                "expected at least \"sha256\" and \"path\" columns.")
            return

        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.item_paths.clear()
        self.item_hashes.clear()

        self.status_text.set("Verifying {} imported record(s)...".format(len(rows)))
        self.root.update_idletasks()

        missing, changed, checked = [], [], []
        for row in rows:
            path = (row.get("path") or "").strip()
            imported_hash = (row.get("sha256") or "").strip()
            if not path:
                continue
            if not os.path.exists(path):
                missing.append({"path": path, "hash": imported_hash, "note": "missing since import"})
                continue
            try:
                current_hash, size = sha256_of_file(path)
            except OSError as exc:
                missing.append({"path": path, "hash": imported_hash,
                                 "note": "unreadable now: {}".format(exc.strerror or exc)})
                continue
            entry = {"path": path, "size": size, "hash": current_hash}
            if imported_hash and current_hash != imported_hash:
                entry["note"] = "hash differs from imported record"
                changed.append(entry)
            checked.append(entry)

        by_hash = {}
        for e in checked:
            by_hash.setdefault(e["hash"], []).append(e)
        duplicates = {h: rows_ for h, rows_ in by_hash.items() if len(rows_) > 1}

        self._populate_import_results(duplicates, changed, missing)

        self.status_text.set(
            "Import check complete: {} record(s), {} duplicate groups, {} changed since import, "
            "{} missing since import.".format(len(rows), len(duplicates), len(changed), len(missing)))
        log_operation("import_hashes", path=import_path, record_count=len(rows),
                       duplicate_groups=len(duplicates), changed=len(changed), missing=len(missing))
        self._refresh_log_panel()

    def _populate_import_results(self, duplicates, changed, missing):
        dup_group = self.tree.insert(
            "", "end", text="Duplicates - re-checked from import ({} groups)".format(len(duplicates)),
            tags=("group",), open=True)
        for h, entries in duplicates.items():
            g = self.tree.insert(dup_group, "end", text="{} identical copies".format(len(entries)),
                                  values=("", h[:16] + "...", ""), tags=("group",), open=False)
            for e in entries:
                iid = self.tree.insert(g, "end", text=e["path"],
                                        values=(human_size(e["size"]), e["hash"][:16] + "...", "duplicate"),
                                        tags=("dup",))
                self.item_paths[iid] = e["path"]
                self.item_hashes[iid] = e["hash"]

        changed_group = self.tree.insert(
            "", "end", text="Changed / Corrupted Since Import ({})".format(len(changed)),
            tags=("group",), open=len(changed) > 0)
        for e in changed:
            iid = self.tree.insert(changed_group, "end", text=e["path"],
                                    values=(human_size(e.get("size", 0)), e["hash"][:16] + "...", e["note"]),
                                    tags=("bad",))
            self.item_paths[iid] = e["path"]
            self.item_hashes[iid] = e["hash"]

        missing_group = self.tree.insert(
            "", "end", text="Missing Since Import ({})".format(len(missing)),
            tags=("group",), open=len(missing) > 0)
        for e in missing:
            # Nothing on disk to act on, so these rows are display-only -
            # intentionally left out of item_paths (no right-click actions).
            self.tree.insert(missing_group, "end", text=e["path"],
                              values=("", (e["hash"] or "")[:16], e["note"]), tags=("bad",))

    # -------------------------------------------------------------- log ---
    @staticmethod
    def _format_log_entry(e):
        action = e.get("action", "")
        t = e.get("time", "")
        if action == "scan":
            detail = "{} files scanned in {}".format(e.get("file_count", "?"), e.get("source", ""))
        elif action == "reveal":
            detail = e.get("path", "")
        elif action == "rename":
            detail = "{} -> {}".format(e.get("old_path", ""), e.get("new_path", ""))
        elif action == "copy_to":
            detail = "{} -> {} ({})".format(e.get("src", ""), e.get("dest", ""),
                                             "verified" if e.get("verified") else "HASH MISMATCH")
        elif action == "delete":
            detail = "{} -> quarantine ({})".format(e.get("original_path", ""), e.get("quarantine_path", ""))
        elif action == "replace":
            detail = "{} (previous version backed up to {})".format(e.get("target", ""), e.get("backup_path", ""))
        elif action == "replace_failed_reverted":
            detail = "{} - verification FAILED, reverted from backup".format(e.get("target", ""))
        elif action == "log_cleared":
            detail = "operation log history cleared"
        elif action == "export_hashes":
            detail = "{} record(s) -> {}".format(e.get("count", "?"), e.get("path", ""))
        elif action == "import_hashes":
            detail = "{} record(s) from {} ({} dup groups, {} changed, {} missing)".format(
                e.get("record_count", "?"), e.get("path", ""), e.get("duplicate_groups", 0),
                e.get("changed", 0), e.get("missing", 0))
        else:
            detail = e.get("path") or e.get("target") or e.get("source") or ""
        return "[{}] {}: {}".format(t, action, detail)

    def _refresh_log_panel(self):
        entries = read_recent_log(50)
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        for e in entries[-50:]:
            self.log_box.insert("end", self._format_log_entry(e) + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _act_clear_log(self):
        if not os.path.isfile(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
            messagebox.showinfo(APP_NAME, "Operation log is already empty.")
            return
        confirm = messagebox.askyesno(
            APP_NAME,
            "This permanently deletes DriveGuard's operation log history.\n\n"
            "It does NOT touch any of your real files or backups - only this "
            "app's own record of past scans, renames, copies, deletes, and "
            "replacements.\n\nContinue?")
        if not confirm:
            return
        try:
            open(LOG_PATH, "w", encoding="utf-8").close()
            log_operation("log_cleared")
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Could not clear log:\n{}".format(exc))
            return
        self._refresh_log_panel()
        self.status_text.set("Operation log cleared.")


# --------------------------------------------------------------------------- #
def main():
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = DriveGuardApp(root)  # noqa: F841 - keep reference alive
    root.mainloop()


if __name__ == "__main__":
    main()
