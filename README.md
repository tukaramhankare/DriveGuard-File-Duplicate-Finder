# DriveGuard

A native Windows desktop tool that scans a drive, folder, or removable media
device; verifies every file by SHA-256; visualises duplicates and corrupted
files; and lets you act on any file at its **original location** — reveal,
rename, copy/backup, replace (hash-verified), or delete (to a recoverable
quarantine folder, never a silent permanent erase).

**Repository:** https://github.com/tukaramhankare/DriveGuard-File-Duplicate-Finder
**Look at (download page):** https://tukaramhankare.github.io/DriveGuard-File-Duplicate-Finder/
**Direct download:** https://github.com/tukaramhankare/DriveGuard-File-Duplicate-Finder/raw/refs/heads/main/DriveGuard.exe

---

## Features

- **SHA-256 integrity scan** of a drive, folder, or media device — one pass computes a hash for every file
- **Duplicate detection** — groups files by identical hash
- **Corruption detection**, three independent checks reused across every scan/import:
  - unreadable / empty files
  - content signature vs. extension mismatches (e.g. a `.jpg` that isn't really a JPEG)
  - hash changed since the last scan of that same source (bit-rot, via a saved baseline manifest)
- **Export / Import SHA-256** — export any scan to a portable CSV (`sha256, size_bytes, path, status, signature_check`); import a CSV later to re-verify those exact files against what's currently on disk, using the same hashing and duplicate-grouping logic as a live scan
- **File manager actions**, right-click or long-press, single file or multi-select:
  - **Open containing folder** — jumps straight to the file at its real location
  - **Rename**
  - **Copy / backup to...** — bulk-aware, hash-verifies every copy, auto-resolves filename collisions instead of silently overwriting
  - **Replace with... (verified)** — overwrites a file at its original location only after backing up the current version and verifying the write by SHA-256; reverts automatically on mismatch
  - **Delete** — moves file(s) to a local quarantine folder rather than erasing outright, with a confirmation dialog showing item count and total size
- **Operation log** — every action recorded, with a one-click Clear Log that only touches the log file, never real files
- **Dark and Light/Light-Gray themes**, toggle at runtime

## Requirements

- Windows (uses `explorer /select` for reveal-in-folder and requests admin elevation for drive-level access)
- Python 3.8+ if running from source — **zero external pip dependencies**, standard library only

## Getting started

```bash
git clone https://github.com/tukaramhankare/DriveGuard-File-Duplicate-Finder.git
cd DriveGuard-File-Duplicate-Finder
python DriveGuard.py
```

## Building the .exe

```bash
pip install --upgrade pyinstaller
pyinstaller --onefile --noconsole --clean --hidden-import=tkinter --uac-admin --name DriveGuard DriveGuard.py
```

The finished executable is written to `dist/DriveGuard.exe`. `--uac-admin`
prompts for elevation on launch, needed for scanning locations outside your
own user folders. Unsigned executables commonly trigger a SmartScreen
warning on first run — that's expected for an unsigned build, not a sign
something's wrong.

## Where DriveGuard keeps its own data

Everything DriveGuard writes for itself lives under your user profile, never
mixed in with the files you're scanning:

```
~/.driveguard/
├── backups/      # quarantined deletes + pre-replace backups
├── manifests/    # per-source baseline hashes, for bit-rot detection
└── operations.log.jsonl
```

## Known limitations

- **File-level, not sector-level.** DriveGuard copies and verifies files — it does not create a byte-for-byte disk image (boot sector, partition table, unallocated space). Sector-level imaging is a deliberately separate problem (needs elevated raw device access and a live-volume snapshot step) and isn't built yet.
- **Import matches by path.** Re-verifying an imported CSV assumes the same machine/drive layout it was exported from — if a file moved, it shows as missing rather than being re-located automatically.

## License

Apache License 2.0

## Author

**Tukaram Hankare** — Farmer, Coder & Web Developer, Solapur, Maharashtra, India
[github.com/tukaramhankare](https://github.com/tukaramhankare)
