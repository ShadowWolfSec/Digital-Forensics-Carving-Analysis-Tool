from __future__ import annotations

import sys
from pathlib import Path


def is_physical_drive(path: str) -> bool:
    if path.startswith("/dev/"):
        return True
    clean_path = path.replace("/", "\\") if sys.platform == "win32" else path
    return (
        clean_path.startswith("\\\\.\\")
        or clean_path.startswith("//./")
        or clean_path.startswith("/dev/")
    )


def is_disk_image_extension(ext: str) -> bool:
    ext = ext.lower()
    # 1. Split raw segments (.001, .002, etc.)
    if len(ext) == 4 and ext[1:].isdigit():
        return True
    # 2. Standard image extensions
    return ext in (".dd", ".raw", ".img", ".bin", ".iso", ".vhd", ".vhdx", ".vmdk", ".dmg")


def detect_source_type(path: str) -> str:
  
    if is_physical_drive(path):
        return "physical_drive"

    p = Path(path)
    if p.is_dir():
        return "directory"

    if not p.is_file():
        return "file"

    ext = p.suffix.lower()

    if len(ext) == 4 and ext[1:].isdigit():
        return "disk_image"

    if is_disk_image_extension(ext):
        return "disk_image"

    if ext in (".e01", ".ex01"):
        try:
            import pyewf  
            return "e01"
        except ImportError:
            return "disk_image"

    # 4. Check AFF
    if ext in (".aff", ".afd", ".afm", ".aff4"):
        try:
            from pyaff4 import container  
            return "aff"
        except ImportError:
            return "disk_image"

    try:
        with open(path, "rb") as f:
            head = f.read(1024)

        if head.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
            try:
                import pyewf  
                return "e01"
            except ImportError:
                return "disk_image"

        if head.startswith(b"aff4") or head.startswith(b"AFF"):
            return "aff"

        if len(head) >= 512 and head[510:512] == b"\x55\xaa":
            return "disk_image"

        if len(head) >= 11 and head[3:11] in (b"MSDOS5.0", b"MSWIN4.1", b"NTFS    ", b"EXFAT   "):
            return "disk_image"

        if b"EFI PART" in head[:520]:
            return "disk_image"

    except Exception:
        pass

    return "file"
