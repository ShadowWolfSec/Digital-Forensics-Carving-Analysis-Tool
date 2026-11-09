from __future__ import annotations

import ctypes
import os
import string
import sys
from typing import Any, Dict, List


def get_system_drives() -> List[Dict[str, Any]]:
    drives: List[Dict[str, Any]] = []

    if sys.platform == "win32":
        kernel32 = ctypes.windll.kernel32
        for i in range(16):
            drive_path = f"\\\\.\\PhysicalDrive{i}"
            handle = kernel32.CreateFileW(
                drive_path,
                0x80000000,  
                0x00000001 | 0x00000002,  
                None,
                3,  
                0,
                None,
            )
            if handle not in (-1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
                kernel32.CloseHandle(handle)
                drives.append({
                    "id": drive_path,
                    "kind": "physical_drive",
                    "display": f"Physical Disk {i} ({drive_path})",
                    "accessible": True,
                    "size_gb": None,
                })
            else:
                err = kernel32.GetLastError()
                if err == 5:
                    drives.append({
                        "id": drive_path,
                        "kind": "physical_drive",
                        "display": f"Physical Disk {i} ({drive_path}) [Requires Administrator]",
                        "accessible": False,
                        "size_gb": None,
                    })
                elif i < 2:
                    drives.append({
                        "id": drive_path,
                        "kind": "physical_drive",
                        "display": f"Physical Disk {i} ({drive_path})",
                        "accessible": False,
                        "size_gb": None,
                    })

        try:
            bitmask = kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    dl = f"{letter}:"
                    vol_name = ctypes.create_unicode_buffer(261)
                    fs_name = ctypes.create_unicode_buffer(261)
                    serial = ctypes.c_ulong()
                    max_comp = ctypes.c_ulong()
                    flags = ctypes.c_ulong()
                    kernel32.GetVolumeInformationW(
                        f"{dl}\\",
                        vol_name,
                        260,
                        ctypes.byref(serial),
                        ctypes.byref(max_comp),
                        ctypes.byref(flags),
                        fs_name,
                        260,
                    )
                    free_bytes = ctypes.c_ulonglong()
                    total_bytes = ctypes.c_ulonglong()
                    total_free = ctypes.c_ulonglong()
                    kernel32.GetDiskFreeSpaceExW(
                        f"{dl}\\",
                        ctypes.byref(free_bytes),
                        ctypes.byref(total_bytes),
                        ctypes.byref(total_free),
                    )
                    size_gb = round(total_bytes.value / (1024**3), 2) if total_bytes.value else 0
                    label = vol_name.value or "Local Disk"
                    fs = fs_name.value or "Unknown"
                    drives.append({
                        "id": f"\\\\.\\{dl}",
                        "kind": "logical_volume",
                        "display": f"Volume {dl} [{label}] - {fs} ({size_gb} GB)",
                        "letter": dl,
                        "size_gb": size_gb,
                        "accessible": True,
                    })
                bitmask >>= 1
        except Exception:
            pass

    elif sys.platform.startswith("linux"):
        # Linux Physical Block Devices
        for letter in ["a", "b", "c", "d", "e", "f"]:
            dev = f"/dev/sd{letter}"
            if os.path.exists(dev):
                drives.append({
                    "id": dev,
                    "kind": "physical_drive",
                    "display": f"Disk {dev}",
                    "accessible": os.access(dev, os.R_OK),
                    "size_gb": None,
                })
        for i in range(8):
            dev = f"/dev/nvme0n{i}"
            if os.path.exists(dev):
                drives.append({
                    "id": dev,
                    "kind": "physical_drive",
                    "display": f"NVMe Disk {dev}",
                    "accessible": os.access(dev, os.R_OK),
                    "size_gb": None,
                })
        for i in range(8):
            dev = f"/dev/loop{i}"
            if os.path.exists(dev):
                drives.append({
                    "id": dev,
                    "kind": "logical_volume",
                    "display": f"Loop Device {dev}",
                    "accessible": os.access(dev, os.R_OK),
                    "size_gb": None,
                })

    elif sys.platform == "darwin":
        # macOS
        for i in range(5):
            dev = f"/dev/rdisk{i}"
            if os.path.exists(dev):
                drives.append({
                    "id": dev,
                    "kind": "physical_drive",
                    "display": f"Raw Disk {dev}",
                    "accessible": os.access(dev, os.R_OK),
                    "size_gb": None,
                })

    return drives
