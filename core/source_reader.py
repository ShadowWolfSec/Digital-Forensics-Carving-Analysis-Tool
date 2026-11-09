from __future__ import annotations

import sys
import os
import logging
from typing import Optional

from .models import HashBundle, calculate_hashes_from_stream

logger = logging.getLogger(__name__)


class SourceReader:

    def __init__(self, path: str):
        self.path = path
        self._file = None
        self.size: int = 0

    def open(self):
        # On Windows, physical drives need special open flags
        clean_path = self.path.replace("/", "\\")
        if sys.platform == "win32" and clean_path.startswith("\\\\.\\"):
            import ctypes
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x1
            FILE_SHARE_WRITE = 0x2
            OPEN_EXISTING = 3
            handle = ctypes.windll.kernel32.CreateFileW(
                clean_path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            if handle in (-1, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF):
                raise PermissionError(f"Cannot open physical drive '{self.path}' — Administrator privileges required.")

            length_bytes = ctypes.c_int64()
            bytes_returned = ctypes.c_ulong()
            IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
            if ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0,
                ctypes.byref(length_bytes), ctypes.sizeof(length_bytes),
                ctypes.byref(bytes_returned), None
            ):
                self.size = int(length_bytes.value)
            else:
                self.size = 0

            ctypes.windll.kernel32.CloseHandle(handle)
            self._file = open(clean_path, "rb")
        else:
            self._file = open(self.path, "rb")
            try:
                self._file.seek(0, 2)
                self.size = self._file.tell()
                self._file.seek(0)
            except OSError:
                self.size = 0

    def read_at(self, offset: int, length: int) -> bytes:
        try:
            self._file.seek(offset)
            return self._file.read(length)
        except OSError:
            return b""

    def close(self):
        if self._file:
            self._file.close()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    def hash_source(self, max_bytes: int = 50 * 1024 * 1024) -> Optional[HashBundle]:
        self._file.seek(0)
        return calculate_hashes_from_stream(self._file.read, max_bytes)
