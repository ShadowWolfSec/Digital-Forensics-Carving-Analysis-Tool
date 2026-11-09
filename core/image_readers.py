from __future__ import annotations

import hashlib
import logging
from typing import Optional

from .models import HashBundle, calculate_hashes_from_stream

logger = logging.getLogger(__name__)


class BaseImageReader:
    def __init__(self, path: str):
        self.path = path
        self.size: int = 0

    def open(self):
        raise NotImplementedError

    def read_at(self, offset: int, length: int) -> bytes:
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def hash_source(self, max_bytes: int = 50 * 1024 * 1024):
        pos = [0]  # Use list to allow modification in closure
        
        def read_fn(length: int) -> bytes:
            chunk = self.read_at(pos[0], length)
            pos[0] += len(chunk)
            return chunk
        
        result = calculate_hashes_from_stream(read_fn, max_bytes)
        if result is None:
            logger.warning(f"Failed to hash source {self.path}")
        return result

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()


class RawReader(BaseImageReader):
    def __init__(self, path: str):
        super().__init__(path)
        self._file = None

    def open(self):
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


class E01Reader(BaseImageReader):
    def __init__(self, path: str):
        super().__init__(path)
        self._handle = None
        self._err: Optional[str] = None

    @property
    def error(self) -> Optional[str]:
        return self._err

    def open(self):
        try:
            import pyewf  # type: ignore
        except ImportError as e:
            self._err = f"pyewf is not installed: {e}"
            logger.warning(f"E01 reader not available: {e}")
            raise RuntimeError(self._err)
        except Exception as e:
            self._err = f"Failed to import pyewf: {e}"
            logger.error(f"Unexpected error importing pyewf: {e}")
            raise RuntimeError(self._err)

        self._handle = pyewf.handle()
        self._handle.open([self.path])
        self.size = int(self._handle.get_media_size())
        logger.debug(f"E01 image opened: {self.path}, size={self.size}")

    def read_at(self, offset: int, length: int) -> bytes:
        try:
            self._handle.seek(offset)
            return self._handle.read(length)
        except Exception as e:
            logger.debug(f"E01 read error at offset {offset}: {e}")
            return b""

    def close(self):
        if self._handle:
            try:
                self._handle.close()
            except Exception:
                pass


class AFFReader(BaseImageReader):
    def __init__(self, path: str):
        super().__init__(path)
        self._img = None
        self._err: Optional[str] = None

    @property
    def error(self) -> Optional[str]:
        return self._err

    def open(self):
        try:
            from pyaff4 import container  # type: ignore
        except ImportError as e:
            self._err = f"pyaff4 is not installed: {e}"
            logger.warning(f"AFF reader not available: {e}")
            raise RuntimeError(self._err)
        except Exception as e:
            self._err = f"Failed to import pyaff4: {e}"
            logger.error(f"Unexpected error importing pyaff4: {e}")
            raise RuntimeError(self._err)

        self._img = container.Container.open(self.path)
        self.size = int(getattr(self._img, "size", 0))
        logger.debug(f"AFF image opened: {self.path}, size={self.size}")

    def read_at(self, offset: int, length: int) -> bytes:
        try:
            if hasattr(self._img, "seek"):
                self._img.seek(offset)
                return self._img.read(length)
            if hasattr(self._img, "read"):
                return self._img.read(offset, length)
        except Exception as e:
            logger.debug(f"AFF read error at offset {offset}: {e}")
            return b""
        return b""

    def close(self):
        if self._img and hasattr(self._img, "close"):
            try:
                self._img.close()
            except Exception:
                pass


def reader_for_source(path: str, source_type: str):
    from .source_reader import SourceReader

    if source_type == "e01":
        try:
            import pyewf  
            with open(path, "rb") as test_f:
                head = test_f.read(8)
            if head.startswith(b"EVF"):
                return E01Reader(path)
            else:
                logger.info(f"Target '{path}' does not have EVF header. Using SourceReader (Raw disk reader).")
        except Exception as e:
            logger.warning(f"E01 reader not available or not applicable ({e}). Falling back to SourceReader for {path}")
        return SourceReader(path)

    if source_type == "aff":
        try:
            from pyaff4 import container  
            return AFFReader(path)
        except Exception as e:
            logger.warning(f"AFF reader not available ({e}). Falling back to SourceReader for {path}")
        return SourceReader(path)

    return SourceReader(path)

