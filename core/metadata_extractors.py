from __future__ import annotations

import logging
import struct
from typing import Any, Dict

logger = logging.getLogger(__name__)


def extract_basic_metadata(data: bytes, validator: str) -> Dict[str, Any]:
   
    meta: Dict[str, Any] = {}
    if not data or not validator:
        return meta

    try:
        if validator == "validate_png":
            if len(data) >= 24:
                w = struct.unpack_from(">I", data, 16)[0]
                h = struct.unpack_from(">I", data, 20)[0]
                meta["width"] = w
                meta["height"] = h
                meta["dimensions"] = f"{w}x{h}"

        elif validator == "validate_jpeg":
            i = 2
            while i + 8 < min(len(data), 65536):
                if data[i] != 0xFF:
                    break
                marker = data[i + 1]
                length = struct.unpack_from(">H", data, i + 2)[0]
                if length < 2:
                    break
                if marker in (0xC0, 0xC1, 0xC2):
                    h = struct.unpack_from(">H", data, i + 5)[0]
                    w = struct.unpack_from(">H", data, i + 7)[0]
                    meta["width"] = w
                    meta["height"] = h
                    meta["dimensions"] = f"{w}x{h}"
                    break
                i += 2 + length

        elif validator == "validate_bmp":
            if len(data) >= 26:
                meta["width"] = struct.unpack_from("<I", data, 18)[0]
                meta["height"] = struct.unpack_from("<I", data, 22)[0]

        elif validator == "validate_pe":
            if len(data) >= 64:
                pe_off = struct.unpack_from("<I", data, 60)[0]
                if pe_off + 6 <= len(data) and data[pe_off : pe_off + 4] == b"PE\x00\x00":
                    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
                    meta["machine"] = f"0x{machine:04X}"
                    meta["arch"] = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(machine, "unknown")

        elif validator == "validate_pdf":
            ver_end = data.find(b"\n", 5)
            if ver_end > 0:
                meta["pdf_version"] = data[5:ver_end].decode("ascii", errors="replace").strip()

    except Exception as e:
        logger.debug(f"Basic metadata extraction failed: {e}")

    return meta


def extract_file_metadata(data: bytes, sig: Any) -> Dict[str, Any]:

    validator = getattr(sig, "validator", "")
    category = getattr(sig, "category", "")
    signature_id = getattr(sig, "id", "")

    meta = extract_basic_metadata(data, validator)
    meta.update(
        extract_advanced_metadata(
            data[: min(len(data), 2 * 1024 * 1024)],
            category=category,
            signature_id=signature_id,
        )
    )
    return meta


def extract_advanced_metadata(data: bytes, category: str = "", signature_id: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not data:
        return out

    if category == "image" or signature_id in ("jpeg", "png", "tiff_le", "tiff_be", "webp"):
        out.update(_extract_exif(data))
        out.update(_extract_iptc(data))
        out.update(_extract_xmp(data))
    elif signature_id == "pdf":
        out.update(_extract_pdf_meta(data))
    return out


def _extract_exif(data: bytes) -> Dict[str, Any]:
    try:
        from PIL import Image  
        from PIL.ExifTags import TAGS, GPSTAGS  
        import io

        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
        if not exif:
            return {}
        parsed: Dict[str, Any] = {}
        gps_parsed: Dict[str, Any] = {}
        for tag_id, value in exif.items():
            key = TAGS.get(tag_id, str(tag_id))
            if key == "GPSInfo" and isinstance(value, dict):
                for gk, gv in value.items():
                    gps_parsed[GPSTAGS.get(gk, str(gk))] = _to_jsonable(gv)
            else:
                parsed[key] = _to_jsonable(value)
        out = {"exif": parsed}
        if gps_parsed:
            out["gps"] = gps_parsed
        return out
    except ImportError:
        logger.debug("PIL not available, skipping EXIF extraction")
        return {}
    except Exception as e:
        logger.debug(f"EXIF extraction failed: {e}")
        return {}


def _extract_iptc(data: bytes) -> Dict[str, Any]:
    if len(data) < 64 or b"\x1c\x02" not in data:
        return {}
    try:
        from iptcinfo3 import IPTCInfo  # type: ignore
        import tempfile
        from pathlib import Path

        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
            tmp.write(data)
            p = tmp.name
        try:
            info = IPTCInfo(p, force=True)
            if not info:
                return {}
            parsed = {}
            for k in info._data.keys():  
                v = info[k]
                if v:
                    parsed[str(k)] = _to_jsonable(v)
            return {"iptc": parsed} if parsed else {}
        finally:
            Path(p).unlink(missing_ok=True)
    except ImportError:
        logger.debug("iptcinfo3 not available, skipping IPTC extraction")
        return {}
    except Exception as e:
        logger.debug(f"IPTC extraction failed: {e}")
        return {}


def _extract_xmp(data: bytes) -> Dict[str, Any]:
    start = data.find(b"<x:xmpmeta")
    if start == -1:
        start = data.find(b"<rdf:RDF")
    if start == -1:
        return {}
    end = data.find(b"</x:xmpmeta>", start)
    if end != -1:
        end += len(b"</x:xmpmeta>")
    else:
        end = data.find(b"</rdf:RDF>", start)
        if end != -1:
            end += len(b"</rdf:RDF>")
    if end == -1 or end <= start:
        return {}
    try:
        snippet = data[start:end].decode("utf-8", errors="replace")
        return {"xmp_raw": snippet[:5000]}
    except Exception as e:
        logger.debug(f"XMP extraction failed: {e}")
        return {}


def _extract_pdf_meta(data: bytes) -> Dict[str, Any]:
    try:
        text = data[:200000].decode("latin-1", errors="ignore")
        out = {}
        for key in ("/Author", "/Creator", "/Producer", "/Title", "/CreationDate", "/ModDate"):
            idx = text.find(key)
            if idx != -1:
                seg = text[idx: idx + 200]
                out[key.strip("/").lower()] = seg.split("\n", 1)[0][:120]
        return {"pdf_meta": out} if out else {}
    except Exception as e:
        logger.debug(f"PDF metadata extraction failed: {e}")
        return {}


def _to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (int, float, str, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        try:
            if value.denominator == 0:
                return 0
            if value.denominator == 1:
                return int(value.numerator)
            return float(value)
        except Exception:
            return str(value)
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if hasattr(value, "items"):
        try:
            return {str(k): _to_jsonable(v) for k, v in value.items()}
        except Exception:
            pass
    try:
        return float(value)
    except Exception:
        return str(value)

