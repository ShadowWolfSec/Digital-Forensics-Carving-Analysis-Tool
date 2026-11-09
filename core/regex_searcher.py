from __future__ import annotations

import re
import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .source_reader import SourceReader

logger = logging.getLogger("core.regex_searcher")


@dataclass(slots=True)
class PatternMatch:
    id: int
    category: str            
    label: str                
    value: str              
    masked_value: str          
    offset: int               
    offset_hex: str            
    source_file: str          
    context_text: str         
    context_hex: str          
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "label": self.label,
            "value": self.value,
            "masked_value": self.masked_value,
            "offset": self.offset,
            "offset_hex": self.offset_hex,
            "source_file": self.source_file,
            "context_text": self.context_text,
            "context_hex": self.context_hex,
            "metadata": self.metadata,
        }




def luhn_checksum(card_number: str) -> bool:
    """Validate numeric string using Luhn (Mod 10) algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def identify_card_brand(digits: str) -> str:
    """Identify card network brand from leading IIN/BIN digits."""
    if digits.startswith("4") and len(digits) in (13, 16, 19):
        return "Visa"
    if (len(digits) == 16 and (
        51 <= int(digits[:2]) <= 55 or
        2221 <= int(digits[:4]) <= 2720
    )):
        return "MasterCard"
    if len(digits) == 15 and digits[:2] in ("34", "37"):
        return "American Express"
    if len(digits) == 16 and (
        digits.startswith("6011") or
        digits.startswith("65") or
        644 <= int(digits[:3]) <= 649 or
        622126 <= int(digits[:6]) <= 622925
    ):
        return "Discover"
    if len(digits) == 14 and (digits[:2] in ("36", "38") or 300 <= int(digits[:3]) <= 305):
        return "Diners Club"
    if len(digits) == 16 and 3528 <= int(digits[:4]) <= 3589:
        return "JCB"
    return "Credit Card"


def mask_card_number(val: str) -> str:
    """Mask middle digits of a card number for safe reporting."""
    digits = [c for c in val if c.isdigit()]
    if len(digits) < 10:
        return val
    # Keep first 4 and last 4
    masked_digits = digits[:4] + ["*"] * (len(digits) - 8) + digits[-4:]
    # Reconstruct with original spacing/hyphens if present
    res = []
    d_idx = 0
    for char in val:
        if char.isdigit():
            res.append(masked_digits[d_idx])
            d_idx += 1
        else:
            res.append(char)
    return "".join(res)


RE_CREDIT_CARD = re.compile(
    rb"(?:\b|\D)"
    rb"((?:4[0-9]{3}|5[1-5][0-9]{2}|6(?:011|5[0-9]{2})|3[47][0-9]{2})"
    rb"(?:[ -]?[0-9]{4}){2}(?:[ -]?[0-9]{1,4})?)"
    rb"(?:\b|\D)"
)

RE_EMAIL = re.compile(
    rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

RE_IPV4 = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

RE_CRYPTO_BTC = re.compile(
    rb"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b"
)

RE_CRYPTO_ETH = re.compile(
    rb"\b0x[a-fA-F0-9]{40}\b"
)

RE_PHONE = re.compile(
    rb"(?:\b|\s)(?:\+?[1-9]\d{0,2}[-.\s]?)?"
    rb"(?:\(?\d{2,4}\)?[-.\s]?)?"
    rb"\d{3,4}[-.\s]?\d{3,4}\b"
)




def _make_context_text(chunk: bytes, start_idx: int, end_idx: int) -> str:
    ctx_start = max(0, start_idx - 32)
    ctx_end = min(len(chunk), end_idx + 32)
    sub = chunk[ctx_start:ctx_end]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in sub)


def _make_context_hex(chunk: bytes, start_idx: int, end_idx: int, abs_offset: int) -> str:
    ctx_start = max(0, start_idx - 16)
    ctx_end = min(len(chunk), end_idx + 16)
    sub = chunk[ctx_start:ctx_end]
    start_addr = abs_offset - (start_idx - ctx_start)
    rows = []
    for i in range(0, len(sub), 16):
        c = sub[i:i+16]
        h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        rows.append(f"{start_addr + i:08X}  {h:<48}  |{a}|")
    return "\n".join(rows)



class RegexRawSearcher:
  

    def __init__(self, chunk_size: int = 1024 * 1024, overlap: int = 256):
        self.chunk_size = chunk_size
        self.overlap = overlap

    def search(
        self,
        source_path: str,
        enabled_patterns: Optional[List[str]] = None,
        custom_regex: str = "",
        max_bytes: Optional[int] = None,
        start_offset: int = 0,
        progress_cb: Optional[Callable[[int, int, int], None]] = None,
        stop_flag: Optional[List[bool]] = None,
    ) -> List[PatternMatch]:
     
        if enabled_patterns is None:
            enabled_patterns = ["credit_card", "email", "ipv4", "crypto", "phone"]

        enabled_set = set(enabled_patterns)
        custom_compiled = None
        if custom_regex:
            try:
                custom_compiled = re.compile(custom_regex.encode("utf-8", errors="replace"), re.IGNORECASE)
            except Exception as e:
                logger.warning(f"Invalid custom regex pattern '{custom_regex}': {e}")

        stop = stop_flag or [False]
        cb = progress_cb or (lambda *_: None)

        from .image_readers import reader_for_source
        clean_path = source_path.replace("/", "\\")
        is_device = clean_path.startswith("\\\\.\\")
        ext = Path(clean_path).suffix.lower() if not is_device else ""
        stype = "e01" if ext in (".e01", ".ex01") else ("aff" if ext in (".aff", ".afd", ".afm") else "file")
        reader = reader_for_source(source_path, stype)

        matches: List[PatternMatch] = []
        seen_offsets: Set[Tuple[str, int]] = set()  # (category, abs_offset) deduplication
        match_counter = 0

        with reader:
            total_size = reader.size if reader.size and reader.size > 0 else 0
            if max_bytes and max_bytes > 0:
                scan_total = min(max_bytes, total_size - start_offset) if total_size > start_offset else max_bytes
            else:
                scan_total = max(0, total_size - start_offset)

            curr_offset = start_offset
            bytes_scanned = 0

            while True:
                if stop[0]:
                    break

                read_len = self.chunk_size
                if max_bytes and (bytes_scanned + read_len > max_bytes):
                    read_len = max_bytes - bytes_scanned
                if read_len <= 0:
                    break

                # Read chunk with extra overlap from next block if possible
                chunk = reader.read_at(curr_offset, read_len + self.overlap)
                if not chunk:
                    break

                actual_chunk_len = min(len(chunk), read_len)

                if "credit_card" in enabled_set:
                    for m in RE_CREDIT_CARD.finditer(chunk):
                        raw_val = m.group(1)
                        clean_digits = "".join(chr(b) for b in raw_val if 48 <= b <= 57)
                        if 13 <= len(clean_digits) <= 19 and luhn_checksum(clean_digits):
                            val_str = raw_val.decode("ascii", errors="replace").strip()
                            rel_idx = m.start(1)
                            abs_off = curr_offset + rel_idx

                            # Avoid duplicate hits that fall in overlap
                            if ( "credit_card", abs_off ) not in seen_offsets:
                                seen_offsets.add(("credit_card", abs_off))
                                brand = identify_card_brand(clean_digits)
                                match_counter += 1
                                matches.append(
                                    PatternMatch(
                                        id=match_counter,
                                        category="credit_card",
                                        label=brand,
                                        value=val_str,
                                        masked_value=mask_card_number(val_str),
                                        offset=abs_off,
                                        offset_hex=f"0x{abs_off:08X}",
                                        source_file=source_path,
                                        context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                        context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                        metadata={"brand": brand, "luhn_valid": True},
                                    )
                                )

                if "email" in enabled_set:
                    for m in RE_EMAIL.finditer(chunk):
                        raw_val = m.group(0)
                        val_str = raw_val.decode("ascii", errors="replace").strip()
                        if len(val_str) > 6 and "." in val_str.split("@")[-1]:
                            domain_part = val_str.split("@")[-1]
                            tld = domain_part.split(".")[-1].lower()
                            if len(tld) >= 2 and tld.isalpha() and tld not in ("png", "jpg", "gif", "exe", "dll", "bin", "dat"):
                                rel_idx = m.start(0)
                                abs_off = curr_offset + rel_idx
                                if ("email", abs_off) not in seen_offsets:
                                    seen_offsets.add(("email", abs_off))
                                    match_counter += 1
                                    matches.append(
                                        PatternMatch(
                                            id=match_counter,
                                            category="email",
                                            label="Email Address",
                                            value=val_str,
                                            masked_value=val_str,
                                            offset=abs_off,
                                            offset_hex=f"0x{abs_off:08X}",
                                            source_file=source_path,
                                            context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                            context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                            metadata={"domain": domain_part},
                                        )
                                    )

                if "ipv4" in enabled_set:
                    for m in RE_IPV4.finditer(chunk):
                        raw_val = m.group(0)
                        val_str = raw_val.decode("ascii", errors="replace").strip()
                        if val_str not in ("0.0.0.0", "255.255.255.255", "1.0.0.0", "1.1.1.1"):
                            try:
                                ip_obj = ipaddress.IPv4Address(val_str)
                                rel_idx = m.start(0)
                                abs_off = curr_offset + rel_idx
                                if ("ipv4", abs_off) not in seen_offsets:
                                    seen_offsets.add(("ipv4", abs_off))
                                    match_counter += 1
                                    matches.append(
                                        PatternMatch(
                                            id=match_counter,
                                            category="ipv4",
                                            label="IPv4 Address",
                                            value=val_str,
                                            masked_value=val_str,
                                            offset=abs_off,
                                            offset_hex=f"0x{abs_off:08X}",
                                            source_file=source_path,
                                            context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                            context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                            metadata={"is_private": ip_obj.is_private},
                                        )
                                    )
                            except Exception:
                                pass

                if "crypto" in enabled_set:
                    # Bitcoin
                    for m in RE_CRYPTO_BTC.finditer(chunk):
                        raw_val = m.group(0)
                        val_str = raw_val.decode("ascii", errors="replace").strip()
                        rel_idx = m.start(0)
                        abs_off = curr_offset + rel_idx
                        if ("crypto", abs_off) not in seen_offsets:
                            seen_offsets.add(("crypto", abs_off))
                            match_counter += 1
                            matches.append(
                                PatternMatch(
                                    id=match_counter,
                                    category="crypto",
                                    label="Bitcoin Address",
                                    value=val_str,
                                    masked_value=val_str,
                                    offset=abs_off,
                                    offset_hex=f"0x{abs_off:08X}",
                                    source_file=source_path,
                                    context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                    context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                    metadata={"crypto_type": "Bitcoin"},
                                )
                            )

                    for m in RE_CRYPTO_ETH.finditer(chunk):
                        raw_val = m.group(0)
                        val_str = raw_val.decode("ascii", errors="replace").strip()
                        rel_idx = m.start(0)
                        abs_off = curr_offset + rel_idx
                        if ("crypto", abs_off) not in seen_offsets:
                            seen_offsets.add(("crypto", abs_off))
                            match_counter += 1
                            matches.append(
                                PatternMatch(
                                    id=match_counter,
                                    category="crypto",
                                    label="Ethereum Address",
                                    value=val_str,
                                    masked_value=val_str,
                                    offset=abs_off,
                                    offset_hex=f"0x{abs_off:08X}",
                                    source_file=source_path,
                                    context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                    context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                    metadata={"crypto_type": "Ethereum"},
                                )
                            )

                if "phone" in enabled_set:
                    for m in RE_PHONE.finditer(chunk):
                        raw_val = m.group(0).strip()
                        digits_only = "".join(chr(b) for b in raw_val if 48 <= b <= 57)
                        if 7 <= len(digits_only) <= 15:
                            val_str = raw_val.decode("ascii", errors="replace").strip()
                            rel_idx = m.start(0)
                            abs_off = curr_offset + rel_idx
                            if ("phone", abs_off) not in seen_offsets:
                                seen_offsets.add(("phone", abs_off))
                                match_counter += 1
                                matches.append(
                                    PatternMatch(
                                        id=match_counter,
                                        category="phone",
                                        label="Phone Number",
                                        value=val_str,
                                        masked_value=val_str,
                                        offset=abs_off,
                                        offset_hex=f"0x{abs_off:08X}",
                                        source_file=source_path,
                                        context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                        context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                        metadata={"digits": digits_only},
                                    )
                                )

                if custom_compiled:
                    for m in custom_compiled.finditer(chunk):
                        raw_val = m.group(0)
                        val_str = raw_val.decode("utf-8", errors="replace").strip()
                        rel_idx = m.start(0)
                        abs_off = curr_offset + rel_idx
                        if ("custom", abs_off) not in seen_offsets:
                            seen_offsets.add(("custom", abs_off))
                            match_counter += 1
                            matches.append(
                                PatternMatch(
                                    id=match_counter,
                                    category="custom",
                                    label="Custom Pattern",
                                    value=val_str,
                                    masked_value=val_str,
                                    offset=abs_off,
                                    offset_hex=f"0x{abs_off:08X}",
                                    source_file=source_path,
                                    context_text=_make_context_text(chunk, rel_idx, rel_idx + len(raw_val)),
                                    context_hex=_make_context_hex(chunk, rel_idx, rel_idx + len(raw_val), abs_off),
                                    metadata={"pattern": custom_regex},
                                )
                            )

                curr_offset += actual_chunk_len
                bytes_scanned += actual_chunk_len
                cb(bytes_scanned, scan_total, len(matches))

                if actual_chunk_len < read_len:
                    break

        return matches
