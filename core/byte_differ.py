from __future__ import annotations
from typing import Any, Dict, List, Optional

class ByteDiffer:

    @classmethod
    def diff(
        cls,
        data_a: bytes,
        data_b: bytes,
        max_blocks: int = 150,
        chunk_align: int = 16,
    ) -> Dict[str, Any]:
        len_a = len(data_a)
        len_b = len(data_b)

        if data_a == data_b:
            return {
                "identical": True,
                "similarity_pct": 100.0,
                "len_a": len_a,
                "len_b": len_b,
                "differing_bytes": 0,
                "differing_blocks_count": 0,
                "truncated": False,
                "diff_blocks": [],
            }

        min_len = min(len_a, len_b)
        max_len = max(len_a, len_b)

        differing_bytes = 0
        diff_ranges: List[tuple[int, int]] = [] 

        in_diff = False
        diff_start = 0

        for i in range(min_len):
            if data_a[i] != data_b[i]:
                differing_bytes += 1
                if not in_diff:
                    in_diff = True
                    diff_start = i
            else:
                if in_diff:
                    diff_ranges.append((diff_start, i))
                    in_diff = False

        if in_diff:
            diff_ranges.append((diff_start, min_len))

        if len_a != len_b:
            diff_ranges.append((min_len, max_len))
            differing_bytes += (max_len - min_len)

        matching_bytes = max_len - differing_bytes
        similarity_pct = round((matching_bytes / max_len) * 100.0, 2) if max_len > 0 else 100.0

        total_blocks = len(diff_ranges)
        truncated = total_blocks > max_blocks
        selected_ranges = diff_ranges[:max_blocks]

        formatted_blocks = []
        for start_off, end_off in selected_ranges:
            length = end_off - start_off
            sub_a = data_a[start_off:end_off] if start_off < len_a else b""
            sub_b = data_b[start_off:end_off] if start_off < len_b else b""

            # Truncate representation to at most 32 bytes for display in single block
            disp_len = min(32, length)
            disp_a = sub_a[:disp_len]
            disp_b = sub_b[:disp_len]

            formatted_blocks.append({
                "offset": start_off,
                "offset_hex": f"0x{start_off:08X}",
                "length": length,
                "hex_a": " ".join(f"{b:02X}" for b in disp_a) if disp_a else "<EOF>",
                "ascii_a": "".join(chr(b) if 32 <= b < 127 else "." for b in disp_a) if disp_a else "",
                "hex_b": " ".join(f"{b:02X}" for b in disp_b) if disp_b else "<EOF>",
                "ascii_b": "".join(chr(b) if 32 <= b < 127 else "." for b in disp_b) if disp_b else "",
            })

        return {
            "identical": False,
            "similarity_pct": similarity_pct,
            "len_a": len_a,
            "len_b": len_b,
            "differing_bytes": differing_bytes,
            "differing_blocks_count": total_blocks,
            "truncated": truncated,
            "diff_blocks": formatted_blocks,
        }
