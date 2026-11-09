from __future__ import annotations

from dataclasses import replace
from typing import List

from .models import CarvedFile, EntropyResult, HashBundle
from .validators import dispatch


def recover_fragmented_candidates(files: List[CarvedFile], max_gap: int = 4 * 4096) -> List[CarvedFile]:
    if not files:
        return []

    by_off = sorted(files, key=lambda f: f.start_offset)
    out: List[CarvedFile] = []
    next_id = max((f.id for f in by_off), default=0) + 1

    for i in range(len(by_off) - 1):
        a = by_off[i]
        b = by_off[i + 1]
        if a.signature.id != b.signature.id:
            continue
        gap = b.start_offset - a.end_offset
        if gap < 0 or gap > max_gap:
            continue

        if not a.data or not b.data:
            continue

        if a.entropy and b.entropy and a.entropy.classification != b.entropy.classification:
            continue

        merged = a.data + b.data
        vr = dispatch(a.signature.validator, merged[: min(len(merged), 2 * 1024 * 1024)])
        if not vr.is_valid and vr.confidence_boost < -0.25:
            continue

        entropy = EntropyResult.from_bytes(merged[: min(len(merged), 65536)])
        hashes = HashBundle.from_bytes(merged)
        cf = replace(
            a,
            id=next_id,
            end_offset=b.end_offset,
            size=len(merged),
            confidence=round(max(0.05, min(1.0, (a.confidence + b.confidence) / 2 - 0.05)), 4),
            recovery_status="FRAGMENTED",
            validation=vr,
            hashes=hashes,
            entropy=entropy,
            blocks=[(a.start_offset, a.end_offset), (b.start_offset, b.end_offset)],
            data=merged if len(merged) <= 10 * 1024 * 1024 else None,
        )
        out.append(cf)
        next_id += 1

    return out

