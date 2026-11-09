from __future__ import annotations
from typing import Dict, Tuple

MAX_OVERLAP_GAP = 512  


class OffsetRegistry:
    def __init__(self):
        self._registry: Dict[Tuple[str, int], Tuple[float, int]] = {}

    def can_register(self, offset: int, confidence: float, source_path: str = "") -> bool:
        for (reg_source, reg_off), (reg_conf, _) in self._registry.items():
            if reg_source == source_path:
                if abs(offset - reg_off) < MAX_OVERLAP_GAP:
                    return confidence > reg_conf  # only replace if strictly better
        return True

    def register(self, offset: int, confidence: float, file_id: int, source_path: str = ""):
        to_remove = [
            (s, o) for (s, o) in self._registry
            if s == source_path and abs(offset - o) < MAX_OVERLAP_GAP
        ]
        for key in to_remove:
            del self._registry[key]
        self._registry[(source_path, offset)] = (confidence, file_id)

    def clear(self):
        self._registry.clear()

    def __len__(self) -> int:
        return len(self._registry)
