from __future__ import annotations

import logging
from typing import Dict, List, Optional
from .models import CustodyEntry

logger = logging.getLogger("core.custody")


class CustodyManager:
    def __init__(self, analyst: str = "analyst"):
        self.analyst = analyst
        self._entries: List[CustodyEntry] = []

    def reset(self):
        self._entries.clear()

    def log(
        self,
        action: str,
        details: str = "",
        source_hash: str = "",
    ) -> CustodyEntry:
        logger.info(action)
        entry = CustodyEntry.now(
            action=action,
            analyst=self.analyst,
            details=details,
            source_hash=source_hash,
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> List[CustodyEntry]:
        return list(self._entries)

    def to_dict_list(self) -> List[Dict[str, str]]:
        return [e.to_dict() for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)
