from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: List[str]
    offset: int
    strings: List[str]

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "offset": self.offset,
            "strings": self.strings,
        }


class YaraScanner:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self._rules = None
        self._err = ""
        try:
            import yara

            self._rules = yara.compile(filepath=rules_path)
            logger.debug(f"YARA rules loaded from: {rules_path}")
        except ImportError as e:
            self._err = str(e)
            logger.warning(f"YARA not available (yara-python not installed): {e}")
        except Exception as e:
            self._err = str(e)
            logger.error(f"Failed to compile YARA rules from {rules_path}: {e}")

    @property
    def available(self) -> bool:
        return self._rules is not None

    @property
    def error(self) -> str:
        return self._err

    def scan_bytes(self, data: bytes, abs_offset: int = 0) -> List[YaraMatch]:
        if not self._rules or not data:
            return []
        out: List[YaraMatch] = []
        try:
            hits = self._rules.match(data=data)
            for hit in hits:
                strings: List[str] = []
                first_off = abs_offset
                for s in getattr(hit, "strings", []):
                    if hasattr(s, "instances"):
                        for inst in s.instances:
                            first_off = min(first_off, abs_offset + int(inst.offset))
                            strings.append(getattr(s, "identifier", "$?"))
                    elif isinstance(s, tuple) and len(s) >= 3:
                        first_off = min(first_off, abs_offset + int(s[0]))
                        strings.append(str(s[1]))
                out.append(
                    YaraMatch(
                        rule=hit.rule,
                        namespace=getattr(hit, "namespace", "default"),
                        tags=list(getattr(hit, "tags", [])),
                        offset=first_off,
                        strings=sorted(set(strings)),
                    )
                )
        except Exception as e:
            logger.warning(f"YARA scan failed: {e}")
            return []
        return out

