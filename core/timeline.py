from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ScanResult


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    source: str
    description: str
    offset: Optional[int] = None
    file_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source": self.source,
            "description": self.description,
            "offset": self.offset,
            "file_id": self.file_id,
        }


class TimelineAnalyzer:
    @staticmethod
    def build(result: ScanResult) -> List[TimelineEvent]:
        events: List[TimelineEvent] = []

        for entry in result.custody_log:
            events.append(
                TimelineEvent(
                    timestamp=entry.timestamp,
                    event_type="CUSTODY",
                    source="chain_of_custody",
                    description=entry.action,
                )
            )

        end_dt = result.end_time or datetime.now(timezone.utc)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
        end_ts_str = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        for f in result.carved_files:
            events.append(
                TimelineEvent(
                    timestamp=end_ts_str,
                    event_type="FILE_CARVED",
                    source=f.signature.id,
                    description=f"Recovered {f.type_name} ({f.recovery_status})",
                    offset=f.start_offset,
                    file_id=f.id,
                )
            )
            if "pdf_version" in f.metadata:
                events.append(
                    TimelineEvent(
                        timestamp=end_ts_str,
                        event_type="METADATA",
                        source="pdf",
                        description=f"PDF version: {f.metadata['pdf_version']}",
                        offset=f.start_offset,
                        file_id=f.id,
                    )
                )

        events.sort(key=lambda e: _parse_ts(e.timestamp))
        return events


def save_timeline_json(events: List[TimelineEvent], output_path: str):
    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "events": [e.to_dict() for e in events],
    }
    Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_ts(ts: str) -> datetime:
    try:
        cleaned = ts.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1]
            if not ("+" in cleaned or "-" in cleaned[10:]):
                cleaned += "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)

