from __future__ import annotations
import json
from pathlib import Path

from sdk import ForensicsCarver, SDKOptions

def main():
    root = Path(__file__).resolve().parent.parent
    source = root / "demo_workspace" / "demo.img"
    out = root / "sdk_output"
    out.mkdir(parents=True, exist_ok=True)

    options = SDKOptions(
        analyst="sdk_demo_user",
        compute_hashes=True,
        compute_entropy=True,
        yara_rules_path="",
        signature_db_path=":memory:",
    )
    carver = ForensicsCarver(options)

    plugins_dir = root / "plugins"
    loaded = carver.load_plugins(str(plugins_dir))
    print(f"Loaded plugins: {loaded or 'none'}")

    result = carver.scan(
        source_path=str(source),
        source_type="auto",
        recover_fragments=True,
    )
    print(f"Files found: {result.files_found}")

    view = carver.scan_view(source_path=str(source), source_type="auto")
    images = view.filter(category="image", min_confidence=0.5)
    print(f"Image files (>=50% confidence): {len(images)}")

    # Reports
    view.generate_report(str(out / "report.json"), fmt="json")
    view.generate_report(str(out / "report.csv"), fmt="csv")
    view.generate_report(str(out / "report.html"), fmt="html")
    try:
        view.generate_report(str(out / "report.pdf"), fmt="pdf")
    except Exception as e:
        print(f"PDF report skipped: {e}")

    events = carver.generate_timeline(result, str(out / "timeline.json"))
    print(f"Timeline events: {len(events)}")

    triage = carver.triage_scan(result)
    triage_json = {"items": [t.to_dict() for t in triage]}
    (out / "triage.json").write_text(json.dumps(triage_json, indent=2), encoding="utf-8")
    print(f"Triage items: {len(triage)}")

    print(f"Outputs written to: {out}")


if __name__ == "__main__":
    main()
