from __future__ import annotations
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from .models import ScanResult, CarvedFile


def seal_report(file_path: str | Path) -> str:
    p = Path(file_path)
    if not p.is_file():
        return ""
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    seal_path = p.with_name(p.name + ".sha256")
    seal_path.write_text(f"{digest}  {p.name}\n", encoding="utf-8")
    return digest


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "numerator") and hasattr(obj, "denominator"):
        try:
            if obj.denominator == 0:
                return 0
            if obj.denominator == 1:
                return int(obj.numerator)
            return float(obj)
        except Exception:
            return str(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def save_json(result: ScanResult, output_path: str):
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "tool": "Digital Forensics Tool v2.0",
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": result.summary(),
        "chain_of_custody": [e.to_dict() for e in result.custody_log],
        "files": [f.to_dict() for f in result.carved_files],
        "errors": result.errors,
    }
    p.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )
    seal_report(p)


def save_jsonl(result: ScanResult, output_path: str):
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        header = {
            "record_type": "header",
            "tool": "Digital Forensics Tool v2.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": result.summary(),
            "errors": result.errors,
        }
        f.write(json.dumps(header, ensure_ascii=False, default=_json_default) + "\n")

        for e in result.custody_log:
            entry = {"record_type": "custody", "data": e.to_dict()}
            f.write(json.dumps(entry, ensure_ascii=False, default=_json_default) + "\n")

        for cf in result.carved_files:
            cf_record = {"record_type": "carved_file", "data": cf.to_dict()}
            f.write(json.dumps(cf_record, ensure_ascii=False, default=_json_default) + "\n")

    seal_report(p)


def save_csv(result: ScanResult, output_path: str):
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    headers = [
        "ID", "Type", "Category", "Signature",
        "Start Offset (hex)", "End Offset (hex)", "Size (bytes)", "Size",
        "Confidence", "Recovery Status", "Validation",
        "MD5", "SHA256",
        "Entropy", "Entropy Class", "Encrypted",
        "Metadata",
    ]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for cf in result.carved_files:
            w.writerow([
                cf.id,
                cf.type_name,
                cf.signature.category,
                cf.signature.id,
                f"0x{cf.start_offset:X}",
                f"0x{cf.end_offset:X}",
                cf.size,
                _human(cf.size),
                f"{cf.confidence:.4f}",
                cf.recovery_status,
                cf.validation.message,
                cf.hashes.md5 if cf.hashes else "",
                cf.hashes.sha256 if cf.hashes else "",
                f"{cf.entropy.value:.4f}" if cf.entropy else "",
                cf.entropy.classification if cf.entropy else "",
                str(cf.entropy.is_encrypted) if cf.entropy else "",
                json.dumps(cf.metadata, ensure_ascii=False) if cf.metadata else "",
            ])
    seal_report(p)


def save_html(result: ScanResult, output_path: str, case_name: str = ""):
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    summary = result.summary()
    rows = _generate_file_rows(result.carved_files)
    custody_rows = _generate_custody_rows(result.custody_log)
    type_rows = _generate_type_rows(summary.get("by_type", {}))
    
    html = _generate_html(result, summary, rows, custody_rows, type_rows, case_name)
    p.write_text(html, encoding="utf-8")
    seal_report(p)


def _generate_file_rows(carved_files: list) -> str:
    rows = ""
    for cf in carved_files:
        conf_class = (
            "high" if cf.confidence >= 0.75
            else "med" if cf.confidence >= 0.50
            else "low"
        )
        enc_badge = (
            '<span class="badge enc">ENCRYPTED</span>'
            if cf.entropy and cf.entropy.is_encrypted else ""
        )
        status_class = "complete" if cf.recovery_status == "COMPLETE" else "partial"
        rows += f"""
        <tr>
          <td class="mono">{cf.id}</td>
          <td><strong>{cf.type_name}</strong><br><small>{cf.signature.category}</small></td>
          <td class="mono small">0x{cf.start_offset:X}</td>
          <td class="mono small">0x{cf.end_offset:X}</td>
          <td>{_human(cf.size)}</td>
          <td><span class="conf {conf_class}">{cf.confidence:.0%}</span></td>
          <td><span class="status {status_class}">{cf.recovery_status}</span></td>
          <td class="small">{cf.validation.message}{enc_badge}</td>
          <td class="mono small">{cf.hashes.md5[:12] + "..." if cf.hashes else "—"}</td>
          <td class="small">{cf.entropy.value:.2f} ({cf.entropy.classification})</td>
          <td class="small">{json.dumps(cf.metadata) if cf.metadata else "—"}</td>
        </tr>"""
    return rows


def _generate_custody_rows(custody_log: list) -> str:
    rows = ""
    for e in custody_log:
        rows += f"""
        <tr>
          <td class="mono small">{e.timestamp}</td>
          <td>{e.action}</td>
          <td>{e.analyst}</td>
        </tr>"""
    return rows


def _generate_type_rows(by_type: dict) -> str:
    return "".join(
        f"<tr><td>{t}</td><td>{c}</td></tr>"
        for t, c in sorted(by_type.items(), key=lambda x: -x[1])
    )


def _generate_html(result: ScanResult, summary: dict, rows: str, 
                    custody_rows: str, type_rows: str, case_name: str) -> str:
    header = _generate_html_header(case_name or result.source_path)
    body = _generate_html_body(result, summary, rows, custody_rows, type_rows, case_name)
    footer = _generate_html_footer()
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
{header}
</head>
<body>
{body}
{footer}
</body>
</html>"""


def _generate_html_header(title: str) -> str:
    return f"""<title>Forensic Report — {title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 13px;
         color: #1a1a1a; background: #f4f6f9; padding: 24px; }}
  .page {{ max-width: 1400px; margin: 0 auto; }}
  header {{ background: #0d2240; color: #fff; padding: 24px 32px;
             border-radius: 8px; margin-bottom: 24px; }}
  header h1 {{ font-size: 22px; font-weight: 600; margin-bottom: 4px; }}
  header p {{ opacity: 0.75; font-size: 12px; }}
  .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 16px 20px;
            border: 1px solid #e0e6ed; }}
  .card-label {{ font-size: 11px; color: #666; text-transform: uppercase;
                 letter-spacing: .5px; margin-bottom: 4px; }}
  .card-value {{ font-size: 26px; font-weight: 600; color: #0d2240; }}
  .card-sub {{ font-size: 11px; color: #888; margin-top: 2px; }}
  section {{ background: #fff; border-radius: 8px; border: 1px solid #e0e6ed;
             margin-bottom: 24px; overflow: hidden; }}
  section h2 {{ font-size: 14px; font-weight: 600; padding: 14px 20px;
                 border-bottom: 1px solid #e0e6ed; background: #f9fafc;
                 color: #0d2240; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ font-size: 11px; font-weight: 600; text-transform: uppercase;
         letter-spacing: .4px; color: #555; padding: 10px 12px;
         background: #f9fafc; border-bottom: 1px solid #e0e6ed; text-align: left; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
  tr:hover td {{ background: #f7f9ff; }}
  .mono {{ font-family: 'Consolas', 'Courier New', monospace; }}
  .small {{ font-size: 11px; }}
  .conf {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-weight: 600; font-size: 12px; }}
  .conf.high {{ background: #e6f4ea; color: #1a7340; }}
  .conf.med  {{ background: #fff8e1; color: #856404; }}
  .conf.low  {{ background: #fce8e6; color: #b01010; }}
  .status {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
              font-size: 11px; }}
  .status.complete {{ background: #e6f4ea; color: #1a7340; }}
  .status.partial  {{ background: #fff3cd; color: #856404; }}
  .badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px;
             font-size: 10px; font-weight: 700; margin-left: 4px; }}
  .badge.enc {{ background: #dc3545; color: #fff; }}
  .summary-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; padding: 20px; }}
  .hash-block {{ font-family: monospace; font-size: 11px; color: #444;
                 background: #f4f6f9; padding: 12px; border-radius: 4px;
                 line-height: 1.8; }}
  footer {{ text-align: center; font-size: 11px; color: #888; padding: 16px 0; }}
</style>"""


def _generate_html_body(result: ScanResult, summary: dict, rows: str,
                        custody_rows: str, type_rows: str, case_name: str) -> str:
    return f"""<div class="page">
<header>
  <h1>Digital Forensic Analysis Report</h1>
  <p>Case: {case_name or "—"} &nbsp;|&nbsp;
     Source: {result.source_path} &nbsp;|&nbsp;
     Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
</header>

<div class="cards">
  <div class="card">
    <div class="card-label">Files Found</div>
    <div class="card-value">{result.files_found}</div>
    <div class="card-sub">across all types</div>
  </div>
  <div class="card">
    <div class="card-label">Data Scanned</div>
    <div class="card-value">{_human(summary['bytes_scanned'])}</div>
    <div class="card-sub">{summary['blocks_scanned']:,} blocks</div>
  </div>
  <div class="card">
    <div class="card-label">Scan Duration</div>
    <div class="card-value">{summary['duration_seconds']:.1f}s</div>
    <div class="card-sub">wall clock</div>
  </div>
  <div class="card">
    <div class="card-label">Source Type</div>
    <div class="card-value" style="font-size:18px">{result.source_type}</div>
    <div class="card-sub">{result.source_path}</div>
  </div>
</div>

<section>
  <h2>Source Integrity (Chain of Custody)</h2>
  <div class="summary-grid">
    <div>
      <div class="hash-block">
        MD5 &nbsp;&nbsp; {result.source_hash.md5 if result.source_hash else 'N/A'}<br>
        SHA1 &nbsp; {result.source_hash.sha1 if result.source_hash else 'N/A'}<br>
        SHA256 {result.source_hash.sha256 if result.source_hash else 'N/A'}
      </div>
    </div>
    <div>
      <table>
        <tr><th>Type</th><th>Count</th></tr>
        {type_rows}
      </table>
    </div>
  </div>
</section>

<section>
  <h2>Recovered Files ({result.files_found})</h2>
  <table>
    <tr>
      <th>#</th><th>Type</th><th>Start</th><th>End</th>
      <th>Size</th><th>Confidence</th><th>Status</th>
      <th>Validation</th><th>MD5 (partial)</th>
      <th>Entropy</th><th>Metadata</th>
    </tr>
    {rows}
  </table>
</section>

<section>
  <h2>Chain of Custody Log ({len(result.custody_log)} entries)</h2>
  <table>
    <tr><th>Timestamp (UTC)</th><th>Action</th><th>Analyst</th></tr>
    {custody_rows}
  </table>
</section>
</div>"""


def _generate_html_footer() -> str:
    return """<footer>
  Produced by Digital Forensics Tool v2.0 &nbsp;|&nbsp;
  This report is for authorized forensic investigation only
</footer>"""


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"