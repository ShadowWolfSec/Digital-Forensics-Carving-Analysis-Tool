from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path
from datetime import datetime
from core import setup_logging

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import (
    AITriageEngine,
    CarvingEngine,
    SignatureDatabase,
    setup_logging,
    save_json,
    save_csv,
    save_html,
    save_jsonl,
    save_pdf,
    sign_pdf,
    seal_report,
)
from core.timeline import TimelineAnalyzer, save_timeline_json



def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _supports_utf8_output() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
    if "utf" in encoding:
        return True
    if os.environ.get("PYTHONUTF8") == "1":
        return True
    return False


C = _supports_color()
UTF8 = _supports_utf8_output()
RESET  = "\033[0m"   if C else ""
BOLD   = "\033[1m"   if C else ""
DIM    = "\033[2m"   if C else ""
GREEN  = "\033[92m"  if C else ""
YELLOW = "\033[93m"  if C else ""
RED    = "\033[91m"  if C else ""
CYAN   = "\033[96m"  if C else ""
BLUE   = "\033[94m"  if C else ""
MAGENTA= "\033[95m"  if C else ""


if UTF8:
    BANNER = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════╗
║          Digital Forensics Tool  v2.0                   ║
║       File Carving & Evidence Recovery Engine           ║
╚══════════════════════════════════════════════════════════╝{RESET}
"""
else:
    BANNER = f"""{CYAN}{BOLD}
+----------------------------------------------------------+
|          Digital Forensics Tool  v2.0                   |
|       File Carving & Evidence Recovery Engine           |
+----------------------------------------------------------+{RESET}
"""


class LiveProgress:
    """Thread-safe progress bar printed to stderr."""

    def __init__(self, total: int):
        self.total = total or 1
        self._lock = threading.Lock()
        self._files = 0
        self._done = 0
        self._start = time.time()

    def update(self, done: int, total: int, files: int):
        with self._lock:
            self._done = done
            self._files = files
            self._render()

    def _render(self):
        pct = min(self._done / self.total, 1.0)
        bar_w = 40
        filled = int(bar_w * pct)
        if UTF8:
            bar = "█" * filled + "░" * (bar_w - filled)
        else:
            bar = "#" * filled + "-" * (bar_w - filled)
        elapsed = time.time() - self._start
        speed = self._done / elapsed / 1024 / 1024 if elapsed > 0 else 0
        done_mb = self._done / 1024 / 1024
        total_mb = self.total / 1024 / 1024
        sys.stderr.write(
            f"\r{CYAN}[{bar}]{RESET} "
            f"{BOLD}{pct:5.1%}{RESET} "
            f"{done_mb:6.1f}/{total_mb:.1f} MB  "
            f"{GREEN}{speed:5.1f} MB/s{RESET}  "
            f"{YELLOW}Files: {self._files}{RESET}   "
        )
        sys.stderr.flush()

    def finish(self):
        sys.stderr.write("\n")
        sys.stderr.flush()



def _sep(char: str = "─", width: int = 64) -> str:
    if not UTF8 and char == "─":
        char = "-"
    return DIM + char * width + RESET


def _print_summary(result):
    s = result.summary()
    line = "─" * 64 if UTF8 else "-" * 64
    print(f"\n{BOLD}{line}")
    print(f"  Scan Complete")
    print(f"{line}{RESET}")
    print(f"  Source       : {s['source']}")
    print(f"  Type         : {s['source_type']}")
    print(f"  Data scanned : {s['bytes_scanned_human']} ({s['blocks_scanned']:,} blocks)")
    print(f"  Duration     : {s['duration_seconds']:.2f}s")
    print(f"  Files found  : {BOLD}{GREEN}{s['files_found']}{RESET}")
    if s["source_hash"]:
        h = s["source_hash"]
        print(f"\n  {BOLD}Source integrity:{RESET}")
        print(f"    MD5    : {DIM}{h['md5']}{RESET}")
        print(f"    SHA1   : {DIM}{h['sha1']}{RESET}")
        print(f"    SHA256 : {DIM}{h['sha256']}{RESET}")
    if s["by_type"]:
        print(f"\n  {BOLD}By type:{RESET}")
        for t, c in sorted(s["by_type"].items(), key=lambda x: -x[1]):
            bar = ("▮" if UTF8 else "#") * min(c, 30)
            print(f"    {t:<30} {CYAN}{bar}{RESET} {c}")
    if s["errors"]:
        print(f"\n  {RED}Errors:{RESET}")
        for e in s["errors"]:
            print(f"    {e}")
    print(f"{BOLD}{line}{RESET}\n")


def _print_files(result, show_hashes: bool = False, min_conf: float = 0.0):
    files = [f for f in result.carved_files if f.confidence >= min_conf]
    if not files:
        print(f"{YELLOW}  No files above confidence threshold {min_conf:.0%}{RESET}")
        return

    print(f"\n{BOLD}  Recovered Files ({len(files)}){RESET}")
    print(_sep())
    print(
        f"  {'#':>4}  {'Type':<24} {'Start':>12}  {'Size':>10}  "
        f"{'Conf':>6}  {'Status':<10}  Validation"
    )
    print(_sep())

    for cf in files:
        conf_color = GREEN if cf.confidence >= 0.75 else (YELLOW if cf.confidence >= 0.5 else RED)
        status_color = GREEN if cf.recovery_status == "COMPLETE" else YELLOW
        enc = f" {RED}[ENC]{RESET}" if cf.entropy and cf.entropy.is_encrypted else ""
        print(
            f"  {cf.id:>4}  {cf.type_name:<24} "
            f"0x{cf.start_offset:>10X}  {_human(cf.size):>10}  "
            f"{conf_color}{cf.confidence:>5.0%}{RESET}  "
            f"{status_color}{cf.recovery_status:<10}{RESET}  "
            f"{DIM}{cf.validation.message[:40]}{RESET}{enc}"
        )
        if cf.metadata:
            for k, v in cf.metadata.items():
                print(f"         {DIM}{k}: {v}{RESET}")
        if show_hashes and cf.hashes:
            print(f"         {DIM}MD5: {cf.hashes.md5}{RESET}")
            print(f"         {DIM}SHA256: {cf.hashes.sha256}{RESET}")

    print(_sep())


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _recover_files(result, output_dir: str, min_conf: float = 0.0, default_source: str = ""):
    out = Path(output_dir) / "recovered"
    out.mkdir(parents=True, exist_ok=True)
    recovered = 0
    skipped = 0
    manifest = []

    for cf in result.carved_files:
        if cf.confidence < min_conf:
            skipped += 1
            continue

        data = getattr(cf, "data", None)
        if data is None:
            # Read on demand from source
            src = cf.metadata.get("source_file") or default_source
            if src:
                try:
                    from core.image_readers import reader_for_source
                    clean = src.replace("/", "\\")
                    stype = "e01" if clean.lower().endswith((".e01", ".ex01")) else "file"
                    with reader_for_source(src, stype) as r:
                        data = r.read_at(cf.start_offset, cf.size)
                except Exception:
                    data = None

        if not data:
            skipped += 1
            continue

        fname = (
            f"file_{cf.id:04d}_{cf.signature.id}_"
            f"0x{cf.start_offset:08X}.{cf.extension}"
        )
        fpath = (out / fname).resolve()
        if not fpath.is_relative_to(out.resolve()):
            continue

        try:
            fpath.write_bytes(data)
            recovered += 1
            manifest.append({
                "id": cf.id,
                "filename": fname,
                "type": cf.type_name,
                "offset": cf.start_offset,
                "size": cf.size,
                "confidence": cf.confidence,
                "hashes": cf.hashes.to_dict() if cf.hashes else None,
            })
        except Exception as e:
            print(f"{RED}  Failed to write {fname}: {e}{RESET}")

    if manifest:
        try:
            import json
            m_path = out / "recovered_manifest.json"
            m_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
            seal_report(m_path)
        except Exception:
            pass

    arrow = "→" if UTF8 else "->"
    print(f"\n  {GREEN}Recovered{RESET} {recovered} files {arrow} {out}")
    if skipped:
        print(f"  {YELLOW}Skipped{RESET} {skipped} (below confidence threshold {min_conf:.0%})")
    return recovered


# ─────────────────────────────────────────────
#  Signature management
# ─────────────────────────────────────────────

def _cmd_list_sigs(db: SignatureDatabase):
    print(f"\n{BOLD}  Loaded Signatures ({len(db.all)}){RESET}")
    print(_sep())
    stats = db.stats()
    for cat, count in sorted(stats.items()):
        sigs = [s for s in db.all if s.category == cat]
        print(f"\n  {BOLD}{cat.upper()}{RESET} ({count})")
        for s in sigs:
            trailer = f" ...{s.trailer.hex().upper()}" if s.trailer else ""
            print(
                f"    {CYAN}{s.id:<20}{RESET} {s.name:<28} "
                f"{DIM}{s.header.hex().upper()}{trailer}{RESET}  "
                f"conf={s.confidence:.2f}"
            )
    print()


def _cmd_add_sig(db: SignatureDatabase, db_path: str):
    print(f"\n{BOLD}  Add Custom Signature{RESET}")
    print(_sep())
    from core.models import FileSignature
    try:
        sig_id    = input("  ID          : ").strip()
        name      = input("  Name        : ").strip()
        desc      = input("  Description : ").strip()
        cat       = input("  Category    : ").strip() or "custom"
        exts      = input("  Extensions  : ").strip()
        mime      = input("  MIME type   : ").strip() or "application/octet-stream"
        hdr_hex   = input("  Header (hex): ").strip().replace(" ", "")
        trl_hex   = input("  Trailer (hex, optional): ").strip().replace(" ", "")
        maxmb     = input("  Max size MB [50]: ").strip() or "50"
        conf      = input("  Confidence [0.7]: ").strip() or "0.7"

        if not sig_id or not hdr_hex:
            print(f"{RED}  ID and Header are required{RESET}")
            return

        sig = FileSignature(
            id=sig_id, name=name, description=desc, category=cat,
            extensions=[e.strip() for e in exts.split(",") if e.strip()],
            mime_type=mime,
            header=bytes.fromhex(hdr_hex),
            trailer=bytes.fromhex(trl_hex) if trl_hex else None,
            max_file_size=int(maxmb) * 1024 * 1024,
            validator="validate_generic",
            confidence=float(conf),
        )
        # Persist to SQLite
        db2 = SignatureDatabase(db_path=db_path)
        db2.add_custom(sig)
        print(f"\n  {GREEN}Signature '{sig_id}' added successfully{RESET}")
    except (ValueError, KeyboardInterrupt) as e:
        print(f"\n  {RED}Cancelled: {e}{RESET}")


def _cmd_search(args):
    from core.regex_searcher import RegexRawSearcher
    print(f"\n{BOLD}  Pattern & Sensitive Data Search{RESET}")
    print(_sep())
    print(f"  {BOLD}Source:{RESET}   {args.source}")
    print(f"  {BOLD}Patterns:{RESET} {', '.join(args.patterns)}")
    if args.regex:
        print(f"  {BOLD}Custom:{RESET}   {args.regex}")
    print()

    searcher = RegexRawSearcher()
    max_bytes = args.max_mb * 1024 * 1024 if args.max_mb else None
    start_offset = args.start_mb * 1024 * 1024

    try:
        total_estimate = (
            os.path.getsize(args.source)
            if os.path.isfile(args.source) else max_bytes or 1
        )
    except Exception:
        total_estimate = max_bytes or 1

    progress = LiveProgress(max_bytes or total_estimate)

    def on_progress(done, total, files):
        progress.update(done, total or 1, files)

    hits = searcher.search(
        source_path=args.source,
        enabled_patterns=args.patterns,
        custom_regex=args.regex,
        max_bytes=max_bytes,
        start_offset=start_offset,
        progress_cb=on_progress,
    )
    progress.finish()

    print(f"\n{BOLD}  Matches Found ({len(hits)}){RESET}")
    print(_sep())
    if not hits:
        print(f"  {YELLOW}No matching patterns found.{RESET}")
    for h in hits:
        val = h.value if args.unmask else h.masked_value
        print(f"  {CYAN}{h.offset_hex:>10}{RESET}  [{BOLD}{h.label:<16}{RESET}]  {val}")
        if args.context:
            print(f"              {DIM}Context: {h.context_text}{RESET}")

    if args.output:
        import json
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(
            json.dumps([h.to_dict() for h in hits], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        seal_report(out_p)
        print(f"\n  {GREEN}Matches exported:{RESET} {out_p} (+ .sha256)")
    print()


def _cmd_mft(args):
    from core.mft_parser import MFTParser
    print(f"\n{BOLD}  NTFS Master File Table ($MFT) Parser{RESET}")
    print(_sep())
    print(f"  {BOLD}Source:{RESET} {args.source}")
    print()

    start_off = args.start_mb * 1024 * 1024
    max_b = args.max_mb * 1024 * 1024 if args.max_mb else None

    try:
        total_estimate = (
            os.path.getsize(args.source)
            if os.path.isfile(args.source) else max_b or 1
        )
    except Exception:
        total_estimate = max_b or 1

    progress = LiveProgress(max_b or total_estimate)

    def on_progress(done, total, files):
        progress.update(done, total or 1, files)

    records = MFTParser.scan_source(
        source_path=args.source,
        start_offset=start_off,
        max_bytes=max_b,
        progress_cb=on_progress,
    )
    progress.finish()

    if args.deleted_only:
        records = [r for r in records if r.is_deleted]

    print(f"\n{BOLD}  MFT Records Found ({len(records)}){RESET}")
    print(_sep())
    if not records:
        print(f"  {YELLOW}No NTFS MFT records identified in source.{RESET}")
    else:
        print(f"  {'#':<8} {'Status':<10} {'Type':<6} {'Filename':<32} {'Size':>10}  Modified (UTC)")
        print(_sep())
        for r in records[:100]:
            status_str = f"{RED}DELETED{RESET}" if r.is_deleted else f"{GREEN}ACTIVE{RESET}"
            type_str = "DIR" if r.is_directory else "FILE"
            fname = (r.filename or f"Record_{r.record_number}")[:30]
            print(f"  {r.record_number:<8} {status_str:<19} {type_str:<6} {fname:<32} {r.file_size:>10}  {DIM}{r.modified_time or '—'}{RESET}")

        if len(records) > 100:
            print(f"\n  {YELLOW}... showing first 100 of {len(records)} records. Use -o to export all.{RESET}")

    if args.output and records:
        import json
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if str(out_p).lower().endswith(".csv"):
            import csv
            with open(out_p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Record", "Deleted", "Directory", "Filename", "Path", "Size", "Allocated", "Created", "Modified", "Offset"])
                for r in records:
                    w.writerow([r.record_number, r.is_deleted, r.is_directory, r.filename, r.full_path, r.file_size, r.allocated_size, r.created_time, r.modified_time, f"0x{r.raw_offset:X}"])
        else:
            out_p.write_text(
                json.dumps([r.to_dict() for r in records], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        seal_report(out_p)
        print(f"\n  {GREEN}MFT records exported:{RESET} {out_p} (+ .sha256)")
    print()

def main():
    # setup_logging(level=logging.INFO)  # ✅ تهيئة النظام

    # Initialize logging
    log_level = logging.DEBUG if "--debug" in sys.argv else logging.INFO
    setup_logging(level=log_level, console=True)
    
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="forensics",
        description="Digital Forensics Tool — File Carving & Evidence Recovery",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command")

    # ── scan ────────────────────────────────
    sp = sub.add_parser("scan", help="Scan a source for deleted/hidden files")
    sp.add_argument("source", help="Path to file, disk image, or physical drive")
    sp.add_argument("-o", "--output", help="Output directory for reports and recovered files")
    sp.add_argument("--type", choices=["auto", "file", "directory", "disk_image", "physical_drive", "e01", "aff"],
                    default="auto", help="Source type (default: auto-detect)")
    sp.add_argument("--max-mb", type=int, default=0,
                    help="Limit scan to first N megabytes (0 = no limit)")
    sp.add_argument("--start-mb", type=int, default=0,
                    help="Start scan at offset N megabytes")
    sp.add_argument("--min-conf", type=float, default=0.3,
                    help="Minimum confidence to display (default: 0.30)")
    sp.add_argument("--analyst", default="analyst",
                    help="Analyst name for chain of custody")
    sp.add_argument("--mode", choices=["deep", "triage"], default="deep",
                    help="Scan mode: deep (carve embedded objects) or triage (fast file check)")
    sp.add_argument("--no-hash", action="store_true",
                    help="Skip MD5/SHA hash computation (faster)")
    sp.add_argument("--no-entropy", action="store_true",
                    help="Skip entropy analysis (faster)")
    sp.add_argument("--recover", action="store_true",
                    help="Write recovered files to output directory")
    sp.add_argument("--format", choices=["json", "jsonl", "csv", "html", "pdf", "all"],
                    default="json", help="Report format (default: json)")
    sp.add_argument("--show-hashes", action="store_true",
                    help="Print hashes in file listing")
    sp.add_argument("--db", default=":memory:",
                    help="Path to signature database (default: in-memory)")
    sp.add_argument("--yara-rules", default="",
                    help="Path to YARA rules file for malware triage")
    sp.add_argument("--recover-fragments", action="store_true",
                    help="Enable heuristic fragmented file recovery")
    sp.add_argument("--timeline", action="store_true",
                    help="Generate timeline JSON from scan events")
    sp.add_argument("--triage", action="store_true",
                    help="Generate AI triage JSON for recovered files")
    sp.add_argument("--sign-pdf", action="store_true",
                    help="Digitally sign generated PDF report (requires pyHanko)")
    sp.add_argument("--cert-pem", default="",
                    help="Certificate PEM path used with --sign-pdf")
    sp.add_argument("--key-pem", default="",
                    help="Private key PEM path used with --sign-pdf")
    sp.add_argument("--key-pass", default="",
                    help="Private key passphrase used with --sign-pdf")

    # ── search (PII & Regex) ────────────────
    s_p = sub.add_parser("search", help="Scan raw binary source for sensitive data and regex patterns")
    s_p.add_argument("source", help="Path to file, disk image, or physical drive")
    s_p.add_argument("-o", "--output", help="Save pattern matches to JSON report file")
    s_p.add_argument("--patterns", nargs="+", default=["credit_card", "email", "ipv4", "crypto", "phone"],
                     choices=["credit_card", "email", "ipv4", "crypto", "phone"],
                     help="Pattern categories to detect")
    s_p.add_argument("--regex", default="", help="Custom regex expression to scan for")
    s_p.add_argument("--max-mb", type=int, default=0, help="Max MB to scan (0 = all)")
    s_p.add_argument("--start-mb", type=int, default=0, help="Start scan offset in MB")
    s_p.add_argument("--unmask", action="store_true", help="Display full unmasked values instead of PII safe masks")
    s_p.add_argument("--context", action="store_true", help="Print printable context snippet for matches")

    # ── mft (NTFS Parser) ───────────────────
    m_p = sub.add_parser("mft", help="Parse NTFS Master File Table ($MFT) and recover deleted file metadata")
    m_p.add_argument("source", help="Path to NTFS raw drive, image, or extracted $MFT file")
    m_p.add_argument("-o", "--output", help="Export MFT records to JSON or CSV file")
    m_p.add_argument("--deleted-only", action="store_true", help="Filter for deleted records only")
    m_p.add_argument("--max-mb", type=int, default=0, help="Max MB to parse (0 = all)")
    m_p.add_argument("--start-mb", type=int, default=0, help="Start offset in MB")

    # ── signatures ──────────────────────────
    ss = sub.add_parser("sigs", help="Manage signature database")
    ss.add_argument("action", choices=["list", "add", "remove"],
                    help="Action to perform")
    ss.add_argument("--id", help="Signature ID (for remove)")
    ss.add_argument("--db", default="signatures.db",
                    help="Path to signature database")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # ── Search command ───────────────────────
    if args.command == "search":
        _cmd_search(args)
        return

    # ── MFT command ──────────────────────────
    if args.command == "mft":
        _cmd_mft(args)
        return

    # ── Signatures command ───────────────────
    if args.command == "sigs":
        db = SignatureDatabase(db_path=args.db)
        if args.action == "list":
            _cmd_list_sigs(db)
        elif args.action == "add":
            _cmd_add_sig(db, args.db)
        elif args.action == "remove":
            if not args.id:
                print(f"{RED}  --id required{RESET}")
                return
            db.remove(args.id)
            print(f"  {GREEN}Removed signature '{args.id}'{RESET}")
        return

    # ── Scan command ─────────────────────────
    if args.command == "scan":
        db = SignatureDatabase(db_path=args.db)
        print(f"  {BOLD}Source:{RESET}  {args.source}")
        print(f"  {BOLD}Sigs loaded:{RESET} {len(db.all)}")
        print(f"  {BOLD}Analyst:{RESET} {args.analyst}")
        print()

        stop_flag = [False]
        max_bytes = args.max_mb * 1024 * 1024 if args.max_mb else None
        start_offset = args.start_mb * 1024 * 1024

        # Rough size estimate for progress bar
        try:
            total_bytes = (
                os.path.getsize(args.source)
                if os.path.isfile(args.source) else max_bytes or 1
            )
        except Exception:
            total_bytes = max_bytes or 1

        progress = LiveProgress(total_bytes)

        def on_progress(done, total, files):
            progress.update(done, total or 1, files)

        engine = CarvingEngine(
            sig_db=db,
            analyst=args.analyst,
            compute_hashes=not args.no_hash,
            compute_entropy=not args.no_entropy,
            yara_rules_path=args.yara_rules,
            stop_flag=stop_flag,
            progress_cb=on_progress,
        )

        try:
            result = engine.scan(
                source_path=args.source,
                source_type=args.type,
                max_bytes=max_bytes,
                start_offset=start_offset,
                recover_fragments=args.recover_fragments,
                scan_mode=args.mode,
            )
        except KeyboardInterrupt:
            stop_flag[0] = True
            progress.finish()
            print(f"\n{YELLOW}  Scan interrupted by user{RESET}")
            return

        progress.finish()

        # Display results
        _print_summary(result)
        _print_files(result, show_hashes=args.show_hashes, min_conf=args.min_conf)

        # Recover files
        if args.recover and args.output:
            _recover_files(result, args.output, min_conf=args.min_conf, default_source=args.source)

        # Save reports
        if args.output:
            out = Path(args.output)
            out.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fmt = args.format

            if fmt in ("json", "all"):
                p = out / f"report_{ts}.json"
                save_json(result, str(p))
                print(f"  {GREEN}JSON report:{RESET} {p} (+ .sha256)")

            if fmt in ("jsonl", "all"):
                p = out / f"report_{ts}.jsonl"
                save_jsonl(result, str(p))
                print(f"  {GREEN}JSONL report:{RESET} {p} (+ .sha256)")

            if fmt in ("csv", "all"):
                p = out / f"report_{ts}.csv"
                save_csv(result, str(p))
                print(f"  {GREEN}CSV report:{RESET}  {p}")

            if fmt in ("html", "all"):
                p = out / f"report_{ts}.html"
                save_html(result, str(p))
                print(f"  {GREEN}HTML report:{RESET} {p}")

            if fmt in ("pdf", "all"):
                p = out / f"report_{ts}.pdf"
                try:
                    save_pdf(result, str(p))
                    print(f"  {GREEN}PDF report:{RESET} {p}")
                    if args.sign_pdf:
                        if args.cert_pem and args.key_pem:
                            signed = out / f"report_{ts}.signed.pdf"
                            sign_pdf(str(p), str(signed), args.cert_pem, args.key_pem, args.key_pass or None)
                            print(f"  {GREEN}Signed PDF:{RESET} {signed}")
                        else:
                            print(f"  {YELLOW}Skipping PDF signing: --cert-pem and --key-pem are required{RESET}")
                except Exception as e:
                    print(f"  {YELLOW}Skipping PDF report (reportlab optional library needed): {e}{RESET}")

            if args.timeline:
                p = out / f"timeline_{ts}.json"
                events = TimelineAnalyzer.build(result)
                save_timeline_json(events, str(p))
                print(f"  {GREEN}Timeline report:{RESET} {p}")

            if args.triage:
                import json

                p = out / f"triage_{ts}.json"
                triage = AITriageEngine().classify_many(result.carved_files)
                payload = {"items": [t.to_dict() for t in triage]}
                p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                print(f"  {GREEN}Triage report:{RESET} {p}")

        print()


if __name__ == "__main__":
    main()
