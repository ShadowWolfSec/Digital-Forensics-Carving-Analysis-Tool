# Digital Forensics Carving Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white" alt="Python Versions" />
  <img src="https://img.shields.io/badge/Core%20Dependencies-0%20(Standard%20Library)-success" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/Tests-47%20Passing%20(100%25)-brightgreen" alt="Tests" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg" alt="License" />
</p>

A modular Python tool for file carving, unallocated disk space analysis, NTFS `$MFT` record parsing, and sensitive data (PII) pattern matching. It works with raw disk images (`.raw`, `.dd`, `.001`) and direct physical drives on Windows (`\\.\PhysicalDriveN`).

---

## Features

- **File Carving**: Recovers common file types (JPEG, PNG, GIF, PDF, ZIP/DOCX/XLSX, RIFF/WAV/AVI, SQLite, and executables) using structural format validation rather than simple header-matching.
- **NTFS $MFT Analysis**: Parses raw Master File Table records directly, handles sector Update Sequence Array (USA) fixups, extracts resident file data, and reconstructs folder trees for deleted files.
- **Sensitive Data & PII Search**: Scans raw binary blocks for credit card numbers (Visa, MasterCard, Amex, Discover, JCB) verified with the **Luhn Mod 10** algorithm, cryptocurrency addresses, and email addresses, with automatic number masking.
- **Low Memory Overhead**: Built with `@dataclass(slots=True)` and on-demand byte reading. Discovered file contents are not kept in RAM, allowing large images to be scanned with minimal memory consumption.
- **Integrity & Sealing**: Generates companion `.sha256` files for all export reports and recovered manifests, alongside UTC timestamped audit logs.
- **Zero-Dependency Core**: The core carving engine, CLI, and SDK require only the Python standard library.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ShadowWolfSec/Digital-Forensics-Carving-Analysis-Tool.git
cd forensics-carver
```

Verify that all unit and integration tests pass (no external packages needed):

```bash
python -m unittest discover tests -v
```

---

## Usage

### 1. Web Dashboard (Primary Interface)

The interactive web dashboard provides a complete graphical interface for scanning, browsing results, viewing hex sectors, and exploring NTFS directories.

```bash
# 1. Install lightweight GUI & reporting packages
pip install -r requirements.txt

# 2. Launch the local web server
python gui_app.py
```

Open your browser at **`http://127.0.0.1:5000`** to access:
- **Scan Manager**: Configure block sizes, select file signatures, and track real-time carving progress.
- **Results Explorer**: Filter and sort recovered files with instant image previews.
- **Hex Viewer**: Interactive sector-aligned byte visualizer with ASCII translation and offset jumping.
- **MFT Explorer**: Navigate NTFS directory structures and view deleted records.
- **Evidence Comparison**: Side-by-side binary diffing and image similarity comparison.

---

### 2. Command-Line Interface (CLI)

The CLI tool [`cli.py`](cli.py) runs headless with zero third-party dependencies:

```bash
# Basic scan: carve files and generate reports
python cli.py scan evidence.raw --output ./recovered --recover

# Carve only specific categories or signatures
python cli.py scan evidence.raw --category Documents --recover
python cli.py scan evidence.raw --signatures jpeg,png,sqlite --output ./extracted

# Scan for payment cards and sensitive PII
python cli.py search evidence.raw --output pii_findings.json

# Parse NTFS $MFT and list deleted records
python cli.py mft evidence.raw --deleted-only --output mft_report.json

# View registered file signatures
python cli.py sigs --category Images

# Quick evidence inspection (size, format, preliminary hash)
python cli.py info evidence.raw
```

---

### 3. Python SDK (`sdk.py`)

You can integrate the carver into custom scripts or automation pipelines using the [`ForensicsCarver`](sdk.py) class:

```python
from sdk import ForensicsCarver

# Initialize session
carver = ForensicsCarver("evidence.raw", output_dir="./case_output")

# Run carving pass
result = carver.scan(category="Images")

# Save recovered files to disk
recovered_count = carver.recover_files(result)
print(f"Recovered {recovered_count} files.")

# Generate sealed reports
carver.generate_report(result, fmt="json")
carver.generate_report(result, fmt="html")

# Search raw disk for sensitive patterns
matches = carver.search_sensitive_data()
for match in matches:
    print(f"Found {match.pattern_type} [{match.masked_value}] at offset 0x{match.offset:X}")
```

---

### 4. Desktop GUI (PyQt5 Alternative)

A standalone desktop interface is also available using PyQt5:

```bash
pip install PyQt5
python desktop_gui.py
```

---

## Supported Evidence Inputs

| Format | Description |
| :--- | :--- |
| **Raw / DD** (`.raw`, `.dd`, `.img`, `.bin`) | Flat sector-by-sector uncompressed bitstream copies. |
| **Split Raw** (`.001`, `.002`, ...) | Multi-part raw disk segments read sequentially. |
| **Physical Media** (`\\.\PhysicalDrive0`) | Direct read-only access to physical disks on Windows (requires Administrator). |

---

## Requirements Overview

| File | Purpose | Included Packages |
| :--- | :--- | :--- |
| **None** (Standard Library) | Core Engine, CLI, and SDK | `hashlib`, `struct`, `ctypes`, `sqlite3`, `dataclasses` |
| [`requirements.txt`](requirements.txt) | Web Dashboard & PDF reports | `Flask`, `Pillow`, `reportlab` |
| [`requirements-optional.txt`](requirements-optional.txt) | Extra tools & desktop UI | `pyHanko`, `iptcinfo3`, `PyQt5`, `yara-python` |

---

## Testing

The test suite includes 47 unit and integration tests covering signature matching, validators, MFT parsing, Luhn checksums, and path traversal prevention:

```bash
python -m unittest discover tests -v
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Developed by* ***Eng. RASHEED AL-RAJEHI @ SHADOW WOLF SECURITY***