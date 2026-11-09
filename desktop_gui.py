from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

_pkg_dir = str(Path(__file__).parent)
if _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

try:
    from forensics_tool.sdk import ForensicsCarver, SDKOptions
except ImportError:
    from sdk import ForensicsCarver, SDKOptions

@dataclass
class AppState:
    result: Any = None
    triage: List[Any] = None
    timeline: List[Any] = None
    source_path: str = ""

    def __post_init__(self):
        self.triage = self.triage or []
        self.timeline = self.timeline or []


class ScanWorker(QThread):
    success = pyqtSignal(object, object, object, str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        source_path: str,
        source_type: str,
        analyst: str,
        signature_db: str,
        yara_rules: str,
        plugins_dir: str,
        output_dir: str,
        start_mb: int,
        max_mb: int,
        recover_fragments: bool,
        no_hash: bool,
        no_entropy: bool,
    ):
        super().__init__()
        self.source_path = source_path
        self.source_type = source_type
        self.analyst = analyst
        self.signature_db = signature_db
        self.yara_rules = yara_rules
        self.plugins_dir = plugins_dir
        self.output_dir = output_dir
        self.start_mb = start_mb
        self.max_mb = max_mb
        self.recover_fragments = recover_fragments
        self.no_hash = no_hash
        self.no_entropy = no_entropy

    def run(self):
        try:
            options = SDKOptions(
                analyst=self.analyst or "desktop_user",
                compute_hashes=not self.no_hash,
                compute_entropy=not self.no_entropy,
                yara_rules_path=self.yara_rules,
                signature_db_path=self.signature_db or ":memory:",
            )
            carver = ForensicsCarver(options)
            if self.plugins_dir:
                carver.load_plugins(self.plugins_dir)

            max_bytes = self.max_mb * 1024 * 1024 if self.max_mb > 0 else None
            start_offset = self.start_mb * 1024 * 1024

            result = carver.scan(
                source_path=self.source_path,
                source_type=self.source_type,
                max_bytes=max_bytes,
                start_offset=start_offset,
                recover_fragments=self.recover_fragments,
            )
            triage = carver.triage_scan(result)
            timeline_path = str(Path("desktop_timeline_latest.json").resolve())
            timeline = carver.generate_timeline(result, timeline_path)

            if self.output_dir:
                out = Path(self.output_dir)
                out.mkdir(parents=True, exist_ok=True)
                view = carver.view_result(result)
                view.generate_report(str(out / "report.json"), fmt="json")
                view.generate_report(str(out / "report.csv"), fmt="csv")
                view.generate_report(str(out / "report.html"), fmt="html")
                try:
                    view.generate_report(str(out / "report.pdf"), fmt="pdf")
                except Exception:
                    pass
                (out / "triage.json").write_text(
                    json.dumps({"items": [t.to_dict() for t in triage]}, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )

            self.success.emit(result, triage, timeline, self.source_path)
        except Exception as e:
            self.failed.emit(str(e))


class ScanTab(QWidget):
    scan_completed = pyqtSignal(object, object, object, str)

    def __init__(self):
        super().__init__()
        self.worker: Optional[ScanWorker] = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        form_group = QGroupBox("Scan Configuration")
        form = QFormLayout(form_group)

        self.source_path = QLineEdit()
        self.source_btn = QPushButton("Browse")
        self.source_btn.clicked.connect(self._on_browse_source)
        form.addRow("Source Path*", self._with_button(self.source_path, self.source_btn))

        self.source_type = QComboBox()
        self.source_type.addItems(["auto", "file", "directory", "disk_image", "physical_drive", "e01", "aff"])
        form.addRow("Source Type", self.source_type)

        self.analyst = QLineEdit("desktop_user")
        form.addRow("Analyst", self.analyst)

        self.signature_db = QLineEdit(":memory:")
        form.addRow("Signature DB", self.signature_db)

        self.use_yara = QCheckBox("Use YARA")
        self.yara_rules = QLineEdit()
        self.yara_btn = QPushButton("Browse")
        self.yara_btn.clicked.connect(lambda: self._pick_file(self.yara_rules))
        self._set_enabled_pair(self.yara_rules, self.yara_btn, False)
        self.use_yara.toggled.connect(lambda v: self._set_enabled_pair(self.yara_rules, self.yara_btn, v))
        form.addRow(self.use_yara, self._with_button(self.yara_rules, self.yara_btn))

        self.use_plugins = QCheckBox("Use Plugins Directory")
        self.plugins_dir = QLineEdit()
        self.plugins_btn = QPushButton("Browse")
        self.plugins_btn.clicked.connect(lambda: self._pick_dir(self.plugins_dir))
        self._set_enabled_pair(self.plugins_dir, self.plugins_btn, False)
        self.use_plugins.toggled.connect(lambda v: self._set_enabled_pair(self.plugins_dir, self.plugins_btn, v))
        form.addRow(self.use_plugins, self._with_button(self.plugins_dir, self.plugins_btn))

        self.use_output = QCheckBox("Save Reports to Output Directory")
        self.output_dir = QLineEdit()
        self.output_btn = QPushButton("Browse")
        self.output_btn.clicked.connect(lambda: self._pick_dir(self.output_dir))
        self._set_enabled_pair(self.output_dir, self.output_btn, False)
        self.use_output.toggled.connect(lambda v: self._set_enabled_pair(self.output_dir, self.output_btn, v))
        form.addRow(self.use_output, self._with_button(self.output_dir, self.output_btn))

        grid = QGridLayout()
        self.start_mb = QSpinBox()
        self.start_mb.setMaximum(10_000_000)
        self.max_mb = QSpinBox()
        self.max_mb.setMaximum(10_000_000)
        grid.addWidget(QLabel("Start MB"), 0, 0)
        grid.addWidget(self.start_mb, 0, 1)
        grid.addWidget(QLabel("Max MB (0=all)"), 0, 2)
        grid.addWidget(self.max_mb, 0, 3)
        form.addRow(grid)

        flags = QHBoxLayout()
        self.recover_fragments = QCheckBox("Recover Fragments")
        self.no_hash = QCheckBox("No Hash")
        self.no_entropy = QCheckBox("No Entropy")
        flags.addWidget(self.recover_fragments)
        flags.addWidget(self.no_hash)
        flags.addWidget(self.no_entropy)
        form.addRow(flags)

        self.run_btn = QPushButton("Start Scan")
        self.run_btn.clicked.connect(self.start_scan)
        self.status = QLabel("Ready")

        root.addWidget(form_group)
        root.addWidget(self.run_btn)
        root.addWidget(self.status)
        root.addStretch(1)

    @staticmethod
    def _with_button(line: QLineEdit, btn: QPushButton):
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.addWidget(line)
        h.addWidget(btn)
        return w

    @staticmethod
    def _set_enabled_pair(line: QLineEdit, btn: QPushButton, enabled: bool):
        line.setEnabled(enabled)
        btn.setEnabled(enabled)

    @staticmethod
    def _pick_file(target: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(None, "Select File")
        if path:
            target.setText(path)

    @staticmethod
    def _pick_dir(target: QLineEdit):
        path = QFileDialog.getExistingDirectory(None, "Select Directory")
        if path:
            target.setText(path)

    def _on_browse_source(self):
        st = self.source_type.currentText()
        if st == "directory":
            self._pick_dir(self.source_path)
        elif st == "physical_drive":
            self._pick_drive(self.source_path)
        else:
            self._pick_file(self.source_path)

    def _pick_drive(self, target: QLineEdit):
        from core.drive_detector import get_system_drives
        drives = get_system_drives()
        if drives:
            items = [f"{d['id']}  [{d['display']}]" for d in drives]
        elif sys.platform == "win32":
            items = [f"\\\\.\\PhysicalDrive{i}" for i in range(8)] + [r"\\.\C:", r"\\.\D:", r"\\.\E:"]
        else:
            items = ["/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/nvme0n1", "/dev/loop0"]

        drive, ok = QInputDialog.getItem(self, "Select Drive / Volume", "Available Drives & Partitions:", items, 0, False)
        if ok and drive:
            # Extract just the drive ID part before the brackets
            selected_id = drive.split("  [")[0].strip()
            target.setText(selected_id)

    def start_scan(self):
        source = self.source_path.text().strip()
        if not source:
            QMessageBox.warning(self, "Missing Input", "Source Path is required.")
            return
        is_device = source.startswith("\\\\.\\") or source.startswith("//./") or source.startswith("/dev/")
        if not is_device and not Path(source).exists():
            QMessageBox.warning(self, "Invalid Path", f"Source path does not exist:\n{source}")
            return

        yara = self.yara_rules.text().strip() if self.use_yara.isChecked() else ""
        plugs = self.plugins_dir.text().strip() if self.use_plugins.isChecked() else ""
        out = self.output_dir.text().strip() if self.use_output.isChecked() else ""
        if self.use_yara.isChecked() and not yara:
            QMessageBox.warning(self, "Missing Input", "YARA is enabled but path is empty.")
            return
        if self.use_plugins.isChecked() and not plugs:
            QMessageBox.warning(self, "Missing Input", "Plugins is enabled but directory is empty.")
            return
        if self.use_output.isChecked() and not out:
            QMessageBox.warning(self, "Missing Input", "Output is enabled but directory is empty.")
            return

        self.run_btn.setEnabled(False)
        self.status.setText("Scanning... please wait")
        self.worker = ScanWorker(
            source_path=source,
            source_type=self.source_type.currentText(),
            analyst=self.analyst.text().strip(),
            signature_db=self.signature_db.text().strip(),
            yara_rules=yara,
            plugins_dir=plugs,
            output_dir=out,
            start_mb=self.start_mb.value(),
            max_mb=self.max_mb.value(),
            recover_fragments=self.recover_fragments.isChecked(),
            no_hash=self.no_hash.isChecked(),
            no_entropy=self.no_entropy.isChecked(),
        )
        self.worker.success.connect(self._on_success)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def _on_success(self, result, triage, timeline, source_path):
        self.run_btn.setEnabled(True)
        self.status.setText(f"Done: {result.files_found} files found")
        self.scan_completed.emit(result, triage, timeline, source_path)

    def _on_failed(self, err: str):
        self.run_btn.setEnabled(True)
        self.status.setText("Scan failed")
        QMessageBox.critical(self, "Scan Error", err)


class ResultsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.files_table = QTableWidget(0, 6)
        self.files_table.setHorizontalHeaderLabels(["ID", "Type", "Start", "Size", "Confidence", "Status"])
        self.triage_table = QTableWidget(0, 5)
        self.triage_table.setHorizontalHeaderLabels(["File", "Priority", "Risk", "Score", "Reasons"])
        self.timeline_table = QTableWidget(0, 3)
        self.timeline_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Description"])

        splitter = QSplitter()
        top = QWidget()
        top_l = QVBoxLayout(top)
        top_l.addWidget(QLabel("Summary"))
        top_l.addWidget(self.summary)
        top_l.addWidget(QLabel("Recovered Files"))
        top_l.addWidget(self.files_table)
        bottom = QWidget()
        bottom_l = QVBoxLayout(bottom)
        bottom_l.addWidget(QLabel("AI Triage"))
        bottom_l.addWidget(self.triage_table)
        bottom_l.addWidget(QLabel("Timeline"))
        bottom_l.addWidget(self.timeline_table)
        splitter.addWidget(top)
        splitter.addWidget(bottom)
        root.addWidget(splitter)

    def set_data(self, result, triage, timeline):
        s = result.summary()
        self.summary.setPlainText(
            f"Source: {s['source']}\n"
            f"Type: {s['source_type']}\n"
            f"Files Found: {s['files_found']}\n"
            f"Bytes Scanned: {s['bytes_scanned_human']}\n"
            f"Duration: {s['duration_seconds']}s\n"
            f"Errors: {len(s['errors'])}\n"
        )

        self.files_table.setRowCount(len(result.carved_files))
        for r, f in enumerate(result.carved_files):
            self.files_table.setItem(r, 0, QTableWidgetItem(str(f.id)))
            self.files_table.setItem(r, 1, QTableWidgetItem(f.type_name))
            self.files_table.setItem(r, 2, QTableWidgetItem(f"0x{f.start_offset:X}"))
            self.files_table.setItem(r, 3, QTableWidgetItem(str(f.size)))
            self.files_table.setItem(r, 4, QTableWidgetItem(f"{f.confidence:.2f}"))
            self.files_table.setItem(r, 5, QTableWidgetItem(f.recovery_status))

        triage_items = [t.to_dict() if hasattr(t, "to_dict") else t for t in triage]
        self.triage_table.setRowCount(len(triage_items))
        for r, t in enumerate(triage_items):
            self.triage_table.setItem(r, 0, QTableWidgetItem(f"#{t.get('file_id', '')}"))
            self.triage_table.setItem(r, 1, QTableWidgetItem(str(t.get("priority", ""))))
            self.triage_table.setItem(r, 2, QTableWidgetItem(str(t.get("risk", ""))))
            self.triage_table.setItem(r, 3, QTableWidgetItem(str(t.get("score", ""))))
            self.triage_table.setItem(r, 4, QTableWidgetItem(", ".join(t.get("reasons", []))))

        timeline_items = [e.to_dict() if hasattr(e, "to_dict") else e for e in timeline[:500]]
        self.timeline_table.setRowCount(len(timeline_items))
        for r, e in enumerate(timeline_items):
            self.timeline_table.setItem(r, 0, QTableWidgetItem(str(e.get("timestamp", ""))))
            self.timeline_table.setItem(r, 1, QTableWidgetItem(str(e.get("event_type", ""))))
            self.timeline_table.setItem(r, 2, QTableWidgetItem(str(e.get("description", ""))))


class HexViewerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.current_source = ""
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        top = QHBoxLayout()
        self.source = QLineEdit()
        browse = QPushButton("Browse")
        browse.clicked.connect(self._pick_source)
        self.offset = QSpinBox()
        self.offset.setMaximum(2_000_000_000)
        self.length = QSpinBox()
        self.length.setRange(16, 8192)
        self.length.setValue(512)
        self.width = QSpinBox()
        self.width.setRange(8, 32)
        self.width.setValue(16)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Hex search e.g. 50 4B 03 04")
        load = QPushButton("Load")
        load.clicked.connect(self.load_hex)
        prev_btn = QPushButton("Prev")
        prev_btn.clicked.connect(self.prev_page)
        next_btn = QPushButton("Next")
        next_btn.clicked.connect(self.next_page)

        top.addWidget(QLabel("Source"))
        top.addWidget(self.source, 1)
        top.addWidget(browse)
        top.addWidget(QLabel("Offset"))
        top.addWidget(self.offset)
        top.addWidget(QLabel("Length"))
        top.addWidget(self.length)
        top.addWidget(QLabel("Width"))
        top.addWidget(self.width)
        top.addWidget(self.search, 1)
        top.addWidget(load)
        top.addWidget(prev_btn)
        top.addWidget(next_btn)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Offset", "Hex", "ASCII"])
        self.table.setColumnWidth(0, 120)
        self.table.setColumnWidth(1, 520)
        root.addLayout(top)
        root.addWidget(self.table)

    def set_source(self, source: str):
        if source:
            self.source.setText(source)
            self.current_source = source

    def _pick_source(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Source File")
        if path:
            self.set_source(path)

    def load_hex(self):
        source = self.source.text().strip()
        if not source:
            QMessageBox.warning(self, "Missing Input", "Source file or device path is required.")
            return
        is_device = source.startswith("\\\\.\\") or source.startswith("//./") or source.startswith("/dev/")
        if not is_device and not Path(source).exists():
            QMessageBox.warning(self, "Invalid Path", f"File not found:\n{source}")
            return

        offset = self.offset.value()
        length = self.length.value()
        width = self.width.value()

        from core.image_readers import reader_for_source
        ext = Path(source).suffix.lower() if not is_device else ""
        stype = "e01" if ext in (".e01", ".ex01") else ("aff" if ext in (".aff", ".afd", ".afm") else "file")
        try:
            with reader_for_source(source, stype) as reader:
                data = reader.read_at(offset, length)
        except Exception as e:
            QMessageBox.critical(self, "Read Error", f"Failed reading source: {e}")
            return

        query = self.search.text().strip().upper()
        self.table.setRowCount(0)
        for i in range(0, len(data), width):
            chunk = data[i : i + width]
            off = offset + i
            hex_text = " ".join(f"{b:02X}" for b in chunk)
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(f"0x{off:X}"))
            self.table.setItem(r, 1, QTableWidgetItem(hex_text))
            self.table.setItem(r, 2, QTableWidgetItem(ascii_text))
            if query and query in hex_text:
                for c in (0, 1, 2):
                    self.table.item(r, c).setBackground(QtColor.yellow())

    def prev_page(self):
        self.offset.setValue(max(0, self.offset.value() - self.length.value()))
        self.load_hex()

    def next_page(self):
        self.offset.setValue(self.offset.value() + self.length.value())
        self.load_hex()


class QtColor:
    @staticmethod
    def yellow():
        from PyQt5.QtGui import QColor

        return QColor(255, 245, 157)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital Forensics Tool - Desktop GUI")
        self.resize(1400, 900)
        self.state = AppState()
        self._build_ui()

    def _build_ui(self):
        tabs = QTabWidget()
        self.scan_tab = ScanTab()
        self.results_tab = ResultsTab()
        self.hex_tab = HexViewerTab()
        tabs.addTab(self.scan_tab, "Scan")
        tabs.addTab(self.results_tab, "Results")
        tabs.addTab(self.hex_tab, "Hex Viewer")
        self.scan_tab.scan_completed.connect(self.on_scan_completed)
        self.setCentralWidget(tabs)

    def on_scan_completed(self, result, triage, timeline, source_path):
        self.state.result = result
        self.state.triage = triage
        self.state.timeline = timeline
        self.state.source_path = source_path
        self.results_tab.set_data(result, triage, timeline)
        self.hex_tab.set_source(source_path)
        QMessageBox.information(self, "Scan Complete", f"Recovered files: {result.files_found}")


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

