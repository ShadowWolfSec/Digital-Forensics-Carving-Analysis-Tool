import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import CarvingEngine
from core.signatures import SignatureDatabase
from datetime import datetime


def test_prepare_scan():
    sig_db = SignatureDatabase()
    engine = CarvingEngine(sig_db)
    
    start_time, source_type = engine._prepare_scan("test.bin", "file")
    
    assert engine._file_counter == 0
    assert len(engine._custody) == 1
    assert len(engine._errors) == 0
    assert isinstance(start_time, datetime)
    assert source_type == "file"
    print("[PASS] test_prepare_scan passed")


def test_prepare_scan_auto_detect():
    """Test _prepare_scan with auto type detection."""
    sig_db = SignatureDatabase()
    engine = CarvingEngine(sig_db)
    
    start_time, source_type = engine._prepare_scan("test.bin", "auto")
    assert source_type in ("file", "disk_image", "physical_drive")
    print("[PASS] test_prepare_scan_auto_detect passed")


def test_finalize_scan():
    """Test _finalize_scan creates proper ScanResult."""
    sig_db = SignatureDatabase()
    engine = CarvingEngine(sig_db)
    
    from core.models import CarvedFile, FileSignature, HashBundle, ValidationResult
    
    sig = FileSignature(
        id="test",
        name="Test",
        description="Test desc",
        category="test",
        extensions=["bin"],
        mime_type="application/octet-stream",
        header=b"TEST",
        header_offset=0,
        validator="validate_png",
        confidence=0.9
    )
    
    carved = [
        CarvedFile(
            id=1,
            signature=sig,
            start_offset=0,
            end_offset=100,
            size=100,
            confidence=0.9,
            recovery_status="COMPLETE",
            header_hex="54455354",
            trailer_hex="",
            validation=ValidationResult(is_valid=True, message="Valid", confidence_boost=0.0),
            hashes=HashBundle(md5="abc", sha1="def", sha256="ghi"),
            entropy=None,
            metadata=None,
            data=None,
            blocks=[(0, 100)]
        )
    ]
    
    source_hash = HashBundle(md5="test_md5", sha1="test_sha1", sha256="test_sha256")
    start_time = datetime.utcnow()
    
    result = engine._finalize_scan(
        source_path="test.bin",
        source_type="file",
        source_hash=source_hash,
        start_time=start_time,
        carved=carved,
        bytes_scanned=1000,
        blocks_scanned=10
    )
    
    # Verify result
    assert result.source_path == "test.bin"
    assert result.source_type == "file"
    assert result.source_hash == source_hash
    assert result.files_found == 1
    assert result.blocks_scanned == 10
    assert result.bytes_scanned == 1000
    assert len(result.carved_files) == 1
    print("[PASS] test_finalize_scan passed")


def test_engine_initialization():
    """Test CarvingEngine initialization."""
    sig_db = SignatureDatabase()
    engine = CarvingEngine(sig_db)
    
    assert engine.sig_db == sig_db
    assert engine._file_counter == 0
    assert len(engine._custody) == 0
    assert len(engine._errors) == 0
    print("[PASS] test_engine_initialization passed")


def test_engine_stop_flag():
    """Test engine stop flag functionality."""
    sig_db = SignatureDatabase()
    engine = CarvingEngine(sig_db)
    
    assert engine._stop[0] == False
    
    engine.stop()
    assert engine._stop[0] == True
    print("[PASS] test_engine_stop_flag passed")


def test_engine_with_temp_file():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        temp_path = f.name
        f.write(b"\x89PNG\r\n\x1a\n")  
        f.write(b"IHDR" + b"\x00" * 13)
        f.write(b"X" * 1000)
    
    try:
        sig_db = SignatureDatabase()
        engine = CarvingEngine(sig_db)
        
        result = engine.scan(temp_path, source_type="file", max_bytes=2000)
        
        assert result.source_path == temp_path
        assert result.source_type == "file"
        assert isinstance(result.files_found, int)
        assert isinstance(result.blocks_scanned, int)
        assert isinstance(result.bytes_scanned, int)
        assert isinstance(result.carved_files, list)
        print("[PASS] test_engine_with_temp_file passed")
    finally:
        Path(temp_path).unlink()


def test_engine_triage_mode():
    """Test Fast Triage scan mode returns primary files without carving embedded objects."""
    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp()
    try:
        png_path = Path(temp_dir) / "image.png"
        png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00"
        png_path.write_bytes(png_header + b"\x00" * 200)

        pdf_path = Path(temp_dir) / "doc.pdf"
        pdf_data = b"%PDF-1.4\n" + b"A" * 100 + b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xFF\xD9" + b"\n%%EOF"
        pdf_path.write_bytes(pdf_data)

        sig_db = SignatureDatabase()
        engine = CarvingEngine(sig_db)

        # Triage mode
        result = engine.scan(temp_dir, source_type="directory", scan_mode="triage")
        assert result.files_found == 2, f"Expected 2 files in triage, got {result.files_found}"
        assert result.primary_files_count == 2
        assert result.embedded_artifacts_count == 0
        for f in result.carved_files:
            assert f.is_embedded == False
            assert f.artifact_type == "primary"
        print("[PASS] test_engine_triage_mode passed")
    finally:
        shutil.rmtree(temp_dir)


def test_engine_hierarchy_classification():
    """Test that Deep Carving correctly classifies primary files vs embedded objects."""
    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp()
    try:
        pdf_path = Path(temp_dir) / "embedded_test.pdf"
        jpeg_part = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"X" * 100 + b"\xFF\xC0\x00\x11\x08\x00\x10\x00\x10\x01\x01\x11\x00\xFF\xDA\x00\x08\x01\x01\x00\x00\x3F\x00" + b"\xFF\xD9"
        pdf_data = b"%PDF-1.5\n" + b"B" * 500 + jpeg_part + b"\n%%EOF"
        pdf_path.write_bytes(pdf_data)

        sig_db = SignatureDatabase()
        engine = CarvingEngine(sig_db)

        result = engine.scan(temp_dir, source_type="directory", scan_mode="deep")
        primary_items = [f for f in result.carved_files if not f.is_embedded]
        embedded_items = [f for f in result.carved_files if f.is_embedded]

        assert len(primary_items) >= 1, "Expected primary container PDF"
        assert primary_items[0].start_offset == 0
        assert primary_items[0].artifact_type == "primary"

        if len(embedded_items) >= 1:
            assert embedded_items[0].start_offset > 0
            assert embedded_items[0].artifact_type == "embedded"
            assert "parent_container" in embedded_items[0].metadata

        print("[PASS] test_engine_hierarchy_classification passed")
    finally:
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    print("Running engine tests...")
    print()
    
    test_prepare_scan()
    test_prepare_scan_auto_detect()
    test_finalize_scan()
    test_engine_initialization()
    test_engine_stop_flag()
    test_engine_with_temp_file()
    test_engine_triage_mode()
    test_engine_hierarchy_classification()
    
    print()
    print("All engine tests passed! [PASS]")
