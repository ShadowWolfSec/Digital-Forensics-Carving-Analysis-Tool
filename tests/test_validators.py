import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.validators import dispatch, validate_png, validate_jpeg, validate_pdf, validate_zip
from core.models import ValidationResult


def test_validate_png_valid():
    """Test PNG validation with valid PNG data."""
    png_header = b"\x89PNG\r\n\x1a\n"
    ihdr = b"\x00\x00\x00\x0dIHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00"
    png_data = png_header + ihdr
    
    result = validate_png(png_data)
    
    assert result.is_valid
    assert result.confidence_boost >= -0.15
    assert "PNG" in result.message.upper()
    print("[PASS] test_validate_png_valid passed")


def test_validate_png_invalid():
    """Test PNG validation with invalid data."""
    invalid_data = b"This is not a PNG file"
    
    result = validate_png(invalid_data)
    
    assert not result.is_valid
    assert result.confidence_boost < 0.0
    print("[PASS] test_validate_png_invalid passed")


def test_validate_jpeg_valid():
    # Minimal valid JPEG: SOI marker
    jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    
    result = validate_jpeg(jpeg_data)
    
    assert result.is_valid
    assert result.confidence_boost >= -0.2
    print("[PASS] test_validate_jpeg_valid passed")


def test_validate_jpeg_invalid():
    """Test JPEG validation with invalid data."""
    invalid_data = b"Not a JPEG file"
    
    result = validate_jpeg(invalid_data)
    
    assert not result.is_valid
    assert result.confidence_boost < 0.0
    print("[PASS] test_validate_jpeg_invalid passed")


def test_validate_pdf_valid():
    """Test PDF validation with valid PDF data."""
    pdf_data = b"%PDF-1.4\n%%EOF"
    
    result = validate_pdf(pdf_data)
    
    assert result.is_valid
    assert result.confidence_boost >= -0.1
    print("[PASS] test_validate_pdf_valid passed")


def test_validate_pdf_invalid():
    """Test PDF validation with invalid data."""
    invalid_data = b"Not a PDF file"
    
    result = validate_pdf(invalid_data)
    
    assert not result.is_valid
    assert result.confidence_boost < 0.0
    print("[PASS] test_validate_pdf_invalid passed")


def test_validate_zip_valid():
    """Test ZIP validation with valid ZIP data."""
    # Minimal valid ZIP: Local file header
    zip_data = b"PK\x03\x04" + b"\x00" * 26  # Signature + header
    zip_data += b"test.txt" + b"\x00" * 6  # Filename + extra field
    zip_data += b"PK\x05\x06" + b"\x00" * 18  # End of central directory
    
    result = validate_zip(zip_data)
    
    assert result.is_valid
    assert result.confidence_boost >= -0.2
    print("[PASS] test_validate_zip_valid passed")


def test_validate_zip_invalid():
    """Test ZIP validation with invalid data."""
    invalid_data = b"Not a ZIP file"
    
    result = validate_zip(invalid_data)
    
    assert not result.is_valid
    assert result.confidence_boost < 0.0
    print("[PASS] test_validate_zip_invalid passed")


def test_dispatch_png():
    """Test dispatch function with PNG validator."""
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR" + b"\x00" * 13
    
    result = dispatch("validate_png", png_data)
    
    assert result is not None
    assert isinstance(result, ValidationResult)
    print("[PASS] test_dispatch_png passed")


def test_dispatch_invalid_validator():
    data = b"Some data"
    
    result = dispatch("nonexistent_validator", data)
    
    assert result is not None
    assert isinstance(result, ValidationResult)
    assert result.is_valid
    print("[PASS] test_dispatch_invalid_validator passed")


def test_dispatch_exception_handling():
    bad_data = b"\x00" * 10
    
    result = dispatch("validate_png", bad_data)
    
    # Should not crash, return a ValidationResult
    assert result is not None
    assert isinstance(result, ValidationResult)
    print("[PASS] test_dispatch_exception_handling passed")


def test_strict_rejects_false_positives():
    fake_pe = b"MZ" + bytes(100)
    res_pe = dispatch("validate_pe", fake_pe)
    assert not res_pe.is_valid, "Random MZ must be rejected"

    fake_bmp = b"BM" + bytes(100)
    res_bmp = dispatch("validate_bmp", fake_bmp)
    assert not res_bmp.is_valid, "Random BM must be rejected"

    fake_gz = b"\x1F\x8B\xFA\xFF" + bytes(50)
    res_gz = dispatch("validate_gz", fake_gz)
    assert not res_gz.is_valid, "Random GZ must be rejected"

    fake_id3 = b"ID3\x09\x99\xFF\x80\x00\x00\x01\x12\x34"
    res_id3 = dispatch("validate_id3", fake_id3)
    assert not res_id3.is_valid, "Random ID3 bytes must be rejected"

    valid_id3 = b"ID3\x03\x00\x00\x00\x00\x07\x68TIT2\x00\x00\x00\x0A\x00\x00" + b"Test Title"
    res_valid_id3 = dispatch("validate_id3", valid_id3)
    assert res_valid_id3.is_valid, "Valid ID3 tag must pass"
    print("[PASS] test_strict_rejects_false_positives passed")


def test_validate_bz2():
    valid_bz2 = b"BZh9" + bytes.fromhex("314159265359") + b"\x00" * 30
    res = dispatch("validate_bz2", valid_bz2)
    assert res.is_valid, f"Valid BZ2 should pass: {res.message}"

    fake_bz2_level = b"BZhX" + bytes.fromhex("314159265359")
    res_fake = dispatch("validate_bz2", fake_bz2_level)
    assert not res_fake.is_valid, "Invalid level must fail"

    fake_bz2_magic = b"BZh9randomdatahere"
    res_fake_magic = dispatch("validate_bz2", fake_bz2_magic)
    assert not res_fake_magic.is_valid, "Invalid magic must fail"
    print("[PASS] test_validate_bz2 passed")


def test_validate_eml():
    valid_eml = b"From: user@test.com\r\nSubject: Test Subject\r\nDate: Sat, 31 Oct 2026\r\n\r\nBody text"
    res = dispatch("validate_eml", valid_eml)
    assert res.is_valid, f"Valid EML should pass: {res.message}"

    fake_eml = b"From our analysis, this text is not an email."
    res_fake = dispatch("validate_eml", fake_eml)
    assert not res_fake.is_valid, "Plain text starting with 'From ' must fail"
    print("[PASS] test_validate_eml passed")


if __name__ == "__main__":
    print("Running validator tests...")
    print()
    
    test_validate_png_valid()
    test_validate_png_invalid()
    test_validate_jpeg_valid()
    test_validate_jpeg_invalid()
    test_validate_pdf_valid()
    test_validate_pdf_invalid()
    test_validate_zip_valid()
    test_validate_zip_invalid()
    test_dispatch_png()
    test_dispatch_invalid_validator()
    test_dispatch_exception_handling()
    test_strict_rejects_false_positives()
    test_validate_bz2()
    test_validate_eml()
    
    print()
    print("All validator tests passed! [PASS]")
