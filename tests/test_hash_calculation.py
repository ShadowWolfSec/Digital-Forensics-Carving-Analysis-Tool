"""
Unit tests for hash calculation functions.
Tests the calculate_hashes_from_stream function from core.models.
"""

import sys
from pathlib import Path
from io import BytesIO

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import calculate_hashes_from_stream, HashBundle


def test_hash_from_bytes():
    """Test hashing from a simple bytes object."""
    data = b"Hello, World! This is a test string for hashing."
    bio = BytesIO(data)
    
    result = calculate_hashes_from_stream(bio.read, max_bytes=len(data))
    
    assert result is not None
    assert isinstance(result, HashBundle)
    assert len(result.md5) == 32
    assert len(result.sha1) == 40
    assert len(result.sha256) == 64
    print("[PASS] test_hash_from_bytes passed")


def test_hash_from_file_like():
    """Test hashing from a file-like object (BytesIO)."""
    data = b"Another test string for file-like object hashing."
    bio = BytesIO(data)
    
    result = calculate_hashes_from_stream(bio.read, max_bytes=len(data))
    
    assert result is not None
    assert isinstance(result, HashBundle)
    assert len(result.md5) == 32
    assert len(result.sha1) == 40
    assert len(result.sha256) == 64
    print("[PASS] test_hash_from_file_like passed")


def test_hash_with_max_bytes():
    """Test hashing with max_bytes limit."""
    data = b"X" * 10000  
    
    bio1 = BytesIO(data)
    bio2 = BytesIO(data)
    
    # Hash only first 1KB
    result = calculate_hashes_from_stream(bio1.read, max_bytes=1024)
    full_hash = calculate_hashes_from_stream(bio2.read, max_bytes=len(data))
    
    assert result is not None
    assert full_hash is not None
    assert result.md5 != full_hash.md5
    print("[PASS] test_hash_with_max_bytes passed")


def test_hash_empty_data():
    """Test hashing empty data."""
    def read_fn(length):
        return b""
    
    result = calculate_hashes_from_stream(read_fn, max_bytes=100)
    
    assert result is not None
    assert result.md5 == "d41d8cd98f00b204e9800998ecf8427e"  # MD5 of empty string
    print("[PASS] test_hash_empty_data passed")


def test_hash_error_handling():
    """Test error handling when read_fn raises exception."""
    def failing_read_fn(length):
        raise IOError("Simulated read error")
    
    result = calculate_hashes_from_stream(failing_read_fn, max_bytes=100)
    
    assert result is None
    print("[PASS] test_hash_error_handling passed")


def test_hash_chunked_reading():
    """Test that data is read in chunks (memory efficiency)."""
    large_data = b"X" * 200000 
    bio = BytesIO(large_data)
    call_count = [0]
    
    def chunked_read_fn(length):
        call_count[0] += 1
        return bio.read(length)
    
    result = calculate_hashes_from_stream(chunked_read_fn, max_bytes=len(large_data))
    
    assert result is not None
    assert call_count[0] > 1
    print("[PASS] test_hash_chunked_reading passed")


if __name__ == "__main__":
    print("Running hash calculation tests...")
    print()
    
    test_hash_from_bytes()
    test_hash_from_file_like()
    test_hash_with_max_bytes()
    test_hash_empty_data()
    test_hash_error_handling()
    test_hash_chunked_reading()
    
    print()
    print("All hash calculation tests passed! [PASS]")
