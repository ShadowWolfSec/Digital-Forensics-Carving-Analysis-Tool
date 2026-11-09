from __future__ import annotations

import io
import math
from typing import Any, Dict, List, Optional, Tuple

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def _compute_dct_2d(matrix: List[List[float]], n: int = 32) -> List[List[float]]:
    dct = [[0.0] * n for _ in range(n)]
    factor = math.pi / (2.0 * n)

    # Precompute cosines
    cos_cache = [[math.cos((2 * i + 1) * k * factor) for k in range(n)] for i in range(n)]

    for u in range(min(n, 8)):
        alpha_u = 1.0 / math.sqrt(n) if u == 0 else math.sqrt(2.0 / n)
        for v in range(min(n, 8)):
            alpha_v = 1.0 / math.sqrt(n) if v == 0 else math.sqrt(2.0 / n)
            sum_val = 0.0
            for i in range(n):
                c_i = cos_cache[i][u]
                for j in range(n):
                    sum_val += matrix[i][j] * c_i * cos_cache[j][v]
            dct[u][v] = alpha_u * alpha_v * sum_val

    return dct


def _get_pixel_list(img: Image.Image) -> list:
    if hasattr(img, "get_flattened_data"):
        return list(img.get_flattened_data())
    return list(img.getdata())


class PerceptualHasher:

    @classmethod
    def is_available(cls) -> bool:
        return PIL_AVAILABLE

    @classmethod
    def _load_image(cls, img_data: bytes | io.BytesIO) -> Optional[Image.Image]:
        if not PIL_AVAILABLE:
            return None
        try:
            if isinstance(img_data, bytes):
                img_io = io.BytesIO(img_data)
            else:
                img_io = img_data
            img = Image.open(img_io)
            return img.convert("L")  
        except Exception:
            return None

    @classmethod
    def dhash(cls, img_data: bytes) -> Optional[str]:
        """
        Compute Difference Hash (dHash).
        Resizes to 9x8, compares horizontal gradient. Returns 16-char hex string.
        """
        img = cls._load_image(img_data)
        if img is None:
            return None

        resized = img.resize((9, 8), Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.ANTIALIAS)
        pixels = _get_pixel_list(resized)

        diff = 0
        for row in range(8):
            row_start = row * 9
            for col in range(8):
                left = pixels[row_start + col]
                right = pixels[row_start + col + 1]
                diff = (diff << 1) | (1 if left > right else 0)

        return f"{diff:016x}"

    @classmethod
    def ahash(cls, img_data: bytes) -> Optional[str]:
        """
        Compute Average Hash (aHash).
        Resizes to 8x8, compares each pixel to mean. Returns 16-char hex string.
        """
        img = cls._load_image(img_data)
        if img is None:
            return None

        resized = img.resize((8, 8), Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.ANTIALIAS)
        pixels = _get_pixel_list(resized)
        avg = sum(pixels) / len(pixels) if pixels else 0

        hash_int = 0
        for p in pixels:
            hash_int = (hash_int << 1) | (1 if p >= avg else 0)

        return f"{hash_int:016x}"

    @classmethod
    def phash(cls, img_data: bytes) -> Optional[str]:
        """
        Compute Perceptual Hash (pHash) via Discrete Cosine Transform.
        Resizes to 32x32, computes DCT, extracts top 8x8 frequencies. Returns 16-char hex string.
        """
        img = cls._load_image(img_data)
        if img is None:
            return None

        resized = img.resize((32, 32), Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.ANTIALIAS)
        raw_pixels = _get_pixel_list(resized)
        matrix = [raw_pixels[i * 32 : (i + 1) * 32] for i in range(32)]

        # 2D DCT top-left 8x8
        dct = _compute_dct_2d(matrix, n=32)

        # Exclude DC component (0, 0)
        vals = []
        for u in range(8):
            for v in range(8):
                if u == 0 and v == 0:
                    continue
                vals.append(dct[u][v])

        if not vals:
            return "0" * 16

        median = sorted(vals)[len(vals) // 2]
        hash_int = 0
        for val in vals:
            hash_int = (hash_int << 1) | (1 if val > median else 0)

        return f"{hash_int:016x}"

    @classmethod
    def hamming_distance(cls, hash1: str, hash2: str) -> int:
        """Calculate bitwise Hamming distance between two 16-character hex hashes (0 to 64)."""
        if not hash1 or not hash2 or len(hash1) != 16 or len(hash2) != 16:
            return 64
        try:
            x = int(hash1, 16) ^ int(hash2, 16)
            return bin(x).count("1")
        except ValueError:
            return 64

    @classmethod
    def similarity_percentage(cls, hash1: str, hash2: str) -> float:
        """
        Convert Hamming distance to similarity percentage:
        0 distance = 100% similarity (visually identical)
        <= 6 distance = 90%+ similarity (slight compression/crop)
        """
        dist = cls.hamming_distance(hash1, hash2)
        score = (1.0 - dist / 64.0) * 100.0
        return round(max(0.0, min(100.0, score)), 1)

    @classmethod
    def compare_images(cls, img_a: bytes, img_b: bytes) -> Dict[str, Any]:
        """Perform comprehensive visual comparison between two images."""
        d1 = cls.dhash(img_a)
        d2 = cls.dhash(img_b)
        p1 = cls.phash(img_a)
        p2 = cls.phash(img_b)
        a1 = cls.ahash(img_a)
        a2 = cls.ahash(img_b)

        if not d1 or not d2:
            return {
                "ok": False,
                "error": "Failed to decode one or both images.",
            }

        d_dist = cls.hamming_distance(d1, d2)
        p_dist = cls.hamming_distance(p1, p2) if p1 and p2 else 64
        a_dist = cls.hamming_distance(a1, a2) if a1 and a2 else 64

        d_sim = cls.similarity_percentage(d1, d2)
        p_sim = cls.similarity_percentage(p1, p2) if p1 and p2 else 0.0
        a_sim = cls.similarity_percentage(a1, a2) if a1 and a2 else 0.0

        # Weighted composite visual score (pHash has highest weight for structural similarity)
        composite_score = round(0.5 * p_sim + 0.35 * d_sim + 0.15 * a_sim, 1)

        is_identical = d_dist == 0 and p_dist == 0 and a_dist == 0
        is_tampered_or_derived = composite_score >= 80.0 and not is_identical

        verdict = "Identical Image" if is_identical else (
            "Visually Similar / Derived Copy" if composite_score >= 85.0 else (
                "Related / Partially Similar" if composite_score >= 65.0 else "Completely Different"
            )
        )

        return {
            "ok": True,
            "composite_similarity": composite_score,
            "verdict": verdict,
            "is_identical": is_identical,
            "is_tampered_or_derived": is_tampered_or_derived,
            "dhash": {"hash_a": d1, "hash_b": d2, "distance": d_dist, "similarity": d_sim},
            "phash": {"hash_a": p1, "hash_b": p2, "distance": p_dist, "similarity": p_sim},
            "ahash": {"hash_a": a1, "hash_b": a2, "distance": a_dist, "similarity": a_sim},
        }
