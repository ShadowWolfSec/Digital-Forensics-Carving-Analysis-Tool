from __future__ import annotations

import math
from typing import Optional, Tuple

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ROLLING_WINDOW = 7
MIN_BLOCK_SIZE = 3
SPAMSUM_LENGTH = 64


class RollingHash:
    __slots__ = ("window", "w_idx", "h1", "h2", "h3")

    def __init__(self):
        self.window = [0] * ROLLING_WINDOW
        self.w_idx = 0
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0

    def update(self, b: int):
        self.h2 = (self.h2 - self.h1 + ROLLING_WINDOW * b) & 0xFFFFFFFF
        self.h1 = (self.h1 + b - self.window[self.w_idx]) & 0xFFFFFFFF
        self.window[self.w_idx] = b
        self.w_idx = (self.w_idx + 1) % ROLLING_WINDOW
        self.h3 = ((self.h3 << 5) ^ b) & 0xFFFFFFFF

    @property
    def value(self) -> int:
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF


def _fnv_hash_byte(h: int, b: int) -> int:
    """FNV-1a 32-bit hash step."""
    return ((h ^ b) * 0x01000193) & 0xFFFFFFFF


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if len(s2) == 0:
        return len(s1)

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1] + [0] * len(s2)
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr[j + 1] = min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost)
        prev = curr
    return prev[len(s2)]


def _common_substring_score(s1: str, s2: str) -> int:
    dist = _levenshtein_distance(s1, s2)
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 100
    score = int(math.floor((1.0 - float(dist) / float(max_len)) * 100.0))
    return max(0, min(100, score))


class FuzzyHasher:

    @classmethod
    def compute(cls, data: bytes) -> str:
       
        if not data:
            return f"{MIN_BLOCK_SIZE}::"

        data_len = len(data)
        # Determine starting block size
        bs = MIN_BLOCK_SIZE
        while bs * SPAMSUM_LENGTH < data_len:
            bs *= 2

        # Hash with block_size bs and 2*bs
        while True:
            h1, h2 = cls._hash_with_block_size(data, bs)
            if bs <= MIN_BLOCK_SIZE or len(h1) >= (SPAMSUM_LENGTH // 2):
                break
            bs = max(MIN_BLOCK_SIZE, bs // 2)

        return f"{bs}:{h1}:{h2}"

    @classmethod
    def _hash_with_block_size(cls, data: bytes, bs: int) -> Tuple[str, str]:
        h1_chars = []
        h2_chars = []

        roll = RollingHash()
        fnv1 = 0x811C9DC5
        fnv2 = 0x811C9DC5

        for b in data:
            roll.update(b)
            fnv1 = _fnv_hash_byte(fnv1, b)
            fnv2 = _fnv_hash_byte(fnv2, b)

            # Check boundary for block size bs
            if (roll.value % bs) == (bs - 1):
                if len(h1_chars) < (SPAMSUM_LENGTH - 1):
                    h1_chars.append(B64_ALPHABET[fnv1 % 64])
                    fnv1 = 0x811C9DC5

            # Check boundary for block size 2*bs
            if (roll.value % (bs * 2)) == ((bs * 2) - 1):
                if len(h2_chars) < (SPAMSUM_LENGTH // 2 - 1):
                    h2_chars.append(B64_ALPHABET[fnv2 % 64])
                    fnv2 = 0x811C9DC5

        # Append final tail hashes
        h1_chars.append(B64_ALPHABET[fnv1 % 64])
        h2_chars.append(B64_ALPHABET[fnv2 % 64])

        return "".join(h1_chars), "".join(h2_chars)

    @classmethod
    def compare(cls, hash1: str, hash2: str) -> int:
        """
        Compare two fuzzy hashes and return a similarity score from 0 to 100.
        Scores >= 50 indicate strong similarity / shared lineage.
        Scores >= 90 indicate near-identical files with minor modifications.
        """
        if not hash1 or not hash2:
            return 0
        if hash1 == hash2:
            return 100

        try:
            parts1 = hash1.split(":")
            parts2 = hash2.split(":")
            if len(parts1) != 3 or len(parts2) != 3:
                return 0

            bs1 = int(parts1[0])
            s1_1, s1_2 = parts1[1], parts1[2]
            bs2 = int(parts2[0])
            s2_1, s2_2 = parts2[1], parts2[2]
        except (ValueError, IndexError):
            return 0

        score = 0
        # Compare strings when block sizes match
        if bs1 == bs2:
            score1 = _common_substring_score(s1_1, s2_1)
            score2 = _common_substring_score(s1_2, s2_2)
            score = max(score1, score2)
        elif bs1 == bs2 * 2:
            score = _common_substring_score(s1_1, s2_2)
        elif bs2 == bs1 * 2:
            score = _common_substring_score(s1_2, s2_1)

        return score

    @classmethod
    def score_similarity(cls, data1: bytes, data2: bytes) -> int:
        """Helper to directly compare two byte streams."""
        h1 = cls.compute(data1)
        h2 = cls.compute(data2)
        return cls.compare(h1, h2)
