#!/usr/bin/env python3
"""
delta_domain_compare.py
=======================

Minimum-viable validation: does moving delta encoding from cipher domain to
plaintext domain actually unlock significant storage savings? If yes, the
"client-side delta + plaintext feature" architecture is worth pursuing as the
core contribution of the paper.

Pipeline (mirrors EDRStore's m=2 mode at chunk granularity):
  1. FastCDC chunking (8 KB avg) on each input file in order.
  2. SHA-256 dedup against all prior chunks.
  3. For each new (non-duplicate) chunk:
       a. Compute 3 Finesse-style super-features (XXHash64 of 4 sorted
          Rabin-like sub-features) on the *plaintext*.
       b. Look up super-features in a global index. If any matches, use the
          matched chunk as base candidate; else mark this chunk as a new base.
  4. For each (chunk, base) pair, compute two deltas via xdelta3:
       - delta_plain : xdelta3 on raw bytes
       - delta_cipher: xdelta3 on AES-256-ECB(key=K) output of both base and
                       chunk; K is the same for (chunk, base) per server-aided
                       MLE simulation.
  5. Sum everything up and report:
       - storage with cipher-domain delta (matches EDRStore today)
       - storage with plaintext-domain delta (proposed direction)

Run:
    python3 delta_domain_compare.py \\
        /data/shared_datasets/tar/gcc/gcc-3.4.1.tar \\
        /data/shared_datasets/tar/gcc/gcc-3.4.6.tar \\
        /data/shared_datasets/tar/gcc/gcc-4.3.1.tar

Notes:
- We use xxhash for super-feature aggregation (matches EDRStore FinesseUtil).
- Sub-feature is the max of a simple sliding hash over each sub-chunk; this
  is a faithful enough analog of Rabin max-FP for the experiment.
- zstd is invoked once per non-similar unique chunk as the "local compression"
  baseline so the savings attribution between dedup, local comp, and delta is
  visible.
"""

import argparse
import ctypes
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import xxhash
import zstandard as zstd
from Crypto.Cipher import AES
from fastcdc import fastcdc

# -------- Load native odess extractor --------
_HERE = os.path.dirname(os.path.abspath(__file__))
_SO_PATH = os.path.join(_HERE, "libodess_native.so")
_SRC_PATH = os.path.join(_HERE, "odess_native.c")
if not os.path.exists(_SO_PATH) or \
   os.path.getmtime(_SO_PATH) < os.path.getmtime(_SRC_PATH):
    print(f"[*] compiling {_SO_PATH}...", file=sys.stderr)
    rc = subprocess.run(
        ["g++", "-O3", "-shared", "-fPIC", "-x", "c++",
         "-o", _SO_PATH, _SRC_PATH],
        cwd=_HERE,
    )
    if rc.returncode != 0:
        sys.exit("native build failed; run gcc manually")
_LIB = ctypes.CDLL(_SO_PATH)
_LIB.odess_extract.argtypes = [
    ctypes.c_char_p, ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint64),
]
_LIB.odess_extract.restype = None


def odess_features(data: bytes) -> Tuple[int, ...]:
    out = (ctypes.c_uint64 * 12)()
    _LIB.odess_extract(data, len(data), out)
    return tuple(out)

# -------- Constants chosen to match EDRStore defaults --------
MIN_CHUNK = 4096
AVG_CHUNK = 8192
MAX_CHUNK = 16384
SUPER_FEATURE_PER_CHUNK = 3
FEATURE_PER_SUPER_FEATURE = 4
FEATURE_PER_CHUNK = SUPER_FEATURE_PER_CHUNK * FEATURE_PER_SUPER_FEATURE  # 12
SUB_FEATURE_PER_CHUNK = 12       # odess
MIN_MATCH_FOR_SIMILAR = 4        # odess voting threshold
ODESS_SAMPLE_MASK = 0x7F         # odess sampling: ~1/128 bytes
GLOBAL_SECRET = b"\x01" * 32
AES_KEY_LEN = 32  # AES-256

# Odess transform coefficients (matches Muti-delta-methods/feature/features.cpp)
ODESS_M = [
    0x5b49898a, 0xe4f94e27, 0x95f658b2, 0x8f9c99fc,
    0xeba8d4d8, 0xba2c8e92, 0xa868aeb4, 0xd767df82,
    0x843606a4, 0xc1e70129, 0x32d9d1b0, 0xeb91e53c,
]
ODESS_A = [
    0x0ff4be8c, 0x6f485986, 0x012843ff, 0x5b47dc4d,
    0x7faa9b8a, 0xd547b8ba, 0xf9979921, 0x4f5400da,
    0x725f79a9, 0x3c9321ac, 0x0032716d, 0x3f5adf5d,
]
U32_MASK = 0xFFFFFFFF


# -------- Stats --------
@dataclass
class Stats:
    total_logical_bytes: int = 0
    total_logical_chunks: int = 0
    unique_chunks: int = 0
    unique_bytes_raw: int = 0  # sum of plaintext sizes of non-dup chunks
    unique_bytes_zstd: int = 0  # sum of zstd-compressed sizes (local comp)
    similar_chunks: int = 0  # had a base candidate
    similar_input_bytes: int = 0  # raw size of chunks that ended up similar
    new_base_chunks: int = 0  # unique but no base found
    new_base_bytes_zstd: int = 0  # zstd-compressed bytes of new bases
    delta_plain_bytes: int = 0
    delta_cipher_bytes: int = 0


class ProgressBar:
    """Small dependency-free byte progress bar for interactive terminals."""

    def __init__(self, total: int, width: int = 30) -> None:
        self.total = total
        self.width = width
        self.done = 0
        self.file_name = ""
        self.started_at = time.monotonic()
        self.last_draw = 0.0
        self.enabled = sys.stderr.isatty()

    @staticmethod
    def _fmt_bytes(n: float) -> str:
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if n < 1024 or unit == "TiB":
                return f"{n:.1f}{unit}"
            n /= 1024
        return f"{n:.1f}TiB"

    @staticmethod
    def _fmt_time(seconds: float) -> str:
        seconds = max(0, int(seconds))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours:d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def set_file(self, path: str) -> None:
        self.file_name = os.path.basename(path)
        self.draw(force=True)

    def update(self, n: int) -> None:
        self.done += n
        self.draw()

    def draw(self, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and self.done < self.total and now - self.last_draw < 0.1:
            return
        self.last_draw = now
        ratio = min(self.done / self.total, 1.0) if self.total else 1.0
        filled = int(self.width * ratio)
        bar = "#" * filled + "-" * (self.width - filled)
        elapsed = max(now - self.started_at, 1e-9)
        speed = self.done / elapsed
        eta = (self.total - self.done) / speed if speed else 0
        name = self.file_name
        if len(name) > 24:
            name = "..." + name[-21:]
        line = (
            f"\r[{bar}] {ratio:6.2%} "
            f"{self._fmt_bytes(self.done)}/{self._fmt_bytes(self.total)} "
            f"{self._fmt_bytes(speed)}/s ETA {self._fmt_time(eta)} "
            f"{name}"
        )
        print(f"{line:<120}", end="", file=sys.stderr, flush=True)

    def close(self) -> None:
        if self.enabled:
            print(file=sys.stderr)


# -------- Finesse-style super-feature on plaintext --------
def finesse_features(data: bytes) -> Tuple[int, ...]:
    """3 super-features, each = xxhash64 of 4 sorted sub-feature maxes."""
    if len(data) < FEATURE_PER_CHUNK:
        return (0, 0, 0)
    sub_size = len(data) // FEATURE_PER_CHUNK
    # Simple "max rolling hash" per sub-chunk - faithful analog of Rabin max-FP.
    subs: List[int] = []
    for i in range(FEATURE_PER_CHUNK):
        seg = data[i * sub_size:(i + 1) * sub_size] if i < FEATURE_PER_CHUNK - 1 \
            else data[i * sub_size:]
        # Sliding XXHash64 over a 48-byte window; take max
        win = 48
        m = 0
        for j in range(0, len(seg) - win + 1, 8):  # stride 8 for speed
            v = xxhash.xxh64_intdigest(seg[j:j + win])
            if v > m:
                m = v
        subs.append(m)
    # Group into 4 sub-features per super-feature, sort within each group, hash
    out = []
    for i in range(SUPER_FEATURE_PER_CHUNK):
        group = sorted(subs[i * FEATURE_PER_SUPER_FEATURE:
                            (i + 1) * FEATURE_PER_SUPER_FEATURE], reverse=True)
        buf = b"".join(struct.pack("<Q", v) for v in group)
        out.append(xxhash.xxh64_intdigest(buf))
    return tuple(out)


# -------- Base-selection abstractions --------
class FinesseIndex:
    """Single-value lookup, ≥1-of-3 super-feature match wins."""
    name = "finesse"

    def __init__(self) -> None:
        # super_feature -> (chunk_fp, plaintext_bytes)
        self._idx: Dict[int, Tuple[bytes, bytes]] = {}

    def lookup(self, data: bytes) -> Optional[Tuple[bytes, bytes]]:
        for sf in finesse_features(data):
            if sf in self._idx:
                fp, pdata = self._idx[sf]
                return (pdata, fp)
        return None

    def insert(self, data: bytes, fp: bytes) -> None:
        for sf in finesse_features(data):
            self._idx[sf] = (fp, data)


class OdessIndex:
    """12-slot inverted index, ≥MIN_MATCH_FOR_SIMILAR voting, top-1 winner."""
    name = "odess"

    def __init__(self) -> None:
        # 12 maps, each: sub_feature_value -> list of (fp, data)
        self._tables: List[Dict[int, List[Tuple[bytes, bytes]]]] = \
            [{} for _ in range(SUB_FEATURE_PER_CHUNK)]

    def lookup(self, data: bytes) -> Optional[Tuple[bytes, bytes]]:
        sfs = odess_features(data)
        votes: Dict[bytes, Tuple[int, bytes]] = {}
        for i, sf in enumerate(sfs):
            entries = self._tables[i].get(sf)
            if not entries:
                continue
            for fp, pdata in entries:
                cur = votes.get(fp)
                if cur is None:
                    votes[fp] = (1, pdata)
                else:
                    votes[fp] = (cur[0] + 1, cur[1])
        if not votes:
            return None
        best_fp, (best_cnt, best_data) = max(votes.items(),
                                              key=lambda kv: kv[1][0])
        if best_cnt < MIN_MATCH_FOR_SIMILAR:
            return None
        return (best_data, best_fp)

    def insert(self, data: bytes, fp: bytes) -> None:
        sfs = odess_features(data)
        for i, sf in enumerate(sfs):
            self._tables[i].setdefault(sf, []).append((fp, data))


# -------- Encryption simulating EDRStore's ECB-only encryption --------
def derive_key_from_fp(fp: bytes) -> bytes:
    """Key derived from the *base* chunk's fingerprint. Similar chunks reuse
    the base's key, so the keystream is identical between base and target —
    matching EDRStore's server-aided MLE invariant."""
    return hashlib.sha256(GLOBAL_SECRET + fp).digest()


def ecb_pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    """AES-256-ECB with PKCS#7 padding, matching TwoPhaseEnc.cc."""
    ecb = AES.new(key, AES.MODE_ECB)
    return ecb.encrypt(ecb_pad(data))


# -------- xdelta3 wrapper --------
def xdelta_size(src: bytes, target: bytes) -> int:
    """Return encoded delta size, or len(target) if xdelta fails."""
    with tempfile.NamedTemporaryFile(delete=False) as fs, \
         tempfile.NamedTemporaryFile(delete=False) as ft, \
         tempfile.NamedTemporaryFile(delete=False) as fo:
        sp, tp, op = fs.name, ft.name, fo.name
    try:
        with open(sp, "wb") as f:
            f.write(src)
        with open(tp, "wb") as f:
            f.write(target)
        r = subprocess.run(
            ["xdelta3", "-e", "-f", "-9", "-S", "none", "-s", sp, tp, op],
            capture_output=True,
        )
        if r.returncode != 0:
            return len(target)
        return os.path.getsize(op)
    finally:
        for p in (sp, tp, op):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


def zstd_size(data: bytes) -> int:
    return len(zstd.ZstdCompressor(level=3).compress(data))


# -------- Main pipeline --------
def process_files(paths: List[str], feature: str) -> Stats:
    stats = Stats()
    seen_fps: Dict[bytes, None] = {}
    progress = ProgressBar(sum(os.path.getsize(path) for path in paths))

    if feature == "finesse":
        index = FinesseIndex()
    elif feature == "odess":
        index = OdessIndex()
    else:
        raise ValueError(f"unknown feature: {feature}")

    for path in paths:
        size = os.path.getsize(path)
        progress.set_file(path)
        with open(path, "rb") as fh:
            for ch in fastcdc(path, min_size=MIN_CHUNK, avg_size=AVG_CHUNK,
                              max_size=MAX_CHUNK, hf=hashlib.sha256):
                fh.seek(ch.offset)
                data = fh.read(ch.length)
                fp = bytes.fromhex(ch.hash)

                stats.total_logical_bytes += len(data)
                stats.total_logical_chunks += 1

                if fp in seen_fps:
                    progress.update(len(data))
                    continue  # exact dedup

                seen_fps[fp] = None
                stats.unique_chunks += 1
                stats.unique_bytes_raw += len(data)

                # Find a base. lookup returns (base_data, base_fp) or None.
                hit = index.lookup(data)

                if hit is None:
                    stats.new_base_chunks += 1
                    z = zstd_size(data)
                    stats.new_base_bytes_zstd += z
                    stats.unique_bytes_zstd += z
                    index.insert(data, fp)
                    progress.update(len(data))
                    continue

                base_data, base_fp = hit
                # Don't delta against self
                if base_fp == fp:
                    stats.new_base_chunks += 1
                    z = zstd_size(data)
                    stats.new_base_bytes_zstd += z
                    stats.unique_bytes_zstd += z
                    index.insert(data, fp)
                    progress.update(len(data))
                    continue

                stats.similar_chunks += 1
                stats.similar_input_bytes += len(data)

                d_plain = xdelta_size(base_data, data)
                stats.delta_plain_bytes += d_plain

                # Key derivation: similar chunks share base's key (MLE).
                key = derive_key_from_fp(base_fp)
                base_cipher = encrypt_ecb(base_data, key)
                input_cipher = encrypt_ecb(data, key)
                d_cipher = xdelta_size(base_cipher, input_cipher)
                stats.delta_cipher_bytes += d_cipher

                # Account zstd cost as if it were a fresh base (worst case).
                stats.unique_bytes_zstd += zstd_size(data)
                progress.update(len(data))

    progress.close()
    return stats


def fmt_mb(n: int) -> str:
    return f"{n/1e6:.2f} MB"


def report(stats: Stats, feature: str) -> None:
    print(f"\n=== Aggregate stats (feature={feature}) ===")
    print(f"logical chunks       : {stats.total_logical_chunks:,}")
    print(f"logical bytes        : {fmt_mb(stats.total_logical_bytes)}")
    print(f"unique chunks        : {stats.unique_chunks:,} "
          f"(dedup hit rate {1 - stats.unique_chunks/stats.total_logical_chunks:.1%})")
    print(f"  new bases          : {stats.new_base_chunks:,}")
    print(f"  similar (had base) : {stats.similar_chunks:,}")
    print(f"unique raw bytes     : {fmt_mb(stats.unique_bytes_raw)}")
    print(f"similar input bytes  : {fmt_mb(stats.similar_input_bytes)}")
    print(f"new-base zstd bytes  : {fmt_mb(stats.new_base_bytes_zstd)}")

    print("\n=== Delta sizes (only similar chunks) ===")
    print(f"delta_plain          : {fmt_mb(stats.delta_plain_bytes)}")
    print(f"delta_cipher (EDR)   : {fmt_mb(stats.delta_cipher_bytes)}")
    if stats.similar_input_bytes > 0:
        rp = stats.delta_plain_bytes / stats.similar_input_bytes
        rc = stats.delta_cipher_bytes / stats.similar_input_bytes
        print(f"delta/input ratio    : plain={rp:.1%}  cipher={rc:.1%}")

    # Final storage comparison
    print("\n=== End-to-end storage (zstd-compressed bases + deltas) ===")
    s_plain = stats.new_base_bytes_zstd + stats.delta_plain_bytes
    s_cipher = stats.new_base_bytes_zstd + stats.delta_cipher_bytes
    print(f"plaintext-delta arch : {fmt_mb(s_plain)}  "
          f"(reduction {stats.total_logical_bytes/max(s_plain,1):.2f}x)")
    print(f"cipher-delta arch    : {fmt_mb(s_cipher)}  "
          f"(reduction {stats.total_logical_bytes/max(s_cipher,1):.2f}x)")
    if s_cipher > 0:
        gain = (s_cipher - s_plain) / s_cipher
        print(f"plaintext saves      : {gain:.1%} relative storage vs cipher")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", help="input files in upload order")
    ap.add_argument("--feature", choices=["finesse", "odess"],
                    default="finesse",
                    help="base-selection algorithm (default: finesse)")
    args = ap.parse_args()
    stats = process_files(args.files, feature=args.feature)
    report(stats, feature=args.feature)


if __name__ == "__main__":
    main()
