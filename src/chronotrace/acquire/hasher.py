"""Streaming SHA-256 and multi-hash calculation engine."""

from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

DEFAULT_BUFFER_SIZE = 8 * 1024 * 1024  # 8 MiB chunks per specification


class Hasher:
    """Computes streaming cryptographic hashes with constant memory footprint."""

    def __init__(self, extra_algorithms: Optional[List[str]] = None):
        # SHA-256 is always mandatory
        self.algorithms = ["sha256"]
        if extra_algorithms:
            for algo in extra_algorithms:
                algo_clean = algo.lower().strip()
                if algo_clean not in self.algorithms and algo_clean in hashlib.algorithms_available:
                    self.algorithms.append(algo_clean)

    def hash_file(
        self,
        filepath: Union[str, Path],
        buffer_size: int = DEFAULT_BUFFER_SIZE,
    ) -> Tuple[Dict[str, str], int]:
        """
        Stream a file in 8 MiB chunks and calculate all registered hashes and total byte size.
        Returns: (hash_dict, total_bytes)
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Evidence file not found: {filepath}")

        hashers = {algo: hashlib.new(algo) for algo in self.algorithms}
        total_bytes = 0

        with open(path, "rb") as f:
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                for h in hashers.values():
                    h.update(chunk)

        result = {algo: h.hexdigest() for algo, h in hashers.items()}
        return result, total_bytes

    def stream_copy_and_hash(
        self,
        src_path: Union[str, Path],
        dst_path: Union[str, Path],
        buffer_size: int = DEFAULT_BUFFER_SIZE,
    ) -> Tuple[Dict[str, str], int]:
        """
        Adversarial Defense: Atomically stream from a single source file descriptor
        directly into destination while calculating multi-hashes on the identical stream.
        Eliminates the TOCTOU gap between reading/hashing and copying.
        """
        src = Path(src_path)
        dst = Path(dst_path)
        if not src.exists():
            raise FileNotFoundError(f"Source evidence file not found: {src_path}")

        hashers = {algo: hashlib.new(algo) for algo in self.algorithms}
        total_bytes = 0

        with open(src, "rb") as f_src, open(dst, "wb") as f_dst:
            while True:
                chunk = f_src.read(buffer_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                for h in hashers.values():
                    h.update(chunk)
                f_dst.write(chunk)
            f_dst.flush()

        result = {algo: h.hexdigest() for algo, h in hashers.items()}
        return result, total_bytes


    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        """Calculate single SHA-256 digest for in-memory bytes."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_file(filepath: Union[str, Path]) -> str:
        """Fast streaming SHA-256 for a single file."""
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(DEFAULT_BUFFER_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()
