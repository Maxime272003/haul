"""Calcul de hash en streaming (jamais de fichier entier en memoire)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

CHUNK = 1 << 20  # 1 MiB


def hash_stream(
    stream: BinaryIO,
    algo: str = "sha256",
    on_chunk: Callable[[int], None] | None = None,
) -> str:
    digest = hashlib.new(algo)
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        digest.update(block)
        if on_chunk:
            on_chunk(len(block))
    return digest.hexdigest()


def hash_file(
    path: Path,
    algo: str = "sha256",
    on_chunk: Callable[[int], None] | None = None,
) -> str:
    with path.open("rb") as fh:
        return hash_stream(fh, algo=algo, on_chunk=on_chunk)


def human_size(num: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(num) < 1024 or unit == "To":
            return f"{num:.0f} {unit}" if unit == "o" else f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} To"
