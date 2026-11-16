"""Lancement sûr de programmes externes (liste d'arguments, délai)."""
from __future__ import annotations

import shutil
import subprocess


def which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run(argv: list[str], timeout: int = 900) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, "", f"Délai dépassé ({timeout} s)"
    except FileNotFoundError:
        return -1, "", f"Programme introuvable : {argv[0]}"
