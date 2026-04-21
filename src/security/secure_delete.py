"""
Secure deletion utilities.
Overwrites file contents before deletion to prevent forensic recovery.
Also provides in-memory sensitive data clearing helpers.
"""
import ctypes
import logging
import os
import platform
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_OVERWRITE_PASSES = 3


class SecureDelete:
    """Secure file and memory management for sensitive analysis data."""

    # ── File deletion ─────────────────────────────────────────────────────────

    @staticmethod
    def shred(path: str | Path, passes: int = _OVERWRITE_PASSES) -> bool:
        """
        Overwrite file with random bytes then zeros, then delete.
        Returns True on success.
        """
        p = Path(path)
        if not p.exists():
            return False

        try:
            size = p.stat().st_size
            if size == 0:
                p.unlink()
                return True

            with open(p, "r+b") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
                # Final zeroes pass
                f.seek(0)
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())

            p.unlink()
            logger.debug("[SecDel] Shredded: %s (%d bytes, %d passes)", p, size, passes)
            return True

        except Exception as exc:
            logger.warning("[SecDel] Shred failed for %s: %s", p, exc)
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
            return False

    @staticmethod
    def shred_directory(dir_path: str | Path, passes: int = _OVERWRITE_PASSES) -> int:
        """Recursively shred all files in a directory. Returns count of shredded files."""
        dp = Path(dir_path)
        count = 0
        for fpath in dp.rglob("*"):
            if fpath.is_file():
                if SecureDelete.shred(fpath, passes):
                    count += 1
        try:
            for sub in sorted(dp.rglob("*"), reverse=True):
                if sub.is_dir():
                    sub.rmdir()
            dp.rmdir()
        except Exception:
            pass
        return count

    # ── Temp file context manager ─────────────────────────────────────────────

    @contextmanager
    def secure_temp_file(self, suffix: str = ".tmp"):
        """
        Context manager that creates a temp file and securely deletes it on exit.

        Usage:
            with SecureDelete().secure_temp_file() as path:
                path.write_bytes(sensitive_data)
                # process ...
            # file is shredded here
        """
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp_path = Path(tmp.name)
        tmp.close()
        try:
            yield tmp_path
        finally:
            self.shred(tmp_path)

    # ── In-memory clearing ────────────────────────────────────────────────────

    @staticmethod
    def clear_bytes(data: bytearray):
        """Zero-fill a bytearray in-place."""
        for i in range(len(data)):
            data[i] = 0

    @staticmethod
    def clear_string(s: str) -> str:
        """
        Best-effort string clearing.
        Python strings are immutable so we cannot truly zero them,
        but we can dereference and suggest GC.
        """
        del s
        return ""

    @staticmethod
    def clear_dict(d: dict):
        """Clear all values in a dict in-place."""
        for k in list(d.keys()):
            v = d[k]
            if isinstance(v, bytearray):
                SecureDelete.clear_bytes(v)
            d[k] = None
        d.clear()
