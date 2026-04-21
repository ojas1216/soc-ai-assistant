"""
Anti-tamper protection.
Verifies SHA-256 checksums of core files at startup.
Detects debugger presence on Windows and Linux.
Raises TamperError if tampering is detected.
"""
import hashlib
import json
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path(__file__).parents[2] / ".integrity.json"
CORE_FILES = [
    "src/core/ensemble_detector.py",
    "src/core/inference_engine.py",
    "src/core/zero_day_detector.py",
    "src/core/existing_threat_detector.py",
    "src/models/voting_classifier.py",
    "src/security/license_manager.py",
    "src/security/anti_tamper.py",
]


class TamperError(RuntimeError):
    pass


class AntiTamper:
    """
    Integrity verification for core source files.
    Run generate_manifest() once during packaging.
    Run verify() at application startup.
    """

    def __init__(self, project_root: Optional[Path] = None):
        self._root = project_root or Path(__file__).parents[2]

    def verify(self, strict: bool = False):
        """
        Verify file integrity.
        strict=True  → raise TamperError if any file is modified
        strict=False → log warning only
        """
        if not MANIFEST_PATH.exists():
            logger.debug("[AntiTamper] No integrity manifest found — skipping verification")
            return

        try:
            manifest = json.loads(MANIFEST_PATH.read_text())
        except Exception as exc:
            logger.warning("[AntiTamper] Manifest read error: %s", exc)
            return

        violations = []
        for rel_path, expected_hash in manifest.items():
            fpath = self._root / rel_path
            if not fpath.exists():
                violations.append(f"MISSING: {rel_path}")
                continue
            actual = self._sha256(fpath)
            if actual != expected_hash:
                violations.append(f"MODIFIED: {rel_path}")

        if violations:
            msg = "Integrity check failed:\n" + "\n".join(violations)
            if strict:
                raise TamperError(msg)
            logger.warning("[AntiTamper] %s", msg)
        else:
            logger.debug("[AntiTamper] All %d files verified OK", len(manifest))

    def generate_manifest(self) -> dict:
        """
        Compute and save SHA-256 hashes for all core files.
        Run this once during packaging — not at runtime.
        """
        manifest = {}
        for rel_path in CORE_FILES:
            fpath = self._root / rel_path
            if fpath.exists():
                manifest[rel_path] = self._sha256(fpath)
                logger.info("[AntiTamper] Hashed: %s", rel_path)
            else:
                logger.warning("[AntiTamper] File not found: %s", rel_path)

        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))
        logger.info("[AntiTamper] Manifest written to %s (%d files)", MANIFEST_PATH, len(manifest))
        return manifest

    def check_debugger(self) -> bool:
        """Return True if a debugger is detected (best-effort)."""
        return self._check_debugger_windows() or self._check_debugger_linux()

    def abort_if_debugged(self):
        """Exit the process if a debugger is detected."""
        if self.check_debugger():
            logger.warning("[AntiTamper] Debugger detected — exiting")
            sys.exit(1)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _check_debugger_windows() -> bool:
        if platform.system() != "Windows":
            return False
        try:
            import ctypes
            return bool(ctypes.windll.kernel32.IsDebuggerPresent())
        except Exception:
            return False

    @staticmethod
    def _check_debugger_linux() -> bool:
        if platform.system() != "Linux":
            return False
        try:
            status = Path("/proc/self/status").read_text()
            for line in status.splitlines():
                if line.startswith("TracerPid:"):
                    pid = int(line.split(":")[1].strip())
                    return pid != 0
        except Exception:
            pass
        return False
