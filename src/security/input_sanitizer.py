"""
Input sanitizer — prevents injection attacks, validates file types,
enforces size limits, and redacts PII from logs before analysis.
"""
import hashlib
import html
import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MAX_FILE_SIZE_MB = 50
ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".csv", ".pcap", ".cap", ".evtx", ".xml", ".tsv"}

# MIME magic bytes for file type verification
MAGIC_BYTES = {
    b"\x1f\x8b":         ".gz",
    b"PK\x03\x04":       ".zip",
    b"\xd4\xc3\xb2\xa1": ".pcap",
    b"\xa1\xb2\xc3\xd4": ".pcap",
    b"\x0a\x0d\x0d\x0a": ".pcapng",
    b"ELF":              ".elf",
    b"MZ":               ".exe",
}

# PII redaction patterns
_PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL_REDACTED]"),
    (re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),                    "[PHONE_REDACTED]"),
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),                           "[CARD_REDACTED]"),
    (re.compile(r"\bpassword\s*[:=]\s*\S+", re.IGNORECASE),                "password:[REDACTED]"),
    (re.compile(r"\bpwd\s*[:=]\s*\S+", re.IGNORECASE),                     "pwd:[REDACTED]"),
    (re.compile(r"\bapi[_\-]?key\s*[:=]\s*\S+", re.IGNORECASE),           "api_key:[REDACTED]"),
    (re.compile(r"\btoken\s*[:=]\s*[A-Za-z0-9\-_\.]{20,}", re.IGNORECASE), "token:[REDACTED]"),
    (re.compile(r"\bsecret\s*[:=]\s*\S+", re.IGNORECASE),                  "secret:[REDACTED]"),
]


class InputSanitizer:
    """All input validation and sanitization for the analysis pipeline."""

    def __init__(self, max_size_mb: int = MAX_FILE_SIZE_MB):
        self._max_bytes = max_size_mb * 1024 * 1024

    # ── File validation ───────────────────────────────────────────────────────

    def validate_upload(self, filename: str, content: bytes) -> tuple[bool, str]:
        """
        Validate an uploaded file before processing.
        Returns (is_valid: bool, message: str)
        """
        # Size check
        if len(content) > self._max_bytes:
            return False, f"File exceeds maximum size of {MAX_FILE_SIZE_MB} MB"

        # Extension check
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            return False, f"File type '{ext}' not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"

        # PCAP binary type — allow without text decoding
        if ext in (".pcap", ".cap", ".pcapng"):
            return True, "OK"

        # Magic byte check — block executables disguised as logs
        for magic, detected_ext in MAGIC_BYTES.items():
            if content.startswith(magic) and detected_ext in (".exe", ".elf"):
                return False, f"Binary executable disguised as log file — rejected"

        # Empty content
        if not content.strip():
            return False, "File is empty"

        return True, "OK"

    # ── Text sanitization ─────────────────────────────────────────────────────

    def sanitize_text(self, text: str, redact_pii: bool = True) -> str:
        """
        Clean text input for safe processing.
        - Strips null bytes and control characters
        - Limits line length to prevent ReDoS
        - Optionally redacts PII
        """
        if not isinstance(text, str):
            text = str(text)

        # Remove null bytes
        text = text.replace("\x00", "")

        # Strip dangerous control characters (keep \t \n \r)
        text = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        # Enforce line length (prevents extremely long lines that cause ReDoS)
        lines = []
        for line in text.splitlines():
            if len(line) > 4096:
                line = line[:4096] + " [TRUNCATED]"
            lines.append(line)
        text = "\n".join(lines)

        if redact_pii:
            text = self.redact_pii(text)

        return text

    def sanitize_filename(self, filename: str) -> str:
        """Return a safe filename with no path traversal."""
        name = Path(filename).name  # strips directory components
        # Keep only safe characters
        safe = re.sub(r"[^A-Za-z0-9_\-\. ]", "_", name)
        return safe[:128] or "uploaded_file"

    @staticmethod
    def redact_pii(text: str) -> str:
        """Replace PII patterns with redaction markers."""
        for pattern, replacement in _PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    # ── String injection prevention ────────────────────────────────────────────

    @staticmethod
    def sanitize_for_html(text: str) -> str:
        """Escape text for safe HTML embedding."""
        return html.escape(str(text))

    @staticmethod
    def sanitize_for_shell(value: str) -> str:
        """
        Return a shell-safe version of a value.
        NEVER pass this to shell= True — use subprocess list form instead.
        This is a last-resort filter only.
        """
        return re.sub(r"[;&|`$<>(){}'\"\\\n\r]", "", value)[:512]

    @staticmethod
    def validate_ioc(ioc: str) -> tuple[bool, str]:
        """Validate an IOC string (IP, domain, hash, CVE)."""
        ioc = ioc.strip()
        if not ioc:
            return False, "Empty IOC"

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            parts = ioc.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                return True, "ip"

        if re.match(r"^[a-zA-Z0-9\-]{2,63}(\.[a-zA-Z0-9\-]{2,63})+$", ioc):
            return True, "domain"

        if re.match(r"^[0-9a-fA-F]{32}$", ioc):
            return True, "md5"
        if re.match(r"^[0-9a-fA-F]{40}$", ioc):
            return True, "sha1"
        if re.match(r"^[0-9a-fA-F]{64}$", ioc):
            return True, "sha256"

        if re.match(r"^CVE-\d{4}-\d{4,7}$", ioc, re.IGNORECASE):
            return True, "cve"

        return False, f"Unrecognised IOC format: {ioc[:30]}"

    @staticmethod
    def hash_customer_id(customer_id: str) -> str:
        """One-way hash a customer ID for logging (privacy)."""
        return hashlib.sha256(customer_id.encode()).hexdigest()[:12]
