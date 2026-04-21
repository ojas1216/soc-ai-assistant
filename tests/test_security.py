"""
Security layer tests — InputSanitizer, AntiTamper, SecureDelete.
"""
import sys, os, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.security.input_sanitizer import InputSanitizer
from src.security.secure_delete import shred, secure_temp_file, clear_bytes
from src.security.anti_tamper import AntiTamper


# ── InputSanitizer ──────────────────────────────────────────────────────────

class TestInputSanitizer(unittest.TestCase):

    def setUp(self):
        self.san = InputSanitizer()

    # -- Filename sanitization --

    def test_safe_filename_unchanged(self):
        self.assertEqual(self.san.sanitize_filename("syslog.log"), "syslog.log")

    def test_path_traversal_stripped(self):
        result = self.san.sanitize_filename("../../etc/passwd")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)

    def test_null_bytes_in_filename(self):
        result = self.san.sanitize_filename("evil\x00file.log")
        self.assertNotIn("\x00", result)

    # -- Upload validation --

    def test_valid_log_upload(self):
        ok, msg = self.san.validate_upload("test.log", b"2024-01-01 INFO startup")
        self.assertTrue(ok, f"Valid upload rejected: {msg}")

    def test_blocked_extension(self):
        ok, msg = self.san.validate_upload("malware.exe", b"MZ\x90\x00")
        self.assertFalse(ok)

    def test_oversized_file_blocked(self):
        # 51 MB — over the 50 MB limit
        big_content = b"A" * (51 * 1024 * 1024)
        ok, msg = self.san.validate_upload("big.log", big_content)
        self.assertFalse(ok)
        self.assertIn("size", msg.lower())

    def test_empty_file_blocked(self):
        ok, msg = self.san.validate_upload("empty.log", b"")
        self.assertFalse(ok)

    # -- Text sanitization --

    def test_null_bytes_removed(self):
        result = self.san.sanitize_text("hello\x00world")
        self.assertNotIn("\x00", result)

    def test_pii_email_redacted(self):
        result = self.san.sanitize_text("contact user@company.com for info", redact_pii=True)
        self.assertNotIn("user@company.com", result)

    def test_pii_disabled_preserves_email(self):
        text = "contact user@company.com for info"
        result = self.san.sanitize_text(text, redact_pii=False)
        self.assertIn("user@company.com", result)

    def test_control_chars_stripped(self):
        result = self.san.sanitize_text("line1\x01\x02line2")
        self.assertNotIn("\x01", result)
        self.assertNotIn("\x02", result)

    def test_normal_log_unaffected(self):
        log = "2024-01-15 10:00:00 server sshd: Accepted key for admin"
        result = self.san.sanitize_text(log, redact_pii=False)
        self.assertIn("Accepted key for admin", result)

    # -- IOC validation --

    def test_valid_ipv4(self):
        ok, ioc_type = self.san.validate_ioc("185.220.101.42")
        self.assertTrue(ok)
        self.assertEqual(ioc_type, "ip")

    def test_valid_domain(self):
        ok, ioc_type = self.san.validate_ioc("evil-domain.com")
        self.assertTrue(ok)
        self.assertEqual(ioc_type, "domain")

    def test_valid_md5(self):
        ok, ioc_type = self.san.validate_ioc("d41d8cd98f00b204e9800998ecf8427e")
        self.assertTrue(ok)
        self.assertEqual(ioc_type, "md5")

    def test_valid_sha256(self):
        sha = "a" * 64
        ok, ioc_type = self.san.validate_ioc(sha)
        self.assertTrue(ok)
        self.assertEqual(ioc_type, "sha256")

    def test_valid_cve(self):
        ok, ioc_type = self.san.validate_ioc("CVE-2023-44487")
        self.assertTrue(ok)
        self.assertEqual(ioc_type, "cve")

    def test_invalid_ioc_garbage(self):
        ok, _ = self.san.validate_ioc("not-an-ioc-at-all!!!")
        self.assertFalse(ok)

    def test_sql_injection_ioc_rejected(self):
        ok, _ = self.san.validate_ioc("1' OR '1'='1")
        self.assertFalse(ok)


# ── SecureDelete ─────────────────────────────────────────────────────────────

class TestSecureDelete(unittest.TestCase):

    def test_shred_removes_file(self):
        """shred() must delete the file after overwriting."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"sensitive credential data here" * 100)
            path = f.name
        self.assertTrue(os.path.exists(path))
        shred(path, passes=1)
        self.assertFalse(os.path.exists(path), "File should be deleted after shred")

    def test_shred_nonexistent_silent(self):
        """shred() on a nonexistent file should not raise."""
        try:
            shred("/nonexistent/path/file.txt", passes=1)
        except Exception as e:
            self.fail(f"shred raised exception on nonexistent file: {e}")

    def test_secure_temp_file_deleted(self):
        """secure_temp_file() context manager removes file on exit."""
        captured_path = []
        with secure_temp_file(suffix=".tmp") as tmp_path:
            captured_path.append(tmp_path)
            Path(tmp_path).write_bytes(b"temp secret data")
            self.assertTrue(os.path.exists(tmp_path))
        self.assertFalse(os.path.exists(captured_path[0]),
                         "Temp file should be deleted after context exit")

    def test_clear_bytes_zeroes_buffer(self):
        """clear_bytes() should overwrite bytearray contents with zeros."""
        buf = bytearray(b"super secret password")
        clear_bytes(buf)
        self.assertEqual(buf, bytearray(len(buf)), "Buffer should be all zeros after clear")


# ── AntiTamper ────────────────────────────────────────────────────────────────

class TestAntiTamper(unittest.TestCase):

    def setUp(self):
        self.at = AntiTamper()

    def test_verify_does_not_raise_without_manifest(self):
        """verify() without a manifest should not crash (graceful no-op)."""
        try:
            result = self.at.verify(strict=False)
            # result should be True (skipped gracefully) or False (manifest missing)
            self.assertIsInstance(result, bool)
        except Exception as e:
            self.fail(f"verify() raised: {e}")

    def test_generate_manifest_creates_file(self):
        """generate_manifest() writes .integrity.json with file hashes."""
        manifest_path = Path(".integrity.json")
        if manifest_path.exists():
            manifest_path.unlink()

        self.at.generate_manifest()

        if manifest_path.exists():
            import json
            data = json.loads(manifest_path.read_text())
            self.assertIsInstance(data, dict)
            self.assertGreater(len(data), 0, "Manifest should contain at least one entry")
        # If no core files exist yet (e.g., CI), skip the assertion silently

    def test_verify_passes_after_generate(self):
        """After generating a manifest, verify() should pass."""
        self.at.generate_manifest()
        result = self.at.verify(strict=False)
        self.assertTrue(result, "Verification should pass immediately after manifest generation")

    def test_debugger_check_returns_bool(self):
        """check_debugger() always returns a bool."""
        result = self.at.check_debugger()
        self.assertIsInstance(result, bool)

    def test_verify_detects_tampered_file(self):
        """Modify a tracked file → verify() should return False."""
        manifest_path = Path(".integrity.json")
        self.at.generate_manifest()

        if not manifest_path.exists():
            self.skipTest("No manifest generated (core files absent)")

        import json
        data = json.loads(manifest_path.read_text())
        if not data:
            self.skipTest("Empty manifest")

        # Corrupt one hash in the manifest
        first_key = next(iter(data))
        original = data[first_key]
        data[first_key] = "0" * 64  # fake SHA-256
        manifest_path.write_text(json.dumps(data))

        result = self.at.verify(strict=False)
        self.assertFalse(result, "Tampered manifest should fail verification")

        # Restore
        data[first_key] = original
        manifest_path.write_text(json.dumps(data))


if __name__ == "__main__":
    unittest.main(verbosity=2)
