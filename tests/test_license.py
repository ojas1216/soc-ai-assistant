"""
License manager tests — simple key, RSA key, hardware ID, expiry, tier detection.
"""
import sys, unittest, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.security.license_manager import (
    LicenseManager, generate_simple_key, generate_rsa_key, EMBEDDED_PUBLIC_KEY
)


class TestSimpleKey(unittest.TestCase):

    def _mgr(self, key: str) -> LicenseManager:
        mgr = LicenseManager.__new__(LicenseManager)
        mgr.key_path = None
        mgr._key = key
        mgr._validated = False
        mgr._tier = "community"
        mgr._expiry = None
        return mgr

    def test_generate_and_validate_simple_key(self):
        """Generated simple key must validate successfully."""
        key = generate_simple_key("test@example.com")
        self.assertTrue(key.startswith("SOC-"))
        parts = key.split("-")
        self.assertEqual(len(parts), 5, f"Expected 5 parts, got {parts}")

    def test_simple_key_structure(self):
        """Simple key has correct hex segment lengths."""
        key = generate_simple_key("user@domain.com")
        _, p1, p2, p3, chk = key.split("-")
        self.assertEqual(len(p1), 8)
        self.assertEqual(len(p2), 8)
        self.assertEqual(len(p3), 8)
        self.assertEqual(len(chk), 4)

    def test_simple_key_validates(self):
        """LicenseManager accepts a freshly generated simple key."""
        key = generate_simple_key("buyer@example.com")
        mgr = LicenseManager.__new__(LicenseManager)
        mgr.key_path = None
        mgr._key = key
        mgr._validated = False
        mgr._tier = "community"
        mgr._expiry = None
        valid, msg = mgr._validate_simple(key)
        self.assertTrue(valid, f"Simple key rejected: {msg}")

    def test_tampered_simple_key_rejected(self):
        """Changing one character in the checksum invalidates the key."""
        key = generate_simple_key("buyer@example.com")
        parts = key.split("-")
        chk = parts[-1]
        bad_chk = chk[:-1] + ("A" if chk[-1] != "A" else "B")
        parts[-1] = bad_chk
        bad_key = "-".join(parts)
        mgr = LicenseManager.__new__(LicenseManager)
        mgr.key_path = None
        mgr._key = bad_key
        mgr._validated = False
        mgr._tier = "community"
        mgr._expiry = None
        valid, _ = mgr._validate_simple(bad_key)
        self.assertFalse(valid, "Tampered key should not validate")

    def test_empty_key_rejected(self):
        """Empty string is not a valid license key."""
        mgr = LicenseManager(key_path="nonexistent_license.txt")
        valid, msg = mgr.validate()
        self.assertFalse(valid)
        self.assertIn("not found", msg.lower(), f"Expected 'not found' in: {msg}")

    def test_garbage_key_rejected(self):
        """Random garbage string is not a valid key."""
        mgr = LicenseManager.__new__(LicenseManager)
        mgr.key_path = None
        mgr._key = "GARBAGE-KEY-12345"
        mgr._validated = False
        mgr._tier = "community"
        mgr._expiry = None
        valid, _ = mgr._validate_simple("GARBAGE-KEY-12345")
        self.assertFalse(valid)


class TestHardwareID(unittest.TestCase):

    def test_hardware_id_deterministic(self):
        """Same machine should produce the same hardware ID on repeated calls."""
        id1 = LicenseManager._compute_hardware_id()
        id2 = LicenseManager._compute_hardware_id()
        self.assertEqual(id1, id2)

    def test_hardware_id_format(self):
        """Hardware ID is 32 uppercase hex characters."""
        hw_id = LicenseManager._compute_hardware_id()
        self.assertEqual(len(hw_id), 32)
        self.assertTrue(hw_id.isupper() or hw_id == hw_id.upper(),
                        "Hardware ID should be uppercase")
        int(hw_id, 16)  # raises ValueError if not valid hex

    def test_hardware_id_non_empty(self):
        hw_id = LicenseManager._compute_hardware_id()
        self.assertTrue(len(hw_id) > 0)


class TestLicenseTier(unittest.TestCase):

    def test_community_tier_default(self):
        """Without valid license, tier is 'community'."""
        mgr = LicenseManager(key_path="nonexistent_file.txt")
        mgr.validate()
        self.assertEqual(mgr.get_tier(), "community")

    def test_service_mode_blocked_community(self):
        """Community tier cannot use service mode."""
        mgr = LicenseManager(key_path="nonexistent_file.txt")
        mgr.validate()
        self.assertFalse(mgr.is_service_mode_allowed())


class TestRSAKeyGeneration(unittest.TestCase):

    def test_rsa_key_starts_with_soc_pro(self):
        """RSA-signed keys begin with SOC-PRO-."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, NoEncryption
            )
            pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            hw_id = LicenseManager._compute_hardware_id()
            key = generate_rsa_key(hw_id, "pro", "2030-12-31", pem)
            self.assertTrue(key.startswith("SOC-PRO-"),
                            f"RSA key should start with SOC-PRO-, got: {key[:20]}")
        except ImportError:
            self.skipTest("cryptography package not available")

    def test_rsa_key_contains_payload(self):
        """RSA key payload contains hardware_id:tier:expiry."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, NoEncryption
            )
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            hw_id = LicenseManager._compute_hardware_id()
            key = generate_rsa_key(hw_id, "enterprise", "2030-01-01", pem)
            # Key format: SOC-PRO-{b64sig}|{payload}
            payload_part = key.split("|", 1)[1] if "|" in key else ""
            self.assertIn(hw_id, payload_part)
            self.assertIn("enterprise", payload_part)
        except ImportError:
            self.skipTest("cryptography package not available")


if __name__ == "__main__":
    unittest.main(verbosity=2)
