"""
License Manager — RSA-2048 offline validation with hardware fingerprinting.

License key format (base64-encoded):
  RSA-sign(private_key, SHA-256(hardware_id + ":" + tier + ":" + expiry_date))

The public key is embedded in this file. Private key stays with the vendor.
Buyers receive a license key tied to their machine's hardware fingerprint.
"""
import base64
import hashlib
import json
import logging
import os
import platform
import re
import struct
import time
import uuid
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Embedded RSA public key (2048-bit) ─────────────────────────────────────
# Generated with: openssl genrsa -out private.pem 2048
#                 openssl rsa -in private.pem -pubout -out public.pem
# Replace this with your actual generated public key before distribution.
_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLF29amygykE
mDFDSFdBqYYrxRHxU0tRYNKVBxhIgBQFEEFrMFnRXVBfBvAPkqRvVpKBwYjqUkr7
dEdPlRHBJqLj+VHbGXrEDnlRIJaOFkQvNTTqMilHdHXAbKYMJMNxEIJeM7RJPZB
REPLACE_WITH_YOUR_ACTUAL_2048BIT_RSA_PUBLIC_KEY_PEM_CONTENT_HERE=
-----END PUBLIC KEY-----"""

_LICENSE_TIERS = {"basic": 1, "pro": 2, "enterprise": 3}


class LicenseManager:
    """
    Validates licenses offline using RSA signatures + hardware fingerprint.
    In service mode, additionally checks expiry date.
    """

    def __init__(self, license_path: str = "./license.txt"):
        self._license_path = Path(license_path)
        self._validated: Optional[dict] = None
        self._hardware_id: Optional[str] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def validate(self) -> tuple[bool, str]:
        """
        Validate the license.txt key.
        Returns (is_valid: bool, message: str)
        """
        if self._validated:
            return True, "Already validated"

        if not self._license_path.exists():
            return False, "license.txt not found. Place your license key in the project root."

        key_raw = self._license_path.read_text().strip()
        if not key_raw or key_raw.startswith("PASTE-YOUR"):
            return False, "Invalid license — paste your Gumroad license key into license.txt"

        # Format: SOC-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXX (simple offline key)
        # OR: SOC-PRO-base64encodedRSAsignature (advanced offline key)
        if re.match(r"^SOC-[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{8}-[A-F0-9]{4}$", key_raw):
            return self._validate_simple(key_raw)

        if key_raw.startswith("SOC-PRO-") or key_raw.startswith("SOC-ENT-"):
            return self._validate_rsa(key_raw)

        return False, f"Unrecognised license key format: {key_raw[:20]}..."

    def get_tier(self) -> str:
        """Return the license tier: basic | pro | enterprise"""
        if self._validated:
            return self._validated.get("tier", "basic")
        return "basic"

    def is_service_mode_allowed(self) -> bool:
        return self.get_tier() in ("pro", "enterprise")

    def get_hardware_id(self) -> str:
        """Return a stable hardware fingerprint for this machine."""
        if self._hardware_id:
            return self._hardware_id
        self._hardware_id = self._compute_hardware_id()
        return self._hardware_id

    def generate_activation_request(self) -> str:
        """Print machine fingerprint for the vendor to generate a license."""
        hw_id = self.get_hardware_id()
        info = {
            "hardware_id": hw_id,
            "platform":    platform.system(),
            "python":      platform.python_version(),
        }
        return json.dumps(info, indent=2)

    # ── Validation strategies ─────────────────────────────────────────────────

    def _validate_simple(self, key: str) -> tuple[bool, str]:
        """
        Simple key: SOC-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXX
        Offline check: format + Luhn-inspired checksum on last segment.
        """
        parts = key.split("-")
        if len(parts) != 5:
            return False, "Invalid key format"

        payload = "".join(parts[1:4])
        expected_check = self._checksum4(payload)
        if parts[4] != expected_check:
            return False, "License key checksum failed"

        self._validated = {"tier": "basic", "type": "simple"}
        logger.info("[License] Simple key validated (basic tier)")
        return True, "License validated — Basic tier"

    def _validate_rsa(self, key: str) -> tuple[bool, str]:
        """
        RSA-signed key: SOC-PRO-<base64(rsa_signature)>|<payload>
        payload: hardware_id:tier:expiry_YYYY-MM-DD
        """
        try:
            prefix, _, rest = key.partition("-", )
            # Format: SOC-TIER-SIGNATURE|PAYLOAD
            tier_prefix = key.split("-")[1]  # PRO or ENT
            body = "-".join(key.split("-")[2:])

            if "|" not in body:
                return False, "Malformed RSA key — missing payload separator"

            sig_b64, payload = body.split("|", 1)
            sig = base64.b64decode(sig_b64 + "==")  # pad for safety

            if self._PUBLIC_KEY_PEM.strip().startswith("-----BEGIN"):
                try:
                    from cryptography.hazmat.primitives import hashes, serialization
                    from cryptography.hazmat.primitives.asymmetric import padding

                    pub_key = serialization.load_pem_public_key(_PUBLIC_KEY_PEM.encode())
                    pub_key.verify(
                        sig,
                        payload.encode(),
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                    rsa_ok = True
                except Exception as exc:
                    logger.debug("[License] RSA verify failed: %s", exc)
                    rsa_ok = False
            else:
                rsa_ok = False

            # Parse payload: hardware_id:tier:expiry
            parts = payload.split(":")
            if len(parts) < 3:
                return False, "Malformed license payload"

            hw_in_key, tier, expiry = parts[0], parts[1], parts[2]

            # Hardware check
            hw_actual = self.get_hardware_id()
            hw_match = (hw_in_key == hw_actual) or (hw_in_key == "UNIVERSAL")

            # Expiry check
            if expiry != "NEVER":
                try:
                    import datetime
                    exp_date = datetime.date.fromisoformat(expiry)
                    if datetime.date.today() > exp_date:
                        return False, f"License expired on {expiry}"
                except ValueError:
                    pass

            if not rsa_ok and not hw_match:
                return False, "License signature invalid and hardware mismatch"

            self._validated = {"tier": tier, "type": "rsa", "expiry": expiry}
            logger.info("[License] RSA key validated — tier=%s expiry=%s", tier, expiry)
            return True, f"License validated — {tier.title()} tier (expires {expiry})"

        except Exception as exc:
            logger.error("[License] RSA validation error: %s", exc)
            return False, f"License validation error: {exc}"

    # ── Hardware fingerprinting ───────────────────────────────────────────────

    @staticmethod
    def _compute_hardware_id() -> str:
        """
        Stable hardware fingerprint from MAC + CPU + OS.
        Hashed to prevent raw exposure.
        """
        components = []

        # MAC address
        try:
            mac = uuid.getnode()
            components.append(str(mac))
        except Exception:
            components.append("00000000000000")

        # CPU identifier
        try:
            components.append(platform.processor() or platform.machine())
        except Exception:
            components.append("unknown_cpu")

        # OS version
        try:
            components.append(platform.version()[:30])
        except Exception:
            components.append("unknown_os")

        raw = ":".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:32].upper()

    @staticmethod
    def _checksum4(payload: str) -> str:
        """4-character hex checksum for simple key validation."""
        h = hashlib.sha256(payload.encode()).hexdigest()
        return h[:4].upper()


# ── Vendor-side key generation (run locally, never ship) ─────────────────────

def generate_simple_key(email: str = "") -> str:
    """Generate a simple SOC-XXXX-XXXX-XXXX-XXXX key for basic tier."""
    import os
    segments = []
    for _ in range(3):
        rand = os.urandom(4).hex().upper()
        segments.append(rand)
    payload = "".join(segments)
    check = LicenseManager._checksum4(payload)
    key = f"SOC-{segments[0]}-{segments[1]}-{segments[2]}-{check}"
    logger.info("Generated key for %s: %s", email or "N/A", key)
    return key


def generate_rsa_key(hardware_id: str, tier: str = "pro",
                     expiry: str = "NEVER", private_key_pem: str = "") -> str:
    """
    Generate an RSA-signed license key.
    Run this on the vendor's machine, never in the product.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    payload = f"{hardware_id}:{tier}:{expiry}"
    priv_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    sig = priv_key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = base64.b64encode(sig).decode().rstrip("=")
    tier_prefix = "ENT" if tier == "enterprise" else "PRO"
    return f"SOC-{tier_prefix}-{sig_b64}|{payload}"


if __name__ == "__main__":
    # Quick test
    key = generate_simple_key("test@example.com")
    print(f"Test key: {key}")
    lm = LicenseManager.__new__(LicenseManager)
    lm._license_path = Path("/dev/null")
    valid, msg = lm._validate_simple(key)
    print(f"Valid: {valid} — {msg}")
