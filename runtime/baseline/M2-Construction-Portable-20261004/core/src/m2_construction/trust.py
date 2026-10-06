"""TEST_ONLY external-pin verification. This module never signs scopes."""
import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import Denied, bytes_hash, canonical, exact_fields, hash_text, require, strict_json


def _b64(value, size):
    require(type(value) is str, "TRUST_BASE64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Denied("TRUST_BASE64") from None
    require(len(decoded) == size, "TRUST_KEY_LENGTH")
    return decoded


def load_pin(pin_path: Path, expected_sha256: str, workspace: Path):
    require(hash_text(expected_sha256), "TRUST_EXPECTED_PIN_HASH")
    pin_path = Path(pin_path)
    workspace = Path(workspace).resolve()
    require(pin_path.resolve() != workspace and workspace not in pin_path.resolve().parents,
            "TRUST_PIN_INSIDE_WORKSPACE")
    raw = pin_path.read_bytes()
    require(bytes_hash(raw) == expected_sha256, "TRUST_PIN_CHANGED")
    pin = strict_json(raw)
    exact_fields(pin, "schema trust_domain public_key_b64 fingerprint", "TRUST_PIN_FIELDS")
    require(pin["schema"] == "M2_CONSTRUCTION_PIN_1" and pin["trust_domain"] == "TEST_ONLY",
            "TRUST_PIN_DOMAIN")
    key = _b64(pin["public_key_b64"], 32)
    require(pin["fingerprint"] == bytes_hash(key), "TRUST_PIN_FINGERPRINT")
    return pin, key


def verify_signed_scope(signed, pin_path, expected_pin_sha256, workspace):
    exact_fields(signed, "schema body signature_b64", "SCOPE_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_SCOPE_1", "SCOPE_ENVELOPE_SCHEMA")
    pin, public = load_pin(pin_path, expected_pin_sha256, workspace)
    body = signed["body"]
    require(type(body) is dict and body.get("trust_domain") == pin["trust_domain"],
            "SCOPE_TRUST_DOMAIN")
    signature = _b64(signed["signature_b64"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(body))
    except InvalidSignature:
        raise Denied("SCOPE_SIGNATURE") from None
    return body
