"""Verify externally pinned TEST_ONLY author and independent reviewer proofs.

Signing is deliberately outside this library. A role string, caller-supplied
``verified`` flag, or reviewer's own claim of authorship has no authority.
"""

import base64
from pathlib import Path
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import (Denied, bytes_hash, canonical, exact_fields, hash_text,
                        require, strict_json)
from .trust import load_pin


def _public_pin(path, expected_sha256, workspace):
    require(hash_text(expected_sha256), "REVIEW_PIN_HASH")
    path = Path(path)
    workspace = Path(workspace).resolve(strict=True)
    require(path.is_absolute() and path.is_file(), "REVIEW_PIN_MISSING")
    resolved = path.resolve(strict=True)
    require(resolved == path, "REVIEW_PIN_LINK")
    require(resolved != workspace and workspace not in resolved.parents,
            "REVIEW_PIN_INSIDE_WORKSPACE")
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not (getattr(info, "st_file_attributes", 0) &
                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
            "REVIEW_PIN_LINK")
    raw = path.read_bytes()
    require(bytes_hash(raw) == expected_sha256, "REVIEW_PIN_CHANGED")
    try:
        pin = strict_json(raw)
        require(canonical(pin) == raw, "REVIEW_PIN_CANONICAL")
        exact_fields(pin, "schema trust_domain public_key_b64 fingerprint",
                     "REVIEW_PIN_FIELDS")
        require(pin["schema"] == "M2_CONSTRUCTION_REVIEWER_PIN_1" and
                pin["trust_domain"] == "TEST_ONLY", "REVIEW_PIN_DOMAIN")
        public = base64.b64decode(pin["public_key_b64"], validate=True)
        require(len(public) == 32 and pin["fingerprint"] == bytes_hash(public),
                "REVIEW_PIN_KEY")
        return pin, public
    except (KeyError, TypeError, ValueError, UnicodeError, base64.binascii.Error) as exc:
        raise Denied("REVIEW_PIN_INVALID") from exc


def _verify_signature(public, signature_b64, body, code):
    require(type(signature_b64) is str, code)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        require(len(signature) == 64, code)
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(body))
    except (InvalidSignature, TypeError, ValueError, base64.binascii.Error) as exc:
        raise Denied(code) from exc


def verify_author_attestation(signed, *, root_pin_path, expected_root_pin_sha256,
                              workspace, grant_id, task_id, task_revision,
                              manifest_sha256):
    """Validate a Test Root attestation of the actual candidate author.

    A future trusted Controller must obtain and record the actual author
    identity before requesting this attestation. Current patch events do not
    contain that identity; this verifier does not infer it from request JSON.
    """
    exact_fields(signed, "schema body signature_b64", "AUTHOR_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1",
            "AUTHOR_ENVELOPE_SCHEMA")
    body = signed["body"]
    exact_fields(body, "schema trust_domain grant_id task_id task_revision candidate_sha256 author_fingerprint",
                 "AUTHOR_BODY_FIELDS")
    require(body["schema"] == "M2_CONSTRUCTION_AUTHORSHIP_1" and
            body["trust_domain"] == "TEST_ONLY", "AUTHOR_DOMAIN")
    require(hash_text(body["author_fingerprint"]), "AUTHOR_FINGERPRINT")
    require((body["grant_id"], body["task_id"], body["task_revision"],
             body["candidate_sha256"]) ==
            (grant_id, task_id, task_revision, manifest_sha256), "AUTHOR_BINDING")
    pin, public = load_pin(root_pin_path, expected_root_pin_sha256, workspace)
    require(pin["fingerprint"] != body["author_fingerprint"], "AUTHOR_ROOT_COLLISION")
    _verify_signature(public, signed["signature_b64"], body, "AUTHOR_SIGNATURE")
    return {"status": "VERIFIED", "author_fingerprint": body["author_fingerprint"],
            "attestation_sha256": bytes_hash(canonical(signed)),
            "authority": "EVIDENCE_ONLY"}


def verify_review_proof(signed, *, pin_path, expected_pin_sha256, workspace,
                        author_fingerprint, grant_id, task_id, task_revision,
                        manifest_sha256, test_receipts, freeze_event_hash):
    """Verify a GO/NO_GO signed by the externally pinned reviewer public key.

    ``author_fingerprint`` must come from independently verified authorship;
    this pure verifier never treats its caller as a source of that fact.
    """
    exact_fields(signed, "schema body signature_b64", "REVIEW_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_REVIEW_1",
            "REVIEW_ENVELOPE_SCHEMA")
    body = signed["body"]
    exact_fields(body, "schema trust_domain grant_id task_id task_revision candidate_sha256 "
                       "test_receipts freeze_event_hash author_fingerprint "
                       "reviewer_fingerprint decision reason", "REVIEW_BODY_FIELDS")
    require(body["schema"] == "M2_CONSTRUCTION_REVIEW_BODY_1" and
            body["trust_domain"] == "TEST_ONLY", "REVIEW_DOMAIN")
    require(body["decision"] in ("GO", "NO_GO") and
            type(body["reason"]) is str and 0 < len(body["reason"]) <= 4096,
            "REVIEW_DECISION")
    require(hash_text(author_fingerprint) and hash_text(manifest_sha256) and
            hash_text(freeze_event_hash), "REVIEW_EXPECTED_BINDING")
    require(type(test_receipts) is list and test_receipts and
            all(type(item) is dict and set(item) == {"operation_id", "receipt_sha256"} and
                type(item["operation_id"]) is str and hash_text(item["receipt_sha256"])
                for item in test_receipts) and
            len({item["operation_id"] for item in test_receipts}) == len(test_receipts),
            "REVIEW_EXPECTED_RECEIPTS")
    require((body["grant_id"], body["task_id"], body["task_revision"],
             body["candidate_sha256"], body["test_receipts"],
             body["freeze_event_hash"], body["author_fingerprint"]) ==
            (grant_id, task_id, task_revision, manifest_sha256, test_receipts,
             freeze_event_hash, author_fingerprint), "REVIEW_BINDING")
    pin, public = _public_pin(pin_path, expected_pin_sha256, workspace)
    require(body["reviewer_fingerprint"] == pin["fingerprint"],
            "REVIEWER_IDENTITY")
    _verify_signature(public, signed["signature_b64"], body, "REVIEW_SIGNATURE")
    require(pin["fingerprint"] != author_fingerprint, "REVIEW_NOT_INDEPENDENT")
    return {"status": "VERIFIED", "decision": body["decision"],
            "reviewer_fingerprint": pin["fingerprint"],
            "candidate_sha256": manifest_sha256,
            "review_sha256": bytes_hash(canonical(signed)),
            "authority": "EVIDENCE_ONLY"}
