"""Independent TEST_ONLY review proofs are signed by the pinned reviewer key."""

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m2_construction.contracts import Denied, bytes_hash, canonical
from m2_construction.review import verify_review_proof


def _public(private):
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _setup(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    reviewer = Ed25519PrivateKey.generate()
    public = _public(reviewer)
    pin_path = tmp_path / "independent-reviewer" / "pin.json"
    pin_path.parent.mkdir()
    pin_path.write_bytes(canonical({
        "schema": "M2_CONSTRUCTION_REVIEWER_PIN_1",
        "trust_domain": "TEST_ONLY",
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "fingerprint": bytes_hash(public),
    }))
    kwargs = {
        "pin_path": pin_path,
        "expected_pin_sha256": bytes_hash(pin_path.read_bytes()),
        "workspace": workspace,
        "author_fingerprint": "a" * 64,
        "grant_id": "grant-01",
        "task_id": "task-01",
        "task_revision": 1,
        "manifest_sha256": "b" * 64,
        "test_receipts": [{"operation_id": "test-01", "receipt_sha256": "c" * 64}],
        "freeze_event_hash": "d" * 64,
    }
    return reviewer, kwargs


def _proof(reviewer, kwargs, decision="GO", **changes):
    body = {
        "schema": "M2_CONSTRUCTION_REVIEW_BODY_1",
        "trust_domain": "TEST_ONLY",
        "grant_id": kwargs["grant_id"],
        "task_id": kwargs["task_id"],
        "task_revision": kwargs["task_revision"],
        "candidate_sha256": kwargs["manifest_sha256"],
        "test_receipts": kwargs["test_receipts"],
        "freeze_event_hash": kwargs["freeze_event_hash"],
        "author_fingerprint": kwargs["author_fingerprint"],
        "reviewer_fingerprint": bytes_hash(_public(reviewer)),
        "decision": decision,
        "reason": "Independently checked the frozen evidence.",
    }
    body.update(changes)
    return {"schema": "M2_CONSTRUCTION_SIGNED_REVIEW_1", "body": body,
            "signature_b64": base64.b64encode(reviewer.sign(canonical(body))).decode("ascii")}


def test_go_and_no_go_are_signed_for_exact_candidate_and_passing_receipt(tmp_path):
    reviewer, kwargs = _setup(tmp_path)
    for decision in ("GO", "NO_GO"):
        proof = _proof(reviewer, kwargs, decision)
        result = verify_review_proof(proof, **kwargs)
        assert result["status"] == "VERIFIED"
        assert result["decision"] == decision
        assert result["candidate_sha256"] == kwargs["manifest_sha256"]
        assert result["reviewer_fingerprint"] == bytes_hash(_public(reviewer))
        assert result["authority"] == "EVIDENCE_ONLY"
        assert result["review_sha256"] == bytes_hash(canonical(proof))


def test_role_claim_forged_signature_and_changed_external_pin_are_rejected(tmp_path):
    reviewer, kwargs = _setup(tmp_path)
    proof = _proof(reviewer, kwargs)
    proof["role"] = "independent-reviewer"
    with pytest.raises(Denied, match="REVIEW_ENVELOPE_FIELDS"):
        verify_review_proof(proof, **kwargs)
    del proof["role"]
    proof["body"]["decision"] = "NO_GO"
    with pytest.raises(Denied, match="REVIEW_SIGNATURE"):
        verify_review_proof(proof, **kwargs)
    proof = _proof(reviewer, kwargs)
    kwargs["pin_path"].write_bytes(kwargs["pin_path"].read_bytes() + b" ")
    with pytest.raises(Denied, match="REVIEW_PIN_CHANGED"):
        verify_review_proof(proof, **kwargs)


def test_reviewer_must_differ_from_trusted_author_and_pin_must_be_external(tmp_path):
    reviewer, kwargs = _setup(tmp_path)
    kwargs["author_fingerprint"] = bytes_hash(_public(reviewer))
    with pytest.raises(Denied, match="REVIEW_NOT_INDEPENDENT"):
        verify_review_proof(_proof(reviewer, kwargs), **kwargs)
    kwargs["author_fingerprint"] = "a" * 64
    inside = Path(kwargs["workspace"]) / "reviewer-pin.json"
    inside.write_bytes(kwargs["pin_path"].read_bytes())
    kwargs["pin_path"] = inside
    with pytest.raises(Denied, match="REVIEW_PIN_INSIDE_WORKSPACE"):
        verify_review_proof(_proof(reviewer, kwargs), **kwargs)


@pytest.mark.parametrize("field,value", [
    ("manifest_sha256", "f" * 64),
    ("test_receipts", [{"operation_id": "test-01", "receipt_sha256": "f" * 64}]),
    ("freeze_event_hash", "f" * 64),
    ("task_id", "other-task"),
])
def test_signed_review_cannot_be_transferred_to_another_binding(tmp_path, field, value):
    reviewer, kwargs = _setup(tmp_path)
    proof = _proof(reviewer, kwargs)
    kwargs[field] = value
    with pytest.raises(Denied, match="REVIEW_BINDING"):
        verify_review_proof(proof, **kwargs)
