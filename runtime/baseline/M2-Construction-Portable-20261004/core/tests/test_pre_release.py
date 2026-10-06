"""CEO acceptance follows an actual child return and parent TEST/freeze."""

import copy
import json
from pathlib import Path
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m2_construction.adjudication import local_adjudicate
from m2_construction.contracts import bytes_hash, canonical
from m2_construction.pre_release import pre_release_readonly, record_ceo_acceptance
import m2_construction.pre_release as pre_release_module
from test_adjudication import _pin, _public, _sign
from test_internal_return import _consume, _ready


def _record(controller, args):
    return record_ceo_acceptance(
        controller, args["signed_ceo_acceptance"], **{
            key: value for key, value in args.items()
            if key not in ("ledger_path", "workspace", "state_dir",
                           "root_pin_path", "expected_root_pin_sha256",
                           "signed_ceo_acceptance")
        })


def _grant_new_revision(controller, root, task):
    workspace = controller.workspace
    path = "parent/src/value.py" if task == "parent" else "src/value.py"
    task_id = "parent-task" if task == "parent" else "task-01"
    revision = 2 if task == "parent" else 3
    now = int(time.time())
    scope = {
        "schema": "M2_CONSTRUCTION_SCOPE_1", "trust_domain": "TEST_ONLY",
        "grant_id": f"{task}-new-grant", "task_id": task_id,
        "task_revision": revision, "workspace_root": str(workspace),
        "state_root": str(controller.state_dir),
        "baseline_files": {path: bytes_hash((workspace / path).read_bytes())},
        "allowed_files": [path], "allowed_effects": ["PATCH"],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 1, "max_patch_bytes": 1024,
    }
    granted = controller.register_grant(
        _sign(root, "M2_CONSTRUCTION_SIGNED_SCOPE_1", scope))
    assert granted["status"] == "GRANTED", granted


def _ready_parent(tmp_path, *, parent_review_decision="GO", ceo_key=None,
                  record=True):
    controller, child_args, root, _, signed_return, returned_files = _ready(tmp_path)
    returned = _consume(controller, child_args, signed_return)
    assert returned["status"] == "COMPLETED", returned
    tested = controller.run_command(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-test-01", command_id="parent-check")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-freeze-01", source_files=["parent/src/value.py"],
        test_files=["parent/tests/check.py"], build_files=[],
        test_operation_ids=["parent-test-01"])
    assert frozen["status"] == "FROZEN", frozen

    author = Ed25519PrivateKey.generate()
    reviewer = Ed25519PrivateKey.generate()
    reviewer_pin = tmp_path / "parent-reviewer" / "pin.json"
    reviewer_pin_sha = _pin(reviewer_pin, reviewer, "M2_CONSTRUCTION_REVIEWER_PIN_1")
    author_fp = bytes_hash(_public(author))
    authorship = _sign(root, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", {
        "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
        "grant_id": "parent-grant", "task_id": "parent-task", "task_revision": 1,
        "candidate_sha256": frozen["manifest_sha256"],
        "author_fingerprint": author_fp,
    })
    recorded = controller.record_author_attestation(
        authorship, grant_id="parent-grant", task_id="parent-task",
        task_revision=1, manifest_sha256=frozen["manifest_sha256"])
    assert recorded["status"] == "ATTESTED", recorded
    freeze_hash = next(row[3] for row in controller.ledger.events()
                       if json.loads(row[4]).get("kind") == "CANDIDATE_FROZEN"
                       and json.loads(row[4]).get("grant_id") == "parent-grant")
    signed_review = _sign(reviewer, "M2_CONSTRUCTION_SIGNED_REVIEW_1", {
        "schema": "M2_CONSTRUCTION_REVIEW_BODY_1", "trust_domain": "TEST_ONLY",
        "grant_id": "parent-grant", "task_id": "parent-task", "task_revision": 1,
        "candidate_sha256": frozen["manifest_sha256"],
        "test_receipts": [{"operation_id": "parent-test-01",
                           "receipt_sha256": tested["receipt_sha256"]}],
        "freeze_event_hash": freeze_hash, "author_fingerprint": author_fp,
        "reviewer_fingerprint": bytes_hash(_public(reviewer)),
        "decision": parent_review_decision, "reason": "Independent parent integration review.",
    })
    parent_args = dict(child_args)
    parent_args.update(
        child_reviewer_pin_path=child_args["reviewer_pin_path"],
        expected_child_reviewer_pin_sha256=child_args["expected_reviewer_pin_sha256"],
        reviewer_pin_path=reviewer_pin,
        expected_reviewer_pin_sha256=reviewer_pin_sha,
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        manifest_path=Path(frozen["manifest_path"]),
        expected_manifest_sha256=frozen["manifest_sha256"],
        signed_review=signed_review,
    )
    if parent_review_decision == "GO":
        assert local_adjudicate(**{
            key: value for key, value in parent_args.items()
            if not key.startswith("child_") and
            key != "expected_child_reviewer_pin_sha256"
        })["status"] == "PASS"
    ceo_key = ceo_key or Ed25519PrivateKey.generate()
    ceo_pin = tmp_path / "ceo-key" / "pin.json"
    ceo_pin_sha = _pin(ceo_pin, ceo_key, "M2_CONSTRUCTION_CEO_PIN_1")
    consumed_hash = next(row[3] for row in controller.ledger.events()
                         if json.loads(row[4]).get("kind") == "INTERNAL_RETURN_CONSUMED"
                         and json.loads(row[4]).get("operation_id") ==
                         returned["operation_id"])
    signed_roles = _sign(root, "M2_CONSTRUCTION_SIGNED_PRE_RELEASE_ROLES_1", {
        "schema": "M2_CONSTRUCTION_PRE_RELEASE_ROLES_1",
        "trust_domain": "TEST_ONLY", "parent_grant_id": "parent-grant",
        "parent_task_id": "parent-task", "parent_task_revision": 1,
        "candidate_sha256": frozen["manifest_sha256"],
        "review_sha256": bytes_hash(canonical(signed_review)),
        "reviewer_fingerprint": bytes_hash(_public(reviewer)),
        "ceo_fingerprint": bytes_hash(_public(ceo_key)),
    })
    now = int(time.time())
    ceo_body = {
        "schema": "M2_CONSTRUCTION_CEO_ACCEPTANCE_BODY_1",
        "trust_domain": "TEST_ONLY", "decision": "ACCEPT",
        "ceo_fingerprint": bytes_hash(_public(ceo_key)),
        "parent_grant_id": "parent-grant", "parent_task_id": "parent-task",
        "parent_task_revision": 1,
        "candidate_sha256": frozen["manifest_sha256"],
        "review_sha256": bytes_hash(canonical(signed_review)),
        "internal_return_operation_id": returned["operation_id"],
        "internal_return_files_sha256": returned["files_sha256"],
        "internal_return_event_hash": consumed_hash,
        "child_grant_id": signed_return["body"]["child_grant_id"],
        "child_task_id": signed_return["body"]["child_task_id"],
        "child_task_revision": signed_return["body"]["child_task_revision"],
        "child_candidate_sha256": signed_return["body"]["candidate_sha256"],
        "not_before": now - 60, "expires_at": now + 3600,
        "signed_roles": signed_roles,
    }
    parent_args.update(
        ceo_pin_path=ceo_pin, expected_ceo_pin_sha256=ceo_pin_sha,
        signed_ceo_acceptance=_sign(ceo_key, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1",
                                    ceo_body),
    )
    if record and parent_review_decision == "GO":
        accepted = _record(controller, parent_args)
        assert accepted["status"] == "ACCEPTED", accepted
    return controller, parent_args, ceo_key, ceo_body, root, reviewer, author, returned_files


def test_real_parent_integration_ceo_acceptance_is_read_only(tmp_path):
    controller, args, _, body, _, _, _, returned_files = _ready_parent(tmp_path)
    events_before = controller.ledger.events()
    db_before = controller.ledger.path.read_bytes()
    result = pre_release_readonly(**args)
    assert result["status"] == "PASS", result
    assert result["dispatch_allowed"] is False
    assert result["candidate_sha256"] == body["candidate_sha256"]
    assert result["review_sha256"] == body["review_sha256"]
    assert result["internal_return_operation_id"] == body["internal_return_operation_id"]
    assert result["internal_return_files_sha256"] == body["internal_return_files_sha256"]
    assert result["internal_return_event_hash"] == body["internal_return_event_hash"]
    assert len(result["ceo_accepted_event_hash"]) == 64
    assert len(result["ceo_acceptance_sha256"]) == 64
    assert len(result["pre_release_sha256"]) == 64
    assert controller.ledger.events() == events_before
    assert controller.ledger.path.read_bytes() == db_before
    assert sum(json.loads(row[4]).get("kind") == "CEO_ACCEPTED"
               for row in events_before) == 1
    for item in returned_files:
        target = controller.workspace.joinpath(*item["destination"].split("/"))
        assert bytes_hash(target.read_bytes()) == item["sha256"]


@pytest.mark.parametrize("identity", ["root", "reviewer", "author"])
def test_ceo_identity_must_be_independent(tmp_path, identity):
    controller, args, _, body, root, reviewer, author, _ = _ready_parent(
        tmp_path, record=False)
    key = {"root": root, "reviewer": reviewer, "author": author}[identity]
    ceo_pin = tmp_path / "colliding-ceo" / "pin.json"
    args["ceo_pin_path"] = ceo_pin
    args["expected_ceo_pin_sha256"] = _pin(
        ceo_pin, key, "M2_CONSTRUCTION_CEO_PIN_1")
    body["ceo_fingerprint"] = bytes_hash(_public(key))
    args["signed_ceo_acceptance"] = _sign(
        key, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1", body)
    verdict = _record(controller, args)
    assert verdict["status"] == "DENIED", verdict
    assert verdict["dispatch_allowed"] is False


def test_fresh_ceo_pin_cannot_self_select_authority(tmp_path):
    controller, args, _, body, _, _, _, _ = _ready_parent(
        tmp_path, record=False)
    attacker = Ed25519PrivateKey.generate()
    pin = tmp_path / "attacker-ceo" / "pin.json"
    args["ceo_pin_path"] = pin
    args["expected_ceo_pin_sha256"] = _pin(
        pin, attacker, "M2_CONSTRUCTION_CEO_PIN_1")
    args["signed_ceo_acceptance"] = _sign(
        attacker, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1",
        {**body, "ceo_fingerprint": bytes_hash(_public(attacker))})
    verdict = _record(controller, args)
    assert verdict["status"] == "DENIED", verdict
    assert verdict["reason"] == "ROLE_BINDING"
    assert pre_release_readonly(**args)["status"] == "FAIL"


def test_fresh_parent_reviewer_pin_cannot_self_select_authority(tmp_path):
    controller, args, ceo, body, _, _, _, _ = _ready_parent(
        tmp_path, record=False)
    attacker = Ed25519PrivateKey.generate()
    pin = tmp_path / "attacker-reviewer" / "pin.json"
    args["reviewer_pin_path"] = pin
    args["expected_reviewer_pin_sha256"] = _pin(
        pin, attacker, "M2_CONSTRUCTION_REVIEWER_PIN_1")
    review_body = {**args["signed_review"]["body"],
                   "reviewer_fingerprint": bytes_hash(_public(attacker))}
    args["signed_review"] = _sign(
        attacker, "M2_CONSTRUCTION_SIGNED_REVIEW_1", review_body)
    changed = {**body, "review_sha256": bytes_hash(
        canonical(args["signed_review"]))}
    args["signed_ceo_acceptance"] = _sign(
        ceo, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1", changed)
    verdict = _record(controller, args)
    assert verdict["status"] == "DENIED", verdict
    assert verdict["reason"] == "ROLE_BINDING"
    assert pre_release_readonly(**args)["status"] == "FAIL"


def test_role_binding_requires_actual_test_root_signature(tmp_path):
    controller, args, ceo, body, _, _, _, _ = _ready_parent(
        tmp_path, record=False)
    attacker = Ed25519PrivateKey.generate()
    changed = {**body, "signed_roles": _sign(
        attacker, "M2_CONSTRUCTION_SIGNED_PRE_RELEASE_ROLES_1",
        body["signed_roles"]["body"])}
    args["signed_ceo_acceptance"] = _sign(
        ceo, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1", changed)
    verdict = _record(controller, args)
    assert verdict["status"] == "DENIED", verdict
    assert verdict["reason"] == "ROLE_SIGNATURE"


@pytest.mark.parametrize("task", ["parent", "child"])
def test_newer_root_signed_revision_invalidates_old_acceptance(tmp_path, task):
    controller, args, _, _, root, _, _, _ = _ready_parent(tmp_path)
    assert pre_release_readonly(**args)["status"] == "PASS"
    _grant_new_revision(controller, root, task)
    verdict = pre_release_readonly(**args)
    assert verdict["status"] == "FAIL", verdict
    assert verdict["reason"] == (
        "PARENT_REVISION_SUPERSEDED" if task == "parent"
        else "CHILD_REVISION_SUPERSEDED")


@pytest.mark.parametrize("task", ["parent", "child"])
def test_newer_root_signed_revision_blocks_ceo_record(tmp_path, task):
    controller, args, _, _, root, _, _, _ = _ready_parent(
        tmp_path, record=False)
    _grant_new_revision(controller, root, task)
    verdict = _record(controller, args)
    assert verdict["status"] == "DENIED", verdict
    assert verdict["reason"] == (
        "PARENT_REVISION_SUPERSEDED" if task == "parent"
        else "CHILD_REVISION_SUPERSEDED")
    assert all(json.loads(row[4]).get("kind") != "CEO_ACCEPTED"
               for row in controller.ledger.events())


def test_ceo_event_must_follow_parent_freeze(tmp_path, monkeypatch):
    _, args, _, _, _, _, _, _ = _ready_parent(tmp_path)
    read_events = pre_release_module._read_events

    def reordered_for_check(db):
        events = read_events(db)
        freeze_seq = next(entry["seq"] for entry in events
                          if entry["body"].get("kind") == "CANDIDATE_FROZEN" and
                          entry["body"].get("grant_id") == "parent-grant")
        for entry in events:
            if entry["body"].get("kind") == "CEO_ACCEPTED":
                entry["seq"] = freeze_seq
        return events

    monkeypatch.setattr(pre_release_module, "_read_events", reordered_for_check)
    verdict = pre_release_readonly(**args)
    assert verdict["status"] == "FAIL", verdict
    assert verdict["reason"] == "CEO_ACCEPTANCE_EVENT_CHANGED"


def test_pre_release_needs_durable_ceo_event_and_record_is_idempotent(tmp_path):
    controller, args, _, _, _, _, _, _ = _ready_parent(tmp_path, record=False)
    assert pre_release_readonly(**args)["status"] != "PASS"
    first = _record(controller, args)
    assert first["status"] == "ACCEPTED", first
    assert first["effect_executed"] is True
    second = _record(controller, args)
    assert second["status"] == "ACCEPTED", second
    assert second["effect_executed"] is False
    assert pre_release_readonly(**args)["status"] == "PASS"
    assert sum(json.loads(row[4]).get("kind") == "CEO_ACCEPTED"
               for row in controller.ledger.events()) == 1


def test_second_signed_proof_for_same_parent_candidate_conflicts(tmp_path):
    controller, args, key, body, _, _, _, _ = _ready_parent(tmp_path)
    changed = {**body, "expires_at": body["expires_at"] + 1}
    args["signed_ceo_acceptance"] = _sign(
        key, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1", changed)
    assert _record(controller, args)["status"] == "DENIED"
    assert pre_release_readonly(**args)["status"] == "FAIL"


def test_missing_return_operation_cannot_be_accepted(tmp_path):
    controller, args, key, body, _, _, _, _ = _ready_parent(tmp_path, record=False)
    args["signed_ceo_acceptance"] = _sign(
        key, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1",
        {**body, "internal_return_operation_id": "missing-return"})
    assert _record(controller, args)["status"] == "DENIED"
    assert pre_release_readonly(**args)["status"] != "PASS"


def test_ceo_signature_scope_and_candidate_are_exact(tmp_path):
    controller, args, key, body, _, _, _, _ = _ready_parent(tmp_path)
    bad = copy.deepcopy(args)
    bad["signed_ceo_acceptance"]["body"]["candidate_sha256"] = "0" * 64
    assert pre_release_readonly(**bad)["status"] != "PASS"
    for field, wrong in (("parent_task_revision", 2),
                         ("internal_return_operation_id", "other-return"),
                         ("internal_return_files_sha256", "0" * 64),
                         ("review_sha256", "0" * 64)):
        rebound = copy.deepcopy(args)
        changed = {**body, field: wrong}
        rebound["signed_ceo_acceptance"] = _sign(
            key, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1", changed)
        assert pre_release_readonly(**rebound)["status"] != "PASS", field
    controller.revoke_grant("parent-grant")
    assert pre_release_readonly(**args)["status"] == "FAIL"


def test_unknown_return_and_changed_target_cannot_pass(tmp_path):
    controller, args, _, body, _, _, _, _ = _ready_parent(tmp_path)
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE operations SET status='UNKNOWN' WHERE operation_id=?",
                   (body["internal_return_operation_id"],))
    verdict = pre_release_readonly(**args)
    assert verdict["status"] != "PASS", verdict

    controller, args, _, _, _, _, _, _ = _ready_parent(tmp_path / "changed")
    (controller.workspace / "parent" / "src" / "value.py").write_bytes(b"tampered\n")
    verdict = pre_release_readonly(**args)
    assert verdict["status"] == "FAIL", verdict


def test_ceo_cannot_override_parent_no_go_or_changed_pin(tmp_path):
    _, args, _, _, _, _, _, _ = _ready_parent(tmp_path, parent_review_decision="NO_GO")
    assert pre_release_readonly(**args)["status"] == "FAIL"
    _, args, _, _, _, _, _, _ = _ready_parent(tmp_path / "pin-change")
    args["ceo_pin_path"].write_bytes(args["ceo_pin_path"].read_bytes() + b" ")
    assert pre_release_readonly(**args)["status"] != "PASS"


def test_ceo_event_is_required_even_if_signed_proof_remains_valid(tmp_path):
    controller, args, _, _, _, _, _, _ = _ready_parent(tmp_path)
    assert pre_release_readonly(**args)["status"] == "PASS"
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("DELETE FROM events WHERE seq=(SELECT MAX(seq) FROM events)")
    assert pre_release_readonly(**args)["status"] == "INDETERMINATE"


def test_child_revoke_or_new_parent_freeze_invalidates_prior_acceptance(tmp_path):
    controller, args, _, _, _, _, _, _ = _ready_parent(tmp_path)
    controller.revoke_grant("grant-01")
    assert pre_release_readonly(**args)["status"] == "FAIL"

    controller, args, _, _, _, _, _, _ = _ready_parent(tmp_path / "new-freeze")
    tested = controller.run_command(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-test-02", command_id="parent-check")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-freeze-02", source_files=["parent/src/value.py"],
        test_files=["parent/tests/check.py"], build_files=[],
        test_operation_ids=["parent-test-02"])
    assert frozen["status"] == "FROZEN", frozen
    assert pre_release_readonly(**args)["status"] == "FAIL"


def test_ceo_pin_must_be_outside_workspace_and_state(tmp_path):
    controller, args, _, _, _, _, _, _ = _ready_parent(tmp_path, record=False)
    inside = controller.workspace / "ceo-pin.json"
    inside.write_bytes(args["ceo_pin_path"].read_bytes())
    args["ceo_pin_path"] = inside
    assert _record(controller, args)["status"] == "DENIED"
    assert pre_release_readonly(**args)["status"] != "PASS"
