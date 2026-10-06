"""A local verdict reads a real SQLite snapshot and actual frozen file bytes."""

import base64
import json
from pathlib import Path
import sqlite3
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m2_construction.adapters import run_fixed_command
from m2_construction.adjudication import local_adjudicate
from m2_construction.artifacts import freeze_candidate
from m2_construction.contracts import bytes_hash, canonical, digest
from m2_construction.controller import Controller


def _public(private):
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _pin(path, private, schema):
    public = _public(private)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical({"schema": schema, "trust_domain": "TEST_ONLY",
                                "public_key_b64": base64.b64encode(public).decode("ascii"),
                                "fingerprint": bytes_hash(public)}))
    return bytes_hash(path.read_bytes())


def _sign(private, schema, body):
    return {"schema": schema, "body": body,
            "signature_b64": base64.b64encode(private.sign(canonical(body))).decode("ascii")}


def _fixture(tmp_path, *, register_test=True, freeze_event=True, author_event=True,
             decision="GO", same_author=False, root_is_reviewer=False):
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "tests").mkdir()
    source = workspace / "src" / "value.py"
    test = workspace / "tests" / "check.py"
    source.write_bytes(b"value = 1\n")
    test.write_bytes(b"print('real pass')\n")
    root_key = Ed25519PrivateKey.generate()
    reviewer_key = root_key if root_is_reviewer else Ed25519PrivateKey.generate()
    author_key = reviewer_key if same_author else Ed25519PrivateKey.generate()
    root_pin = tmp_path / "root-key" / "pin.json"
    reviewer_pin = tmp_path / "reviewer-key" / "pin.json"
    root_pin_sha = _pin(root_pin, root_key, "M2_CONSTRUCTION_PIN_1")
    reviewer_pin_sha = _pin(reviewer_pin, reviewer_key, "M2_CONSTRUCTION_REVIEWER_PIN_1")
    state = tmp_path / "state"
    controller = Controller(workspace=workspace, state_dir=state, pin_path=root_pin,
                            expected_pin_sha256=root_pin_sha)
    now = int(time.time())
    scope = {
        "schema": "M2_CONSTRUCTION_SCOPE_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 1,
        "workspace_root": str(workspace), "state_root": str(state),
        "baseline_files": {"src/value.py": bytes_hash(source.read_bytes())},
        "allowed_files": ["src/value.py"], "allowed_effects": ["PATCH"],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 2, "max_patch_bytes": 1024,
    }
    assert controller.register_grant(_sign(root_key, "M2_CONSTRUCTION_SIGNED_SCOPE_1", scope))["status"] == "GRANTED"
    receipt = run_fixed_command(
        argv=[sys.executable, str(test)], cwd=workspace, env={}, timeout_seconds=5,
        expected_program_sha256=bytes_hash(Path(sys.executable).read_bytes()),
        log_dir=tmp_path / "evidence" / "tests", operation_id="test-01",
        tracked_root=workspace,
        tracked_files={"src/value.py": bytes_hash(source.read_bytes()),
                       "tests/check.py": bytes_hash(test.read_bytes())},
    )
    assert receipt["status"] == "PASSED"
    frozen = freeze_candidate(root=workspace, source_files=["src/value.py"],
                              test_files=["tests/check.py"], build_files=[],
                              test_receipts=[receipt],
                              manifest_path=tmp_path / "evidence" / "manifest.json")
    author_fp = bytes_hash(_public(author_key))
    with controller.ledger.transaction() as db:
        if register_test:
            controller.ledger.event(db, {"kind": "TEST_RECEIPT", "grant_id": "grant-01",
                                         "task_id": "task-01", "task_revision": 1,
                                         "operation_id": "test-01", "status": "PASSED",
                                         "receipt_sha256": receipt["receipt_sha256"]})
        if freeze_event:
            freeze_hash = controller.ledger.event(db, {
                "kind": "CANDIDATE_FROZEN", "grant_id": "grant-01", "task_id": "task-01",
                "task_revision": 1, "manifest_path": frozen["manifest_path"],
                "manifest_sha256": frozen["manifest_sha256"]})
        else:
            freeze_hash = "0" * 64
        if author_event:
            authorship = _sign(root_key, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", {
                "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
                "grant_id": "grant-01", "task_id": "task-01", "task_revision": 1,
                "candidate_sha256": frozen["manifest_sha256"],
                "author_fingerprint": author_fp,
            })
            controller.ledger.event(db, {"kind": "AUTHOR_ATTESTED", "authorship": authorship})
    review_body = {
        "schema": "M2_CONSTRUCTION_REVIEW_BODY_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 1,
        "candidate_sha256": frozen["manifest_sha256"],
        "test_receipts": [{"operation_id": "test-01", "receipt_sha256": receipt["receipt_sha256"]}],
        "freeze_event_hash": freeze_hash, "author_fingerprint": author_fp,
        "reviewer_fingerprint": bytes_hash(_public(reviewer_key)),
        "decision": decision, "reason": "Independent byte and receipt review.",
    }
    signed_review = _sign(reviewer_key, "M2_CONSTRUCTION_SIGNED_REVIEW_1", review_body)
    args = dict(ledger_path=controller.ledger.path, workspace=workspace, state_dir=state,
                root_pin_path=root_pin, expected_root_pin_sha256=root_pin_sha,
                reviewer_pin_path=reviewer_pin, expected_reviewer_pin_sha256=reviewer_pin_sha,
                grant_id="grant-01", task_id="task-01", task_revision=1,
                manifest_path=Path(frozen["manifest_path"]),
                expected_manifest_sha256=frozen["manifest_sha256"],
                signed_review=signed_review)
    return controller, args, frozen


def _v2_fixture(tmp_path, *, author_event=False):
    """Use Controller for TEST/freeze; synthesize only TEST_ONLY author/review proof."""
    workspace = tmp_path / "workspace"
    source = workspace / "src" / "value.py"
    test = workspace / "tests" / "check.py"
    source.parent.mkdir(parents=True)
    test.parent.mkdir()
    source.write_bytes(b"value = 1\n")
    test.write_text("from pathlib import Path\n"
                    "assert Path('src/value.py').read_bytes() == b'value = 1\\n'\n",
                    encoding="utf-8")
    root_key = Ed25519PrivateKey.generate()
    reviewer_key = Ed25519PrivateKey.generate()
    author_key = Ed25519PrivateKey.generate()
    root_pin = tmp_path / "root-key" / "pin.json"
    reviewer_pin = tmp_path / "reviewer-key" / "pin.json"
    root_pin_sha = _pin(root_pin, root_key, "M2_CONSTRUCTION_PIN_1")
    reviewer_pin_sha = _pin(reviewer_pin, reviewer_key, "M2_CONSTRUCTION_REVIEWER_PIN_1")
    state = tmp_path / "state"
    controller = Controller(workspace=workspace, state_dir=state, pin_path=root_pin,
                            expected_pin_sha256=root_pin_sha)
    program = Path(sys.executable).resolve(strict=True)
    now = int(time.time())
    scope = {
        "schema": "M2_CONSTRUCTION_SCOPE_2", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 2,
        "workspace_root": str(workspace), "state_root": str(state),
        "baseline_files": {"src/value.py": bytes_hash(source.read_bytes()),
                           "tests/check.py": bytes_hash(test.read_bytes())},
        "allowed_files": ["src/value.py", "tests/check.py"],
        "allowed_effects": ["PATCH", "TEST", "FREEZE"],
        "allowed_commands": [{
            "command_id": "check-value", "kind": "TEST",
            "argv": [str(program), str(test)], "cwd": ".", "env": {},
            "timeout_seconds": 5, "program_sha256": bytes_hash(program.read_bytes()),
            "tracked_paths": ["src/value.py", "tests/check.py"],
        }],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 5, "max_patch_bytes": 1024,
    }
    registered = controller.register_grant(
        _sign(root_key, "M2_CONSTRUCTION_SIGNED_SCOPE_1", scope))
    assert registered["status"] == "GRANTED", registered
    tested = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=2, operation_id="test-01",
                                    command_id="check-value")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="grant-01", task_id="task-01", task_revision=2,
        operation_id="freeze-01", source_files=["src/value.py"],
        test_files=["tests/check.py"], build_files=[],
        test_operation_ids=["test-01"])
    assert frozen["status"] == "FROZEN", frozen
    freeze_hash = next(row[3] for row in controller.ledger.events()
                       if json.loads(row[4]).get("kind") == "CANDIDATE_FROZEN")
    author_fp = bytes_hash(_public(author_key))
    if author_event:
        authorship = _sign(root_key, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", {
            "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
            "grant_id": "grant-01", "task_id": "task-01", "task_revision": 2,
            "candidate_sha256": frozen["manifest_sha256"],
            "author_fingerprint": author_fp,
        })
        with controller.ledger.transaction() as db:
            controller.ledger.event(db, {"kind": "AUTHOR_ATTESTED",
                                         "authorship": authorship})
    review = _sign(reviewer_key, "M2_CONSTRUCTION_SIGNED_REVIEW_1", {
        "schema": "M2_CONSTRUCTION_REVIEW_BODY_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 2,
        "candidate_sha256": frozen["manifest_sha256"],
        "test_receipts": [{"operation_id": "test-01",
                           "receipt_sha256": tested["receipt_sha256"]}],
        "freeze_event_hash": freeze_hash, "author_fingerprint": author_fp,
        "reviewer_fingerprint": bytes_hash(_public(reviewer_key)),
        "decision": "GO", "reason": "Independent byte and receipt review.",
    })
    args = dict(ledger_path=controller.ledger.path, workspace=workspace, state_dir=state,
                root_pin_path=root_pin, expected_root_pin_sha256=root_pin_sha,
                reviewer_pin_path=reviewer_pin,
                expected_reviewer_pin_sha256=reviewer_pin_sha,
                grant_id="grant-01", task_id="task-01", task_revision=2,
                manifest_path=Path(frozen["manifest_path"]),
                expected_manifest_sha256=frozen["manifest_sha256"],
                signed_review=review)
    return controller, args, scope, root_key


def _v3_build_fixture(tmp_path, *, author_event=False):
    """Use signed v3 authority and real BUILD, TEST, and freeze effects."""
    workspace = tmp_path / "workspace"
    source = workspace / "src" / "value.py"
    test = workspace / "tests" / "check.py"
    output = workspace / "dist" / "package.bin"
    for path in (source, test, output):
        path.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"value = 1\n")
    test.write_text("from pathlib import Path\n"
                    "assert Path('src/value.py').read_bytes() == b'value = 1\\n'\n"
                    "assert Path('dist/package.bin').read_bytes() == b'built-by-command'\n",
                    encoding="utf-8")
    output.write_bytes(b"old-output")
    root_key = Ed25519PrivateKey.generate()
    reviewer_key = Ed25519PrivateKey.generate()
    author_key = Ed25519PrivateKey.generate()
    root_pin = tmp_path / "root-key" / "pin.json"
    reviewer_pin = tmp_path / "reviewer-key" / "pin.json"
    root_pin_sha = _pin(root_pin, root_key, "M2_CONSTRUCTION_PIN_1")
    reviewer_pin_sha = _pin(reviewer_pin, reviewer_key, "M2_CONSTRUCTION_REVIEWER_PIN_1")
    state = tmp_path / "state"
    controller = Controller(workspace=workspace, state_dir=state, pin_path=root_pin,
                            expected_pin_sha256=root_pin_sha)
    program = Path(sys.executable).resolve(strict=True)
    now = int(time.time())
    scope = {
        "schema": "M2_CONSTRUCTION_SCOPE_3", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 3,
        "workspace_root": str(workspace), "state_root": str(state),
        "baseline_files": {"src/value.py": bytes_hash(source.read_bytes()),
                           "tests/check.py": bytes_hash(test.read_bytes()),
                           "dist/package.bin": bytes_hash(output.read_bytes())},
        "allowed_files": ["src/value.py", "tests/check.py", "dist/package.bin"],
        "creatable_files": [], "allowed_effects": ["BUILD", "TEST", "FREEZE"],
        "allowed_commands": [{
            "command_id": "build-package", "kind": "BUILD",
            "argv": [str(program), "-c", "from pathlib import Path; "
                     "Path('dist/package.bin').write_bytes(b'built-by-command')"],
            "cwd": ".", "env": {}, "timeout_seconds": 5,
            "program_sha256": bytes_hash(program.read_bytes()),
            "tracked_paths": ["src/value.py", "tests/check.py"],
            "output_files": {"dist/package.bin": bytes_hash(output.read_bytes())},
        }, {
            "command_id": "check-package", "kind": "TEST",
            "argv": [str(program), str(test)],
            "cwd": ".", "env": {}, "timeout_seconds": 5,
            "program_sha256": bytes_hash(program.read_bytes()),
            "tracked_paths": ["src/value.py", "tests/check.py", "dist/package.bin"],
            "output_files": {},
        }],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 6, "max_patch_bytes": 1024,
    }
    registered = controller.register_grant(
        _sign(root_key, "M2_CONSTRUCTION_SIGNED_SCOPE_1", scope))
    assert registered["status"] == "GRANTED", registered
    built = controller.run_command(grant_id="grant-01", task_id="task-01",
                                   task_revision=3, operation_id="build-01",
                                   command_id="build-package")
    assert built["status"] == "PASSED", built
    tested = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=3, operation_id="test-01",
                                    command_id="check-package")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="grant-01", task_id="task-01", task_revision=3,
        operation_id="freeze-01", source_files=["src/value.py"],
        test_files=["tests/check.py"], build_files=["dist/package.bin"],
        test_operation_ids=["test-01"], build_operation_ids=["build-01"])
    assert frozen["status"] == "FROZEN", frozen
    manifest = json.loads(Path(frozen["manifest_path"]).read_bytes())
    assert manifest["schema"] == "M2_CONSTRUCTION_FREEZE_2"
    assert manifest["build_receipts"][0]["receipt_sha256"] == built["receipt_sha256"]
    freeze_hash = next(row[3] for row in controller.ledger.events()
                       if json.loads(row[4]).get("kind") == "CANDIDATE_FROZEN")
    author_fp = bytes_hash(_public(author_key))
    if author_event:
        authorship = _sign(root_key, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", {
            "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
            "grant_id": "grant-01", "task_id": "task-01", "task_revision": 3,
            "candidate_sha256": frozen["manifest_sha256"],
            "author_fingerprint": author_fp,
        })
        with controller.ledger.transaction() as db:
            controller.ledger.event(db, {"kind": "AUTHOR_ATTESTED",
                                         "authorship": authorship})
    review = _sign(reviewer_key, "M2_CONSTRUCTION_SIGNED_REVIEW_1", {
        "schema": "M2_CONSTRUCTION_REVIEW_BODY_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 3,
        "candidate_sha256": frozen["manifest_sha256"],
        "test_receipts": [{"operation_id": "test-01",
                           "receipt_sha256": tested["receipt_sha256"]}],
        "freeze_event_hash": freeze_hash, "author_fingerprint": author_fp,
        "reviewer_fingerprint": bytes_hash(_public(reviewer_key)),
        "decision": "GO", "reason": "Independent build and test review.",
    })
    args = dict(ledger_path=controller.ledger.path, workspace=workspace, state_dir=state,
                root_pin_path=root_pin, expected_root_pin_sha256=root_pin_sha,
                reviewer_pin_path=reviewer_pin,
                expected_reviewer_pin_sha256=reviewer_pin_sha,
                grant_id="grant-01", task_id="task-01", task_revision=3,
                manifest_path=Path(frozen["manifest_path"]),
                expected_manifest_sha256=frozen["manifest_sha256"],
                signed_review=review)
    return controller, args, frozen


def test_go_passes_using_read_only_snapshot_without_mutating_ledger(tmp_path):
    controller, args, frozen = _fixture(tmp_path)
    before = controller.ledger.path.read_bytes()
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "PASS"
    assert verdict["dispatch_allowed"] is False
    assert verdict["candidate_sha256"] == frozen["manifest_sha256"]
    assert controller.ledger.path.read_bytes() == before
    assert len(controller.ledger.events()) == 4


@pytest.mark.parametrize("missing", ["test", "freeze", "author"])
def test_missing_controller_bound_evidence_is_indeterminate(tmp_path, missing):
    _, args, _ = _fixture(tmp_path, register_test=missing != "test",
                          freeze_event=missing != "freeze", author_event=missing != "author")
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "INDETERMINATE"
    assert verdict["dispatch_allowed"] is False


def test_valid_no_go_and_same_author_reviewer_both_fail(tmp_path):
    _, args, _ = _fixture(tmp_path / "no-go", decision="NO_GO")
    assert local_adjudicate(**args)["status"] == "FAIL"
    _, args, _ = _fixture(tmp_path / "same-author", same_author=True)
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "FAIL"
    assert verdict["reason"] == "REVIEW_NOT_INDEPENDENT"


def test_revoked_scope_tampered_chain_and_modified_source_never_pass(tmp_path):
    controller, args, _ = _fixture(tmp_path / "revoked")
    controller.revoke_grant("grant-01")
    assert local_adjudicate(**args)["status"] == "FAIL"
    controller, args, _ = _fixture(tmp_path / "tampered")
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE events SET body_json='{}' WHERE seq=2")
    assert local_adjudicate(**args)["status"] == "INDETERMINATE"
    _, args, _ = _fixture(tmp_path / "source")
    (args["workspace"] / "src" / "value.py").write_bytes(b"value = 2\n")
    assert local_adjudicate(**args)["status"] == "FAIL"


def test_forged_review_and_rebound_candidate_do_not_pass(tmp_path):
    _, args, _ = _fixture(tmp_path)
    args["signed_review"]["body"]["decision"] = "NO_GO"
    assert local_adjudicate(**args)["status"] == "INDETERMINATE"
    _, args, _ = _fixture(tmp_path / "rebound")
    args["expected_manifest_sha256"] = "f" * 64
    assert local_adjudicate(**args)["status"] == "INDETERMINATE"


def test_root_signed_authorship_cannot_be_replaced_by_an_unsigned_author_claim(tmp_path):
    controller, args, _ = _fixture(tmp_path)
    with sqlite3.connect(controller.ledger.path) as db:
        row = db.execute("SELECT body_json FROM events WHERE seq=4").fetchone()
        event = json.loads(row[0])
        event["authorship"]["body"]["author_fingerprint"] = "f" * 64
        db.execute("UPDATE events SET body_json=? WHERE seq=4",
                   (json.dumps(event, sort_keys=True, separators=(",", ":")),))
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "INDETERMINATE"
    assert verdict["dispatch_allowed"] is False


def test_root_and_reviewer_public_key_cannot_be_same_identity(tmp_path):
    _, args, _ = _fixture(tmp_path, root_is_reviewer=True)
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "FAIL"
    assert verdict["reason"] == "REVIEW_ROOT_COLLISION"
    assert verdict["dispatch_allowed"] is False


def test_real_v2_test_and_freeze_wait_for_trusted_authorship(tmp_path):
    controller, args, _, _ = _v2_fixture(tmp_path)
    before = controller.ledger.path.read_bytes()
    verdict = local_adjudicate(**args)
    assert verdict == {"status": "INDETERMINATE",
                       "reason": "AUTHOR_ATTESTATION_MISSING",
                       "dispatch_allowed": False}
    assert controller.ledger.path.read_bytes() == before


def test_real_v2_test_and_freeze_with_test_only_author_and_review_can_pass(tmp_path):
    controller, args, _, _ = _v2_fixture(tmp_path, author_event=True)
    before = controller.ledger.path.read_bytes()
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "PASS", verdict
    assert verdict["reason"] == "LOCAL_EVIDENCE_CLOSED"
    assert verdict["dispatch_allowed"] is False
    assert controller.ledger.path.read_bytes() == before


def test_v2_scope_tampering_or_invalid_signed_command_is_rejected(tmp_path):
    controller, args, scope, root_key = _v2_fixture(tmp_path)
    altered = dict(scope)
    altered["allowed_commands"] = [dict(scope["allowed_commands"][0], timeout_seconds=0)]
    signed = _sign(root_key, "M2_CONSTRUCTION_SIGNED_SCOPE_1", altered)
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE grants SET envelope_json=?,envelope_hash=? WHERE grant_id=?",
                   (canonical(signed).decode("utf-8"), digest(signed), "grant-01"))
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "INDETERMINATE"
    assert verdict["reason"] == "SCOPE_COMMAND_TIMEOUT"

    signed["body"]["allowed_commands"][0]["timeout_seconds"] = 6
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE grants SET envelope_json=?,envelope_hash=? WHERE grant_id=?",
                   (canonical(signed).decode("utf-8"), digest(signed), "grant-01"))
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "INDETERMINATE"
    assert verdict["reason"] == "SCOPE_SIGNATURE"


def test_v2_frozen_source_tampering_fails(tmp_path):
    _, args, _, _ = _v2_fixture(tmp_path, author_event=True)
    (args["workspace"] / "src" / "value.py").write_bytes(b"value = 2\n")
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "FAIL"
    assert verdict["reason"] == "FROZEN_BYTES_CHANGED"
    assert verdict["dispatch_allowed"] is False


def test_v2_cross_task_and_superseded_candidate_are_rejected(tmp_path):
    controller, args, _, _ = _v2_fixture(tmp_path, author_event=True)
    other_task = dict(args, task_id="task-other")
    verdict = local_adjudicate(**other_task)
    assert verdict["status"] == "INDETERMINATE"
    assert verdict["reason"] == "SCOPE_BINDING"

    tested = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=2, operation_id="test-02",
                                    command_id="check-value")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="grant-01", task_id="task-01", task_revision=2,
        operation_id="freeze-02", source_files=["src/value.py"],
        test_files=["tests/check.py"], build_files=[],
        test_operation_ids=["test-02"])
    assert frozen["status"] == "FROZEN", frozen
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "FAIL"
    assert verdict["reason"] == "CANDIDATE_SUPERSEDED"
    assert verdict["dispatch_allowed"] is False


def test_real_v3_build_test_freeze_waits_for_actual_author_attestation(tmp_path):
    controller, args, _ = _v3_build_fixture(tmp_path)
    before = controller.ledger.path.read_bytes()
    verdict = local_adjudicate(**args)
    assert verdict == {"status": "INDETERMINATE",
                       "reason": "AUTHOR_ATTESTATION_MISSING",
                       "dispatch_allowed": False}
    assert controller.ledger.path.read_bytes() == before


def test_real_v3_build_receipt_must_be_bound_to_ledger_before_author_check(tmp_path):
    controller, args, _ = _v3_build_fixture(tmp_path)
    with controller.ledger.transaction() as db:
        bodies = [json.loads(row[0]) for row in db.execute(
            "SELECT body_json FROM events ORDER BY seq")]
        assert sum(body.get("kind") == "BUILD_RECEIPT" for body in bodies) == 1
        db.execute("DELETE FROM events")
        for body in bodies:
            if body.get("kind") != "BUILD_RECEIPT":
                controller.ledger.event(db, body)
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "INDETERMINATE"
    assert verdict["reason"] == "BUILD_EVENT_MISSING"
    assert verdict["dispatch_allowed"] is False


def test_real_v3_build_with_test_only_author_review_can_pass_and_changed_output_fails(tmp_path):
    controller, args, frozen = _v3_build_fixture(tmp_path, author_event=True)
    before = controller.ledger.path.read_bytes()
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "PASS", verdict
    assert verdict["candidate_sha256"] == frozen["manifest_sha256"]
    assert verdict["dispatch_allowed"] is False
    assert controller.ledger.path.read_bytes() == before

    (args["workspace"] / "dist" / "package.bin").write_bytes(b"changed-later")
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "FAIL"
    assert verdict["reason"] == "FROZEN_BYTES_CHANGED"


def test_controller_records_root_signed_current_authorship_for_local_verdict(tmp_path):
    controller, args, scope, root_key = _v2_fixture(tmp_path, author_event=False)
    assert local_adjudicate(**args)["reason"] == "AUTHOR_ATTESTATION_MISSING"
    author_fp = args["signed_review"]["body"]["author_fingerprint"]
    body = {
        "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
        "grant_id": scope["grant_id"], "task_id": scope["task_id"],
        "task_revision": scope["task_revision"],
        "candidate_sha256": args["expected_manifest_sha256"],
        "author_fingerprint": author_fp,
    }
    signed = _sign(root_key, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", body)
    recorded = controller.record_author_attestation(
        signed, grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"],
        manifest_sha256=args["expected_manifest_sha256"])
    assert recorded["status"] == "ATTESTED", recorded
    assert local_adjudicate(**args)["status"] == "PASS"
    repeated = controller.record_author_attestation(
        signed, grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"],
        manifest_sha256=args["expected_manifest_sha256"])
    assert repeated["status"] == "ATTESTED" and repeated["effect_executed"] is False


def test_self_declared_or_wrong_candidate_authorship_cannot_be_registered(tmp_path):
    controller, args, scope, root_key = _v2_fixture(tmp_path, author_event=False)
    author_fp = args["signed_review"]["body"]["author_fingerprint"]
    body = {
        "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
        "grant_id": scope["grant_id"], "task_id": scope["task_id"],
        "task_revision": scope["task_revision"],
        "candidate_sha256": args["expected_manifest_sha256"],
        "author_fingerprint": author_fp,
    }
    unsigned = {"schema": "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1",
                "body": body, "signature_b64": "self-reported", "verified": True}
    denied = controller.record_author_attestation(
        unsigned, grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"],
        manifest_sha256=args["expected_manifest_sha256"])
    assert denied["status"] == "DENIED"
    body["candidate_sha256"] = "0" * 64
    wrong = _sign(root_key, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", body)
    denied = controller.record_author_attestation(
        wrong, grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"],
        manifest_sha256=args["expected_manifest_sha256"])
    assert denied["status"] == "DENIED"
    assert local_adjudicate(**args)["reason"] == "AUTHOR_ATTESTATION_MISSING"
