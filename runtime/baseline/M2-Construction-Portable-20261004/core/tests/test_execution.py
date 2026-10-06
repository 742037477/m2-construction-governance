"""Task 1: real bytes and real SQLite, no mocked effects."""
import base64
import copy
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m2_construction.controller import Controller
from m2_construction.contracts import Denied


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fixture(tmp_path: Path, *, with_test_command=False, return_signer=False):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "sample.py"
    target.write_bytes(b"value = 1\n")
    private = Ed25519PrivateKey.generate()  # TEST_ONLY; never serialized or returned to worker.
    from cryptography.hazmat.primitives import serialization
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pin = tmp_path / "root-side" / "pin.json"
    pin.parent.mkdir()
    pin.write_text(json.dumps({
        "schema": "M2_CONSTRUCTION_PIN_1",
        "trust_domain": "TEST_ONLY",
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "fingerprint": sha(public),
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    controller = Controller(
        workspace=workspace,
        state_dir=tmp_path / "state",
        pin_path=pin,
        expected_pin_sha256=sha(pin.read_bytes()),
    )
    now = int(time.time())
    body = {
        "schema": "M2_CONSTRUCTION_SCOPE_1",
        "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01",
        "task_id": "task-01",
        "task_revision": 1,
        "workspace_root": str(workspace.resolve()),
        "state_root": str((tmp_path / "state").resolve()),
        "baseline_files": {"sample.py": sha(target.read_bytes())},
        "allowed_files": ["sample.py"],
        "allowed_effects": ["PATCH"],
        "not_before": now - 60,
        "expires_at": now + 3600,
        "max_operations": 2,
        "max_patch_bytes": 1024,
    }
    if with_test_command:
        program = Path(sys.executable).resolve()
        body["schema"] = "M2_CONSTRUCTION_SCOPE_2"
        body["allowed_effects"] = ["PATCH", "TEST"]
        body["allowed_commands"] = [{
            "command_id": "check-sample",
            "kind": "TEST",
            "argv": [str(program), "-c",
                     "from pathlib import Path; assert Path('sample.py').read_bytes() == b'value = 1\\n'"],
            "cwd": ".",
            "env": {},
            "timeout_seconds": 10,
            "program_sha256": sha(program.read_bytes()),
            "tracked_paths": ["sample.py"],
        }]
    signature = private.sign(json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8"))
    signed = {
        "schema": "M2_CONSTRUCTION_SIGNED_SCOPE_1",
        "body": body,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    if return_signer:
        return controller, target, signed, private
    return controller, target, signed


def resign(signed, private):
    signature = private.sign(json.dumps(
        signed["body"], ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8"))
    signed["signature_b64"] = base64.b64encode(signature).decode("ascii")
    return signed


def _new_file_scope(tmp_path):
    controller, target, signed, private = fixture(tmp_path, return_signer=True)
    body = signed["body"]
    body["schema"] = "M2_CONSTRUCTION_SCOPE_3"
    body["allowed_effects"] = ["PATCH", "CREATE", "TEST", "FREEZE"]
    body["allowed_files"].append("tests/new_check.py")
    body["baseline_files"]["tests/new_check.py"] = None
    body["creatable_files"] = ["tests/new_check.py"]
    body["max_operations"] = 10
    program = Path(sys.executable).resolve(strict=True)
    body["allowed_commands"] = [{
        "command_id": "check-new", "kind": "TEST",
        "argv": [str(program), "tests/new_check.py"], "cwd": ".", "env": {},
        "timeout_seconds": 10, "program_sha256": sha(program.read_bytes()),
        "tracked_paths": ["sample.py", "tests/new_check.py"],
        "output_files": {},
    }]
    (target.parent / "tests").mkdir()
    resign(signed, private)
    return controller, target, signed


def test_signed_create_new_test_then_real_test_and_freeze(tmp_path):
    controller, target, signed = _new_file_scope(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    payload = (b"from pathlib import Path\n"
               b"assert Path('sample.py').read_bytes() == b'value = 1\\n'\n")
    request = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                   operation_id="create-new-test", path="tests/new_check.py",
                   content=payload)
    created = controller.create_file(**request)
    assert created["status"] == "COMPLETED", created
    assert (target.parent / "tests/new_check.py").read_bytes() == payload
    replay = controller.create_file(**request)
    assert replay["status"] == "COMPLETED" and replay["effect_executed"] is False
    tested = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=1, operation_id="new-test",
                                    command_id="check-new")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="freeze-new", source_files=["sample.py"],
        test_files=["tests/new_check.py"], build_files=[],
        test_operation_ids=["new-test"])
    assert frozen["status"] == "FROZEN", frozen


def test_create_path_prestate_and_scope_fail_closed(tmp_path):
    controller, target, signed = _new_file_scope(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    base = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                content=b"assert True\n")
    assert controller.create_file(operation_id="create-wrong", path="other.py",
                                  **base)["status"] == "DENIED"
    assert controller.create_file(operation_id="create-overwrite", path="sample.py",
                                  **base)["status"] == "DENIED"
    (target.parent / "tests/new_check.py").write_bytes(b"outside-created\n")
    denied = controller.create_file(operation_id="create-stale",
                                    path="tests/new_check.py", **base)
    assert denied["status"] == "DENIED", denied
    assert (target.parent / "tests/new_check.py").read_bytes() == b"outside-created\n"


def test_create_unknown_after_intent_keeps_same_id_unreplayed(tmp_path, monkeypatch):
    controller, target, signed = _new_file_scope(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    original = os.open
    calls = []

    def blocked_open(path, flags, mode=0o777):
        calls.append(str(path))
        raise OSError("TEST_ONLY create interrupted")

    monkeypatch.setattr("m2_construction.controller.os.open", blocked_open)
    request = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                   operation_id="create-uncertain", path="tests/new_check.py",
                   content=b"assert True\n")
    first = controller.create_file(**request)
    assert first["status"] == "UNKNOWN" and first["new_dispatch"] is True
    monkeypatch.setattr("m2_construction.controller.os.open", original)
    second = controller.create_file(**request)
    assert second["status"] == "UNKNOWN" and second["effect_executed"] is False
    assert len(calls) == 1 and not (target.parent / "tests/new_check.py").exists()


def test_unapproved_patch_has_no_effect(tmp_path):
    controller, target, _ = fixture(tmp_path)
    result = controller.apply_patch(
        grant_id="not-granted", task_id="task-01", task_revision=1,
        operation_id="op-01", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n",
    )
    assert result["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"


def test_signed_scope_permits_one_real_patch_and_repeated_id_does_not_rewrite(tmp_path):
    controller, target, signed = fixture(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    kwargs = dict(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-01", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n",
    )
    result = controller.apply_patch(**kwargs)
    assert result["status"] == "COMPLETED"
    assert result["after_sha256"] == sha(b"value = 2\n")
    assert target.read_bytes() == b"value = 2\n"
    replay = controller.apply_patch(**kwargs)
    assert replay["status"] == "COMPLETED"
    assert replay["effect_executed"] is False
    assert target.read_bytes() == b"value = 2\n"


def test_wrong_before_hash_and_operation_id_collision_do_not_change_bytes(tmp_path):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    wrong = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-bad", path="sample.py",
        before_sha256="0" * 64, content=b"value = 2\n",
    )
    assert wrong["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"
    before = sha(target.read_bytes())
    assert controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-good", path="sample.py",
        before_sha256=before, content=b"value = 2\n",
    )["status"] == "COMPLETED"
    collision = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-good", path="sample.py",
        before_sha256=before, content=b"value = 3\n",
    )
    assert collision["status"] == "CONFLICT"
    assert target.read_bytes() == b"value = 2\n"


def test_changed_external_pin_and_forged_verified_claim_rejected(tmp_path):
    controller, target, signed = fixture(tmp_path)
    signed["verified"] = True
    assert controller.register_grant(signed)["status"] == "DENIED"
    del signed["verified"]
    controller.pin_path.write_text(controller.pin_path.read_text() + " ", encoding="utf-8")
    assert controller.register_grant(signed)["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"


def test_revocation_budget_and_path_escape_fail_closed(tmp_path):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    base = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                before_sha256=sha(target.read_bytes()), content=b"value = 2\n")
    assert controller.apply_patch(operation_id="op-escape", path="../outside.py", **base)["status"] == "DENIED"
    assert controller.apply_patch(operation_id="op-absolute", path=str(target), **base)["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"
    controller.revoke_grant("grant-01")
    assert controller.apply_patch(operation_id="op-revoked", path="sample.py", **base)["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"


def test_uncertain_effect_is_never_automatically_replayed(tmp_path, monkeypatch):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    original = os.replace
    calls = []

    def fail_once(src, dst):
        calls.append((src, dst))
        raise OSError("TEST_ONLY interrupted before replace")

    monkeypatch.setattr("m2_construction.controller.os.replace", fail_once)
    kwargs = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                  operation_id="op-uncertain", path="sample.py",
                  before_sha256=sha(target.read_bytes()), content=b"value = 2\n")
    assert controller.apply_patch(**kwargs)["status"] == "UNKNOWN"
    monkeypatch.setattr("m2_construction.controller.os.replace", original)
    assert controller.apply_patch(**kwargs)["status"] == "UNKNOWN"
    assert len(calls) == 1 and target.read_bytes() == b"value = 1\n"


def test_tampered_event_chain_blocks_a_new_effect(tmp_path):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE events SET body_json='{}' WHERE seq=1")
    result = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-chain", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n",
    )
    assert result["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"


def test_same_signed_grant_cannot_reopen_in_another_state_directory(tmp_path):
    controller, target, signed = fixture(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    second = Controller(
        workspace=target.parent, state_dir=tmp_path / "state-other",
        pin_path=controller.pin_path, expected_pin_sha256=controller.expected_pin_sha256,
    )
    assert second.register_grant(signed)["status"] == "DENIED"


def test_same_target_cannot_have_two_unresolved_writers(tmp_path, monkeypatch):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    entered = threading.Event()
    resume = threading.Event()
    original = os.replace

    def held_replace(src, dst):
        entered.set()
        assert resume.wait(5), "test barrier timed out"
        return original(src, dst)

    monkeypatch.setattr("m2_construction.controller.os.replace", held_replace)
    common = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                  path="sample.py", before_sha256=sha(target.read_bytes()))
    first_result = []
    worker = threading.Thread(target=lambda: first_result.append(controller.apply_patch(
        operation_id="op-first", content=b"value = 2\n", **common)))
    worker.start()
    assert entered.wait(5), "first writer never reached effect barrier"
    second = controller.apply_patch(operation_id="op-second", content=b"value = 3\n", **common)
    resume.set()
    worker.join(5)
    assert not worker.is_alive()
    assert first_result[0]["status"] == "COMPLETED"
    assert second["status"] == "DENIED"
    assert target.read_bytes() == b"value = 2\n"


def test_signed_scope_rejects_two_case_aliases_of_one_real_file(tmp_path):
    controller, target, signed, private = fixture(tmp_path, return_signer=True)
    alias = target.with_name("SAMPLE.py")
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("case aliases are not the same file on this filesystem")
    signed["body"]["allowed_files"].append("SAMPLE.py")
    signed["body"]["baseline_files"]["SAMPLE.py"] = sha(target.read_bytes())
    result = controller.register_grant(resign(signed, private))
    assert result["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"


def test_case_alias_grants_share_one_real_effect_lock(tmp_path, monkeypatch):
    controller, target, signed, private = fixture(tmp_path, return_signer=True)
    alias = target.with_name("SAMPLE.py")
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("case aliases are not the same file on this filesystem")
    other = copy.deepcopy(signed)
    other["body"].update(grant_id="grant-02",
                         allowed_files=["SAMPLE.py"],
                         baseline_files={"SAMPLE.py": sha(target.read_bytes())})
    assert controller.register_grant(signed)["status"] == "GRANTED"
    assert controller.register_grant(resign(other, private))["status"] == "GRANTED"
    second_controller = Controller(
        workspace=target.parent, state_dir=controller.state_dir,
        pin_path=controller.pin_path,
        expected_pin_sha256=controller.expected_pin_sha256,
    )
    entered = threading.Event()
    release = threading.Event()
    original = os.replace
    replacements = []

    def held_first_replace(src, dst):
        replacements.append(str(dst))
        if Path(dst).name == "sample.py":
            entered.set()
            assert release.wait(5), "effect barrier timed out"
        return original(src, dst)

    monkeypatch.setattr("m2_construction.controller.os.replace", held_first_replace)
    common = dict(task_id="task-01", task_revision=1,
                  before_sha256=sha(target.read_bytes()))
    first_result = []
    worker = threading.Thread(target=lambda: first_result.append(controller.apply_patch(
        grant_id="grant-01", operation_id="op-lower", path="sample.py",
        content=b"value = 2\n", **common)))
    worker.start()
    try:
        assert entered.wait(5), "first writer never reached effect barrier"
        second = second_controller.apply_patch(
            grant_id="grant-02", operation_id="op-upper", path="SAMPLE.py",
            content=b"value = 3\n", **common)
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert first_result[0]["status"] == "COMPLETED"
    assert second["status"] == "DENIED"
    assert len(replacements) == 1
    assert target.read_bytes() == b"value = 2\n"
    stale = second_controller.apply_patch(
        grant_id="grant-02", operation_id="op-upper-stale", path="SAMPLE.py",
        content=b"value = 3\n", **common)
    assert stale["status"] == "DENIED"
    assert target.read_bytes() == b"value = 2\n"


def test_legacy_raw_spelling_lock_blocks_case_alias(tmp_path):
    controller, target, signed = fixture(tmp_path)
    alias = target.with_name("SAMPLE.py")
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("case aliases are not the same file on this filesystem")
    assert controller.register_grant(signed)["status"] == "GRANTED"
    with controller.ledger.transaction() as db:
        db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                   ("SAMPLE.py", "legacy-unknown"))
    result = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-under-legacy-lock", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n")
    assert result["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"


def test_legacy_one_file_lock_table_migrates_without_losing_open_lock(tmp_path):
    controller, target, signed = fixture(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    with controller.ledger.transaction() as db:
        db.execute("DROP TABLE resource_locks")
        db.execute("CREATE TABLE resource_locks(path TEXT PRIMARY KEY, "
                   "operation_id TEXT NOT NULL UNIQUE)")
        db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                   ("sample.py", "legacy-open"))
    reopened = Controller(
        workspace=target.parent, state_dir=controller.state_dir,
        pin_path=controller.pin_path,
        expected_pin_sha256=controller.expected_pin_sha256,
    )
    with reopened.ledger.transaction() as db:
        assert db.execute("SELECT path,operation_id FROM resource_locks").fetchall() == [
            ("sample.py", "legacy-open")]
        db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                   ("another.py", "legacy-open"))
    assert reopened.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-after-migration", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n")["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"
    assert sum(json.loads(row[4]).get("kind") == "RESOURCE_LOCK_SCHEMA_MIGRATED"
               for row in reopened.ledger.events()) == 1


def test_test_command_cannot_read_case_alias_during_patch(tmp_path, monkeypatch):
    controller, target, signed, private = fixture(
        tmp_path, with_test_command=True, return_signer=True)
    alias = target.with_name("SAMPLE.py")
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("case aliases are not the same file on this filesystem")
    other = copy.deepcopy(signed)
    other["body"].update(grant_id="grant-02",
                         allowed_files=["SAMPLE.py"],
                         baseline_files={"SAMPLE.py": sha(target.read_bytes())})
    other["body"]["allowed_commands"][0]["tracked_paths"] = ["SAMPLE.py"]
    assert controller.register_grant(signed)["status"] == "GRANTED"
    assert controller.register_grant(resign(other, private))["status"] == "GRANTED"
    entered = threading.Event()
    release = threading.Event()
    original = os.replace

    def held_replace(src, dst):
        entered.set()
        assert release.wait(5), "effect barrier timed out"
        return original(src, dst)

    monkeypatch.setattr("m2_construction.controller.os.replace", held_replace)
    first_result = []
    worker = threading.Thread(target=lambda: first_result.append(controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-patch", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n")))
    worker.start()
    try:
        assert entered.wait(5), "patch never reached effect barrier"
        result = controller.run_command(
            grant_id="grant-02", task_id="task-01", task_revision=1,
            operation_id="op-test-under-patch", command_id="check-sample")
    finally:
        release.set()
        worker.join(5)
    assert first_result[0]["status"] == "COMPLETED"
    assert result["status"] == "DENIED"
    assert target.read_bytes() == b"value = 2\n"


def test_effect_after_replace_then_receipt_failure_is_unknown_not_false(tmp_path, monkeypatch):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    original = os.replace

    def replaced_then_uncertain(src, dst):
        original(src, dst)
        raise OSError("TEST_ONLY crash after replace")

    monkeypatch.setattr("m2_construction.controller.os.replace", replaced_then_uncertain)
    result = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-after-replace", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n",
    )
    assert target.read_bytes() == b"value = 2\n"
    assert result["status"] == "UNKNOWN"
    assert result["effect_executed"] is None
    assert controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-after-replace", path="sample.py",
        before_sha256=sha(b"value = 1\n"), content=b"value = 2\n",
    )["status"] == "UNKNOWN"


def test_scope_revision_expiry_and_operation_budget_are_enforced(tmp_path, monkeypatch):
    controller, target, signed = fixture(tmp_path)
    controller.register_grant(signed)
    shared = dict(grant_id="grant-01", task_id="task-01", path="sample.py")
    invalid = controller.apply_patch(
        task_revision=2, operation_id="op-wrong-revision",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n", **shared)
    assert invalid["status"] == "DENIED"
    first = controller.apply_patch(
        task_revision=1, operation_id="op-one",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n", **shared)
    assert first["status"] == "COMPLETED"
    second = controller.apply_patch(
        task_revision=1, operation_id="op-two",
        before_sha256=sha(target.read_bytes()), content=b"value = 3\n", **shared)
    assert second["status"] == "COMPLETED"
    third = controller.apply_patch(
        task_revision=1, operation_id="op-three",
        before_sha256=sha(target.read_bytes()), content=b"value = 4\n", **shared)
    assert third["status"] == "DENIED"
    assert target.read_bytes() == b"value = 3\n"
    future = signed["body"]["expires_at"] + 1
    monkeypatch.setattr("m2_construction.controller.time.time", lambda: future)
    expired = controller.apply_patch(
        task_revision=1, operation_id="op-expired",
        before_sha256=sha(target.read_bytes()), content=b"value = 4\n", **shared)
    assert expired["status"] == "DENIED"


def test_signed_path_replaced_with_link_never_writes_external_target(tmp_path):
    controller, target, signed = fixture(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"safe\n")
    target.unlink()
    try:
        target.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"Windows symlink creation not available: {exc}")
    result = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-link", path="sample.py",
        before_sha256=sha(b"value = 1\n"), content=b"unsafe\n",
    )
    assert result["status"] == "DENIED"
    assert outside.read_bytes() == b"safe\n"


def test_signed_fixed_test_command_runs_real_process_and_records_receipt(tmp_path):
    controller, target, signed = fixture(tmp_path, with_test_command=True)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    kwargs = dict(grant_id="grant-01", task_id="task-01", task_revision=1,
                  operation_id="op-test", command_id="check-sample")
    result = controller.run_command(**kwargs)
    assert result["status"] == "PASSED"
    assert result["exit_code"] == 0
    assert Path(result["receipt_path"]).is_file()
    assert controller.run_command(**kwargs)["effect_executed"] is False
    assert controller.run_command(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-unauthorized", command_id="arbitrary-shell")["status"] == "DENIED"
    assert target.read_bytes() == b"value = 1\n"
