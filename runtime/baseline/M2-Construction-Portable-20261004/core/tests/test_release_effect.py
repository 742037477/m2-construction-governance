"""Only a separate TEST_ONLY Root lease may publish a CEO-accepted candidate."""

import json
import os
from pathlib import Path
import sqlite3
import time

from m2_construction.contracts import bytes_hash
from m2_construction.pre_release import pre_release_readonly
from m2_construction.release_effect import post_release_readonly
from test_adjudication import _sign
from test_pre_release import _ready_parent


def _ready_release(tmp_path):
    controller, args, _, _, root, _, _, _ = _ready_parent(tmp_path)
    pre = pre_release_readonly(**args)
    assert pre["status"] == "PASS", pre
    target_root = tmp_path / "isolated-release"
    (target_root / "src").mkdir(parents=True)
    (target_root / "tests").mkdir()
    manifest = json.loads(args["manifest_path"].read_bytes())
    files = [
        {"source": name, "destination": name.removeprefix("parent/"),
         "sha256": record["sha256"]}
        for name, record in sorted(manifest["files"].items())
    ]
    now = int(time.time())
    body = {
        "schema": "M2_CONSTRUCTION_RELEASE_BODY_1", "trust_domain": "TEST_ONLY",
        "release_id": "release-01", "parent_grant_id": "parent-grant",
        "parent_task_id": "parent-task", "parent_task_revision": 1,
        "candidate_sha256": pre["candidate_sha256"],
        "review_sha256": pre["review_sha256"],
        "ceo_acceptance_sha256": pre["ceo_acceptance_sha256"],
        "pre_release_sha256": pre["pre_release_sha256"],
        "return_operation_id": pre["internal_return_operation_id"],
        "return_files_sha256": pre["internal_return_files_sha256"],
        "target_root": str(target_root), "files": files,
        "not_before": now - 60, "expires_at": now + 3600,
    }
    signed = _sign(root, "M2_CONSTRUCTION_SIGNED_RELEASE_1", body)
    return controller, args, root, target_root, body, signed


def _consume(controller, args, signed):
    names = ("reviewer_pin_path", "expected_reviewer_pin_sha256",
             "child_reviewer_pin_path", "expected_child_reviewer_pin_sha256",
             "ceo_pin_path", "expected_ceo_pin_sha256",
             "signed_review", "signed_ceo_acceptance")
    return controller.consume_release(
        signed, **{name: args[name] for name in names})


def test_exact_release_then_read_only_post_verifies_real_bytes(tmp_path):
    controller, args, _, target_root, body, signed = _ready_release(tmp_path)
    result = _consume(controller, args, signed)
    assert result["status"] == "COMPLETED", result
    assert result["authority"] == "TEST_ONLY_RELEASE"
    for item in body["files"]:
        assert bytes_hash(target_root.joinpath(*item["destination"].split("/"))
                          .read_bytes()) == item["sha256"]
    events = [json.loads(row[4]) for row in controller.ledger.events()]
    assert sum(item["kind"] == "RELEASE_CONSUMED" for item in events) == 1
    post = post_release_readonly(
        ledger_path=controller.ledger.path, workspace=controller.workspace,
        state_dir=controller.state_dir, root_pin_path=controller.pin_path,
        expected_root_pin_sha256=controller.expected_pin_sha256,
        signed_release=signed)
    assert post["status"] == "VERIFIED", post
    assert post["dispatch_allowed"] is False
    replay = _consume(controller, args, signed)
    assert replay["status"] == "COMPLETED"
    assert replay["effect_executed"] is False
    assert [json.loads(row[4]) for row in controller.ledger.events()] == events


def test_post_rejects_actual_target_change(tmp_path):
    controller, args, _, target_root, body, signed = _ready_release(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    target = target_root.joinpath(*body["files"][0]["destination"].split("/"))
    target.write_bytes(b"different\n")
    post = post_release_readonly(
        ledger_path=controller.ledger.path, workspace=controller.workspace,
        state_dir=controller.state_dir, root_pin_path=controller.pin_path,
        expected_root_pin_sha256=controller.expected_pin_sha256,
        signed_release=signed)
    assert post["status"] == "FAIL", post
    assert post["dispatch_allowed"] is False


def test_post_rejects_operation_request_hash_change(tmp_path):
    controller, args, _, _, _, signed = _ready_release(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE operations SET request_hash=? WHERE operation_id=?",
                   ("0" * 64, signed["body"]["release_id"]))
    post = post_release_readonly(
        ledger_path=controller.ledger.path, workspace=controller.workspace,
        state_dir=controller.state_dir, root_pin_path=controller.pin_path,
        expected_root_pin_sha256=controller.expected_pin_sha256,
        signed_release=signed)
    assert post["status"] == "FAIL", post


def test_post_verified_marker_is_idempotent_and_requires_real_target(tmp_path):
    controller, args, _, target_root, body, signed = _ready_release(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    first = controller.record_post_release(signed)
    assert first["status"] == "VERIFIED", first
    assert first["effect_executed"] is True
    events = controller.ledger.events()
    assert sum(json.loads(row[4])["kind"] == "POST_RELEASE_VERIFIED"
               for row in events) == 1
    second = controller.record_post_release(signed)
    assert second["status"] == "VERIFIED", second
    assert second["effect_executed"] is False
    assert controller.ledger.events() == events
    target = target_root.joinpath(*body["files"][0]["destination"].split("/"))
    target.write_bytes(b"changed after verification\n")
    changed = controller.record_post_release(signed)
    assert changed["status"] == "DENIED", changed
    assert controller.ledger.events() == events


def test_completed_release_can_be_read_after_lease_expiry_without_copy(tmp_path,
                                                                        monkeypatch):
    import m2_construction.release_effect as module

    controller, args, _, _, body, signed = _ready_release(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    events = controller.ledger.events()
    monkeypatch.setattr(module.time, "time", lambda: body["expires_at"] + 1)
    replay = _consume(controller, args, signed)
    assert replay["status"] == "COMPLETED", replay
    assert replay["effect_executed"] is False
    assert controller.ledger.events() == events


def test_release_and_post_require_exact_isolated_target_tree(tmp_path):
    controller, args, _, target_root, _, signed = _ready_release(tmp_path)
    extra = target_root / "unlisted.txt"
    extra.write_bytes(b"not part of signed release\n")
    before = _consume(controller, args, signed)
    assert before["status"] == "DENIED", before
    assert not any(json.loads(row[4])["kind"] == "RELEASE_INTENT"
                   for row in controller.ledger.events())
    extra.unlink()
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    extra.write_bytes(b"added after release\n")
    post = post_release_readonly(
        ledger_path=controller.ledger.path, workspace=controller.workspace,
        state_dir=controller.state_dir, root_pin_path=controller.pin_path,
        expected_root_pin_sha256=controller.expected_pin_sha256,
        signed_release=signed)
    assert post["status"] == "FAIL", post


def test_completed_release_replay_rejects_operation_binding_change(tmp_path):
    controller, args, _, _, _, signed = _ready_release(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    with sqlite3.connect(controller.ledger.path) as db:
        row = db.execute("SELECT result_json FROM operations WHERE operation_id=?",
                         (signed["body"]["release_id"],)).fetchone()
        changed = json.loads(row[0])
        changed["candidate_sha256"] = "0" * 64
        db.execute("UPDATE operations SET result_json=? WHERE operation_id=?",
                   (json.dumps(changed, sort_keys=True, separators=(",", ":")),
                    signed["body"]["release_id"]))
    result = _consume(controller, args, signed)
    assert result["status"] == "DENIED", result


def test_windows_destination_alias_denied_before_intent(tmp_path):
    if os.name != "nt":
        return
    controller, args, root, target_root, body, _ = _ready_release(tmp_path)
    files = [{**body["files"][0], "destination": "src/item.py"},
             {**body["files"][1], "destination": "src/ITEM.py"}]
    signed = _sign(root, "M2_CONSTRUCTION_SIGNED_RELEASE_1",
                   {**body, "files": files})
    result = _consume(controller, args, signed)
    assert result["status"] == "DENIED", result
    assert not any(item["kind"] == "RELEASE_INTENT" for item in
                   (json.loads(row[4]) for row in controller.ledger.events()))


def test_release_rejects_wrong_target_and_changed_parent_bytes(tmp_path):
    controller, args, root, target_root, body, signed = _ready_release(tmp_path)
    wrong = {**body, "target_root": str(controller.workspace)}
    denied = _consume(controller, args, _sign(
        root, "M2_CONSTRUCTION_SIGNED_RELEASE_1", wrong))
    assert denied["status"] == "DENIED"
    (controller.workspace / "parent/src/value.py").write_bytes(b"changed\n")
    denied = _consume(controller, args, signed)
    assert denied["status"] == "DENIED"
    assert all(not target_root.joinpath(*item["destination"].split("/"))
               .exists() for item in body["files"])


def test_release_unknown_does_not_repeat_or_change_target(tmp_path, monkeypatch):
    import m2_construction.release_effect as module

    controller, args, root, target_root, body, signed = _ready_release(tmp_path)
    real_open = module.os.open

    def uncertain(path, *positional, **keyword):
        if target_root in Path(path).parents and Path(path).name == "value.py":
            raise OSError("injected uncertain release")
        return real_open(path, *positional, **keyword)

    monkeypatch.setattr(module.os, "open", uncertain)
    first = _consume(controller, args, signed)
    assert first["status"] == "UNKNOWN"
    monkeypatch.setattr(module.os, "open", real_open)
    second = _consume(controller, args, signed)
    assert second["status"] == "UNKNOWN" and second["new_dispatch"] is False
    other = _sign(root, "M2_CONSTRUCTION_SIGNED_RELEASE_1",
                  {**body, "release_id": "release-02"})
    denied = _consume(controller, args, other)
    assert denied["status"] == "DENIED"
    assert all(not target_root.joinpath(*item["destination"].split("/"))
               .exists() for item in body["files"])
