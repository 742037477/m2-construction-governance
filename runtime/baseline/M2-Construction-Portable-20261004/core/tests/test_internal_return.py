"""A passing local verdict permits only one separately signed parent return."""

import json
from pathlib import Path
import sys
import time

from m2_construction.adjudication import local_adjudicate
from m2_construction.contracts import bytes_hash
from test_adjudication import _sign, _v2_fixture


def _ready(tmp_path):
    controller, args, _, root = _v2_fixture(tmp_path)
    manifest_sha = args["expected_manifest_sha256"]
    author_fp = args["signed_review"]["body"]["author_fingerprint"]
    author = _sign(root, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", {
        "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 2,
        "candidate_sha256": manifest_sha, "author_fingerprint": author_fp,
    })
    assert controller.record_author_attestation(
        author, grant_id="grant-01", task_id="task-01", task_revision=2,
        manifest_sha256=manifest_sha)["status"] == "ATTESTED"
    verdict = local_adjudicate(**args)
    assert verdict["status"] == "PASS", verdict
    workspace = controller.workspace
    (workspace / "parent" / "src").mkdir(parents=True)
    (workspace / "parent" / "tests").mkdir()
    program = Path(sys.executable).resolve(strict=True)
    test_code = (
        "from pathlib import Path\n"
        f"assert Path('parent/src/value.py').read_bytes() == "
        f"{(workspace / 'src/value.py').read_bytes()!r}\n"
        f"assert Path('parent/tests/check.py').read_bytes() == "
        f"{(workspace / 'tests/check.py').read_bytes()!r}\n")
    now = int(time.time())
    parent = {
        "schema": "M2_CONSTRUCTION_SCOPE_3", "trust_domain": "TEST_ONLY",
        "grant_id": "parent-grant", "task_id": "parent-task", "task_revision": 1,
        "workspace_root": str(workspace), "state_root": str(controller.state_dir),
        "baseline_files": {"parent/src/value.py": None,
                           "parent/tests/check.py": None},
        "allowed_files": ["parent/src/value.py", "parent/tests/check.py"],
        "creatable_files": ["parent/src/value.py", "parent/tests/check.py"],
        "allowed_effects": ["CREATE", "PATCH", "TEST", "FREEZE"],
        "allowed_commands": [{
            "command_id": "parent-check", "kind": "TEST",
            "argv": [str(program), "-c", test_code], "cwd": ".", "env": {},
            "timeout_seconds": 10,
            "program_sha256": bytes_hash(program.read_bytes()),
            "tracked_paths": ["parent/src/value.py", "parent/tests/check.py"],
            "output_files": {},
        }],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 5, "max_patch_bytes": 10_000,
    }
    granted = controller.register_grant(_sign(root, "M2_CONSTRUCTION_SIGNED_SCOPE_1",
                                               parent))
    assert granted["status"] == "GRANTED", granted
    manifest = json.loads(args["manifest_path"].read_bytes())
    files = [
        {"source": "src/value.py", "destination": "parent/src/value.py",
         "sha256": manifest["files"]["src/value.py"]["sha256"]},
        {"source": "tests/check.py", "destination": "parent/tests/check.py",
         "sha256": manifest["files"]["tests/check.py"]["sha256"]},
    ]
    body = {
        "schema": "M2_CONSTRUCTION_RETURN_BODY_1", "trust_domain": "TEST_ONLY",
        "return_id": "return-01", "child_grant_id": "grant-01",
        "child_task_id": "task-01", "child_task_revision": 2,
        "parent_grant_id": "parent-grant", "parent_task_id": "parent-task",
        "parent_task_revision": 1, "candidate_sha256": manifest_sha,
        "review_sha256": verdict["review_sha256"], "files": files,
        "not_before": now - 60, "expires_at": now + 3600,
    }
    signed_return = _sign(root, "M2_CONSTRUCTION_SIGNED_RETURN_1", body)
    return controller, args, root, body, signed_return, files


def _consume(controller, args, signed):
    return controller.consume_internal_return(
        signed, signed_review=args["signed_review"],
        reviewer_pin_path=args["reviewer_pin_path"],
        expected_reviewer_pin_sha256=args["expected_reviewer_pin_sha256"])


def test_real_local_pass_consumed_once_into_exact_parent(tmp_path):
    controller, args, _, _, signed, files = _ready(tmp_path)
    result = _consume(controller, args, signed)
    assert result["status"] == "COMPLETED", result
    assert result["authority"] == "INTERNAL_PARENT_ONLY"
    assert result["effect_executed"] is True
    for item in files:
        target = controller.workspace.joinpath(*item["destination"].split("/"))
        assert bytes_hash(target.read_bytes()) == item["sha256"]
    events = [json.loads(row[4]) for row in controller.ledger.events()]
    kinds = [event["kind"] for event in events]
    assert "INTERNAL_RETURN_INTENT" in kinds
    assert "INTERNAL_RETURN_CONSUMED" in kinds
    assert "RELEASE_CONSUMED" not in kinds
    again = _consume(controller, args, signed)
    assert again["status"] == "COMPLETED" and again["effect_executed"] is False
    assert [json.loads(row[4]) for row in controller.ledger.events()] == events


def test_parent_can_run_real_test_and_freeze_returned_bytes(tmp_path):
    controller, args, _, _, signed, files = _ready(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    tested = controller.run_command(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-test-01", command_id="parent-check")
    assert tested["status"] == "PASSED", tested
    frozen = controller.freeze_candidate(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-freeze-01",
        source_files=["parent/src/value.py"],
        test_files=["parent/tests/check.py"], build_files=[],
        test_operation_ids=["parent-test-01"])
    assert frozen["status"] == "FROZEN", frozen
    manifest = json.loads(Path(frozen["manifest_path"]).read_bytes())
    assert manifest["files"]["parent/src/value.py"]["sha256"] == files[0]["sha256"]


def test_parent_patch_uses_actual_return_receipt_as_prestate(tmp_path):
    controller, args, _, _, signed, files = _ready(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    amended = controller.apply_patch(
        grant_id="parent-grant", task_id="parent-task", task_revision=1,
        operation_id="parent-patch-01", path="parent/src/value.py",
        before_sha256=files[0]["sha256"], content=b"value = 2\n")
    assert amended["status"] == "COMPLETED", amended
    assert (controller.workspace / "parent/src/value.py").read_bytes() == b"value = 2\n"


def test_wrong_parent_and_changed_candidate_fail_without_effect(tmp_path):
    controller, args, root, body, _, files = _ready(tmp_path)
    wrong = {**body, "parent_task_id": "other-parent"}
    denied = _consume(controller, args, _sign(root,
                      "M2_CONSTRUCTION_SIGNED_RETURN_1", wrong))
    assert denied["status"] == "DENIED"
    source = controller.workspace / "src" / "value.py"
    source.write_bytes(b"tampered\n")
    denied = _consume(controller, args, _sign(root,
                      "M2_CONSTRUCTION_SIGNED_RETURN_1", body))
    assert denied["status"] == "DENIED"
    assert all(not controller.workspace.joinpath(*item["destination"].split("/"))
               .exists() for item in files)


def test_revoked_parent_and_second_return_id_denied(tmp_path):
    controller, args, root, body, signed, _ = _ready(tmp_path)
    assert _consume(controller, args, signed)["status"] == "COMPLETED"
    duplicate = {**body, "return_id": "return-02"}
    denied = _consume(controller, args, _sign(root,
                      "M2_CONSTRUCTION_SIGNED_RETURN_1", duplicate))
    assert denied["status"] == "DENIED"
    controller.revoke_grant("parent-grant")
    denied = _consume(controller, args, signed)
    assert denied["status"] == "DENIED"


def test_uncertain_parent_copy_is_not_redispatched(tmp_path, monkeypatch):
    import m2_construction.internal_return as return_module

    controller, args, root, body, signed, files = _ready(tmp_path)
    actual_open = return_module.os.open

    def fail_first_target(path, *positional, **keyword):
        if Path(path).name == "value.py" and "parent" in Path(path).parts:
            raise OSError("injected uncertain copy")
        return actual_open(path, *positional, **keyword)

    monkeypatch.setattr(return_module.os, "open", fail_first_target)
    uncertain = _consume(controller, args, signed)
    assert uncertain["status"] == "UNKNOWN", uncertain
    assert uncertain["effect_executed"] is None
    monkeypatch.setattr(return_module.os, "open", actual_open)
    replay = _consume(controller, args, signed)
    assert replay["status"] == "UNKNOWN" and replay["new_dispatch"] is False
    assert all(not controller.workspace.joinpath(*item["destination"].split("/"))
               .exists() for item in files)
    another_id = _sign(root, "M2_CONSTRUCTION_SIGNED_RETURN_1",
                       {**body, "return_id": "return-02"})
    denied = _consume(controller, args, another_id)
    assert denied["status"] == "DENIED"
    assert denied["reason"] == "RETURN_ALREADY_RESERVED"
