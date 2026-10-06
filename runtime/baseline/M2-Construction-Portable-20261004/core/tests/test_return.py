"""Controller return path: signed scope -> real TEST -> trusted freeze event."""

import base64
import copy
import json
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m2_construction.artifacts import verify_frozen_candidate
from m2_construction.contracts import bytes_hash, canonical
from m2_construction.controller import Controller


SOURCE = "src/value.py"
TEST = "tests/check.py"
BUILD = "dist/package.bin"
FILES = (SOURCE, TEST, BUILD)


def _setup(tmp_path, *, test_code=None, tracked_paths=None):
    workspace = tmp_path / "workspace"
    for name in FILES:
        (workspace / name).parent.mkdir(parents=True, exist_ok=True)
    (workspace / SOURCE).write_bytes(b"value = 1\n")
    (workspace / TEST).write_text(
        test_code or "from pathlib import Path\n"
        "assert Path('src/value.py').read_bytes() == b'value = 1\\n'\n",
        encoding="utf-8",
    )
    (workspace / BUILD).write_bytes(b"built-actual-bytes\x00")

    # This key exists only in the test process. Only its public key is persisted.
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pin = tmp_path / "root-side" / "pin.json"
    pin.parent.mkdir()
    pin.write_bytes(canonical({
        "schema": "M2_CONSTRUCTION_PIN_1",
        "trust_domain": "TEST_ONLY",
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "fingerprint": bytes_hash(public),
    }))
    state_dir = tmp_path / "state"
    controller = Controller(
        workspace=workspace,
        state_dir=state_dir,
        pin_path=pin,
        expected_pin_sha256=bytes_hash(pin.read_bytes()),
    )
    program = Path(sys.executable).resolve(strict=True)
    now = int(time.time())
    scope = {
        "schema": "M2_CONSTRUCTION_SCOPE_2",
        "trust_domain": "TEST_ONLY",
        "grant_id": "grant-current",
        "task_id": "task-current",
        "task_revision": 2,
        "workspace_root": str(workspace.resolve(strict=True)),
        "state_root": str(state_dir.resolve()),
        "baseline_files": {
            name: bytes_hash((workspace / name).read_bytes()) for name in FILES
        },
        "allowed_files": list(FILES),
        "allowed_effects": ["PATCH", "TEST", "FREEZE"],
        "allowed_commands": [{
            "command_id": "check-value",
            "kind": "TEST",
            "argv": [str(program), str(workspace / TEST)],
            "cwd": ".",
            "env": {},
            "timeout_seconds": 10,
            "program_sha256": bytes_hash(program.read_bytes()),
            "tracked_paths": tracked_paths if tracked_paths is not None else [SOURCE, TEST],
        }],
        "not_before": now - 60,
        "expires_at": now + 3600,
        "max_operations": 10,
        "max_patch_bytes": 1024,
    }
    return controller, workspace, private, scope


def _register(controller, private, scope):
    signed = {
        "schema": "M2_CONSTRUCTION_SIGNED_SCOPE_1",
        "body": scope,
        "signature_b64": base64.b64encode(private.sign(canonical(scope))).decode("ascii"),
    }
    result = controller.register_grant(signed)
    assert result["status"] == "GRANTED", result


def _test(controller, scope, operation_id="test-current"):
    result = controller.run_command(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id=operation_id,
        command_id="check-value",
    )
    assert result["status"] in ("PASSED", "FAILED"), result
    receipt_path = Path(result["receipt_path"])
    assert receipt_path.is_file()
    assert bytes_hash(receipt_path.read_bytes()) == result["receipt_sha256"]
    assert json.loads(receipt_path.read_bytes())["tracked_files"] == {
        name: bytes_hash((controller.workspace / name).read_bytes())
        for name in scope["allowed_commands"][0]["tracked_paths"]
    }
    return result


def _freeze(controller, scope, *, operation_id="freeze-current", test_operation_ids=None,
            source_files=None, test_files=None, build_files=None):
    return controller.freeze_candidate(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id=operation_id,
        source_files=[SOURCE] if source_files is None else source_files,
        test_files=[TEST] if test_files is None else test_files,
        build_files=[] if build_files is None else build_files,
        test_operation_ids=["test-current"] if test_operation_ids is None else test_operation_ids,
    )


def _events(controller, kind):
    with controller.ledger.transaction() as db:
        controller.ledger.verify_chain(db)
    return [json.loads(row[4]) for row in controller.ledger.events()
            if json.loads(row[4]).get("kind") == kind]


def _manifest_path(controller, operation_id):
    return controller.state_dir / "evidence" / "candidates" / f"{operation_id}.manifest.json"


def test_controller_freezes_real_signed_test_receipt_and_replay_has_no_new_effect(tmp_path):
    controller, workspace, private, scope = _setup(tmp_path)
    _register(controller, private, scope)
    tested = _test(controller, scope)
    assert tested["status"] == "PASSED" and tested["exit_code"] == 0

    test_events = _events(controller, "TEST_RECEIPT")
    assert len(test_events) == 1
    assert {key: test_events[0][key] for key in (
        "grant_id", "task_id", "task_revision", "operation_id", "status", "receipt_sha256"
    )} == {
        "grant_id": scope["grant_id"], "task_id": scope["task_id"],
        "task_revision": scope["task_revision"], "operation_id": "test-current",
        "status": "PASSED", "receipt_sha256": tested["receipt_sha256"],
    }

    frozen = _freeze(controller, scope)
    assert frozen["status"] == "FROZEN", frozen
    manifest_path = _manifest_path(controller, "freeze-current")
    assert frozen["manifest_path"] == str(manifest_path)
    assert frozen["manifest_sha256"] == bytes_hash(manifest_path.read_bytes())
    manifest = json.loads(manifest_path.read_bytes())
    assert set(manifest["files"]) == {SOURCE, TEST}
    for name in (SOURCE, TEST):
        assert manifest["files"][name]["sha256"] == bytes_hash((workspace / name).read_bytes())
        assert (Path(manifest["snapshot_root"]) / name).read_bytes() == (workspace / name).read_bytes()
    assert manifest["test_receipts"][0]["operation_id"] == "test-current"
    assert manifest["test_receipts"][0]["receipt_sha256"] == tested["receipt_sha256"]
    assert verify_frozen_candidate(manifest_path,
        expected_manifest_sha256=frozen["manifest_sha256"])["status"] == "VALID"

    freezes = _events(controller, "CANDIDATE_FROZEN")
    assert len(freezes) == 1
    assert {key: freezes[0][key] for key in (
        "grant_id", "task_id", "task_revision", "manifest_path", "manifest_sha256"
    )} == {
        "grant_id": scope["grant_id"], "task_id": scope["task_id"],
        "task_revision": scope["task_revision"], "manifest_path": str(manifest_path),
        "manifest_sha256": frozen["manifest_sha256"],
    }

    original_manifest = manifest_path.read_bytes()
    repeated = _freeze(controller, scope)
    assert repeated["status"] == "FROZEN"
    assert repeated["effect_executed"] is False
    assert repeated["manifest_sha256"] == frozen["manifest_sha256"]
    assert manifest_path.read_bytes() == original_manifest
    assert len(_events(controller, "CANDIDATE_FROZEN")) == 1
    assert len(_events(controller, "TEST_RECEIPT")) == 1
    conflict = _freeze(controller, scope, test_operation_ids=["other-test"])
    assert conflict["status"] == "CONFLICT"
    assert len(_events(controller, "CANDIDATE_FROZEN")) == 1


def test_failed_controller_test_cannot_freeze(tmp_path):
    controller, _, private, scope = _setup(tmp_path, test_code="raise SystemExit(3)\n")
    _register(controller, private, scope)
    tested = _test(controller, scope)
    assert tested["status"] == "FAILED" and tested["exit_code"] == 3
    denied = _freeze(controller, scope)
    assert denied["status"] == "DENIED", denied
    assert not _manifest_path(controller, "freeze-current").exists()
    assert _events(controller, "CANDIDATE_FROZEN") == []


def test_completed_freeze_id_replay_does_not_claim_changed_bytes_are_valid(tmp_path):
    controller, workspace, private, scope = _setup(tmp_path)
    _register(controller, private, scope)
    assert _test(controller, scope)["status"] == "PASSED"
    frozen = _freeze(controller, scope)
    assert frozen["status"] == "FROZEN"
    (workspace / SOURCE).write_bytes(b"value = 99\n")
    replay = _freeze(controller, scope)
    assert replay["status"] == "DENIED"
    assert replay["effect_executed"] is False
    assert len(_events(controller, "CANDIDATE_FROZEN")) == 1


@pytest.mark.parametrize("changed", [SOURCE, TEST])
def test_changed_source_or_test_bytes_cannot_freeze_a_prior_pass(tmp_path, changed):
    controller, workspace, private, scope = _setup(tmp_path)
    _register(controller, private, scope)
    assert _test(controller, scope)["status"] == "PASSED"
    (workspace / changed).write_bytes((workspace / changed).read_bytes() + b"# changed\n")
    denied = _freeze(controller, scope)
    assert denied["status"] == "DENIED", denied
    assert not _manifest_path(controller, "freeze-current").exists()
    assert _events(controller, "CANDIDATE_FROZEN") == []


@pytest.mark.parametrize("other_identity", [
    {"grant_id": "grant-other-task", "task_id": "task-other"},
    {"grant_id": "grant-old-revision", "task_revision": 1},
])
def test_other_task_or_revision_cannot_reuse_a_controller_test_receipt(tmp_path, other_identity):
    controller, _, private, current = _setup(tmp_path)
    older_or_other = copy.deepcopy(current)
    older_or_other.update(other_identity)
    _register(controller, private, older_or_other)
    assert _test(controller, older_or_other, operation_id="test-other")["status"] == "PASSED"
    _register(controller, private, current)

    denied = _freeze(controller, current, test_operation_ids=["test-other"])
    assert denied["status"] == "DENIED", denied
    assert not _manifest_path(controller, "freeze-current").exists()
    assert _events(controller, "CANDIDATE_FROZEN") == []


def test_test_receipt_must_cover_both_source_and_test_file(tmp_path):
    controller, _, private, scope = _setup(tmp_path, tracked_paths=[SOURCE])
    _register(controller, private, scope)
    assert _test(controller, scope)["status"] == "PASSED"
    denied = _freeze(controller, scope)
    assert denied["status"] == "DENIED", denied
    assert not _manifest_path(controller, "freeze-current").exists()
    assert _events(controller, "CANDIDATE_FROZEN") == []


def test_preexisting_build_file_without_bound_build_output_cannot_freeze(tmp_path):
    controller, workspace, private, scope = _setup(tmp_path)
    assert (workspace / BUILD).is_file()
    _register(controller, private, scope)
    assert _test(controller, scope)["status"] == "PASSED"

    denied = _freeze(controller, scope, build_files=[BUILD])
    assert denied["status"] == "DENIED", denied
    assert denied["reason"] == "BUILD_OUTPUT_PROOF_REQUIRED", denied
    assert not _manifest_path(controller, "freeze-current").exists()
    assert _events(controller, "CANDIDATE_FROZEN") == []


def test_signed_build_output_and_passing_test_are_frozen_as_actual_bytes(tmp_path):
    controller, workspace, private, scope = _setup(
        tmp_path,
        test_code=("from pathlib import Path\n"
                   "assert Path('src/value.py').read_bytes() == b'value = 1\\n'\n"
                   "assert Path('dist/package.bin').read_bytes() == b'new-build-bytes'\n"),
        tracked_paths=[SOURCE, TEST, BUILD],
    )
    program = Path(sys.executable).resolve(strict=True)
    scope["schema"] = "M2_CONSTRUCTION_SCOPE_3"
    scope["creatable_files"] = []
    scope["allowed_effects"].append("BUILD")
    scope["allowed_commands"][0]["output_files"] = {}
    scope["allowed_commands"].append({
        "command_id": "build-package", "kind": "BUILD",
        "argv": [str(program), "-c",
                 "from pathlib import Path; Path('dist/package.bin').write_bytes(b'new-build-bytes')"],
        "cwd": ".", "env": {}, "timeout_seconds": 10,
        "program_sha256": bytes_hash(program.read_bytes()),
        "tracked_paths": [SOURCE, TEST],
        "output_files": {BUILD: bytes_hash((workspace / BUILD).read_bytes())},
    })
    _register(controller, private, scope)
    built = controller.run_command(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="build-current",
        command_id="build-package")
    assert built["status"] == "PASSED", built
    build_receipt = json.loads(Path(built["receipt_path"]).read_bytes())
    assert build_receipt["output_after"][BUILD]["sha256"] == bytes_hash(b"new-build-bytes")
    assert _test(controller, scope)["status"] == "PASSED"

    frozen = controller.freeze_candidate(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="freeze-build",
        source_files=[SOURCE], test_files=[TEST], build_files=[BUILD],
        test_operation_ids=["test-current"], build_operation_ids=["build-current"])
    assert frozen["status"] == "FROZEN", frozen
    manifest = json.loads(Path(frozen["manifest_path"]).read_bytes())
    assert manifest["files"][BUILD]["sha256"] == bytes_hash(b"new-build-bytes")
    assert manifest["build_receipts"][0]["operation_id"] == "build-current"
    assert verify_frozen_candidate(
        frozen["manifest_path"], expected_manifest_sha256=frozen["manifest_sha256"]
    )["status"] == "VALID"


def test_build_output_changed_after_receipt_cannot_freeze(tmp_path):
    controller, workspace, private, scope = _setup(tmp_path)
    program = Path(sys.executable).resolve(strict=True)
    scope["schema"] = "M2_CONSTRUCTION_SCOPE_3"
    scope["creatable_files"] = []
    scope["allowed_effects"].append("BUILD")
    scope["allowed_commands"][0]["output_files"] = {}
    scope["allowed_commands"].append({
        "command_id": "build-package", "kind": "BUILD",
        "argv": [str(program), "-c",
                 "from pathlib import Path; Path('dist/package.bin').write_bytes(b'new-build-bytes')"],
        "cwd": ".", "env": {}, "timeout_seconds": 10,
        "program_sha256": bytes_hash(program.read_bytes()),
        "tracked_paths": [SOURCE, TEST],
        "output_files": {BUILD: bytes_hash((workspace / BUILD).read_bytes())},
    })
    _register(controller, private, scope)
    built = controller.run_command(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="build-current",
        command_id="build-package")
    assert built["status"] == "PASSED", built
    assert _test(controller, scope)["status"] == "PASSED"
    (workspace / BUILD).write_bytes(b"changed-later")
    denied = controller.freeze_candidate(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="freeze-build",
        source_files=[SOURCE], test_files=[TEST], build_files=[BUILD],
        test_operation_ids=["test-current"], build_operation_ids=["build-current"])
    assert denied["status"] == "DENIED", denied
    assert _events(controller, "CANDIDATE_FROZEN") == []


def test_signed_build_creates_absent_output_without_a_preexisting_stub(tmp_path):
    controller, workspace, private, scope = _setup(
        tmp_path,
        test_code=("from pathlib import Path\n"
                   "assert Path('src/value.py').read_bytes() == b'value = 1\\n'\n"
                   "assert Path('dist/package.bin').read_bytes() == b'fresh-output'\n"),
        tracked_paths=[SOURCE, TEST, BUILD],
    )
    (workspace / BUILD).unlink()
    program = Path(sys.executable).resolve(strict=True)
    scope["schema"] = "M2_CONSTRUCTION_SCOPE_3"
    scope["baseline_files"][BUILD] = None
    scope["creatable_files"] = [BUILD]
    scope["allowed_effects"].extend(["CREATE", "BUILD"])
    scope["allowed_commands"][0]["output_files"] = {}
    scope["allowed_commands"].append({
        "command_id": "build-fresh", "kind": "BUILD",
        "argv": [str(program), "-c",
                 "from pathlib import Path; Path('dist/package.bin').write_bytes(b'fresh-output')"],
        "cwd": ".", "env": {}, "timeout_seconds": 10,
        "program_sha256": bytes_hash(program.read_bytes()),
        "tracked_paths": [SOURCE, TEST], "output_files": {BUILD: None},
    })
    _register(controller, private, scope)
    built = controller.run_command(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="build-fresh",
        command_id="build-fresh")
    assert built["status"] == "PASSED", built
    assert _test(controller, scope)["status"] == "PASSED"
    frozen = controller.freeze_candidate(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="freeze-fresh",
        source_files=[SOURCE], test_files=[TEST], build_files=[BUILD],
        test_operation_ids=["test-current"], build_operation_ids=["build-fresh"])
    assert frozen["status"] == "FROZEN", frozen
    manifest = json.loads(Path(frozen["manifest_path"]).read_bytes())
    assert manifest["files"][BUILD]["sha256"] == bytes_hash(b"fresh-output")


def test_scope_without_freeze_effect_cannot_freeze(tmp_path):
    controller, _, private, scope = _setup(tmp_path)
    scope["allowed_effects"].remove("FREEZE")
    _register(controller, private, scope)
    assert _test(controller, scope)["status"] == "PASSED"
    denied = _freeze(controller, scope)
    assert denied["status"] == "DENIED", denied
    assert not _manifest_path(controller, "freeze-current").exists()
    assert _events(controller, "CANDIDATE_FROZEN") == []
