"""Real subprocess/request-file coverage for the TEST_ONLY CLI boundary."""
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from m2_construction.adjudication import local_adjudicate
from m2_construction.contracts import canonical
from test_adjudication import _pin, _sign, _v2_fixture
from test_pre_release import _ready_parent


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"


def _sha(raw):
    return sha256(raw).hexdigest()


def _json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return path


def _setup(tmp_path, *, full=False, bad_program_hash=False):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "sample.py"
    target.write_bytes(b"value = 1\n")
    state = tmp_path / "state"
    private = Ed25519PrivateKey.generate()  # TEST_ONLY; never serialized.
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    pin = _json(tmp_path / "pin.json", {
        "schema": "M2_CONSTRUCTION_PIN_1", "trust_domain": "TEST_ONLY",
        "public_key_b64": base64.b64encode(public).decode("ascii"),
        "fingerprint": _sha(public),
    })
    config = _json(tmp_path / "bootstrap.json", {
        "schema": "M2_CONSTRUCTION_CLI_CONFIG_1",
        "workspace_root": str(workspace.resolve()),
        "state_root": str(state.resolve()),
        "pin_path": str(pin.resolve()),
        "expected_pin_sha256": _sha(pin.read_bytes()),
    })
    now = int(time.time())
    body = {
        "schema": "M2_CONSTRUCTION_SCOPE_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 1,
        "workspace_root": str(workspace.resolve()), "state_root": str(state.resolve()),
        "baseline_files": {"sample.py": _sha(target.read_bytes())},
        "allowed_files": ["sample.py"], "allowed_effects": ["PATCH"],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 2, "max_patch_bytes": 1024,
    }
    if full:
        (workspace / "tests").mkdir()
        (workspace / "dist").mkdir()
        program = Path(sys.executable).resolve(strict=True)
        program_hash = _sha(program.read_bytes())
        body.update({
            "schema": "M2_CONSTRUCTION_SCOPE_3",
            "baseline_files": {"sample.py": _sha(target.read_bytes()),
                               "tests/check.py": None, "dist/package.bin": None},
            "allowed_files": ["sample.py", "tests/check.py", "dist/package.bin"],
            "creatable_files": ["tests/check.py", "dist/package.bin"],
            "allowed_effects": ["CREATE", "BUILD", "TEST", "FREEZE"],
            "allowed_commands": [{
                "command_id": "build-package", "kind": "BUILD",
                "argv": [str(program), "-c", "from pathlib import Path; "
                         "Path('dist/package.bin').write_bytes(b'built-v1')"],
                "cwd": ".", "env": {}, "timeout_seconds": 10,
                "program_sha256": ("0" * 64 if bad_program_hash else program_hash),
                "tracked_paths": ["sample.py", "tests/check.py"],
                "output_files": {"dist/package.bin": None},
            }, {
                "command_id": "check-package", "kind": "TEST",
                "argv": [str(program), "tests/check.py"],
                "cwd": ".", "env": {}, "timeout_seconds": 10,
                "program_sha256": program_hash,
                "tracked_paths": ["sample.py", "tests/check.py", "dist/package.bin"],
                "output_files": {},
            }],
            "max_operations": 10, "max_patch_bytes": 2048,
        })
    signature = private.sign(json.dumps(
        body, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False).encode("utf-8"))
    signed = {
        "schema": "M2_CONSTRUCTION_SIGNED_SCOPE_1", "body": body,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    return workspace, state, target, config, signed


def _call(tmp_path, config, verb, request, *, config_sha=None):
    request_path = _json(tmp_path / f"{verb}-request.json", request)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SOURCE_ROOT)
    result = subprocess.run([
        sys.executable, "-m", "m2_construction.cli",
        "--config", str(config), "--config-sha256",
        config_sha or _sha(config.read_bytes()), verb,
        "--request", str(request_path),
    ], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    return result, json.loads(result.stdout)


def _release_config(tmp_path, args):
    """Provision all four public identities through the trusted bootstrap."""
    return _json(tmp_path / "release-bootstrap.json", {
        "schema": "M2_CONSTRUCTION_CLI_CONFIG_3",
        "workspace_root": str(args["workspace"]),
        "state_root": str(args["state_dir"]),
        "pin_path": str(args["root_pin_path"]),
        "expected_pin_sha256": args["expected_root_pin_sha256"],
        "reviewer_pin_path": str(args["reviewer_pin_path"]),
        "expected_reviewer_pin_sha256": args["expected_reviewer_pin_sha256"],
        "child_reviewer_pin_path": str(args["child_reviewer_pin_path"]),
        "expected_child_reviewer_pin_sha256":
            args["expected_child_reviewer_pin_sha256"],
        "ceo_pin_path": str(args["ceo_pin_path"]),
        "expected_ceo_pin_sha256": args["expected_ceo_pin_sha256"],
    })


def _accept_request(args):
    return {
        "schema": "M2_CONSTRUCTION_CEO_ACCEPT_REQUEST_1",
        "grant_id": args["grant_id"], "task_id": args["task_id"],
        "task_revision": args["task_revision"],
        "manifest_path": str(args["manifest_path"]),
        "expected_manifest_sha256": args["expected_manifest_sha256"],
        "signed_review": args["signed_review"],
        "signed_ceo_acceptance": args["signed_ceo_acceptance"],
    }


def _release_request(root, args, pre, tmp_path):
    target = tmp_path / "isolated-release"
    target.mkdir()
    (target / "src").mkdir()
    (target / "tests").mkdir()
    manifest = json.loads(args["manifest_path"].read_bytes())
    files = [{"source": path, "destination": path.removeprefix("parent/"),
              "sha256": item["sha256"]}
             for path, item in sorted(manifest["files"].items())]
    now = int(time.time())
    body = {
        "schema": "M2_CONSTRUCTION_RELEASE_BODY_1", "trust_domain": "TEST_ONLY",
        "release_id": "cli-release-01", "parent_grant_id": args["grant_id"],
        "parent_task_id": args["task_id"],
        "parent_task_revision": args["task_revision"],
        "candidate_sha256": pre["candidate_sha256"],
        "review_sha256": pre["review_sha256"],
        "ceo_acceptance_sha256": pre["ceo_acceptance_sha256"],
        "pre_release_sha256": pre["pre_release_sha256"],
        "return_operation_id": pre["internal_return_operation_id"],
        "return_files_sha256": pre["internal_return_files_sha256"],
        "target_root": str(target), "files": files,
        "not_before": now - 60, "expires_at": now + 3600,
    }
    return target, {"schema": "M2_CONSTRUCTION_RELEASE_REQUEST_1",
                    "signed_release": _sign(root, "M2_CONSTRUCTION_SIGNED_RELEASE_1", body),
                    "signed_review": args["signed_review"],
                    "signed_ceo_acceptance": args["signed_ceo_acceptance"]}


def test_cli_accept_pre_release_consume_and_post_across_processes(tmp_path):
    controller, args, _, _, root, _, _, _ = _ready_parent(tmp_path, record=False)
    config = _release_config(tmp_path, args)
    accepted_request = _accept_request(args)
    pre_request = {**accepted_request,
                   "schema": "M2_CONSTRUCTION_PRE_RELEASE_REQUEST_1"}
    before = controller.ledger.path.read_bytes()
    launched, missing = _call(tmp_path, config, "pre-release", pre_request)
    assert launched.returncode == 3 and missing["status"] == "INDETERMINATE"
    assert missing["reason"] == "CEO_ACCEPTANCE_MISSING"
    assert controller.ledger.path.read_bytes() == before
    launched, accepted = _call(tmp_path, config, "ceo-accept", accepted_request)
    assert launched.returncode == 0 and accepted["status"] == "ACCEPTED", accepted
    assert accepted["effect_executed"] is True
    launched, replay = _call(tmp_path, config, "ceo-accept", accepted_request)
    assert launched.returncode == 0 and replay["effect_executed"] is False

    before = controller.ledger.path.read_bytes()
    launched, pre = _call(tmp_path, config, "pre-release", pre_request)
    assert launched.returncode == 0 and pre["status"] == "PASS", pre
    assert pre["dispatch_allowed"] is False
    assert controller.ledger.path.read_bytes() == before
    target, release_request = _release_request(root, args, pre, tmp_path)
    launched, consumed = _call(tmp_path, config, "release", release_request)
    assert launched.returncode == 0 and consumed["status"] == "COMPLETED", consumed
    assert consumed["authority"] == "TEST_ONLY_RELEASE"
    assert consumed["effect_executed"] is True
    launched, replay = _call(tmp_path, config, "release", release_request)
    assert launched.returncode == 0 and replay["effect_executed"] is False

    before = controller.ledger.path.read_bytes()
    launched, post = _call(tmp_path, config, "post-release", {
        "schema": "M2_CONSTRUCTION_POST_RELEASE_REQUEST_1",
        "signed_release": release_request["signed_release"],
    })
    assert launched.returncode == 0 and post["status"] == "VERIFIED", post
    assert post["dispatch_allowed"] is False
    assert controller.ledger.path.read_bytes() == before
    post_verify_request = {
        "schema": "M2_CONSTRUCTION_POST_VERIFY_REQUEST_1",
        "signed_release": release_request["signed_release"],
    }
    launched, verified = _call(tmp_path, config, "post-verify", post_verify_request)
    assert launched.returncode == 0 and verified["status"] == "VERIFIED", verified
    assert verified["effect_executed"] is True
    assert verified["dispatch_allowed"] is False
    assert verified["release_id"] == "cli-release-01"
    event_count = len(controller.ledger.events())
    assert sum(json.loads(row[4]).get("kind") == "POST_RELEASE_VERIFIED"
               for row in controller.ledger.events()) == 1
    launched, replay = _call(tmp_path, config, "post-verify", post_verify_request)
    assert launched.returncode == 0 and replay["status"] == "VERIFIED"
    assert replay["effect_executed"] is False
    assert len(controller.ledger.events()) == event_count
    for item in release_request["signed_release"]["body"]["files"]:
        assert _sha((target / item["destination"]).read_bytes()) == item["sha256"]
    for token in ("signature_b64", "public_key_b64", "signed_roles"):
        assert token not in launched.stdout
    first = release_request["signed_release"]["body"]["files"][0]
    (target / first["destination"]).write_bytes(b"changed after release\n")
    before = controller.ledger.path.read_bytes()
    launched, changed = _call(tmp_path, config, "post-release", {
        "schema": "M2_CONSTRUCTION_POST_RELEASE_REQUEST_1",
        "signed_release": release_request["signed_release"],
    })
    assert launched.returncode == 2 and changed["status"] == "FAIL"
    assert changed["reason"] == "POST_RELEASE_BYTES_CHANGED"
    assert controller.ledger.path.read_bytes() == before
    launched, denied = _call(tmp_path, config, "post-verify", post_verify_request)
    assert launched.returncode == 2 and denied["status"] == "DENIED"
    assert denied["reason"] == "POST_REQUIRED"
    assert controller.ledger.path.read_bytes() == before
    assert len(controller.ledger.events()) == event_count


def test_release_cli_rejects_untrusted_identity_overrides_and_config_changes(tmp_path):
    controller, args, ceo, body, _, _, _, _ = _ready_parent(tmp_path, record=False)
    config = _release_config(tmp_path, args)
    request = _accept_request(args)
    launched, denied = _call(tmp_path, config, "ceo-accept", {
        **request, "ceo_pin_path": str(args["ceo_pin_path"]),
    })
    assert launched.returncode == 2 and denied["reason"] == "CLI_CEO_ACCEPT_FIELDS"
    assert not any(json.loads(row[4]).get("kind") == "CEO_ACCEPTED"
                   for row in controller.ledger.events())
    for verb, candidate, expected_reason in (
        ("pre-release", {**request,
                         "schema": "M2_CONSTRUCTION_PRE_RELEASE_REQUEST_1",
                         "reviewer_pin_path": str(args["reviewer_pin_path"])},
         "CLI_PRE_RELEASE_FIELDS"),
        ("release", {"schema": "M2_CONSTRUCTION_RELEASE_REQUEST_1",
                     "signed_release": {}, "signed_review": args["signed_review"],
                     "signed_ceo_acceptance": args["signed_ceo_acceptance"],
                     "ceo_pin_path": str(args["ceo_pin_path"])},
         "CLI_RELEASE_FIELDS"),
        ("post-release", {"schema": "M2_CONSTRUCTION_POST_RELEASE_REQUEST_1",
                          "signed_release": {},
                          "pin_path": str(args["root_pin_path"])},
         "CLI_POST_RELEASE_FIELDS"),
        ("post-verify", {"schema": "M2_CONSTRUCTION_POST_VERIFY_REQUEST_1",
                         "signed_release": {},
                         "pin_path": str(args["root_pin_path"])},
         "CLI_POST_VERIFY_FIELDS"),
    ):
        launched, denied = _call(tmp_path, config, verb, candidate)
        assert launched.returncode == 2 and denied["reason"] == expected_reason

    v2 = _json(tmp_path / "v2-release-bootstrap.json", {
        key: value for key, value in json.loads(config.read_bytes()).items()
        if key not in ("child_reviewer_pin_path",
                       "expected_child_reviewer_pin_sha256", "ceo_pin_path",
                       "expected_ceo_pin_sha256")
    } | {"schema": "M2_CONSTRUCTION_CLI_CONFIG_2"})
    launched, denied = _call(tmp_path, v2, "pre-release", {
        **request, "schema": "M2_CONSTRUCTION_PRE_RELEASE_REQUEST_1"})
    assert launched.returncode == 2 and denied["reason"] == "CLI_RELEASE_PINS_REQUIRED"

    changed = {**body, "signed_roles": {**body["signed_roles"],
                "signature_b64": "AAAA"}}
    launched, denied = _call(tmp_path, config, "ceo-accept", {
        **request, "signed_ceo_acceptance": _sign(
            ceo, "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1", changed),
    })
    assert launched.returncode == 2 and denied["reason"] == "ROLE_SIGNATURE"
    assert not any(json.loads(row[4]).get("kind") == "CEO_ACCEPTED"
                   for row in controller.ledger.events())

    bad_config = _json(tmp_path / "bad-release-bootstrap.json", {
        **json.loads(config.read_bytes()),
        "expected_ceo_pin_sha256": "0" * 64,
    })
    launched, denied = _call(tmp_path, bad_config, "ceo-accept", request)
    assert launched.returncode == 2 and denied["reason"] == "CEO_PIN_CHANGED"
    bad_child_config = _json(tmp_path / "bad-child-bootstrap.json", {
        **json.loads(config.read_bytes()),
        "expected_child_reviewer_pin_sha256": "0" * 64,
    })
    launched, denied = _call(tmp_path, bad_child_config, "ceo-accept", request)
    assert launched.returncode == 2 and denied["reason"] == "REVIEW_PIN_CHANGED"
    missing_state = tmp_path / "missing-state"
    missing_config = _json(tmp_path / "missing-state-bootstrap.json", {
        **json.loads(config.read_bytes()), "state_root": str(missing_state),
    })
    launched, denied = _call(tmp_path, missing_config, "ceo-accept", request)
    assert launched.returncode == 2 and denied["reason"] == "CLI_STATE_NOT_INITIALIZED"
    assert not missing_state.exists()
    launched, denied = _call(tmp_path, config, "ceo-accept", request,
                             config_sha="0" * 64)
    assert launched.returncode == 2 and denied["reason"] == "CLI_CONFIG_CHANGED"


def test_grant_patch_exact_file_bytes_and_read_only_status_across_processes(tmp_path):
    workspace, state, target, config, signed = _setup(tmp_path)
    grant_request = {"schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed}
    launched, granted = _call(tmp_path, config, "grant", grant_request)
    assert launched.returncode == 0 and granted["status"] == "GRANTED"
    content = b"value = b'\xff\x00'\r\n"
    (workspace / "candidate.bin").write_bytes(content)
    patch_request = {
        "schema": "M2_CONSTRUCTION_PATCH_REQUEST_1",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 1,
        "operation_id": "op-01", "path": "sample.py",
        "before_sha256": _sha(b"value = 1\n"),
        "content_file": "candidate.bin",
    }
    launched, patched = _call(tmp_path, config, "patch", patch_request)
    assert launched.returncode == 0 and patched["status"] == "COMPLETED"
    assert patched["after_sha256"] == _sha(content)
    assert target.read_bytes() == content
    launched, replay = _call(tmp_path, config, "patch", patch_request)
    assert launched.returncode == 0 and replay["effect_executed"] is False
    assert target.read_bytes() == content
    db_path = state / "construction.sqlite3"
    before = db_path.read_bytes()
    launched, status = _call(tmp_path, config, "status", {
        "schema": "M2_CONSTRUCTION_STATUS_REQUEST_1", "operation_id": "op-01"})
    assert launched.returncode == 0 and status["status"] == "OK"
    assert status["chain"]["event_count"] >= 3
    assert status["operation"]["status"] == "COMPLETED"
    assert status["operation"]["after_sha256"] == _sha(content)
    assert db_path.read_bytes() == before
    assert "signature_b64" not in launched.stdout
    assert "public_key_b64" not in launched.stdout
    assert "candidate.bin" not in launched.stdout


def test_unpinned_config_and_missing_state_status_fail_without_effect(tmp_path):
    _, state, target, config, signed = _setup(tmp_path)
    launched, result = _call(tmp_path, config, "grant", {
        "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed,
    }, config_sha="0" * 64)
    assert launched.returncode != 0 and result == {
        "status": "DENIED", "reason": "CLI_CONFIG_CHANGED"}
    assert not state.exists() and target.read_bytes() == b"value = 1\n"
    launched, result = _call(tmp_path, config, "status", {
        "schema": "M2_CONSTRUCTION_STATUS_REQUEST_1"})
    assert launched.returncode != 0 and result["reason"] == "CLI_STATE_NOT_INITIALIZED"
    assert not state.exists()


def test_patch_request_cannot_read_outside_workspace_or_override_config(tmp_path):
    workspace, _, target, config, signed = _setup(tmp_path)
    assert _call(tmp_path, config, "grant", {
        "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed,
    })[1]["status"] == "GRANTED"
    secret = tmp_path / "outside-secret.bin"
    secret.write_bytes(b"private input contents")
    request = {
        "schema": "M2_CONSTRUCTION_PATCH_REQUEST_1",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 1,
        "operation_id": "op-02", "path": "sample.py",
        "before_sha256": _sha(target.read_bytes()),
        "content_file": "../outside-secret.bin",
    }
    launched, result = _call(tmp_path, config, "patch", request)
    assert launched.returncode != 0 and result["status"] == "DENIED"
    assert secret.read_bytes() not in launched.stdout.encode("utf-8")
    assert target.read_bytes() == b"value = 1\n"
    request["content_file"] = "sample.py"
    request["workspace_root"] = str(workspace)
    launched, result = _call(tmp_path, config, "patch", request)
    assert launched.returncode != 0 and result["status"] == "DENIED"


def test_status_detects_chain_tamper_without_rewriting_it(tmp_path):
    _, state, _, config, signed = _setup(tmp_path)
    assert _call(tmp_path, config, "grant", {
        "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed,
    })[1]["status"] == "GRANTED"
    db_path = state / "construction.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute("UPDATE events SET body_json='{}' WHERE seq=1")
    before = db_path.read_bytes()
    launched, result = _call(tmp_path, config, "status", {
        "schema": "M2_CONSTRUCTION_STATUS_REQUEST_1"})
    assert launched.returncode != 0
    assert result == {"status": "DENIED", "reason": "EVENT_CHAIN_TAMPERED"}
    assert db_path.read_bytes() == before


def _full_requests(workspace):
    payload = (b"from pathlib import Path\r\n"
               b"assert Path('sample.py').read_bytes() == b'value = 1\\n'\r\n"
               b"assert Path('dist/package.bin').read_bytes() == b'built-v1'\r\n")
    common = {"grant_id": "grant-01", "task_id": "task-01", "task_revision": 1}
    create = {"schema": "M2_CONSTRUCTION_CREATE_REQUEST_2", **common,
              "operation_id": "create-check", "path": "tests/check.py",
              "content_b64": base64.b64encode(payload).decode("ascii")}
    build = {"schema": "M2_CONSTRUCTION_COMMAND_REQUEST_1", **common,
             "operation_id": "build-01", "command_id": "build-package"}
    test = {**build, "operation_id": "test-01", "command_id": "check-package"}
    freeze = {"schema": "M2_CONSTRUCTION_FREEZE_REQUEST_1", **common,
              "operation_id": "freeze-01", "source_files": ["sample.py"],
              "test_files": ["tests/check.py"], "build_files": ["dist/package.bin"],
              "test_operation_ids": ["test-01"], "build_operation_ids": ["build-01"]}
    return payload, create, build, test, freeze


def test_grant_create_build_test_freeze_real_processes_and_bytes(tmp_path):
    workspace, state, _, config, signed = _setup(tmp_path, full=True)
    config_sha = _sha(config.read_bytes())
    payload, create, build, test, freeze = _full_requests(workspace)
    launched, granted = _call(tmp_path, config, "grant", {
        "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed,
    }, config_sha=config_sha)
    assert launched.returncode == 0 and granted["status"] == "GRANTED"
    launched, created = _call(tmp_path, config, "create", create, config_sha=config_sha)
    assert launched.returncode == 0 and created["status"] == "COMPLETED"
    assert not (workspace / "staging.bin").exists()
    assert created["before_state"] == "ABSENT"
    assert created["after_sha256"] == _sha(payload)
    assert (workspace / "tests/check.py").read_bytes() == payload
    launched, replay = _call(tmp_path, config, "create", create, config_sha=config_sha)
    assert launched.returncode == 0 and replay["effect_executed"] is False
    launched, built = _call(tmp_path, config, "command", build, config_sha=config_sha)
    assert launched.returncode == 0 and built["status"] == "PASSED"
    assert built["exit_code"] == 0 and len(built["receipt_sha256"]) == 64
    assert (workspace / "dist/package.bin").read_bytes() == b"built-v1"
    launched, tested = _call(tmp_path, config, "command", test, config_sha=config_sha)
    assert launched.returncode == 0 and tested["status"] == "PASSED"
    assert tested["exit_code"] == 0 and len(tested["receipt_sha256"]) == 64
    launched, denied = _call(tmp_path, config, "freeze", {
        **freeze, "operation_id": "freeze-unknown-test",
        "test_operation_ids": ["missing-test"],
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "TEST_OPERATION_NOT_CURRENT"
    launched, frozen = _call(tmp_path, config, "freeze", freeze, config_sha=config_sha)
    assert launched.returncode == 0 and frozen["status"] == "FROZEN"
    manifest_path = Path(frozen["manifest_path"])
    assert state in manifest_path.parents
    manifest = json.loads(manifest_path.read_bytes())
    assert _sha(manifest_path.read_bytes()) == frozen["manifest_sha256"]
    assert manifest["schema"] == "M2_CONSTRUCTION_FREEZE_2"
    assert manifest["files"]["tests/check.py"]["sha256"] == _sha(payload)
    assert manifest["files"]["dist/package.bin"]["sha256"] == _sha(b"built-v1")
    assert manifest["test_receipts"][0]["receipt_sha256"] == tested["receipt_sha256"]
    assert manifest["build_receipts"][0]["receipt_sha256"] == built["receipt_sha256"]
    launched, status = _call(tmp_path, config, "status", {
        "schema": "M2_CONSTRUCTION_STATUS_REQUEST_1", "operation_id": "freeze-01",
    }, config_sha=config_sha)
    assert launched.returncode == 0 and status["operation"]["status"] == "COMPLETED"
    assert status["operation"]["after_sha256"] == frozen["manifest_sha256"]


def test_full_entry_rejects_scope_overrides_and_unknown_ids(tmp_path):
    workspace, state, _, config, signed = _setup(tmp_path, full=True)
    config_sha = _sha(config.read_bytes())
    _, create, build, _, freeze = _full_requests(workspace)
    for verb, request in (("create", create), ("command", build),
                          ("freeze", freeze)):
        launched, result = _call(tmp_path, config, verb, request,
                                 config_sha=config_sha)
        assert launched.returncode == 2 and result["reason"] == "SCOPE_NOT_CURRENT"
        for override in ("workspace_root", "state_root", "pin_path"):
            launched, result = _call(tmp_path, config, verb, {
                **request, override: str(state),
            }, config_sha=config_sha)
            assert launched.returncode == 2 and result["status"] == "DENIED"
            assert result["reason"] == f"CLI_{verb.upper()}_FIELDS"
    assert _call(tmp_path, config, "grant", {
        "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed,
    }, config_sha=config_sha)[1]["status"] == "GRANTED"
    launched, denied = _call(tmp_path, config, "create", {
        **create, "operation_id": "create-outside", "path": "other.py",
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "CREATE_SCOPE"
    launched, denied = _call(tmp_path, config, "command", {
        **build, "operation_id": "unknown-command", "command_id": "arbitrary",
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "COMMAND_NOT_AUTHORIZED"
    launched, denied = _call(tmp_path, config, "command", {
        **build, "argv": [sys.executable, "-c", "print('outside scope')"],
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "CLI_COMMAND_FIELDS"
    launched, denied = _call(tmp_path, config, "create", {
        **create, "operation_id": "unknown-grant", "grant_id": "missing",
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "SCOPE_NOT_CURRENT"
    launched, denied = _call(tmp_path, config, "create", {
        **create, "operation_id": "outside-payload",
        "content_file": "../outside-secret.bin",
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "CLI_CREATE_FIELDS"
    launched, denied = _call(tmp_path, config, "create", {
        **create, "operation_id": "invalid-inline-content",
        "content_b64": "not valid base64!",
    }, config_sha=config_sha)
    assert launched.returncode == 2 and denied["reason"] == "CLI_CONTENT_BASE64"
    assert not (workspace / "tests/check.py").exists()
    assert not (workspace / "dist/package.bin").exists()
    assert not (state / "evidence").exists()


def test_command_unknown_is_visible_and_same_id_never_redispatches(tmp_path):
    workspace, _, _, config, signed = _setup(
        tmp_path, full=True, bad_program_hash=True)
    config_sha = _sha(config.read_bytes())
    _, create, build, _, _ = _full_requests(workspace)
    assert _call(tmp_path, config, "grant", {
        "schema": "M2_CONSTRUCTION_GRANT_REQUEST_1", "signed_scope": signed,
    }, config_sha=config_sha)[1]["status"] == "GRANTED"
    assert _call(tmp_path, config, "create", create,
                 config_sha=config_sha)[1]["status"] == "COMPLETED"
    launched, unknown = _call(tmp_path, config, "command", build,
                              config_sha=config_sha)
    assert launched.returncode == 3 and unknown == {
        "status": "UNKNOWN", "operation_id": "build-01",
        "effect_executed": None, "new_dispatch": True,
    }
    launched, replay = _call(tmp_path, config, "command", build,
                             config_sha=config_sha)
    assert launched.returncode == 3 and replay["status"] == "UNKNOWN"
    assert replay["new_dispatch"] is False
    assert not (workspace / "dist/package.bin").exists()
    launched, status = _call(tmp_path, config, "status", {
        "schema": "M2_CONSTRUCTION_STATUS_REQUEST_1", "operation_id": "build-01",
    }, config_sha=config_sha)
    assert launched.returncode == 0 and status["operation"]["status"] == "UNKNOWN"


def _return_setup(tmp_path):
    controller, args, _, root_key = _v2_fixture(tmp_path)
    workspace = controller.workspace
    state = controller.state_dir
    (workspace / "parent" / "src").mkdir(parents=True)
    (workspace / "parent" / "tests").mkdir()
    now = int(time.time())
    files = [
        {"source": "src/value.py", "destination": "parent/src/value.py",
         "sha256": _sha((workspace / "src/value.py").read_bytes())},
        {"source": "tests/check.py", "destination": "parent/tests/check.py",
         "sha256": _sha((workspace / "tests/check.py").read_bytes())},
    ]
    parent = {
        "schema": "M2_CONSTRUCTION_SCOPE_3", "trust_domain": "TEST_ONLY",
        "grant_id": "parent-grant", "task_id": "parent-task", "task_revision": 1,
        "workspace_root": str(workspace), "state_root": str(state),
        "baseline_files": {item["destination"]: None for item in files},
        "allowed_files": [item["destination"] for item in files],
        "creatable_files": [item["destination"] for item in files],
        "allowed_effects": ["CREATE"], "allowed_commands": [],
        "not_before": now - 60, "expires_at": now + 3600,
        "max_operations": 5, "max_patch_bytes": 10_000,
    }
    assert controller.register_grant(
        _sign(root_key, "M2_CONSTRUCTION_SIGNED_SCOPE_1", parent)
    )["status"] == "GRANTED"
    manifest_sha = args["expected_manifest_sha256"]
    author = _sign(root_key, "M2_CONSTRUCTION_SIGNED_AUTHORSHIP_1", {
        "schema": "M2_CONSTRUCTION_AUTHORSHIP_1", "trust_domain": "TEST_ONLY",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 2,
        "candidate_sha256": manifest_sha,
        "author_fingerprint": args["signed_review"]["body"]["author_fingerprint"],
    })
    attest = {
        "schema": "M2_CONSTRUCTION_ATTEST_REQUEST_1",
        "grant_id": "grant-01", "task_id": "task-01", "task_revision": 2,
        "manifest_sha256": manifest_sha, "signed_authorship": author,
    }
    return_body = {
        "schema": "M2_CONSTRUCTION_RETURN_BODY_1", "trust_domain": "TEST_ONLY",
        "return_id": "return-01", "child_grant_id": "grant-01",
        "child_task_id": "task-01", "child_task_revision": 2,
        "parent_grant_id": "parent-grant", "parent_task_id": "parent-task",
        "parent_task_revision": 1, "candidate_sha256": manifest_sha,
        "review_sha256": _sha(canonical(args["signed_review"])), "files": files,
        "not_before": now - 60, "expires_at": now + 3600,
    }
    returning = {
        "schema": "M2_CONSTRUCTION_RETURN_REQUEST_1",
        "signed_return": _sign(root_key, "M2_CONSTRUCTION_SIGNED_RETURN_1",
                               return_body),
        "signed_review": args["signed_review"],
    }
    config = _json(tmp_path / "bootstrap-v2.json", {
        "schema": "M2_CONSTRUCTION_CLI_CONFIG_2",
        "workspace_root": str(workspace), "state_root": str(state),
        "pin_path": str(args["root_pin_path"]),
        "expected_pin_sha256": args["expected_root_pin_sha256"],
        "reviewer_pin_path": str(args["reviewer_pin_path"]),
        "expected_reviewer_pin_sha256": args["expected_reviewer_pin_sha256"],
    })
    return controller, args, root_key, config, attest, returning, files


def test_attest_and_return_use_real_processes_and_replay_without_duplicate_effect(tmp_path):
    controller, _, root_key, config, attest, returning, files = _return_setup(tmp_path)
    wrong_revision = {**attest, "task_revision": 1}
    launched, denied = _call(tmp_path, config, "attest", wrong_revision)
    assert launched.returncode == 2 and denied["status"] == "DENIED"
    assert "AUTHOR_ATTESTED" not in [
        json.loads(row[4])["kind"] for row in controller.ledger.events()]

    launched, recorded = _call(tmp_path, config, "attest", attest)
    assert launched.returncode == 0 and recorded["status"] == "ATTESTED"
    assert recorded["effect_executed"] is True
    assert recorded["attestation_sha256"] == _sha(canonical(attest["signed_authorship"]))
    launched, replay = _call(tmp_path, config, "attest", attest)
    assert launched.returncode == 0 and replay["effect_executed"] is False
    assert all(not (controller.workspace / item["destination"]).exists()
               for item in files)

    launched, denied = _call(tmp_path, config, "return", returning,
                             config_sha="0" * 64)
    assert launched.returncode == 2 and denied["reason"] == "CLI_CONFIG_CHANGED"
    launched, denied = _call(tmp_path, config, "return", {
        **returning, "reviewer_pin_path": str(config),
    })
    assert launched.returncode == 2 and denied["reason"] == "CLI_RETURN_FIELDS"
    launched, denied = _call(tmp_path, config, "return", {
        **returning, "signed_review": {**returning["signed_review"],
                                       "signature_b64": "bad-signature"},
    })
    assert launched.returncode == 2 and denied["status"] == "DENIED"
    assert all(not (controller.workspace / item["destination"]).exists()
               for item in files)

    launched, consumed = _call(tmp_path, config, "return", returning)
    assert launched.returncode == 0 and consumed["status"] == "COMPLETED", consumed
    assert consumed["effect_executed"] is True
    assert consumed["authority"] == "INTERNAL_PARENT_ONLY"
    assert consumed["review_sha256"] == returning["signed_return"]["body"]["review_sha256"]
    for item in files:
        assert _sha((controller.workspace / item["destination"]).read_bytes()) == item["sha256"]
    event_count = len(controller.ledger.events())
    launched, replay = _call(tmp_path, config, "return", returning)
    assert launched.returncode == 0 and replay["status"] == "COMPLETED"
    assert replay["effect_executed"] is False
    assert len(controller.ledger.events()) == event_count
    assert "signature_b64" not in launched.stdout
    assert "public_key_b64" not in launched.stdout
    assert '"files":' not in launched.stdout
    assert "value = 1" not in launched.stdout
    assert "private" not in launched.stdout

    duplicate = {**returning, "signed_return": _sign(
        root_key, "M2_CONSTRUCTION_SIGNED_RETURN_1",
        {**returning["signed_return"]["body"], "return_id": "return-02"})}
    launched, denied = _call(tmp_path, config, "return", duplicate)
    assert launched.returncode == 2 and denied["reason"] == "RETURN_ALREADY_RESERVED"
    assert len(controller.ledger.events()) == event_count


def test_return_requires_pinned_reviewer_and_current_parent_scope(tmp_path):
    controller, _, _, config, attest, returning, files = _return_setup(tmp_path)
    assert _call(tmp_path, config, "attest", attest)[1]["status"] == "ATTESTED"
    v1 = _json(tmp_path / "bootstrap-v1.json", {
        key: value for key, value in json.loads(config.read_bytes()).items()
        if key not in ("reviewer_pin_path", "expected_reviewer_pin_sha256")
    } | {"schema": "M2_CONSTRUCTION_CLI_CONFIG_1"})
    launched, denied = _call(tmp_path, v1, "return", returning)
    assert launched.returncode == 2 and denied["reason"] == "CLI_REVIEWER_PIN_REQUIRED"
    assert _call(tmp_path, v1, "status", {
        "schema": "M2_CONSTRUCTION_STATUS_REQUEST_1",
    })[1]["status"] == "OK"

    other_pin = tmp_path / "other-reviewer" / "pin.json"
    other_sha = _pin(other_pin, Ed25519PrivateKey.generate(),
                     "M2_CONSTRUCTION_REVIEWER_PIN_1")
    bad_config = _json(tmp_path / "bad-reviewer-config.json", {
        **json.loads(config.read_bytes()), "reviewer_pin_path": str(other_pin),
        "expected_reviewer_pin_sha256": other_sha,
    })
    launched, denied = _call(tmp_path, bad_config, "return", returning)
    assert launched.returncode == 2 and denied["status"] == "DENIED"
    assert all(not (controller.workspace / item["destination"]).exists()
               for item in files)
    bad_sha = _json(tmp_path / "bad-reviewer-sha.json", {
        **json.loads(config.read_bytes()), "expected_reviewer_pin_sha256": "0" * 64,
    })
    launched, denied = _call(tmp_path, bad_sha, "return", returning)
    assert launched.returncode == 2 and denied["reason"] == "REVIEW_PIN_CHANGED"

    controller.revoke_grant("parent-grant")
    launched, denied = _call(tmp_path, config, "return", returning)
    assert launched.returncode == 2 and denied["status"] == "DENIED"
    assert all(not (controller.workspace / item["destination"]).exists()
               for item in files)


def test_v3_return_uses_child_reviewer_not_parent_reviewer(tmp_path):
    controller, args, _, v2, attest, returning, files = _return_setup(tmp_path)
    assert _call(tmp_path, v2, "attest", attest)[1]["status"] == "ATTESTED"
    assert local_adjudicate(**args)["status"] == "PASS"
    parent_pin = tmp_path / "parent-reviewer" / "pin.json"
    parent_sha = _pin(parent_pin, Ed25519PrivateKey.generate(),
                      "M2_CONSTRUCTION_REVIEWER_PIN_1")
    ceo_pin = tmp_path / "ceo" / "pin.json"
    ceo_sha = _pin(ceo_pin, Ed25519PrivateKey.generate(),
                   "M2_CONSTRUCTION_CEO_PIN_1")
    v3 = _json(tmp_path / "bootstrap-v3.json", {
        **json.loads(v2.read_bytes()),
        "schema": "M2_CONSTRUCTION_CLI_CONFIG_3",
        "reviewer_pin_path": str(parent_pin),
        "expected_reviewer_pin_sha256": parent_sha,
        "child_reviewer_pin_path": str(args["reviewer_pin_path"]),
        "expected_child_reviewer_pin_sha256":
            args["expected_reviewer_pin_sha256"],
        "ceo_pin_path": str(ceo_pin),
        "expected_ceo_pin_sha256": ceo_sha,
    })
    before = controller.ledger.path.read_bytes()
    launched, result = _call(tmp_path, v3, "return", returning)
    assert launched.returncode == 0 and result["status"] == "COMPLETED", result
    assert result["effect_executed"] is True
    assert controller.ledger.path.read_bytes() != before
    for item in files:
        target = controller.workspace / item["destination"]
        assert _sha(target.read_bytes()) == item["sha256"]

    # The older v2 bootstrap keeps its single reviewer identity semantics.
    launched, replay = _call(tmp_path, v2, "return", returning)
    assert launched.returncode == 0 and replay["status"] == "COMPLETED"
    assert replay["effect_executed"] is False
