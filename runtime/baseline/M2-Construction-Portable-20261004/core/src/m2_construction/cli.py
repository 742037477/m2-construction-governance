"""Request-file entry to the local TEST_ONLY Controller.

The trusted caller supplies the expected bootstrap-config hash separately.
Requests cannot select the workspace, state directory, or public pins.
"""
import argparse
import base64
from contextlib import closing
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import sqlite3
import stat

from .contracts import Denied, bytes_hash, canonical, exact_fields, hash_text, require, strict_json
from .controller import Controller
from .ledger import Ledger
from .pre_release import _external_pin, pre_release_readonly, record_ceo_acceptance
from .release_effect import post_release_readonly
from .review import _public_pin
from .trust import load_pin


_CONFIG_FIELDS = "schema workspace_root state_root pin_path expected_pin_sha256"
_CONFIG_2_FIELDS = (_CONFIG_FIELDS +
                    " reviewer_pin_path expected_reviewer_pin_sha256")
_CONFIG_3_FIELDS = (_CONFIG_2_FIELDS +
                    " child_reviewer_pin_path expected_child_reviewer_pin_sha256"
                    " ceo_pin_path expected_ceo_pin_sha256")
_PATCH_FIELDS = ("schema grant_id task_id task_revision operation_id path "
                 "before_sha256 content_file")
_CREATE_FIELDS = "schema grant_id task_id task_revision operation_id path content_file"
_PATCH_INLINE_FIELDS = ("schema grant_id task_id task_revision operation_id path "
                        "before_sha256 content_b64")
_CREATE_INLINE_FIELDS = "schema grant_id task_id task_revision operation_id path content_b64"
_COMMAND_FIELDS = "schema grant_id task_id task_revision operation_id command_id"
_FREEZE_FIELDS = ("schema grant_id task_id task_revision operation_id source_files "
                  "test_files build_files test_operation_ids build_operation_ids")
_ATTEST_FIELDS = ("schema grant_id task_id task_revision manifest_sha256 "
                  "signed_authorship")
_RETURN_FIELDS = "schema signed_return signed_review"
_CEO_ACCEPT_FIELDS = ("schema grant_id task_id task_revision manifest_path "
                      "expected_manifest_sha256 signed_review signed_ceo_acceptance")
_RELEASE_FIELDS = "schema signed_release signed_review signed_ceo_acceptance"
_SAFE_RESULT_FIELDS = frozenset({
    "status", "reason", "grant_id", "scope_hash", "operation_id",
    "before_sha256", "after_sha256", "effect_executed", "new_dispatch",
    "before_state", "exit_code", "receipt_path", "receipt_sha256",
    "manifest_path", "manifest_sha256", "candidate_sha256", "file_count",
    "attestation_sha256", "review_sha256", "files_sha256", "authority",
    "parent_task_id", "dispatch_allowed", "ceo_acceptance_sha256",
    "pre_release_sha256", "internal_return_operation_id",
    "internal_return_files_sha256", "internal_return_event_hash",
    "ceo_accepted_event_hash", "ceo_accepted_event_seq",
    "ledger_head_seq", "ledger_head_event_hash", "release_id", "target_root",
})


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Denied("CLI_ARGUMENTS")


def _parser():
    parser = _Parser(description="Local TEST_ONLY construction request-file entry")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--config-sha256", required=True)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    for name in ("grant", "patch", "create", "command", "freeze", "attest",
                 "return", "status", "ceo-accept", "pre-release", "release",
                 "post-release", "post-verify"):
        command = commands.add_parser(name)
        command.add_argument("--request", required=True, type=Path)
    return parser


def _read_json(path):
    try:
        return strict_json(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise Denied("CLI_JSON_INVALID") from None


def _bootstrap(path, expected_hash):
    require(hash_text(expected_hash), "CLI_CONFIG_HASH_REQUIRED")
    raw = path.read_bytes()
    require(bytes_hash(raw) == expected_hash, "CLI_CONFIG_CHANGED")
    config = strict_json(raw)
    require(type(config) is dict, "CLI_CONFIG_FIELDS")
    schema = config.get("schema")
    if schema == "M2_CONSTRUCTION_CLI_CONFIG_1":
        exact_fields(config, _CONFIG_FIELDS, "CLI_CONFIG_FIELDS")
    elif schema == "M2_CONSTRUCTION_CLI_CONFIG_2":
        exact_fields(config, _CONFIG_2_FIELDS, "CLI_CONFIG_FIELDS")
    elif schema == "M2_CONSTRUCTION_CLI_CONFIG_3":
        exact_fields(config, _CONFIG_3_FIELDS, "CLI_CONFIG_FIELDS")
    else:
        raise Denied("CLI_CONFIG_SCHEMA")
    for field in ("workspace_root", "state_root", "pin_path"):
        require(type(config[field]) is str and Path(config[field]).is_absolute(),
                "CLI_CONFIG_PATH")
    workspace = Path(config["workspace_root"])
    state = Path(config["state_root"])
    pin = Path(config["pin_path"])
    require(workspace.is_dir() and workspace.resolve(strict=True) == workspace,
            "CLI_CONFIG_WORKSPACE")
    require(state != workspace and workspace not in state.parents, "CLI_CONFIG_STATE")
    require(state.resolve() == state and pin.resolve(strict=True) == pin,
            "CLI_CONFIG_PATH_LINK")
    load_pin(pin, config["expected_pin_sha256"], workspace)
    if schema in ("M2_CONSTRUCTION_CLI_CONFIG_2",
                  "M2_CONSTRUCTION_CLI_CONFIG_3"):
        reviewer = config["reviewer_pin_path"]
        require(type(reviewer) is str and Path(reviewer).is_absolute(),
                "CLI_CONFIG_PATH")
        reviewer = Path(reviewer)
        require(reviewer != pin and reviewer != state and state not in reviewer.parents,
                "CLI_REVIEWER_PIN_LOCATION")
        _public_pin(reviewer, config["expected_reviewer_pin_sha256"], workspace)
    if schema == "M2_CONSTRUCTION_CLI_CONFIG_3":
        identity_paths = [pin, reviewer]
        for field in ("child_reviewer_pin_path", "ceo_pin_path"):
            value = config[field]
            require(type(value) is str and Path(value).is_absolute(),
                    "CLI_CONFIG_PATH")
            identity_paths.append(Path(value))
        require(len(set(identity_paths)) == len(identity_paths) and
                all(path != state and state not in path.parents
                    for path in identity_paths), "CLI_IDENTITY_PIN_LOCATION")
        _public_pin(identity_paths[2],
                    config["expected_child_reviewer_pin_sha256"], workspace)
        _external_pin(identity_paths[3], config["expected_ceo_pin_sha256"],
                      workspace, state)
    return config


def _content_bytes(workspace, relative):
    require(type(relative) is str and bool(relative) and "\\" not in relative and
            ":" not in relative and "\x00" not in relative and
            not relative.startswith("/"), "CLI_CONTENT_PATH")
    pure = PurePosixPath(relative)
    require(str(pure) == relative and all(part not in ("", ".", "..")
                                          for part in relative.split("/")),
            "CLI_CONTENT_PATH")
    current = workspace
    for part in pure.parts:
        current = current / part
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and
                not (getattr(info, "st_file_attributes", 0) &
                     getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
                "CLI_CONTENT_LINK")
    require(stat.S_ISREG(current.lstat().st_mode) and
            workspace in current.resolve(strict=True).parents, "CLI_CONTENT_FILE")
    return current.read_bytes()


def _inline_bytes(value):
    require(type(value) is str and len(value) <= 14_000_000, "CLI_CONTENT_SIZE")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Denied("CLI_CONTENT_BASE64") from None


def _safe_controller_result(result):
    require(type(result) is dict and type(result.get("status")) is str,
            "CLI_CONTROLLER_RESULT")
    clean = {key: value for key, value in result.items() if key in _SAFE_RESULT_FIELDS}
    if clean["status"] in ("DENIED", "FAIL", "INDETERMINATE"):
        reason = clean.get("reason")
        if type(reason) is not str or re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", reason) is None:
            clean["reason"] = "CLI_CONTROLLER_DENIED"
    return clean


def _release_pins(config):
    return {
        "reviewer_pin_path": config["reviewer_pin_path"],
        "expected_reviewer_pin_sha256":
            config["expected_reviewer_pin_sha256"],
        "child_reviewer_pin_path": config["child_reviewer_pin_path"],
        "expected_child_reviewer_pin_sha256":
            config["expected_child_reviewer_pin_sha256"],
        "ceo_pin_path": config["ceo_pin_path"],
        "expected_ceo_pin_sha256": config["expected_ceo_pin_sha256"],
    }


def _pre_request(config, request):
    return {
        "grant_id": request["grant_id"], "task_id": request["task_id"],
        "task_revision": request["task_revision"],
        "manifest_path": request["manifest_path"],
        "expected_manifest_sha256": request["expected_manifest_sha256"],
        "signed_review": request["signed_review"],
        **_release_pins(config),
    }


def _require_existing_ledger(config):
    database = Path(config["state_root"]) / "construction.sqlite3"
    require(database.is_file() and not database.is_symlink(),
            "CLI_STATE_NOT_INITIALIZED")
    return database


def _read_status(config, request):
    require(type(request) is dict and
            set(request) in ({"schema"}, {"schema", "operation_id"}),
            "CLI_STATUS_FIELDS")
    require(request["schema"] == "M2_CONSTRUCTION_STATUS_REQUEST_1",
            "CLI_STATUS_SCHEMA")
    operation_id = request.get("operation_id")
    if operation_id is not None:
        require(type(operation_id) is str and
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", operation_id),
                "CLI_OPERATION_ID")
    database = _require_existing_ledger(config)
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        Ledger.verify_chain(db)
        last = db.execute("SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        result = {"status": "OK", "chain": {
            "event_count": last[0] if last else 0,
            "head_sha256": last[1] if last else "0" * 64,
        }}
        if operation_id is not None:
            row = db.execute(
                "SELECT operation_id,status,request_hash,before_sha256,after_sha256 "
                "FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            result["operation"] = None if row is None else {
                "operation_id": row[0], "status": row[1],
                "request_sha256": row[2], "before_sha256": row[3],
                "after_sha256": row[4],
            }
        return result


def _dispatch(args):
    config = _bootstrap(args.config, args.config_sha256)
    request = _read_json(args.request)
    if args.command == "status":
        return _read_status(config, request)
    if args.command in ("ceo-accept", "pre-release", "release",
                        "post-release", "post-verify"):
        require(config["schema"] == "M2_CONSTRUCTION_CLI_CONFIG_3",
                "CLI_RELEASE_PINS_REQUIRED")
        if args.command in ("ceo-accept", "pre-release"):
            exact_fields(request, _CEO_ACCEPT_FIELDS,
                         "CLI_CEO_ACCEPT_FIELDS" if args.command == "ceo-accept"
                         else "CLI_PRE_RELEASE_FIELDS")
            require(request["schema"] == (
                "M2_CONSTRUCTION_CEO_ACCEPT_REQUEST_1" if
                args.command == "ceo-accept" else
                "M2_CONSTRUCTION_PRE_RELEASE_REQUEST_1"),
                "CLI_CEO_ACCEPT_SCHEMA" if args.command == "ceo-accept" else
                "CLI_PRE_RELEASE_SCHEMA")
            pre = _pre_request(config, request)
            if args.command == "pre-release":
                return _safe_controller_result(pre_release_readonly(
                    ledger_path=Path(config["state_root"]) /
                    "construction.sqlite3",
                    workspace=config["workspace_root"],
                    state_dir=config["state_root"],
                    root_pin_path=config["pin_path"],
                    expected_root_pin_sha256=config["expected_pin_sha256"],
                    signed_ceo_acceptance=request["signed_ceo_acceptance"],
                    **pre))
            _require_existing_ledger(config)
            controller = Controller(
                workspace=config["workspace_root"],
                state_dir=config["state_root"], pin_path=config["pin_path"],
                expected_pin_sha256=config["expected_pin_sha256"])
            return _safe_controller_result(record_ceo_acceptance(
                controller, request["signed_ceo_acceptance"], **pre))
        if args.command in ("post-release", "post-verify"):
            exact_fields(request, "schema signed_release",
                         "CLI_POST_RELEASE_FIELDS" if
                         args.command == "post-release" else
                         "CLI_POST_VERIFY_FIELDS")
            require(request["schema"] ==
                    ("M2_CONSTRUCTION_POST_RELEASE_REQUEST_1" if
                     args.command == "post-release" else
                     "M2_CONSTRUCTION_POST_VERIFY_REQUEST_1"),
                    "CLI_POST_RELEASE_SCHEMA" if
                    args.command == "post-release" else
                    "CLI_POST_VERIFY_SCHEMA")
            if args.command == "post-release":
                return _safe_controller_result(post_release_readonly(
                    ledger_path=Path(config["state_root"]) /
                    "construction.sqlite3",
                    workspace=config["workspace_root"],
                    state_dir=config["state_root"],
                    root_pin_path=config["pin_path"],
                    expected_root_pin_sha256=config["expected_pin_sha256"],
                    signed_release=request["signed_release"]))
            _require_existing_ledger(config)
            controller = Controller(
                workspace=config["workspace_root"],
                state_dir=config["state_root"], pin_path=config["pin_path"],
                expected_pin_sha256=config["expected_pin_sha256"])
            return _safe_controller_result(controller.record_post_release(
                request["signed_release"]))
        exact_fields(request, _RELEASE_FIELDS, "CLI_RELEASE_FIELDS")
        require(request["schema"] == "M2_CONSTRUCTION_RELEASE_REQUEST_1",
                "CLI_RELEASE_SCHEMA")
        _require_existing_ledger(config)
        controller = Controller(
            workspace=config["workspace_root"],
            state_dir=config["state_root"], pin_path=config["pin_path"],
            expected_pin_sha256=config["expected_pin_sha256"])
        return _safe_controller_result(controller.consume_release(
            request["signed_release"],
            signed_review=request["signed_review"],
            signed_ceo_acceptance=request["signed_ceo_acceptance"],
            **_release_pins(config)))
    if args.command == "grant":
        exact_fields(request, "schema signed_scope", "CLI_GRANT_FIELDS")
        require(request["schema"] == "M2_CONSTRUCTION_GRANT_REQUEST_1",
                "CLI_GRANT_SCHEMA")
    elif args.command == "patch":
        if request.get("schema") == "M2_CONSTRUCTION_PATCH_REQUEST_2":
            exact_fields(request, _PATCH_INLINE_FIELDS, "CLI_PATCH_FIELDS")
            content = _inline_bytes(request["content_b64"])
        else:
            exact_fields(request, _PATCH_FIELDS, "CLI_PATCH_FIELDS")
            require(request["schema"] == "M2_CONSTRUCTION_PATCH_REQUEST_1",
                    "CLI_PATCH_SCHEMA")
            content = _content_bytes(Path(config["workspace_root"]), request["content_file"])
    elif args.command == "create":
        if request.get("schema") == "M2_CONSTRUCTION_CREATE_REQUEST_2":
            exact_fields(request, _CREATE_INLINE_FIELDS, "CLI_CREATE_FIELDS")
            content = _inline_bytes(request["content_b64"])
        else:
            exact_fields(request, _CREATE_FIELDS, "CLI_CREATE_FIELDS")
            require(request["schema"] == "M2_CONSTRUCTION_CREATE_REQUEST_1",
                    "CLI_CREATE_SCHEMA")
            content = _content_bytes(Path(config["workspace_root"]), request["content_file"])
    elif args.command == "command":
        exact_fields(request, _COMMAND_FIELDS, "CLI_COMMAND_FIELDS")
        require(request["schema"] == "M2_CONSTRUCTION_COMMAND_REQUEST_1",
                "CLI_COMMAND_SCHEMA")
    elif args.command == "freeze":
        exact_fields(request, _FREEZE_FIELDS, "CLI_FREEZE_FIELDS")
        require(request["schema"] == "M2_CONSTRUCTION_FREEZE_REQUEST_1",
                "CLI_FREEZE_SCHEMA")
    elif args.command == "attest":
        exact_fields(request, _ATTEST_FIELDS, "CLI_ATTEST_FIELDS")
        require(request["schema"] == "M2_CONSTRUCTION_ATTEST_REQUEST_1",
                "CLI_ATTEST_SCHEMA")
    elif args.command == "return":
        require(config["schema"] in ("M2_CONSTRUCTION_CLI_CONFIG_2",
                                      "M2_CONSTRUCTION_CLI_CONFIG_3"),
                "CLI_REVIEWER_PIN_REQUIRED")
        exact_fields(request, _RETURN_FIELDS, "CLI_RETURN_FIELDS")
        require(request["schema"] == "M2_CONSTRUCTION_RETURN_REQUEST_1",
                "CLI_RETURN_SCHEMA")
    controller = Controller(
        workspace=config["workspace_root"], state_dir=config["state_root"],
        pin_path=config["pin_path"],
        expected_pin_sha256=config["expected_pin_sha256"],
    )
    if args.command == "grant":
        return _safe_controller_result(controller.register_grant(request["signed_scope"]))
    if args.command == "attest":
        return _safe_controller_result(controller.record_author_attestation(
            request["signed_authorship"], grant_id=request["grant_id"],
            task_id=request["task_id"], task_revision=request["task_revision"],
            manifest_sha256=request["manifest_sha256"]))
    if args.command == "return":
        child_pin = config["schema"] == "M2_CONSTRUCTION_CLI_CONFIG_3"
        reviewer_pin_field = ("child_reviewer_pin_path" if child_pin
                              else "reviewer_pin_path")
        reviewer_hash_field = ("expected_child_reviewer_pin_sha256" if child_pin
                               else "expected_reviewer_pin_sha256")
        return _safe_controller_result(controller.consume_internal_return(
            request["signed_return"], signed_review=request["signed_review"],
            reviewer_pin_path=config[reviewer_pin_field],
            expected_reviewer_pin_sha256=config[reviewer_hash_field]))
    identity = {name: request[name] for name in (
        "grant_id", "task_id", "task_revision", "operation_id")}
    if args.command == "patch":
        result = controller.apply_patch(
            **identity, path=request["path"],
            before_sha256=request["before_sha256"], content=content)
    elif args.command == "create":
        result = controller.create_file(
            **identity, path=request["path"], content=content)
    elif args.command == "command":
        result = controller.run_command(
            **identity, command_id=request["command_id"])
    else:
        result = controller.freeze_candidate(
            **identity, source_files=request["source_files"],
            test_files=request["test_files"], build_files=request["build_files"],
            test_operation_ids=request["test_operation_ids"],
            build_operation_ids=request["build_operation_ids"])
    return _safe_controller_result(result)


def main(argv=None):
    try:
        result = _dispatch(_parser().parse_args(argv))
    except Denied as exc:
        result = {"status": "DENIED", "reason": str(exc)}
    except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError, ValueError):
        result = {"status": "DENIED", "reason": "CLI_INVALID_REQUEST"}
    except sqlite3.Error:
        result = {"status": "DENIED", "reason": "CLI_STATE_UNREADABLE"}
    except OSError:
        result = {"status": "DENIED", "reason": "CLI_IO_ERROR"}
    print(canonical(result).decode("utf-8"))
    return 0 if result["status"] in ("GRANTED", "COMPLETED", "PASSED", "FROZEN",
                                     "ATTESTED", "ACCEPTED", "PASS", "VERIFIED",
                                     "OK") else (
        3 if result["status"] in ("UNKNOWN", "INDETERMINATE") else 2)


if __name__ == "__main__":
    raise SystemExit(main())
