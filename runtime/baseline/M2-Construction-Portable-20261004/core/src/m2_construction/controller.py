"""Trusted local Controller boundary for TEST_ONLY construction effects.

The entry gate controls these effects; it is not an OS sandbox against a
separately privileged process that bypasses this entry.
"""
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import time

from .contracts import Denied, bytes_hash, canonical, digest, exact_fields, hash_text, require, strict_json
from .adapters import run_fixed_command
from .artifacts import (_passing_receipt, _receipt, freeze_candidate as freeze_bytes,
                        verify_frozen_candidate)
from .ledger import Ledger
from .internal_return import consume_internal_return as consume_return_effect
from .review import verify_author_attestation
from .trust import load_pin, verify_signed_scope


SCOPE_FIELDS = (
    "schema trust_domain grant_id task_id task_revision workspace_root state_root "
    "baseline_files allowed_files allowed_effects not_before expires_at "
    "max_operations max_patch_bytes"
)


def _safe_name(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value),
            "INVALID_IDENTIFIER")


def _relative(value):
    require(type(value) is str and bool(value) and "\\" not in value and ":" not in value and
            "\x00" not in value and not value.startswith("/"), "PATH_SCOPE")
    pure = PurePosixPath(value)
    require(str(pure) == value and all(part not in (".", "..", "") for part in value.split("/")),
            "PATH_SCOPE")
    return pure


def _no_link(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not (getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
            "PATH_LINK")


class Controller:
    def __init__(self, *, workspace, state_dir, pin_path, expected_pin_sha256):
        self.workspace = Path(workspace).resolve(strict=True)
        require(self.workspace.is_dir(), "WORKSPACE_REQUIRED")
        _no_link(self.workspace)
        self.state_dir = Path(state_dir).resolve()
        require(self.state_dir != self.workspace and self.workspace not in self.state_dir.parents,
                "STATE_INSIDE_WORKSPACE")
        self.pin_path = Path(pin_path)
        self.expected_pin_sha256 = expected_pin_sha256
        load_pin(self.pin_path, self.expected_pin_sha256, self.workspace)
        self.ledger = Ledger(self.state_dir / "construction.sqlite3")
        with self.ledger.transaction() as db:
            self.ledger.verify_chain(db)
            self.ledger.ensure_multifile_locks(db)

    def _validate_scope(self, body):
        require(type(body) is dict, "SCOPE_FIELDS")
        version = body.get("schema")
        if version == "M2_CONSTRUCTION_SCOPE_1":
            exact_fields(body, SCOPE_FIELDS, "SCOPE_FIELDS")
            require(body["allowed_effects"] == ["PATCH"], "SCOPE_EFFECTS")
        elif version == "M2_CONSTRUCTION_SCOPE_2":
            exact_fields(body, SCOPE_FIELDS + " allowed_commands", "SCOPE_FIELDS")
        elif version == "M2_CONSTRUCTION_SCOPE_3":
            exact_fields(body, SCOPE_FIELDS + " allowed_commands creatable_files", "SCOPE_FIELDS")
        else:
            require(False, "SCOPE_SCHEMA")
        if version in ("M2_CONSTRUCTION_SCOPE_2", "M2_CONSTRUCTION_SCOPE_3"):
            effects = body["allowed_effects"]
            require(type(effects) is list and bool(effects) and
                    len(effects) == len(set(effects)) and
                    set(effects) <= ({"PATCH", "TEST", "BUILD", "FREEZE", "CREATE"}
                                     if version == "M2_CONSTRUCTION_SCOPE_3" else
                                     {"PATCH", "TEST", "BUILD", "FREEZE"}), "SCOPE_EFFECTS")
            commands = body["allowed_commands"]
            require(type(commands) is list and len(commands) <= 30, "SCOPE_COMMANDS")
            seen = set()
            for command in commands:
                exact_fields(command,
                    "command_id kind argv cwd env timeout_seconds program_sha256 tracked_paths" +
                    (" output_files" if version == "M2_CONSTRUCTION_SCOPE_3" else ""),
                    "SCOPE_COMMAND_FIELDS")
                _safe_name(command["command_id"])
                require(command["command_id"] not in seen and
                        command["kind"] in ("TEST", "BUILD") and
                        command["kind"] in effects, "SCOPE_COMMANDS")
                seen.add(command["command_id"])
                require(type(command["argv"]) is list and bool(command["argv"]) and
                        all(type(arg) is str and "\x00" not in arg for arg in command["argv"]) and
                        Path(command["argv"][0]).is_absolute() and
                        hash_text(command["program_sha256"]), "SCOPE_COMMAND_ARGV")
                require(command["cwd"] == "." or
                        type(command["cwd"]) is str and bool(_relative(command["cwd"])),
                        "SCOPE_COMMAND_CWD")
                require(type(command["env"]) is dict and
                        all(type(k) is str and type(v) is str and k and "=" not in k
                            and "\x00" not in k and "\x00" not in v
                            for k, v in command["env"].items()), "SCOPE_COMMAND_ENV")
                require(type(command["timeout_seconds"]) is int and
                        0 < command["timeout_seconds"] <= 3600, "SCOPE_COMMAND_TIMEOUT")
                paths = command["tracked_paths"]
                require(type(paths) is list and bool(paths) and
                        len(paths) == len(set(paths)), "SCOPE_COMMAND_PATHS")
                for path in paths:
                    _relative(path)
                    require(path in body["allowed_files"], "SCOPE_COMMAND_PATHS")
                if version == "M2_CONSTRUCTION_SCOPE_3":
                    outputs = command["output_files"]
                    require(type(outputs) is dict and
                            (command["kind"] == "BUILD" or not outputs) and
                            set(outputs).isdisjoint(paths), "SCOPE_COMMAND_OUTPUTS")
                    for path, expected in outputs.items():
                        _relative(path)
                        require(path in body["allowed_files"] and
                                (expected is None or hash_text(expected)),
                                "SCOPE_COMMAND_OUTPUTS")
        require(body["trust_domain"] == "TEST_ONLY", "SCOPE_SCHEMA")
        _safe_name(body["grant_id"])
        _safe_name(body["task_id"])
        require(type(body["task_revision"]) is int and body["task_revision"] > 0, "SCOPE_REVISION")
        require(body["workspace_root"] == str(self.workspace), "SCOPE_WORKSPACE")
        require(body["state_root"] == str(self.state_dir), "SCOPE_STATE_IDENTITY")
        files = body["allowed_files"]
        require(type(files) is list and 0 < len(files) <= 100 and
                len(set(files)) == len(files), "SCOPE_FILES")
        creatable = body["creatable_files"] if version == "M2_CONSTRUCTION_SCOPE_3" else []
        require(type(creatable) is list and len(creatable) == len(set(creatable)) and
                set(creatable) <= set(files) and
                (not creatable or "CREATE" in body["allowed_effects"]), "SCOPE_CREATE_FILES")
        file_keys = set()
        file_targets = []
        for path in files:
            _relative(path)
            target = self._target(path, allow_missing=path in creatable)
            key = self._resource_key(path, target)
            require(key not in file_keys and
                    not any(target.exists() and previous.exists() and
                            os.path.samefile(target, previous) for previous in file_targets),
                    "SCOPE_FILE_ALIAS")
            file_keys.add(key)
            file_targets.append(target)
        baseline = body["baseline_files"]
        require(type(baseline) is dict and set(baseline) == set(files) and
                all((h is None if path in creatable else hash_text(h))
                    for path, h in baseline.items()), "SCOPE_BASELINE")
        if version == "M2_CONSTRUCTION_SCOPE_3":
            for command in body["allowed_commands"]:
                require(all(baseline[path] == expected for path, expected in
                            command["output_files"].items()),
                        "SCOPE_COMMAND_OUTPUT_BASELINE")
        for field in ("not_before", "expires_at", "max_operations", "max_patch_bytes"):
            require(type(body[field]) is int and body[field] >= 0, "SCOPE_LIMITS")
        require(body["not_before"] < body["expires_at"] and
                0 < body["max_operations"] <= 1000 and
                0 < body["max_patch_bytes"] <= 10_000_000, "SCOPE_LIMITS")

    def register_grant(self, signed):
        try:
            body = verify_signed_scope(signed, self.pin_path, self.expected_pin_sha256, self.workspace)
            self._validate_scope(body)
            for path in body.get("creatable_files", []):
                require(not self._target(path, allow_missing=True).exists(),
                        "SCOPE_CREATE_ALREADY_EXISTS")
            now = int(time.time())
            require(body["not_before"] <= now < body["expires_at"], "SCOPE_TIME")
            envelope_hash = digest(signed)
            with self.ledger.transaction() as db:
                self.ledger.verify_chain(db)
                existing = db.execute(
                    "SELECT envelope_hash,revoked FROM grants WHERE grant_id=?",
                    (body["grant_id"],)).fetchone()
                if existing:
                    require(existing == (envelope_hash, 0), "SCOPE_ID_CONFLICT")
                else:
                    db.execute("INSERT INTO grants(grant_id,envelope_json,envelope_hash) VALUES(?,?,?)",
                               (body["grant_id"], canonical(signed).decode("utf-8"), envelope_hash))
                    self.ledger.event(db, {"kind": "SCOPE_GRANTED", "grant_id": body["grant_id"],
                                           "scope_hash": digest(body), "root_domain": "TEST_ONLY"})
            return {"status": "GRANTED", "grant_id": body["grant_id"], "scope_hash": digest(body)}
        except (Denied, KeyError, TypeError, ValueError) as exc:
            return {"status": "DENIED", "reason": str(exc)}

    def revoke_grant(self, grant_id):
        _safe_name(grant_id)
        with self.ledger.transaction() as db:
            self.ledger.verify_chain(db)
            row = db.execute("SELECT revoked FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
            require(row is not None, "SCOPE_NOT_FOUND")
            if not row[0]:
                db.execute("UPDATE grants SET revoked=1 WHERE grant_id=?", (grant_id,))
                self.ledger.event(db, {"kind": "SCOPE_REVOKED", "grant_id": grant_id})

    def _current_scope(self, db, grant_id, task_id, task_revision):
        row = db.execute("SELECT envelope_json,envelope_hash,revoked FROM grants WHERE grant_id=?",
                         (grant_id,)).fetchone()
        require(row is not None and row[2] == 0, "SCOPE_NOT_CURRENT")
        signed = strict_json(row[0])
        require(digest(signed) == row[1], "SCOPE_STORED_ENVELOPE_CHANGED")
        body = verify_signed_scope(signed, self.pin_path, self.expected_pin_sha256, self.workspace)
        self._validate_scope(body)
        require(body["task_id"] == task_id and body["task_revision"] == task_revision,
                "SCOPE_TASK_VERSION")
        require(body["not_before"] <= int(time.time()) < body["expires_at"], "SCOPE_EXPIRED")
        return body

    def _target(self, value, *, allow_missing=False):
        pure = _relative(value)
        current = self.workspace
        for index, part in enumerate(pure.parts):
            if allow_missing and os.name == "nt":
                require(part.rstrip(" .") == part and not os.path.isreserved(part),
                        "PATH_AMBIGUOUS")
            current = current / part
            if allow_missing and index == len(pure.parts) - 1 and not (
                    current.exists() or current.is_symlink()):
                parent = current.parent.resolve(strict=True)
                require(parent.is_dir() and
                        (parent == self.workspace or self.workspace in parent.parents),
                        "PATH_OUTSIDE_WORKSPACE")
                return parent / part
            require(current.exists() or current.is_symlink(), "PATH_NOT_FOUND")
            _no_link(current)
        require(current.is_file() and self.workspace in current.resolve(strict=True).parents,
                "PATH_OUTSIDE_WORKSPACE")
        return current

    def _resource_key(self, value, target=None):
        """Stable name for a workspace file, including Windows case aliases.

        File IDs change on atomic replace, so a lock cannot use inode alone.
        Keep request/event spelling separately for audit.
        """
        target = self._target(value) if target is None else target
        relative = target.resolve(strict=target.exists()).relative_to(self.workspace).as_posix()
        return relative.casefold() if os.name == "nt" else relative

    def _resource_busy(self, db, key, target):
        # Old TEST_ONLY ledgers may hold a lock under the original spelling.
        # Resolve every unresolved lock; an unresolvable lock fails closed.
        for (locked_path,) in db.execute("SELECT path FROM resource_locks"):
            if locked_path == key or (os.name == "nt" and locked_path.casefold() == key):
                return True
            locked_target = self._target(locked_path, allow_missing=True)
            if (self._resource_key(locked_path, locked_target) == key or
                    (locked_target.exists() and target.exists() and
                     os.path.samefile(locked_target, target))):
                return True
        return False

    def _prior_patch_hash(self, db, grant_id, key):
        # Preserve the original operation path while comparing physical names.
        # A returned child file becomes a parent-owned current prestate only
        # after its own completed operation and chained consume event agree.
        for operation_id, kind, path, after_hash, result_json in db.execute(
                "SELECT operation_id,kind,path,after_sha256,result_json "
                "FROM operations WHERE grant_id=? AND kind IN "
                "('PATCH','CREATE','INTERNAL_RETURN') AND status='COMPLETED' "
                "ORDER BY rowid DESC", (grant_id,)):
            if kind == "INTERNAL_RETURN":
                result = strict_json(result_json)
                files = result.get("files")
                require(result.get("status") == "COMPLETED" and
                        result.get("authority") == "INTERNAL_PARENT_ONLY" and
                        type(files) is dict and files and
                        all(type(name) is str and hash_text(value)
                            for name, value in files.items()) and
                        digest(files) == result.get("files_sha256") == after_hash,
                        "RETURN_PRIOR_RECEIPT")
                matching = []
                for (raw,) in db.execute("SELECT body_json FROM events ORDER BY seq"):
                    event = strict_json(raw)
                    if (event.get("kind") == "INTERNAL_RETURN_CONSUMED" and
                            event.get("operation_id") == operation_id and
                            event.get("files_sha256") == after_hash and
                            event.get("authority") == "INTERNAL_PARENT_ONLY"):
                        matching.append(event)
                require(len(matching) == 1, "RETURN_PRIOR_EVENT")
                for name, actual_hash in files.items():
                    if self._resource_key(name) == key:
                        return actual_hash
            elif self._resource_key(path) == key:
                return after_hash
        return None

    def _prior_build_hash(self, db, grant_id, key):
        """Only a governed passing BUILD receipt can introduce output bytes."""
        rows = db.execute(
            "SELECT operation_id,result_json FROM operations WHERE grant_id=? AND "
            "kind='BUILD' AND status='COMPLETED' ORDER BY rowid DESC", (grant_id,))
        for operation_id, result_json in rows:
            result = strict_json(result_json)
            if result.get("status") != "PASSED":
                continue
            receipt_path = Path(result["receipt_path"])
            require(receipt_path.is_absolute() and
                    self.state_dir in receipt_path.resolve(strict=True).parents,
                    "BUILD_RECEIPT_OUTSIDE_STATE")
            receipt = _receipt(receipt_path, result["receipt_sha256"])
            require(receipt["operation_id"] == operation_id, "BUILD_RECEIPT_BINDING")
            for path, record in receipt.get("output_after", {}).items():
                if self._resource_key(path) == key:
                    require(type(record) is dict and hash_text(record.get("sha256")),
                            "BUILD_OUTPUT_PROOF")
                    return record["sha256"]
        return None

    def apply_patch(self, *, grant_id, task_id, task_revision, operation_id,
                    path, before_sha256, content):
        try:
            _safe_name(grant_id)
            _safe_name(task_id)
            _safe_name(operation_id)
            require(type(task_revision) is int and task_revision > 0 and hash_text(before_sha256) and
                    type(content) is bytes, "PATCH_REQUEST")
            relative = str(_relative(path))
            request = {"schema": "M2_CONSTRUCTION_PATCH_1", "grant_id": grant_id,
                       "task_id": task_id, "task_revision": task_revision,
                       "operation_id": operation_id, "path": relative,
                       "before_sha256": before_sha256, "content_sha256": bytes_hash(content)}
            request_hash = digest(request)
            after_hash = bytes_hash(content)
            with self.ledger.transaction() as db:
                self.ledger.verify_chain(db)
                scope = self._current_scope(db, grant_id, task_id, task_revision)
                require(relative in scope["allowed_files"] and "PATCH" in scope["allowed_effects"],
                        "PATCH_SCOPE")
                require(len(content) <= scope["max_patch_bytes"], "PATCH_SIZE")
                old = db.execute(
                    "SELECT request_hash,status,after_sha256,result_json FROM operations WHERE operation_id=?",
                    (operation_id,)).fetchone()
                if old:
                    if old[0] != request_hash:
                        return {"status": "CONFLICT", "reason": "OPERATION_ID_DIFFERENT_REQUEST"}
                    if old[1] == "COMPLETED":
                        return {**strict_json(old[3]), "effect_executed": False}
                    return {"status": "UNKNOWN", "operation_id": operation_id,
                            "effect_executed": False}
                used = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(content_size),0) FROM operations WHERE grant_id=?",
                    (grant_id,)).fetchone()
                require(used[0] < scope["max_operations"] and
                        used[1] + len(content) <= scope["max_operations"] * scope["max_patch_bytes"],
                        "PATCH_BUDGET")
                target = self._target(relative)
                resource_key = self._resource_key(relative, target)
                require(not self._resource_busy(db, resource_key, target), "PATCH_RESOURCE_BUSY")
                actual_before = bytes_hash(target.read_bytes())
                prior = self._prior_patch_hash(db, grant_id, resource_key)
                expected = prior if prior is not None else scope["baseline_files"][relative]
                require(actual_before == expected == before_sha256, "PATCH_BEFORE_CHANGED")
                db.execute("INSERT INTO operations(operation_id,grant_id,task_id,kind,path,request_hash,"
                           "content_size,status,before_sha256) VALUES(?,?,?,?,?,?,?,?,?)",
                           (operation_id, grant_id, task_id, "PATCH", relative, request_hash,
                            len(content), "INTENT", before_sha256))
                db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                           (resource_key, operation_id))
                self.ledger.event(db, {"kind": "GATE_ALLOW", "operation_id": operation_id,
                                       "request_hash": request_hash, "grant_id": grant_id})
                self.ledger.event(db, {"kind": "INTENT", "operation_id": operation_id,
                                       "path": relative, "before_sha256": before_sha256,
                                       "after_sha256": after_hash})
            # SQLite and the filesystem are not one transaction. The reserved ID is
            # never auto-replayed after this point, even if the process dies.
            tmp_name = None
            try:
                target = self._target(relative)
                require(bytes_hash(target.read_bytes()) == before_sha256, "PATCH_CHANGED_AFTER_INTENT")
                fd, tmp_name = tempfile.mkstemp(prefix=".m2-patch-", dir=target.parent)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                _no_link(target.parent)
                os.replace(tmp_name, target)
                tmp_name = None
                observed = bytes_hash(self._target(relative).read_bytes())
                require(observed == after_hash, "PATCH_EFFECT_UNCERTAIN")
                result = {"status": "COMPLETED", "operation_id": operation_id,
                          "before_sha256": before_sha256, "after_sha256": observed,
                          "effect_executed": True}
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    cursor = db.execute("UPDATE operations SET status='COMPLETED',after_sha256=?,result_json=? "
                                        "WHERE operation_id=? AND status='INTENT'",
                                        (observed, canonical(result).decode("utf-8"), operation_id))
                    require(cursor.rowcount == 1, "PATCH_RECEIPT_RACE")
                    db.execute("DELETE FROM resource_locks WHERE path=? AND operation_id=?",
                               (resource_key, operation_id))
                    self.ledger.event(db, {"kind": "RECEIPT", "operation_id": operation_id,
                                           "request_hash": request_hash, "actual_sha256": observed})
                return result
            except BaseException:
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    db.execute("UPDATE operations SET status='UNKNOWN' WHERE operation_id=? AND status='INTENT'",
                               (operation_id,))
                    self.ledger.event(db, {"kind": "UNKNOWN", "operation_id": operation_id})
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "effect_executed": None, "new_dispatch": True}
            finally:
                if tmp_name and os.path.exists(tmp_name):
                    os.unlink(tmp_name)
        except (Denied, KeyError, TypeError, ValueError, OSError) as exc:
            return {"status": "DENIED", "reason": str(exc), "effect_executed": False}

    def create_file(self, *, grant_id, task_id, task_revision, operation_id, path, content):
        """Create one explicitly signed absent file; never overwrite an existing path.

        A crash after INTENT can leave partial bytes. The operation remains
        UNKNOWN and is never automatically dispatched a second time.
        """
        try:
            for value in (grant_id, task_id, operation_id):
                _safe_name(value)
            require(type(task_revision) is int and task_revision > 0 and
                    type(content) is bytes, "CREATE_REQUEST")
            relative = str(_relative(path))
            request_hash = digest({"schema": "M2_CONSTRUCTION_CREATE_1",
                                   "grant_id": grant_id, "task_id": task_id,
                                   "task_revision": task_revision,
                                   "operation_id": operation_id, "path": relative,
                                   "content_sha256": bytes_hash(content)})
            after_hash = bytes_hash(content)
            with self.ledger.transaction() as db:
                self.ledger.verify_chain(db)
                scope = self._current_scope(db, grant_id, task_id, task_revision)
                require(scope["schema"] == "M2_CONSTRUCTION_SCOPE_3" and
                        "CREATE" in scope["allowed_effects"] and
                        relative in scope["creatable_files"], "CREATE_SCOPE")
                require(len(content) <= scope["max_patch_bytes"], "CREATE_SIZE")
                old = db.execute(
                    "SELECT request_hash,status,after_sha256,result_json FROM operations "
                    "WHERE operation_id=?", (operation_id,)).fetchone()
                if old:
                    if old[0] != request_hash:
                        return {"status": "CONFLICT", "reason": "OPERATION_ID_DIFFERENT_REQUEST"}
                    if old[1] == "COMPLETED":
                        target = self._target(relative)
                        require(bytes_hash(target.read_bytes()) == old[2],
                                "CREATE_RESULT_CHANGED")
                        return {**strict_json(old[3]), "effect_executed": False}
                    return {"status": "UNKNOWN", "operation_id": operation_id,
                            "effect_executed": False}
                used = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(content_size),0) FROM operations "
                    "WHERE grant_id=?", (grant_id,)).fetchone()
                require(used[0] < scope["max_operations"] and
                        used[1] + len(content) <=
                        scope["max_operations"] * scope["max_patch_bytes"],
                        "CREATE_BUDGET")
                target = self._target(relative, allow_missing=True)
                require(not target.exists(), "CREATE_ALREADY_EXISTS")
                resource_key = self._resource_key(relative, target)
                require(not self._resource_busy(db, resource_key, target),
                        "CREATE_RESOURCE_BUSY")
                db.execute(
                    "INSERT INTO operations(operation_id,grant_id,task_id,kind,path,"
                    "request_hash,content_size,status,before_sha256) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (operation_id, grant_id, task_id, "CREATE", relative,
                     request_hash, len(content), "INTENT", "ABSENT"))
                db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                           (resource_key, operation_id))
                self.ledger.event(db, {"kind": "GATE_ALLOW", "operation_id": operation_id,
                                       "grant_id": grant_id,
                                       "request_hash": request_hash})
                self.ledger.event(db, {"kind": "INTENT", "operation_id": operation_id,
                                       "path": relative, "before_state": "ABSENT",
                                       "after_sha256": after_hash})
            try:
                target = self._target(relative, allow_missing=True)
                require(not target.exists(), "CREATE_CHANGED_AFTER_INTENT")
                _no_link(target.parent)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(target, flags, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                observed = bytes_hash(self._target(relative).read_bytes())
                require(observed == after_hash, "CREATE_EFFECT_UNCERTAIN")
                result = {"status": "COMPLETED", "operation_id": operation_id,
                          "before_state": "ABSENT", "after_sha256": observed,
                          "effect_executed": True}
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    cursor = db.execute(
                        "UPDATE operations SET status='COMPLETED',after_sha256=?,"
                        "result_json=? WHERE operation_id=? AND status='INTENT'",
                        (observed, canonical(result).decode("utf-8"), operation_id))
                    require(cursor.rowcount == 1, "CREATE_RECEIPT_RACE")
                    db.execute("DELETE FROM resource_locks WHERE path=? AND operation_id=?",
                               (resource_key, operation_id))
                    self.ledger.event(db, {"kind": "RECEIPT", "operation_id": operation_id,
                                           "request_hash": request_hash,
                                           "actual_sha256": observed})
                return result
            except BaseException:
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    db.execute("UPDATE operations SET status='UNKNOWN' WHERE operation_id=? "
                               "AND status='INTENT'", (operation_id,))
                    self.ledger.event(db, {"kind": "UNKNOWN", "operation_id": operation_id})
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "effect_executed": None, "new_dispatch": True}
        except (Denied, KeyError, TypeError, ValueError, OSError) as exc:
            return {"status": "DENIED", "reason": str(exc), "effect_executed": False}

    def run_command(self, *, grant_id, task_id, task_revision, operation_id, command_id):
        """Run one signed, fixed TEST/BUILD command through Gate and journal."""
        try:
            for value in (grant_id, task_id, operation_id, command_id):
                _safe_name(value)
            require(type(task_revision) is int and task_revision > 0, "COMMAND_REQUEST")
            with self.ledger.transaction() as db:
                self.ledger.verify_chain(db)
                scope = self._current_scope(db, grant_id, task_id, task_revision)
                command = next((item for item in scope.get("allowed_commands", [])
                                if item["command_id"] == command_id), None)
                require(command is not None and command["kind"] in scope["allowed_effects"],
                        "COMMAND_NOT_AUTHORIZED")
                request_hash = digest({"schema": "M2_CONSTRUCTION_COMMAND_1",
                                       "grant_id": grant_id, "task_id": task_id,
                                       "task_revision": task_revision,
                                       "operation_id": operation_id,
                                       "command": command})
                old = db.execute(
                    "SELECT request_hash,status,result_json FROM operations WHERE operation_id=?",
                    (operation_id,)).fetchone()
                if old:
                    if old[0] != request_hash:
                        return {"status": "CONFLICT", "reason": "OPERATION_ID_DIFFERENT_REQUEST"}
                    if old[1] == "COMPLETED":
                        return {**strict_json(old[2]), "effect_executed": False}
                    return {"status": "UNKNOWN", "operation_id": operation_id,
                            "effect_executed": None, "new_dispatch": False}
                count = db.execute("SELECT COUNT(*) FROM operations WHERE grant_id=?",
                                   (grant_id,)).fetchone()[0]
                require(count < scope["max_operations"], "COMMAND_BUDGET")
                tracked = {}
                tracked_keys = {}
                output_expected = command.get("output_files", {})
                output_keys = {}
                for path in command["tracked_paths"]:
                    target = self._target(path)
                    resource_key = self._resource_key(path, target)
                    require(not self._resource_busy(db, resource_key, target),
                            "COMMAND_RESOURCE_BUSY")
                    observed = bytes_hash(target.read_bytes())
                    prior = self._prior_patch_hash(db, grant_id, resource_key)
                    if prior is None:
                        prior = self._prior_build_hash(db, grant_id, resource_key)
                    require(observed == (prior if prior is not None else scope["baseline_files"][path]),
                            "COMMAND_SOURCE_CHANGED")
                    tracked[path] = observed
                    tracked_keys[path] = resource_key
                for path, expected in output_expected.items():
                    target = self._target(path, allow_missing=expected is None)
                    key = self._resource_key(path, target)
                    require(key not in tracked_keys.values() and
                            key not in output_keys.values() and
                            not self._resource_busy(db, key, target),
                            "COMMAND_OUTPUT_BUSY")
                    observed = bytes_hash(target.read_bytes()) if target.exists() else None
                    require(observed == expected and
                            scope["baseline_files"][path] == expected,
                            "COMMAND_OUTPUT_BEFORE_CHANGED")
                    output_keys[path] = key
                cwd = self.workspace if command["cwd"] == "." else self.workspace.joinpath(
                    *command["cwd"].split("/"))
                require(cwd.is_dir() and (cwd == self.workspace or
                        self.workspace in cwd.resolve(strict=True).parents), "COMMAND_CWD")
                _no_link(cwd)
                db.execute("INSERT INTO operations(operation_id,grant_id,task_id,kind,path,request_hash,"
                           "content_size,status,before_sha256) VALUES(?,?,?,?,?,?,?,?,?)",
                           (operation_id, grant_id, task_id, command["kind"], command_id,
                            request_hash, 0, "INTENT", digest(tracked)))
                for path in command["tracked_paths"]:
                    db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                               (tracked_keys[path], operation_id))
                for path in output_expected:
                    db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                               (output_keys[path], operation_id))
                self.ledger.event(db, {"kind": "GATE_ALLOW", "operation_id": operation_id,
                                       "grant_id": grant_id, "request_hash": request_hash})
                self.ledger.event(db, {"kind": "INTENT", "operation_id": operation_id,
                                       "command_id": command_id, "source_hash": digest(tracked)})
            try:
                receipt = run_fixed_command(
                    argv=command["argv"], cwd=cwd, env=command["env"],
                    timeout_seconds=command["timeout_seconds"],
                    expected_program_sha256=command["program_sha256"],
                    log_dir=self.state_dir / "evidence", operation_id=operation_id,
                    tracked_root=self.workspace, tracked_files=tracked,
                    output_files=(output_expected if output_expected else None))
                result = {"status": receipt["status"], "operation_id": operation_id,
                          "exit_code": receipt["exit_code"],
                          "receipt_path": receipt["receipt_path"],
                          "receipt_sha256": receipt["receipt_sha256"],
                          "effect_executed": True}
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    cursor = db.execute("UPDATE operations SET status='COMPLETED',after_sha256=?,"
                                        "result_json=? WHERE operation_id=? AND status='INTENT'",
                                        (receipt["receipt_sha256"], canonical(result).decode("utf-8"),
                                         operation_id))
                    require(cursor.rowcount == 1, "COMMAND_RECEIPT_RACE")
                    for path in command["tracked_paths"]:
                        db.execute("DELETE FROM resource_locks WHERE path=? AND operation_id=?",
                                   (tracked_keys[path], operation_id))
                    for path in output_expected:
                        db.execute("DELETE FROM resource_locks WHERE path=? AND operation_id=?",
                                   (output_keys[path], operation_id))
                    self.ledger.event(db, {"kind": "RECEIPT", "operation_id": operation_id,
                                           "request_hash": request_hash,
                                           "receipt_sha256": receipt["receipt_sha256"],
                                           "status": receipt["status"]})
                    self.ledger.event(db, {"kind": ("TEST_RECEIPT" if command["kind"] == "TEST"
                                                   else "BUILD_RECEIPT"),
                                           "grant_id": grant_id, "task_id": task_id,
                                           "task_revision": task_revision,
                                           "operation_id": operation_id,
                                           "status": receipt["status"],
                                           "receipt_sha256": receipt["receipt_sha256"]})
                return result
            except BaseException:
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    db.execute("UPDATE operations SET status='UNKNOWN' WHERE operation_id=? "
                               "AND status='INTENT'", (operation_id,))
                    self.ledger.event(db, {"kind": "UNKNOWN", "operation_id": operation_id})
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "effect_executed": None, "new_dispatch": True}
        except (Denied, KeyError, TypeError, ValueError, OSError) as exc:
            return {"status": "DENIED", "reason": str(exc), "effect_executed": False}

    def freeze_candidate(self, *, grant_id, task_id, task_revision, operation_id,
                         source_files, test_files, build_files, test_operation_ids,
                         build_operation_ids=()):
        """Freeze real bytes only after same-task governed passing TEST receipts.

        This is a candidate record, not independent review or release permission.
        Build files require same-task governed BUILD output receipts.
        """
        try:
            for value in (grant_id, task_id, operation_id):
                _safe_name(value)
            require(type(task_revision) is int and task_revision > 0,
                    "FREEZE_REQUEST")
            groups = (source_files, test_files, build_files)
            require(all(type(group) in (list, tuple) for group in groups) and
                    bool(source_files) and bool(test_files) and
                    type(test_operation_ids) in (list, tuple) and
                    bool(test_operation_ids) and
                    type(build_operation_ids) in (list, tuple), "FREEZE_REQUEST")
            require(bool(build_files) == bool(build_operation_ids),
                    "BUILD_OUTPUT_PROOF_REQUIRED")
            files = list(source_files) + list(test_files) + list(build_files)
            require(len(files) == len(set(files)) and
                    len(test_operation_ids) == len(set(test_operation_ids)) and
                    len(build_operation_ids) == len(set(build_operation_ids)),
                    "FREEZE_DUPLICATE")
            for value in files:
                _relative(value)
            for value in list(test_operation_ids) + list(build_operation_ids):
                _safe_name(value)
            request = {"schema": ("M2_CONSTRUCTION_FREEZE_REQUEST_2"
                                  if build_operation_ids else "M2_CONSTRUCTION_FREEZE_REQUEST_1"),
                       "grant_id": grant_id, "task_id": task_id,
                       "task_revision": task_revision, "operation_id": operation_id,
                       "source_files": list(source_files), "test_files": list(test_files),
                       "build_files": list(build_files),
                       "test_operation_ids": list(test_operation_ids)}
            if build_operation_ids:
                request["build_operation_ids"] = list(build_operation_ids)
            request_hash = digest(request)
            with self.ledger.transaction() as db:
                self.ledger.verify_chain(db)
                scope = self._current_scope(db, grant_id, task_id, task_revision)
                require("FREEZE" in scope["allowed_effects"] and
                        set(files) <= set(scope["allowed_files"]), "FREEZE_SCOPE")
                old = db.execute(
                    "SELECT request_hash,status,result_json FROM operations WHERE operation_id=?",
                    (operation_id,)).fetchone()
                if old:
                    if old[0] != request_hash:
                        return {"status": "CONFLICT", "reason": "OPERATION_ID_DIFFERENT_REQUEST"}
                    if old[1] == "COMPLETED":
                        cached = strict_json(old[2])
                        verify_frozen_candidate(
                            cached["manifest_path"],
                            expected_manifest_sha256=cached["manifest_sha256"])
                        return {**cached, "effect_executed": False}
                    return {"status": "UNKNOWN", "operation_id": operation_id,
                            "effect_executed": None, "new_dispatch": False}
                used = db.execute("SELECT COUNT(*) FROM operations WHERE grant_id=?",
                                  (grant_id,)).fetchone()[0]
                require(used < scope["max_operations"], "FREEZE_BUDGET")
                keys = {}
                current_hashes = {}
                for path in files:
                    target = self._target(path)
                    key = self._resource_key(path, target)
                    require(key not in keys.values() and
                            not self._resource_busy(db, key, target),
                            "FREEZE_RESOURCE_BUSY")
                    if path in build_files:
                        expected = self._prior_build_hash(db, grant_id, key)
                        require(expected is not None, "BUILD_OUTPUT_PROOF_REQUIRED")
                    else:
                        prior = self._prior_patch_hash(db, grant_id, key)
                        expected = prior if prior is not None else scope["baseline_files"][path]
                    observed = bytes_hash(target.read_bytes())
                    require(observed == expected, "FREEZE_SOURCE_CHANGED")
                    keys[path] = key
                    current_hashes[path] = observed
                receipts = []
                for test_operation_id in test_operation_ids:
                    row = db.execute(
                        "SELECT grant_id,task_id,kind,status,result_json FROM operations "
                        "WHERE operation_id=?", (test_operation_id,)).fetchone()
                    require(row is not None and row[:4] ==
                            (grant_id, task_id, "TEST", "COMPLETED"),
                            "TEST_OPERATION_NOT_CURRENT")
                    result = strict_json(row[4])
                    require(result.get("status") == "PASSED", "TEST_NOT_PASSED")
                    events = [strict_json(body_json) for (body_json,) in db.execute(
                        "SELECT body_json FROM events ORDER BY seq")]
                    matches = [event for event in events
                               if event.get("kind") == "TEST_RECEIPT" and
                               event.get("grant_id") == grant_id and
                               event.get("task_id") == task_id and
                               event.get("task_revision") == task_revision and
                               event.get("operation_id") == test_operation_id and
                               event.get("receipt_sha256") == result.get("receipt_sha256") and
                               event.get("status") == "PASSED"]
                    require(len(matches) == 1, "TEST_EVENT_MISSING")
                    receipt_path = Path(result["receipt_path"])
                    require(receipt_path.is_absolute() and
                            self.state_dir in receipt_path.resolve(strict=True).parents,
                            "TEST_RECEIPT_OUTSIDE_STATE")
                    loaded = _receipt(receipt_path, result["receipt_sha256"])
                    require(loaded["operation_id"] == test_operation_id,
                            "TEST_RECEIPT_BINDING")
                    receipts.append({**loaded, "receipt_path": str(receipt_path),
                                     "receipt_sha256": result["receipt_sha256"]})
                source_test_hashes = {name: current_hashes[name]
                                      for name in list(source_files) + list(test_files)}
                for receipt in receipts:
                    _passing_receipt(self.workspace, current_hashes, receipt)
                build_receipts = []
                for build_operation_id in build_operation_ids:
                    row = db.execute(
                        "SELECT grant_id,task_id,kind,status,result_json FROM operations "
                        "WHERE operation_id=?", (build_operation_id,)).fetchone()
                    require(row is not None and row[:4] ==
                            (grant_id, task_id, "BUILD", "COMPLETED"),
                            "BUILD_OPERATION_NOT_CURRENT")
                    result = strict_json(row[4])
                    require(result.get("status") == "PASSED", "BUILD_NOT_PASSED")
                    events = [strict_json(body_json) for (body_json,) in db.execute(
                        "SELECT body_json FROM events ORDER BY seq")]
                    matches = [event for event in events
                               if event.get("kind") == "BUILD_RECEIPT" and
                               event.get("grant_id") == grant_id and
                               event.get("task_id") == task_id and
                               event.get("task_revision") == task_revision and
                               event.get("operation_id") == build_operation_id and
                               event.get("receipt_sha256") == result.get("receipt_sha256") and
                               event.get("status") == "PASSED"]
                    require(len(matches) == 1, "BUILD_EVENT_MISSING")
                    receipt_path = Path(result["receipt_path"])
                    require(receipt_path.is_absolute() and
                            self.state_dir in receipt_path.resolve(strict=True).parents,
                            "BUILD_RECEIPT_OUTSIDE_STATE")
                    loaded = _receipt(receipt_path, result["receipt_sha256"])
                    require(loaded["operation_id"] == build_operation_id,
                            "BUILD_RECEIPT_BINDING")
                    _passing_receipt(self.workspace,
                                     {name: current_hashes[name] for name in source_files},
                                     loaded)
                    build_receipts.append({**loaded, "receipt_path": str(receipt_path),
                                           "receipt_sha256": result["receipt_sha256"]})
                for path in build_files:
                    witnesses = [receipt["output_after"][path]["sha256"]
                                 for receipt in build_receipts
                                 if path in receipt.get("output_after", {}) and
                                 receipt["output_after"][path] is not None]
                    require(len(witnesses) == 1 and witnesses[0] == current_hashes[path],
                            "BUILD_OUTPUT_PROOF_REQUIRED")
                manifest_path = (self.state_dir / "evidence" / "candidates" /
                                 f"{operation_id}.manifest.json")
                db.execute("INSERT INTO operations(operation_id,grant_id,task_id,kind,path,"
                           "request_hash,content_size,status,before_sha256) "
                           "VALUES(?,?,?,?,?,?,?,?,?)",
                           (operation_id, grant_id, task_id, "FREEZE", str(manifest_path),
                            request_hash, 0, "INTENT", digest(keys)))
                for key in keys.values():
                    db.execute("INSERT INTO resource_locks(path,operation_id) VALUES(?,?)",
                               (key, operation_id))
                self.ledger.event(db, {"kind": "GATE_ALLOW", "operation_id": operation_id,
                                       "grant_id": grant_id, "request_hash": request_hash})
                self.ledger.event(db, {"kind": "INTENT", "operation_id": operation_id,
                                       "source_hash": digest(keys),
                                       "test_operation_ids": list(test_operation_ids),
                                       "build_operation_ids": list(build_operation_ids)})
            try:
                frozen = freeze_bytes(
                    root=self.workspace, source_files=source_files,
                    test_files=test_files, build_files=build_files,
                    test_receipts=receipts, build_receipts=build_receipts,
                    manifest_path=manifest_path)
                result = {**frozen, "operation_id": operation_id,
                          "effect_executed": True}
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    cursor = db.execute(
                        "UPDATE operations SET status='COMPLETED',after_sha256=?,result_json=? "
                        "WHERE operation_id=? AND status='INTENT'",
                        (frozen["manifest_sha256"],
                         canonical(result).decode("utf-8"), operation_id))
                    require(cursor.rowcount == 1, "FREEZE_RECEIPT_RACE")
                    for key in keys.values():
                        db.execute("DELETE FROM resource_locks WHERE path=? AND operation_id=?",
                                   (key, operation_id))
                    self.ledger.event(db, {"kind": "CANDIDATE_FROZEN",
                                           "grant_id": grant_id, "task_id": task_id,
                                           "task_revision": task_revision,
                                           "operation_id": operation_id,
                                           "manifest_path": frozen["manifest_path"],
                                           "manifest_sha256": frozen["manifest_sha256"]})
                return result
            except BaseException:
                with self.ledger.transaction() as db:
                    self.ledger.verify_chain(db)
                    db.execute("UPDATE operations SET status='UNKNOWN' "
                               "WHERE operation_id=? AND status='INTENT'",
                               (operation_id,))
                    self.ledger.event(db, {"kind": "UNKNOWN", "operation_id": operation_id})
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "effect_executed": None, "new_dispatch": True}
        except (Denied, KeyError, TypeError, ValueError, OSError) as exc:
            return {"status": "DENIED", "reason": str(exc), "effect_executed": False}

    def record_author_attestation(self, signed, *, grant_id, task_id,
                                  task_revision, manifest_sha256):
        """Record an external Test Root attestation after a real frozen result.

        This Controller cannot infer a Codex model identity from a request. The
        independent Test Root issuer must verify native caller evidence before
        signing. Merely writing an author role string cannot produce this event.
        """
        try:
            _safe_name(grant_id)
            _safe_name(task_id)
            require(type(task_revision) is int and task_revision > 0 and
                    hash_text(manifest_sha256), "AUTHOR_REQUEST")
            verified = verify_author_attestation(
                signed, root_pin_path=self.pin_path,
                expected_root_pin_sha256=self.expected_pin_sha256,
                workspace=self.workspace, grant_id=grant_id,
                task_id=task_id, task_revision=task_revision,
                manifest_sha256=manifest_sha256)
            with self.ledger.transaction() as db:
                self.ledger.verify_chain(db)
                self._current_scope(db, grant_id, task_id, task_revision)
                events = [strict_json(row[0]) for row in db.execute(
                    "SELECT body_json FROM events ORDER BY seq")]
                freezes = [event for event in events
                           if event.get("kind") == "CANDIDATE_FROZEN" and
                           event.get("grant_id") == grant_id and
                           event.get("task_id") == task_id and
                           event.get("task_revision") == task_revision]
                require(freezes and
                        freezes[-1].get("manifest_sha256") == manifest_sha256,
                        "AUTHOR_CANDIDATE_NOT_CURRENT")
                freeze = freezes[-1]
                row = db.execute(
                    "SELECT kind,status,result_json FROM operations "
                    "WHERE operation_id=?", (freeze["operation_id"],)).fetchone()
                require(row is not None and row[:2] == ("FREEZE", "COMPLETED"),
                        "AUTHOR_FREEZE_OPERATION")
                result = strict_json(row[2])
                require(result.get("manifest_sha256") == manifest_sha256 and
                        result.get("manifest_path") == freeze.get("manifest_path"),
                        "AUTHOR_FREEZE_BINDING")
                path = Path(result["manifest_path"])
                require(path.is_absolute() and
                        self.state_dir in path.resolve(strict=True).parents,
                        "AUTHOR_MANIFEST_OUTSIDE_STATE")
                verify_frozen_candidate(path,
                                        expected_manifest_sha256=manifest_sha256)
                prior = [event for event in events
                         if event.get("kind") == "AUTHOR_ATTESTED" and
                         type(event.get("authorship")) is dict and
                         event["authorship"].get("body", {}).get(
                             "candidate_sha256") == manifest_sha256]
                if prior:
                    require(len(prior) == 1 and prior[0]["authorship"] == signed,
                            "AUTHOR_ATTESTATION_CONFLICT")
                    return {"status": "ATTESTED", "manifest_sha256": manifest_sha256,
                            "attestation_sha256": verified["attestation_sha256"],
                            "effect_executed": False}
                self.ledger.event(db, {"kind": "AUTHOR_ATTESTED",
                                       "authorship": signed,
                                       "attestation_sha256": verified["attestation_sha256"]})
                return {"status": "ATTESTED", "manifest_sha256": manifest_sha256,
                        "attestation_sha256": verified["attestation_sha256"],
                        "effect_executed": True}
        except (Denied, KeyError, IndexError, TypeError, ValueError, OSError) as exc:
            return {"status": "DENIED", "reason": str(exc),
                    "effect_executed": False}

    def consume_internal_return(self, signed, *, signed_review,
                                reviewer_pin_path,
                                expected_reviewer_pin_sha256):
        """Gate one Root-bound internal copy after a fresh read-only verdict."""
        return consume_return_effect(
            self, signed, signed_review=signed_review,
            reviewer_pin_path=reviewer_pin_path,
            expected_reviewer_pin_sha256=expected_reviewer_pin_sha256)

    def consume_release(self, signed, *, reviewer_pin_path,
                        expected_reviewer_pin_sha256, child_reviewer_pin_path,
                        expected_child_reviewer_pin_sha256, ceo_pin_path,
                        expected_ceo_pin_sha256, signed_review,
                        signed_ceo_acceptance):
        """Gate one TEST_ONLY release after fresh PRE and a Root lease."""
        from .release_effect import consume_release as consume_release_effect
        return consume_release_effect(
            self, signed, reviewer_pin_path=reviewer_pin_path,
            expected_reviewer_pin_sha256=expected_reviewer_pin_sha256,
            child_reviewer_pin_path=child_reviewer_pin_path,
            expected_child_reviewer_pin_sha256=
            expected_child_reviewer_pin_sha256,
            ceo_pin_path=ceo_pin_path,
            expected_ceo_pin_sha256=expected_ceo_pin_sha256,
            signed_review=signed_review,
            signed_ceo_acceptance=signed_ceo_acceptance)

    def record_post_release(self, signed_release):
        """Persist only a fresh, independent point-in-time POST verification."""
        from .release_effect import record_post_release_verified
        return record_post_release_verified(self, signed_release)
