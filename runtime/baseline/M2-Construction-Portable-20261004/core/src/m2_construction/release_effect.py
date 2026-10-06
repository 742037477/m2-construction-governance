"""TEST_ONLY isolated release lease and single-consumption boundary.

The actual effect must be preceded by a fresh PRE_RELEASE_READONLY PASS and a
separate Root-signed, exact release lease. Neither a local audit nor a CEO
acceptance by itself authorizes copying files to a release target.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import time

from .artifacts import verify_frozen_candidate
from .contracts import (Denied, bytes_hash, canonical, digest, exact_fields,
                        hash_text, require, strict_json)
from .ledger import Ledger
from .pre_release import pre_release_readonly
from .trust import _b64, load_pin


def verify_signed_release(signed, *, pin_path, expected_pin_sha256, workspace):
    exact_fields(signed, "schema body signature_b64", "RELEASE_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_RELEASE_1",
            "RELEASE_ENVELOPE_SCHEMA")
    body = signed["body"]
    exact_fields(body, "schema trust_domain release_id parent_grant_id "
                       "parent_task_id parent_task_revision candidate_sha256 "
                       "review_sha256 ceo_acceptance_sha256 pre_release_sha256 "
                       "return_operation_id "
                       "return_files_sha256 target_root files not_before expires_at",
                 "RELEASE_BODY_FIELDS")
    require(body["schema"] == "M2_CONSTRUCTION_RELEASE_BODY_1" and
            body["trust_domain"] == "TEST_ONLY" and
            all(hash_text(body[name]) for name in (
                "candidate_sha256", "review_sha256", "ceo_acceptance_sha256",
                "return_files_sha256", "pre_release_sha256")) and
            type(body["not_before"]) is int and
            type(body["expires_at"]) is int and
            body["not_before"] < body["expires_at"] and
            type(body["target_root"]) is str and body["target_root"],
            "RELEASE_BODY")
    require(type(body["files"]) is list and
            0 < len(body["files"]) <= 100, "RELEASE_FILES")
    for item in body["files"]:
        exact_fields(item, "source destination sha256", "RELEASE_FILE_FIELDS")
        require(type(item["source"]) is str and
                type(item["destination"]) is str and
                hash_text(item["sha256"]), "RELEASE_FILE")
    pin, public = load_pin(pin_path, expected_pin_sha256, workspace)
    require(pin["trust_domain"] == body["trust_domain"], "RELEASE_DOMAIN")
    signature = _b64(signed["signature_b64"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(body))
    except InvalidSignature:
        raise Denied("RELEASE_SIGNATURE") from None
    return body


def _target_root(controller, value):
    from .controller import _no_link

    root = Path(value)
    require(root.is_absolute() and root.is_dir() and
            root.resolve(strict=True) == root,
            "RELEASE_TARGET_ROOT")
    _no_link(root)
    for protected in (controller.workspace, controller.state_dir):
        require(root != protected and root not in protected.parents and
                protected not in root.parents, "RELEASE_TARGET_OVERLAP")
    return root


def _target(root, relative, *, allow_missing):
    from .controller import _no_link, _relative

    pure = _relative(relative)
    current = root
    for index, part in enumerate(pure.parts):
        if os.name == "nt":
            require(part.rstrip(" .") == part and not os.path.isreserved(part),
                    "RELEASE_PATH_AMBIGUOUS")
        current = current / part
        if allow_missing and index == len(pure.parts) - 1 and not (
                current.exists() or current.is_symlink()):
            require(current.parent.resolve(strict=True) == current.parent and
                    current.parent.is_dir(), "RELEASE_PARENT_CHANGED")
            return current
        require(current.exists() or current.is_symlink(),
                "RELEASE_TARGET_MISSING")
        _no_link(current)
        if index < len(pure.parts) - 1:
            require(current.is_dir(), "RELEASE_PARENT_NOT_DIRECTORY")
    require(current.is_file() and root in current.resolve(strict=True).parents,
            "RELEASE_TARGET_FILE")
    return current


def _target_tree(root, destinations, *, completed):
    """Require an exact isolated directory tree, not just listed file hashes."""
    from .controller import _no_link

    expected_files = set(destinations)
    expected_dirs = set()
    for name in destinations:
        parts = name.split("/")
        expected_dirs.update("/".join(parts[:index])
                             for index in range(1, len(parts)))
    actual_files = set()
    actual_dirs = set()
    pending = [root]
    visited = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                require(visited <= len(expected_dirs) + len(expected_files),
                        "RELEASE_TARGET_EXTRA")
                path = Path(entry.path)
                _no_link(path)
                relative = path.relative_to(root).as_posix()
                if entry.is_dir(follow_symlinks=False):
                    require(relative in expected_dirs,
                            "RELEASE_TARGET_EXTRA")
                    actual_dirs.add(relative)
                    pending.append(path)
                else:
                    require(entry.is_file(follow_symlinks=False) and
                            relative in expected_files,
                            "RELEASE_TARGET_EXTRA")
                    actual_files.add(relative)
    require(actual_dirs == expected_dirs and
            actual_files == (expected_files if completed else set()),
            "RELEASE_TARGET_TREE")


def _latest_parent_freeze(db, body):
    freezes = []
    for (raw,) in db.execute("SELECT body_json FROM events ORDER BY seq"):
        event = strict_json(raw)
        if (event.get("kind") == "CANDIDATE_FROZEN" and
                event.get("grant_id") == body["parent_grant_id"] and
                event.get("task_id") == body["parent_task_id"] and
                event.get("task_revision") == body["parent_task_revision"]):
            freezes.append(event)
    require(freezes and freezes[-1].get("manifest_sha256") ==
            body["candidate_sha256"], "RELEASE_CANDIDATE_NOT_CURRENT")
    latest = freezes[-1]
    row = db.execute(
        "SELECT grant_id,task_id,kind,status,result_json FROM operations "
        "WHERE operation_id=?", (latest.get("operation_id"),)).fetchone()
    require(row is not None and row[:4] == (
        body["parent_grant_id"], body["parent_task_id"], "FREEZE",
        "COMPLETED"), "RELEASE_FREEZE_OPERATION")
    result = strict_json(row[4])
    require(result.get("manifest_path") == latest.get("manifest_path") and
            result.get("manifest_sha256") == body["candidate_sha256"],
            "RELEASE_FREEZE_OPERATION")
    return latest


def _snapshot(controller, manifest_path, body):
    manifest_path = Path(manifest_path)
    require(manifest_path.is_absolute() and manifest_path.is_file() and
            controller.state_dir in manifest_path.resolve(strict=True).parents,
            "RELEASE_MANIFEST_OUTSIDE_STATE")
    verify_frozen_candidate(manifest_path,
                            expected_manifest_sha256=body["candidate_sha256"])
    manifest = strict_json(manifest_path.read_bytes())
    require(manifest["root"] == str(controller.workspace),
            "RELEASE_WORKSPACE_BINDING")
    snapshot_root = Path(manifest["snapshot_root"])
    require(snapshot_root.is_absolute() and snapshot_root.is_dir() and
            controller.state_dir in snapshot_root.resolve(strict=True).parents,
            "RELEASE_SNAPSHOT_OUTSIDE_STATE")
    return manifest, snapshot_root


def consume_release(controller, signed, *, reviewer_pin_path,
                    expected_reviewer_pin_sha256, child_reviewer_pin_path,
                    expected_child_reviewer_pin_sha256, ceo_pin_path,
                    expected_ceo_pin_sha256, signed_review,
                    signed_ceo_acceptance):
    """Release one CEO-accepted frozen parent candidate to an isolated target."""
    from .controller import _no_link, _relative, _safe_name

    try:
        body = verify_signed_release(
            signed, pin_path=controller.pin_path,
            expected_pin_sha256=controller.expected_pin_sha256,
            workspace=controller.workspace)
        for field in ("release_id", "parent_grant_id", "parent_task_id",
                      "return_operation_id"):
            _safe_name(body[field])
        require(type(body["parent_task_revision"]) is int and
                body["parent_task_revision"] > 0, "RELEASE_TASK_BINDING")
        root = _target_root(controller, body["target_root"])
        sources = [item["source"] for item in body["files"]]
        destinations = [item["destination"] for item in body["files"]]
        for name in sources + destinations:
            _relative(name)
        path_key = (lambda name: name.casefold()) if os.name == "nt" else (lambda name: name)
        require(len({path_key(name) for name in sources}) == len(sources) and
                len({path_key(name) for name in destinations}) == len(destinations),
                "RELEASE_FILE_DUPLICATE")
        request_hash = digest({"schema": "M2_CONSTRUCTION_RELEASE_REQUEST_1",
                               "signed_release": signed,
                               "signed_review": signed_review,
                               "signed_ceo_acceptance": signed_ceo_acceptance})
        operation_id = body["release_id"]
        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            old = db.execute(
                "SELECT grant_id,task_id,kind,path,request_hash,status,"
                "after_sha256,result_json FROM operations WHERE operation_id=?",
                (operation_id,)).fetchone()
            if old:
                if old[:5] != (body["parent_grant_id"], body["parent_task_id"],
                               "RELEASE", str(root), request_hash):
                    return {"status": "CONFLICT",
                            "reason": "OPERATION_ID_DIFFERENT_REQUEST"}
                if old[5] == "COMPLETED":
                    result = strict_json(old[7])
                    expected_files = {item["destination"]: item["sha256"]
                                      for item in body["files"]}
                    require(canonical(result).decode("utf-8") == old[7] and
                            result.get("status") == "COMPLETED" and
                            result.get("operation_id") == operation_id and
                            result.get("authority") == "TEST_ONLY_RELEASE" and
                            result.get("candidate_sha256") ==
                            body["candidate_sha256"] and
                            result.get("target_root") == str(root) and
                            result.get("pre_release_sha256") ==
                            body["pre_release_sha256"] and
                            result.get("files") == expected_files and
                            result.get("files_sha256") == old[6] ==
                            digest(expected_files),
                            "RELEASE_PRIOR_RECEIPT")
                    entries = [(seq, strict_json(raw)) for seq, raw in db.execute(
                        "SELECT seq,body_json FROM events ORDER BY seq")]
                    def matching(kind):
                        return [(seq, event) for seq, event in entries
                                if event.get("kind") == kind and
                                event.get("operation_id") == operation_id]
                    gate, intent, receipt, consumed = (matching(kind) for kind in
                        ("GATE_ALLOW", "RELEASE_INTENT", "RECEIPT",
                         "RELEASE_CONSUMED"))
                    require(all(len(group) == 1 for group in
                                (gate, intent, receipt, consumed)) and
                            gate[0][0] < intent[0][0] < receipt[0][0] <
                            consumed[0][0] and
                            gate[0][1].get("request_hash") == request_hash and
                            intent[0][1].get("signed_release") == signed and
                            intent[0][1].get("signed_review") == signed_review and
                            intent[0][1].get("candidate_sha256") ==
                            body["candidate_sha256"] and
                            intent[0][1].get("target_root") == str(root) and
                            intent[0][1].get("pre_release_sha256") ==
                            body["pre_release_sha256"] and
                            receipt[0][1].get("request_hash") == request_hash and
                            receipt[0][1].get("actual_sha256") == old[6] and
                            consumed[0][1].get("candidate_sha256") ==
                            body["candidate_sha256"] and
                            consumed[0][1].get("target_root") == str(root) and
                            consumed[0][1].get("files_sha256") == old[6] and
                            consumed[0][1].get("pre_release_sha256") ==
                            body["pre_release_sha256"] and
                            consumed[0][1].get("authority") ==
                            "TEST_ONLY_RELEASE", "RELEASE_PRIOR_EVENT")
                    for name, actual_hash in result["files"].items():
                        require(bytes_hash(_target(root, name,
                                                   allow_missing=False).read_bytes()) ==
                                actual_hash, "RELEASE_RESULT_CHANGED")
                    _target_tree(root, destinations, completed=True)
                    return {**result, "effect_executed": False}
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "effect_executed": False, "new_dispatch": False}
            require(body["not_before"] <= int(time.time()) <
                    body["expires_at"], "RELEASE_EXPIRED")
            controller._current_scope(db, body["parent_grant_id"],
                                      body["parent_task_id"],
                                      body["parent_task_revision"])
            _target_tree(root, destinations, completed=False)
            freeze = _latest_parent_freeze(db, body)
            manifest_path = Path(freeze["manifest_path"])

        pre = pre_release_readonly(
            ledger_path=controller.ledger.path,
            workspace=controller.workspace, state_dir=controller.state_dir,
            root_pin_path=controller.pin_path,
            expected_root_pin_sha256=controller.expected_pin_sha256,
            reviewer_pin_path=reviewer_pin_path,
            expected_reviewer_pin_sha256=expected_reviewer_pin_sha256,
            child_reviewer_pin_path=child_reviewer_pin_path,
            expected_child_reviewer_pin_sha256=
            expected_child_reviewer_pin_sha256,
            ceo_pin_path=ceo_pin_path,
            expected_ceo_pin_sha256=expected_ceo_pin_sha256,
            grant_id=body["parent_grant_id"],
            task_id=body["parent_task_id"],
            task_revision=body["parent_task_revision"],
            manifest_path=manifest_path,
            expected_manifest_sha256=body["candidate_sha256"],
            signed_review=signed_review,
            signed_ceo_acceptance=signed_ceo_acceptance)
        require(pre["status"] == "PASS" and
                pre.get("candidate_sha256") == body["candidate_sha256"] and
                pre.get("review_sha256") == body["review_sha256"] and
                pre.get("ceo_acceptance_sha256") ==
                body["ceo_acceptance_sha256"] and
                pre.get("pre_release_sha256") ==
                body["pre_release_sha256"] and
                pre.get("internal_return_operation_id") ==
                body["return_operation_id"] and
                pre.get("internal_return_files_sha256") ==
                body["return_files_sha256"],
                "RELEASE_PRE_REQUIRED")

        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            require(body["not_before"] <= int(time.time()) < body["expires_at"],
                    "RELEASE_EXPIRED")
            parent = controller._current_scope(db, body["parent_grant_id"],
                                               body["parent_task_id"],
                                               body["parent_task_revision"])
            head = db.execute("SELECT seq,event_hash FROM events ORDER BY seq "
                              "DESC LIMIT 1").fetchone()
            require(head == (pre["ledger_head_seq"],
                             pre["ledger_head_event_hash"]),
                    "RELEASE_PRE_STALE")
            freeze = _latest_parent_freeze(db, body)
            require(freeze["manifest_path"] == str(manifest_path),
                    "RELEASE_FREEZE_CHANGED")
            manifest, snapshot_root = _snapshot(controller, manifest_path,
                                                body)
            _target_tree(root, destinations, completed=False)
            require(set(sources) == set(manifest["files"]),
                    "RELEASE_PARTIAL_CANDIDATE")
            for item in body["files"]:
                require(manifest["files"][item["source"]]["sha256"] ==
                        item["sha256"], "RELEASE_FILE_HASH")
                target = _target(root, item["destination"], allow_missing=True)
                require(not target.exists(), "RELEASE_TARGET_EXISTS")
            for (raw,) in db.execute("SELECT body_json FROM events ORDER BY seq"):
                event = strict_json(raw)
                require(not (event.get("kind") == "RELEASE_INTENT" and
                             (event.get("candidate_sha256") ==
                              body["candidate_sha256"] or
                              event.get("target_root") == str(root))),
                        "RELEASE_ALREADY_RESERVED")
            used = db.execute("SELECT COUNT(*),COALESCE(SUM(content_size),0) "
                              "FROM operations WHERE grant_id=?",
                              (body["parent_grant_id"],)).fetchone()
            size = sum(manifest["files"][source]["size"] for source in sources)
            require(used[0] < parent["max_operations"] and
                    all(manifest["files"][source]["size"] <=
                        parent["max_patch_bytes"] for source in sources) and
                    used[1] + size <=
                    parent["max_operations"] * parent["max_patch_bytes"],
                    "RELEASE_BUDGET")
            db.execute(
                "INSERT INTO operations(operation_id,grant_id,task_id,kind,path,"
                "request_hash,content_size,status,before_sha256) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (operation_id, body["parent_grant_id"],
                 body["parent_task_id"], "RELEASE", str(root),
                 request_hash, size, "INTENT", "ABSENT"))
            controller.ledger.event(db, {
                "kind": "GATE_ALLOW", "operation_id": operation_id,
                "grant_id": body["parent_grant_id"],
                "request_hash": request_hash})
            controller.ledger.event(db, {
                "kind": "RELEASE_INTENT", "operation_id": operation_id,
                "parent_grant_id": body["parent_grant_id"],
                "parent_task_id": body["parent_task_id"],
                "parent_task_revision": body["parent_task_revision"],
                "candidate_sha256": body["candidate_sha256"],
                "target_root": str(root),
                "pre_release_sha256": pre["pre_release_sha256"],
                "ceo_acceptance_sha256": body["ceo_acceptance_sha256"],
                "signed_release": signed, "signed_review": signed_review})
        try:
            with controller.ledger.transaction() as db:
                controller.ledger.verify_chain(db)
                require(body["not_before"] <= int(time.time()) <
                        body["expires_at"], "RELEASE_EXPIRED")
                controller._current_scope(db, body["parent_grant_id"],
                                          body["parent_task_id"],
                                          body["parent_task_revision"])
                _snapshot(controller, manifest_path, body)
                require(_target_root(controller, body["target_root"]) == root,
                        "RELEASE_TARGET_CHANGED")
                _target_tree(root, destinations, completed=False)
                actual = {}
                for item in sorted(body["files"],
                                   key=lambda entry: entry["destination"]):
                    source = snapshot_root.joinpath(*item["source"].split("/"))
                    raw = source.read_bytes()
                    require(bytes_hash(raw) == item["sha256"],
                            "RELEASE_SOURCE_CHANGED")
                    target = _target(root, item["destination"],
                                     allow_missing=True)
                    require(not target.exists(), "RELEASE_TARGET_CHANGED")
                    _no_link(target.parent)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(
                        os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(target, flags, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    observed = bytes_hash(_target(root, item["destination"],
                                                  allow_missing=False).read_bytes())
                    require(observed == item["sha256"],
                            "RELEASE_EFFECT_UNCERTAIN")
                    actual[item["destination"]] = observed
                _target_tree(root, destinations, completed=True)
                verify_frozen_candidate(
                    manifest_path,
                    expected_manifest_sha256=body["candidate_sha256"])
                files_sha = digest(actual)
                result = {
                    "status": "COMPLETED", "operation_id": operation_id,
                    "authority": "TEST_ONLY_RELEASE",
                    "candidate_sha256": body["candidate_sha256"],
                    "target_root": str(root), "files": actual,
                    "files_sha256": files_sha,
                    "pre_release_sha256": pre["pre_release_sha256"],
                    "effect_executed": True,
                }
                cursor = db.execute(
                    "UPDATE operations SET status='COMPLETED',after_sha256=?,"
                    "result_json=? WHERE operation_id=? AND status='INTENT'",
                    (files_sha, canonical(result).decode("utf-8"),
                     operation_id))
                require(cursor.rowcount == 1, "RELEASE_RECEIPT_RACE")
                controller.ledger.event(db, {
                    "kind": "RECEIPT", "operation_id": operation_id,
                    "request_hash": request_hash, "actual_sha256": files_sha})
                controller.ledger.event(db, {
                    "kind": "RELEASE_CONSUMED", "operation_id": operation_id,
                    "parent_task_id": body["parent_task_id"],
                    "candidate_sha256": body["candidate_sha256"],
                    "target_root": str(root), "files_sha256": files_sha,
                    "pre_release_sha256": pre["pre_release_sha256"],
                    "authority": "TEST_ONLY_RELEASE"})
            return result
        except BaseException:
            with controller.ledger.transaction() as db:
                controller.ledger.verify_chain(db)
                db.execute("UPDATE operations SET status='UNKNOWN' "
                           "WHERE operation_id=? AND status='INTENT'",
                           (operation_id,))
                controller.ledger.event(db, {"kind": "UNKNOWN",
                                             "operation_id": operation_id})
            return {"status": "UNKNOWN", "operation_id": operation_id,
                    "effect_executed": None, "new_dispatch": True}
    except (Denied, KeyError, IndexError, TypeError, ValueError, OSError) as exc:
        return {"status": "DENIED", "reason": str(exc),
                "effect_executed": False}


def post_release_readonly(*, ledger_path, workspace, state_dir, root_pin_path,
                          expected_root_pin_sha256, signed_release):
    """Independently compare one completed isolated effect to its ledger proof."""
    result = {"status": "INDETERMINATE", "reason": "UNVERIFIED",
              "dispatch_allowed": False}
    try:
        workspace = Path(workspace).resolve(strict=True)
        state_dir = Path(state_dir).resolve(strict=True)
        ledger_path = Path(ledger_path)
        require(ledger_path == state_dir / "construction.sqlite3" and
                ledger_path.is_file() and
                ledger_path.resolve(strict=True) == ledger_path,
                "POST_LEDGER_PATH")
        body = verify_signed_release(
            signed_release, pin_path=root_pin_path,
            expected_pin_sha256=expected_root_pin_sha256,
            workspace=workspace)
        class _Roots:
            pass
        roots = _Roots()
        roots.workspace = workspace
        roots.state_dir = state_dir
        target_root = _target_root(roots, body["target_root"])
        with closing(sqlite3.connect(ledger_path.as_uri() + "?mode=ro",
                                     uri=True, isolation_level=None)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            Ledger.verify_chain(db)
            head = db.execute("SELECT seq,event_hash FROM events "
                              "ORDER BY seq DESC LIMIT 1").fetchone()
            rows = [strict_json(raw) for (raw,) in db.execute(
                "SELECT body_json FROM events ORDER BY seq")]
            intent = [item for item in rows if
                      item.get("kind") == "RELEASE_INTENT" and
                      item.get("operation_id") == body["release_id"]]
            consumed = [item for item in rows if
                        item.get("kind") == "RELEASE_CONSUMED" and
                        item.get("operation_id") == body["release_id"]]
            require(len(intent) == len(consumed) == 1 and
                    intent[0].get("signed_release") == signed_release and
                    consumed[0].get("candidate_sha256") ==
                    body["candidate_sha256"] and
                    consumed[0].get("target_root") == str(target_root),
                    "POST_RELEASE_EVENTS")
            accepted = [item for item in rows if
                        item.get("kind") == "CEO_ACCEPTED" and
                        item.get("ceo_acceptance_sha256") ==
                        body["ceo_acceptance_sha256"]]
            require(len(accepted) == 1 and
                    accepted[0].get("grant_id") ==
                    body["parent_grant_id"] and
                    accepted[0].get("task_id") ==
                    body["parent_task_id"] and
                    accepted[0].get("task_revision") ==
                    body["parent_task_revision"] and
                    accepted[0].get("manifest_sha256") ==
                    body["candidate_sha256"], "POST_CEO_BINDING")
            request_hash = digest({
                "schema": "M2_CONSTRUCTION_RELEASE_REQUEST_1",
                "signed_release": signed_release,
                "signed_review": intent[0].get("signed_review"),
                "signed_ceo_acceptance": accepted[0].get("signed_acceptance"),
            })
            receipts = [item for item in rows if
                        item.get("kind") == "RECEIPT" and
                        item.get("operation_id") == body["release_id"]]
            require(len(receipts) == 1 and
                    receipts[0].get("request_hash") == request_hash and
                    intent[0].get("ceo_acceptance_sha256") ==
                    body["ceo_acceptance_sha256"] and
                    consumed[0].get("pre_release_sha256") ==
                    body["pre_release_sha256"], "POST_RECEIPT_BINDING")
            row = db.execute(
                "SELECT grant_id,task_id,kind,path,request_hash,status,"
                "after_sha256,result_json FROM operations WHERE operation_id=?",
                (body["release_id"],)).fetchone()
            require(row is not None and row[:4] == (
                body["parent_grant_id"], body["parent_task_id"],
                "RELEASE", str(target_root)) and
                row[4] == request_hash and row[5] == "COMPLETED" and
                receipts[0].get("actual_sha256") == row[6],
                "POST_RELEASE_OPERATION")
            stored = strict_json(row[7])
            require(stored.get("authority") == "TEST_ONLY_RELEASE" and
                    stored.get("candidate_sha256") ==
                    body["candidate_sha256"] and
                    stored.get("pre_release_sha256") ==
                    body["pre_release_sha256"] and
                    stored.get("files_sha256") == row[6] ==
                    consumed[0].get("files_sha256") and
                    intent[0].get("pre_release_sha256") ==
                    body["pre_release_sha256"] and
                    type(stored.get("files")) is dict and
                    digest(stored["files"]) == row[6],
                    "POST_RELEASE_BINDING")
            require(stored["files"] == {
                item["destination"]: item["sha256"] for item in body["files"]},
                "POST_RELEASE_FILES")
            for item in body["files"]:
                require(bytes_hash(_target(target_root, item["destination"],
                                           allow_missing=False).read_bytes()) ==
                        item["sha256"], "POST_RELEASE_BYTES_CHANGED")
            _target_tree(target_root, [item["destination"] for item in
                                       body["files"]], completed=True)
        with closing(sqlite3.connect(ledger_path.as_uri() + "?mode=ro",
                                     uri=True, isolation_level=None)) as fresh:
            fresh.execute("PRAGMA query_only=ON")
            current = fresh.execute("SELECT seq,event_hash FROM events "
                                    "ORDER BY seq DESC LIMIT 1").fetchone()
            require(current == head, "POST_LEDGER_CHANGED")
        return {"status": "VERIFIED", "reason": "POST_RELEASE_MATCHED",
                "dispatch_allowed": False,
                "candidate_sha256": body["candidate_sha256"],
                "release_id": body["release_id"],
                "files_sha256": stored["files_sha256"],
                "target_root": str(target_root),
                "ledger_head_seq": head[0],
                "ledger_head_event_hash": head[1]}
    except (Denied, KeyError, IndexError, TypeError, ValueError, OSError,
            sqlite3.Error) as exc:
        return {"status": "FAIL" if isinstance(exc, Denied)
                else "INDETERMINATE", "reason": str(exc),
                "dispatch_allowed": False}


def record_post_release_verified(controller, signed_release):
    """Record a point-in-time POST check; never claim permanent target control."""
    try:
        verdict = post_release_readonly(
            ledger_path=controller.ledger.path,
            workspace=controller.workspace, state_dir=controller.state_dir,
            root_pin_path=controller.pin_path,
            expected_root_pin_sha256=controller.expected_pin_sha256,
            signed_release=signed_release)
        require(verdict["status"] == "VERIFIED", "POST_REQUIRED")
        body = verify_signed_release(
            signed_release, pin_path=controller.pin_path,
            expected_pin_sha256=controller.expected_pin_sha256,
            workspace=controller.workspace)
        root = _target_root(controller, body["target_root"])
        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            head = db.execute("SELECT seq,event_hash FROM events ORDER BY seq "
                              "DESC LIMIT 1").fetchone()
            require(head == (verdict["ledger_head_seq"],
                             verdict["ledger_head_event_hash"]),
                    "POST_SOURCE_CHANGED")
            for item in body["files"]:
                require(bytes_hash(_target(root, item["destination"],
                                           allow_missing=False).read_bytes()) ==
                        item["sha256"], "POST_TARGET_CHANGED")
            _target_tree(root, [item["destination"] for item in body["files"]],
                         completed=True)
            existing = []
            for (raw,) in db.execute("SELECT body_json FROM events ORDER BY seq"):
                event = strict_json(raw)
                if (event.get("kind") == "POST_RELEASE_VERIFIED" and
                        event.get("release_id") == body["release_id"]):
                    existing.append(event)
            if existing:
                require(len(existing) == 1 and
                        existing[0].get("candidate_sha256") ==
                        body["candidate_sha256"] and
                        existing[0].get("files_sha256") ==
                        verdict["files_sha256"] and
                        existing[0].get("target_root") == str(root),
                        "POST_PRIOR_CHANGED")
                return {"status": "VERIFIED", "release_id": body["release_id"],
                        "files_sha256": verdict["files_sha256"],
                        "dispatch_allowed": False, "effect_executed": False}
            controller.ledger.event(db, {
                "kind": "POST_RELEASE_VERIFIED",
                "release_id": body["release_id"],
                "candidate_sha256": body["candidate_sha256"],
                "files_sha256": verdict["files_sha256"],
                "target_root": str(root),
                "verified_source_head_seq": verdict["ledger_head_seq"],
                "verified_source_head_hash": verdict["ledger_head_event_hash"],
                "trust_domain": "TEST_ONLY"})
        return {"status": "VERIFIED", "release_id": body["release_id"],
                "files_sha256": verdict["files_sha256"],
                "dispatch_allowed": False, "effect_executed": True}
    except (Denied, KeyError, IndexError, TypeError, ValueError, OSError,
            sqlite3.Error) as exc:
        return {"status": "DENIED", "reason": str(exc),
                "dispatch_allowed": False, "effect_executed": False}
