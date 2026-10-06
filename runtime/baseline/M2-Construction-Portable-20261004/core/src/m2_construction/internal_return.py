"""Verify a TEST_ONLY Root instruction for one child-to-parent internal return.

This signature is separate from the read-only local verdict. Neither a GO
review nor a PASS verdict alone grants an effect or release permission.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import os
from pathlib import Path
import time

from .artifacts import verify_frozen_candidate
from .contracts import (Denied, bytes_hash, canonical, digest, exact_fields,
                        hash_text, require, strict_json)
from .trust import _b64, load_pin


def verify_signed_return(signed, *, pin_path, expected_pin_sha256, workspace):
    exact_fields(signed, "schema body signature_b64", "RETURN_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_RETURN_1",
            "RETURN_ENVELOPE_SCHEMA")
    body = signed["body"]
    exact_fields(body, "schema trust_domain return_id child_grant_id child_task_id "
                       "child_task_revision parent_grant_id parent_task_id "
                       "parent_task_revision candidate_sha256 review_sha256 files "
                       "not_before expires_at", "RETURN_BODY_FIELDS")
    require(body["schema"] == "M2_CONSTRUCTION_RETURN_BODY_1" and
            body["trust_domain"] == "TEST_ONLY" and
            hash_text(body["candidate_sha256"]) and
            hash_text(body["review_sha256"]) and
            type(body["not_before"]) is int and
            type(body["expires_at"]) is int and
            body["not_before"] < body["expires_at"], "RETURN_BODY")
    require(type(body["files"]) is list and
            0 < len(body["files"]) <= 100, "RETURN_FILES")
    for item in body["files"]:
        exact_fields(item, "source destination sha256", "RETURN_FILE_FIELDS")
        require(type(item["source"]) is str and
                type(item["destination"]) is str and
                hash_text(item["sha256"]), "RETURN_FILE")
    pin, public = load_pin(pin_path, expected_pin_sha256, workspace)
    require(pin["trust_domain"] == body["trust_domain"], "RETURN_DOMAIN")
    signature = _b64(signed["signature_b64"], 64)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(body))
    except InvalidSignature:
        raise Denied("RETURN_SIGNATURE") from None
    return body


def _latest_freeze(db, body):
    freezes = []
    for (raw,) in db.execute("SELECT body_json FROM events ORDER BY seq"):
        event = strict_json(raw)
        if (event.get("kind") == "CANDIDATE_FROZEN" and
                event.get("grant_id") == body["child_grant_id"] and
                event.get("task_id") == body["child_task_id"] and
                event.get("task_revision") == body["child_task_revision"]):
            freezes.append(event)
    require(freezes and freezes[-1].get("manifest_sha256") ==
            body["candidate_sha256"], "RETURN_CANDIDATE_NOT_CURRENT")
    latest = freezes[-1]
    row = db.execute(
        "SELECT grant_id,task_id,kind,status,result_json FROM operations "
        "WHERE operation_id=?", (latest.get("operation_id"),)).fetchone()
    require(row is not None and row[:4] == (
        body["child_grant_id"], body["child_task_id"], "FREEZE", "COMPLETED"),
        "RETURN_FREEZE_OPERATION")
    result = strict_json(row[4])
    require(result.get("manifest_path") == latest.get("manifest_path") and
            result.get("manifest_sha256") == body["candidate_sha256"],
            "RETURN_FREEZE_OPERATION")
    return latest


def _frozen_files(controller, manifest_path, body):
    manifest_path = Path(manifest_path)
    require(manifest_path.is_absolute() and manifest_path.is_file() and
            controller.state_dir in manifest_path.resolve(strict=True).parents,
            "RETURN_MANIFEST_OUTSIDE_STATE")
    verify_frozen_candidate(manifest_path,
                            expected_manifest_sha256=body["candidate_sha256"])
    manifest = strict_json(manifest_path.read_bytes())
    require(manifest["root"] == str(controller.workspace),
            "RETURN_WORKSPACE_BINDING")
    snapshot_root = Path(manifest["snapshot_root"])
    require(snapshot_root.is_absolute() and snapshot_root.is_dir() and
            controller.state_dir in snapshot_root.resolve(strict=True).parents,
            "RETURN_SNAPSHOT_OUTSIDE_STATE")
    return manifest, snapshot_root


def consume_internal_return(controller, signed, *, signed_review,
                            reviewer_pin_path, expected_reviewer_pin_sha256):
    """Consume one independently reviewed candidate into one signed parent.

    Exact copied bytes and evidence remain INTERNAL_PARENT_ONLY. The source
    review is eligibility; the separate Root return contract and current parent
    grant authorize this effect. A post-INTENT uncertainty never auto-replays.
    """
    from .adjudication import local_adjudicate
    from .controller import _no_link, _relative, _safe_name

    try:
        body = verify_signed_return(
            signed, pin_path=controller.pin_path,
            expected_pin_sha256=controller.expected_pin_sha256,
            workspace=controller.workspace)
        for field in ("return_id", "child_grant_id", "child_task_id",
                      "parent_grant_id", "parent_task_id"):
            _safe_name(body[field])
        require(type(body["child_task_revision"]) is int and
                body["child_task_revision"] > 0 and
                type(body["parent_task_revision"]) is int and
                body["parent_task_revision"] > 0 and
                (body["child_grant_id"], body["child_task_id"]) !=
                (body["parent_grant_id"], body["parent_task_id"]),
                "RETURN_TASK_BINDING")
        require(body["not_before"] <= int(time.time()) < body["expires_at"],
                "RETURN_EXPIRED")
        sources = [item["source"] for item in body["files"]]
        destinations = [item["destination"] for item in body["files"]]
        for path in sources + destinations:
            _relative(path)
        require(len(set(sources)) == len(sources) and
                len(set(destinations)) == len(destinations) and
                set(sources).isdisjoint(destinations), "RETURN_FILE_DUPLICATE")

        # Preflight only reads. The final write transaction rechecks the same
        # bindings after the read-only adjudicator returns PASS.
        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            require(body["not_before"] <= int(time.time()) < body["expires_at"],
                    "RETURN_EXPIRED")
            controller._current_scope(db, body["child_grant_id"],
                                      body["child_task_id"],
                                      body["child_task_revision"])
            controller._current_scope(db, body["parent_grant_id"],
                                      body["parent_task_id"],
                                      body["parent_task_revision"])
            freeze = _latest_freeze(db, body)
            manifest_path = Path(freeze["manifest_path"])
        verdict = local_adjudicate(
            ledger_path=controller.ledger.path,
            workspace=controller.workspace, state_dir=controller.state_dir,
            root_pin_path=controller.pin_path,
            expected_root_pin_sha256=controller.expected_pin_sha256,
            reviewer_pin_path=reviewer_pin_path,
            expected_reviewer_pin_sha256=expected_reviewer_pin_sha256,
            grant_id=body["child_grant_id"], task_id=body["child_task_id"],
            task_revision=body["child_task_revision"],
            manifest_path=manifest_path,
            expected_manifest_sha256=body["candidate_sha256"],
            signed_review=signed_review)
        require(verdict["status"] == "PASS" and
                verdict.get("candidate_sha256") == body["candidate_sha256"] and
                verdict.get("review_sha256") == body["review_sha256"],
                "RETURN_LOCAL_VERDICT_REQUIRED")

        request_hash = digest({"schema": "M2_CONSTRUCTION_RETURN_REQUEST_1",
                               "signed_return": signed,
                               "signed_review": signed_review})
        operation_id = body["return_id"]
        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            require(body["not_before"] <= int(time.time()) < body["expires_at"],
                    "RETURN_EXPIRED")
            controller._current_scope(db, body["child_grant_id"],
                                      body["child_task_id"],
                                      body["child_task_revision"])
            parent = controller._current_scope(db, body["parent_grant_id"],
                                               body["parent_task_id"],
                                               body["parent_task_revision"])
            require(parent["schema"] == "M2_CONSTRUCTION_SCOPE_3" and
                    "CREATE" in parent["allowed_effects"], "RETURN_PARENT_SCOPE")
            freeze = _latest_freeze(db, body)
            require(freeze["manifest_path"] == str(manifest_path),
                    "RETURN_FREEZE_CHANGED")
            manifest, snapshot_root = _frozen_files(controller, manifest_path,
                                                    body)
            require(set(sources) == set(manifest["files"]),
                    "RETURN_PARTIAL_CANDIDATE")
            require(set(destinations) <= set(parent["creatable_files"]),
                    "RETURN_PARENT_FILES")
            old = db.execute(
                "SELECT grant_id,task_id,kind,request_hash,status,after_sha256,"
                "result_json FROM operations WHERE operation_id=?",
                (operation_id,)).fetchone()
            if old:
                if old[:4] != (body["parent_grant_id"], body["parent_task_id"],
                               "INTERNAL_RETURN", request_hash):
                    return {"status": "CONFLICT",
                            "reason": "OPERATION_ID_DIFFERENT_REQUEST"}
                if old[4] == "COMPLETED":
                    result = strict_json(old[6])
                    for item in body["files"]:
                        target = controller._target(item["destination"])
                        require(bytes_hash(target.read_bytes()) == item["sha256"],
                                "RETURN_RESULT_CHANGED")
                    return {**result, "effect_executed": False}
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "effect_executed": False, "new_dispatch": False}
            for (raw,) in db.execute("SELECT body_json FROM events ORDER BY seq"):
                event = strict_json(raw)
                require(not (event.get("kind") == "INTERNAL_RETURN_INTENT" and
                             event.get("child_grant_id") == body["child_grant_id"] and
                             event.get("child_task_id") == body["child_task_id"] and
                             event.get("child_task_revision") ==
                             body["child_task_revision"] and
                             event.get("candidate_sha256") ==
                             body["candidate_sha256"]),
                        "RETURN_ALREADY_RESERVED")
            used = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(content_size),0) FROM operations "
                "WHERE grant_id=?", (body["parent_grant_id"],)).fetchone()
            content_size = sum(manifest["files"][source]["size"]
                               for source in sources)
            require(used[0] < parent["max_operations"] and
                    all(manifest["files"][source]["size"] <=
                        parent["max_patch_bytes"] for source in sources) and
                    used[1] + content_size <=
                    parent["max_operations"] * parent["max_patch_bytes"],
                    "RETURN_PARENT_BUDGET")
            keys = {}
            for item in body["files"]:
                source = item["source"]
                destination = item["destination"]
                record = manifest["files"][source]
                require(record["sha256"] == item["sha256"],
                        "RETURN_FILE_HASH")
                source_target = controller._target(source)
                destination_target = controller._target(destination,
                                                        allow_missing=True)
                require(not destination_target.exists(),
                        "RETURN_TARGET_EXISTS")
                for path, target in ((source, source_target),
                                     (destination, destination_target)):
                    key = controller._resource_key(path, target)
                    require(key not in keys.values() and
                            not controller._resource_busy(db, key, target),
                            "RETURN_RESOURCE_BUSY")
                    keys[path] = key
            db.execute(
                "INSERT INTO operations(operation_id,grant_id,task_id,kind,path,"
                "request_hash,content_size,status,before_sha256) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (operation_id, body["parent_grant_id"],
                 body["parent_task_id"], "INTERNAL_RETURN", ".",
                 request_hash, content_size, "INTENT", body["candidate_sha256"]))
            for key in keys.values():
                db.execute("INSERT INTO resource_locks(path,operation_id) "
                           "VALUES(?,?)", (key, operation_id))
            controller.ledger.event(db, {"kind": "GATE_ALLOW",
                                         "operation_id": operation_id,
                                         "grant_id": body["parent_grant_id"],
                                         "request_hash": request_hash})
            controller.ledger.event(db, {
                "kind": "INTERNAL_RETURN_INTENT", "operation_id": operation_id,
                "child_grant_id": body["child_grant_id"],
                "child_task_id": body["child_task_id"],
                "child_task_revision": body["child_task_revision"],
                "parent_grant_id": body["parent_grant_id"],
                "parent_task_id": body["parent_task_id"],
                "parent_task_revision": body["parent_task_revision"],
                "candidate_sha256": body["candidate_sha256"],
                "review_sha256": body["review_sha256"],
                "signed_return": signed, "signed_review": signed_review})
        try:
            # A second write transaction prevents a concurrent revocation or
            # parent operation from interleaving with this bounded file effect.
            # The committed INTENT still survives a crash in this transaction.
            with controller.ledger.transaction() as db:
                controller.ledger.verify_chain(db)
                require(body["not_before"] <= int(time.time()) < body["expires_at"],
                        "RETURN_EXPIRED")
                controller._current_scope(db, body["child_grant_id"],
                                          body["child_task_id"],
                                          body["child_task_revision"])
                controller._current_scope(db, body["parent_grant_id"],
                                          body["parent_task_id"],
                                          body["parent_task_revision"])
                _frozen_files(controller, manifest_path, body)
                actual = {}
                for item in sorted(body["files"],
                                   key=lambda entry: entry["destination"]):
                    source = snapshot_root.joinpath(*item["source"].split("/"))
                    raw = source.read_bytes()
                    require(bytes_hash(raw) == item["sha256"],
                            "RETURN_SOURCE_CHANGED")
                    target = controller._target(item["destination"],
                                                allow_missing=True)
                    require(not target.exists(), "RETURN_TARGET_CHANGED")
                    _no_link(target.parent)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(
                        os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(target, flags, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    observed = bytes_hash(controller._target(
                        item["destination"]).read_bytes())
                    require(observed == item["sha256"], "RETURN_EFFECT_UNCERTAIN")
                    actual[item["destination"]] = observed
                verify_frozen_candidate(
                    manifest_path,
                    expected_manifest_sha256=body["candidate_sha256"])
                after_hash = digest(actual)
                result = {"status": "COMPLETED", "operation_id": operation_id,
                          "authority": "INTERNAL_PARENT_ONLY",
                          "parent_task_id": body["parent_task_id"],
                          "candidate_sha256": body["candidate_sha256"],
                          "review_sha256": body["review_sha256"],
                          "files": actual, "files_sha256": after_hash,
                          "effect_executed": True}
                cursor = db.execute(
                    "UPDATE operations SET status='COMPLETED',after_sha256=?,"
                    "result_json=? WHERE operation_id=? AND status='INTENT'",
                    (after_hash, canonical(result).decode("utf-8"), operation_id))
                require(cursor.rowcount == 1, "RETURN_RECEIPT_RACE")
                for key in keys.values():
                    db.execute("DELETE FROM resource_locks WHERE path=? "
                               "AND operation_id=?", (key, operation_id))
                controller.ledger.event(db, {
                    "kind": "RECEIPT", "operation_id": operation_id,
                    "request_hash": request_hash, "actual_sha256": after_hash})
                controller.ledger.event(db, {
                    "kind": "INTERNAL_RETURN_CONSUMED",
                    "operation_id": operation_id,
                    "child_task_id": body["child_task_id"],
                    "parent_task_id": body["parent_task_id"],
                    "candidate_sha256": body["candidate_sha256"],
                    "review_sha256": body["review_sha256"],
                    "files_sha256": after_hash,
                    "authority": "INTERNAL_PARENT_ONLY"})
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
