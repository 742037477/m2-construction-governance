"""TEST_ONLY CEO acceptance and read-only eligibility for a parent candidate.

This module has no signing key and cannot release files. A PASS binds the
latest parent freeze, current parent review, and one consumed child return.
The later effect gate must recheck all bindings against current state.
"""

from contextlib import closing
import base64
from pathlib import Path
import sqlite3
import stat
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .adjudication import (_author, _freeze_and_receipts, _read_events, _scope,
                           local_adjudicate)
from .artifacts import verify_frozen_candidate
from .contracts import (Denied, bytes_hash, canonical, digest, exact_fields,
                        hash_text, require, strict_json)
from .internal_return import verify_signed_return
from .review import _public_pin, verify_review_proof
from .trust import load_pin, verify_signed_scope


_INDETERMINATE = {"RETURN_MISSING", "RETURN_UNKNOWN", "CHILD_FREEZE_MISSING",
                  "LEDGER_CHANGED", "PARENT_FREEZE_MISSING",
                  "CEO_ACCEPTANCE_MISSING"}


def _external_pin(path, expected_sha256, workspace, state_dir):
    require(hash_text(expected_sha256), "CEO_PIN_HASH")
    path = Path(path)
    require(path.is_absolute() and path.is_file(), "CEO_PIN_MISSING")
    resolved = path.resolve(strict=True)
    require(path == resolved and workspace not in resolved.parents and
            state_dir not in resolved.parents and
            resolved not in (workspace, state_dir), "CEO_PIN_LOCATION")
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not (getattr(info, "st_file_attributes", 0) &
                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
            "CEO_PIN_LINK")
    raw = path.read_bytes()
    require(bytes_hash(raw) == expected_sha256, "CEO_PIN_CHANGED")
    pin = strict_json(raw)
    require(canonical(pin) == raw, "CEO_PIN_CANONICAL")
    exact_fields(pin, "schema trust_domain public_key_b64 fingerprint",
                 "CEO_PIN_FIELDS")
    require(pin["schema"] == "M2_CONSTRUCTION_CEO_PIN_1" and
            pin["trust_domain"] == "TEST_ONLY", "CEO_PIN_DOMAIN")
    require(type(pin["public_key_b64"]) is str, "CEO_PIN_KEY")
    try:
        public = base64.b64decode(pin["public_key_b64"], validate=True)
    except (ValueError, base64.binascii.Error):
        raise Denied("CEO_PIN_KEY") from None
    require(len(public) == 32 and pin["fingerprint"] == bytes_hash(public),
            "CEO_PIN_KEY")
    return pin, public


def _verify_role_binding(signed, *, root_pin_path, expected_root_pin_sha256,
                         workspace, expected):
    """Only the Test Root may name the parent reviewer and CEO for this review."""
    exact_fields(signed, "schema body signature_b64", "ROLE_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_PRE_RELEASE_ROLES_1",
            "ROLE_ENVELOPE_SCHEMA")
    body = signed["body"]
    exact_fields(body, "schema trust_domain parent_grant_id parent_task_id "
                       "parent_task_revision candidate_sha256 review_sha256 "
                       "reviewer_fingerprint ceo_fingerprint", "ROLE_BODY_FIELDS")
    require(body["schema"] == "M2_CONSTRUCTION_PRE_RELEASE_ROLES_1" and
            body["trust_domain"] == "TEST_ONLY" and
            all(body[field] == value for field, value in expected.items()),
            "ROLE_BINDING")
    _, public = load_pin(root_pin_path, expected_root_pin_sha256, workspace)
    require(type(signed["signature_b64"]) is str, "ROLE_SIGNATURE")
    try:
        signature = base64.b64decode(signed["signature_b64"], validate=True)
        require(len(signature) == 64, "ROLE_SIGNATURE")
        Ed25519PublicKey.from_public_bytes(public).verify(signature,
                                                           canonical(body))
    except (InvalidSignature, TypeError, ValueError, base64.binascii.Error):
        raise Denied("ROLE_SIGNATURE") from None


def _require_latest_revision(db, events, *, root_pin_path,
                             expected_root_pin_sha256, workspace, state_dir,
                             task_id, task_revision, code):
    """Compare against all registered Root-signed scopes for the same task."""
    latest = None
    for entry in events:
        event = entry["body"]
        if event.get("kind") != "SCOPE_GRANTED":
            continue
        row = db.execute(
            "SELECT envelope_json,envelope_hash FROM grants WHERE grant_id=?",
            (event.get("grant_id"),)).fetchone()
        require(row is not None, "PRE_SCOPE_REGISTER_CHANGED")
        signed = strict_json(row[0])
        require(canonical(signed).decode("utf-8") == row[0] and
                digest(signed) == row[1], "PRE_SCOPE_REGISTER_CHANGED")
        body = verify_signed_scope(signed, root_pin_path,
                                   expected_root_pin_sha256, workspace)
        require(body.get("grant_id") == event.get("grant_id") and
                digest(body) == event.get("scope_hash") and
                body.get("workspace_root") == str(workspace) and
                body.get("state_root") == str(state_dir),
                "PRE_SCOPE_REGISTER_CHANGED")
        if body.get("task_id") == task_id:
            revision = body.get("task_revision")
            require(type(revision) is int and revision > 0,
                    "PRE_SCOPE_REGISTER_CHANGED")
            latest = revision if latest is None else max(latest, revision)
    require(latest == task_revision, code)


def verify_signed_ceo_acceptance(signed, *, pin_path, expected_pin_sha256,
                                 root_pin_path, expected_root_pin_sha256,
                                 parent_reviewer_fingerprint,
                                 workspace, state_dir, expected,
                                 excluded_fingerprints):
    """Verify an externally signed acceptance; never trust a role claim alone."""
    workspace = Path(workspace).resolve(strict=True)
    state_dir = Path(state_dir).resolve(strict=True)
    exact_fields(signed, "schema body signature_b64", "CEO_ENVELOPE_FIELDS")
    require(signed["schema"] == "M2_CONSTRUCTION_SIGNED_CEO_ACCEPTANCE_1",
            "CEO_ENVELOPE_SCHEMA")
    body = signed["body"]
    exact_fields(body, "schema trust_domain decision ceo_fingerprint "
                       "parent_grant_id parent_task_id parent_task_revision "
                       "candidate_sha256 review_sha256 "
                       "internal_return_operation_id internal_return_files_sha256 "
                       "internal_return_event_hash "
                       "child_grant_id child_task_id child_task_revision "
                       "child_candidate_sha256 not_before expires_at "
                       "signed_roles",
                 "CEO_BODY_FIELDS")
    require(body["schema"] == "M2_CONSTRUCTION_CEO_ACCEPTANCE_BODY_1" and
            body["trust_domain"] == "TEST_ONLY" and
            body["decision"] in ("ACCEPT", "REJECT") and
            type(body["parent_task_revision"]) is int and
            body["parent_task_revision"] > 0 and
            type(body["child_task_revision"]) is int and
            body["child_task_revision"] > 0 and
            all(hash_text(body[name]) for name in (
                "ceo_fingerprint", "candidate_sha256", "review_sha256",
                "internal_return_files_sha256", "internal_return_event_hash",
                "child_candidate_sha256")) and
            all(type(body[name]) is str and body[name] for name in (
                "parent_grant_id", "parent_task_id", "child_grant_id",
                "child_task_id", "internal_return_operation_id")) and
            type(body["not_before"]) is int and
            type(body["expires_at"]) is int and
            body["not_before"] < body["expires_at"], "CEO_BODY")
    pin, public = _external_pin(pin_path, expected_pin_sha256, workspace, state_dir)
    require(body["ceo_fingerprint"] == pin["fingerprint"], "CEO_IDENTITY")
    require(pin["fingerprint"] not in excluded_fingerprints,
            "CEO_ROLE_COLLISION")
    _verify_role_binding(
        body["signed_roles"], root_pin_path=root_pin_path,
        expected_root_pin_sha256=expected_root_pin_sha256,
        workspace=workspace, expected={
            "parent_grant_id": expected["parent_grant_id"],
            "parent_task_id": expected["parent_task_id"],
            "parent_task_revision": expected["parent_task_revision"],
            "candidate_sha256": expected["candidate_sha256"],
            "review_sha256": expected["review_sha256"],
            "reviewer_fingerprint": parent_reviewer_fingerprint,
            "ceo_fingerprint": pin["fingerprint"],
        })
    require(type(signed["signature_b64"]) is str, "CEO_SIGNATURE")
    try:
        signature = base64.b64decode(signed["signature_b64"], validate=True)
        require(len(signature) == 64, "CEO_SIGNATURE")
        Ed25519PublicKey.from_public_bytes(public).verify(signature,
                                                           canonical(body))
    except (InvalidSignature, TypeError, ValueError, base64.binascii.Error):
        raise Denied("CEO_SIGNATURE") from None
    require(all(body[field] == value for field, value in expected.items()),
            "CEO_BINDING")
    require(body["not_before"] <= int(time.time()) < body["expires_at"],
            "CEO_EXPIRED")
    return {"decision": body["decision"],
            "ceo_fingerprint": pin["fingerprint"],
            "ceo_acceptance_sha256": bytes_hash(canonical(signed))}


def _freeze_operation(db, freeze, *, grant_id, task_id, manifest_sha256):
    row = db.execute(
        "SELECT grant_id,task_id,kind,status,result_json FROM operations "
        "WHERE operation_id=?", (freeze["body"].get("operation_id"),)).fetchone()
    require(row is not None and row[:4] ==
            (grant_id, task_id, "FREEZE", "COMPLETED"),
            "PARENT_FREEZE_OPERATION")
    result = strict_json(row[4])
    require(result.get("manifest_sha256") == manifest_sha256 and
            result.get("manifest_path") == freeze["body"].get("manifest_path"),
            "PARENT_FREEZE_OPERATION")


def _return_provenance(db, events, *, root_pin_path, expected_root_pin_sha256,
                       workspace, state_dir, parent_grant_id, parent_task_id,
                       parent_task_revision, parent_freeze, parent_manifest,
                       internal_return_operation_id):
    intents = [entry for entry in events
               if entry["body"].get("kind") == "INTERNAL_RETURN_INTENT" and
               entry["body"].get("operation_id") == internal_return_operation_id]
    consumed = [entry for entry in events
                if entry["body"].get("kind") == "INTERNAL_RETURN_CONSUMED" and
                entry["body"].get("operation_id") == internal_return_operation_id]
    require(len(intents) == 1 and len(consumed) == 1, "RETURN_MISSING")
    intent, effect = intents[0], consumed[0]
    require(intent["seq"] < effect["seq"] < parent_freeze["seq"],
            "RETURN_ORDER")
    signed_return = intent["body"].get("signed_return")
    body = verify_signed_return(
        signed_return, pin_path=root_pin_path,
        expected_pin_sha256=expected_root_pin_sha256, workspace=workspace)
    require(body["return_id"] == internal_return_operation_id and
            (body["parent_grant_id"], body["parent_task_id"],
             body["parent_task_revision"]) ==
            (parent_grant_id, parent_task_id, parent_task_revision) and
            body["review_sha256"] == bytes_hash(canonical(
                intent["body"].get("signed_review"))), "RETURN_BINDING")
    for field in ("child_grant_id", "child_task_id", "child_task_revision",
                  "parent_grant_id", "parent_task_id", "parent_task_revision",
                  "candidate_sha256", "review_sha256"):
        require(intent["body"].get(field) == body[field], "RETURN_BINDING")
    require(effect["body"].get("child_task_id") == body["child_task_id"] and
            effect["body"].get("parent_task_id") == parent_task_id and
            effect["body"].get("candidate_sha256") == body["candidate_sha256"] and
            effect["body"].get("review_sha256") == body["review_sha256"] and
            effect["body"].get("authority") == "INTERNAL_PARENT_ONLY",
            "RETURN_CONSUMED_BINDING")
    row = db.execute(
        "SELECT grant_id,task_id,kind,status,request_hash,before_sha256,"
        "after_sha256,result_json FROM operations WHERE operation_id=?",
        (internal_return_operation_id,)).fetchone()
    require(row is not None, "RETURN_MISSING")
    require(row[3] == "COMPLETED", "RETURN_UNKNOWN")
    request_hash = digest({"schema": "M2_CONSTRUCTION_RETURN_REQUEST_1",
                           "signed_return": signed_return,
                           "signed_review": intent["body"]["signed_review"]})
    require(row[:3] == (parent_grant_id, parent_task_id, "INTERNAL_RETURN") and
            row[4] == request_hash and
            row[5] == body["candidate_sha256"], "RETURN_OPERATION_BINDING")
    result = strict_json(row[7])
    require(canonical(result).decode("utf-8") == row[7] and
            result.get("status") == "COMPLETED" and
            result.get("operation_id") == internal_return_operation_id and
            result.get("authority") == "INTERNAL_PARENT_ONLY" and
            result.get("parent_task_id") == parent_task_id and
            result.get("candidate_sha256") == body["candidate_sha256"] and
            result.get("review_sha256") == body["review_sha256"],
            "RETURN_RESULT_BINDING")
    files = result.get("files")
    require(type(files) is dict and files and
            all(type(path) is str and hash_text(value)
                for path, value in files.items()) and
            digest(files) == result.get("files_sha256") == row[6] ==
            effect["body"].get("files_sha256"), "RETURN_FILES_BINDING")
    expected_files = {item["destination"]: item["sha256"]
                      for item in body["files"]}
    require(len(expected_files) == len(body["files"]) and
            files == expected_files and
            set(files) <= set(parent_manifest["files"]) and
            all(parent_manifest["files"][path]["sha256"] == sha
                for path, sha in files.items()), "RETURN_PARENT_BYTES")
    receipts = [entry for entry in events
                if entry["body"].get("kind") == "RECEIPT" and
                entry["body"].get("operation_id") == internal_return_operation_id]
    require(len(receipts) == 1 and
            intent["seq"] < receipts[0]["seq"] < effect["seq"] and
            receipts[0]["body"].get("request_hash") == request_hash and
            receipts[0]["body"].get("actual_sha256") == row[6],
            "RETURN_RECEIPT_BINDING")
    child_freezes = [entry for entry in events
                     if entry["body"].get("kind") == "CANDIDATE_FROZEN" and
                     entry["body"].get("grant_id") == body["child_grant_id"] and
                     entry["body"].get("task_id") == body["child_task_id"] and
                     entry["body"].get("task_revision") ==
                     body["child_task_revision"]]
    require(child_freezes, "CHILD_FREEZE_MISSING")
    child_freeze = child_freezes[-1]
    require(child_freeze["seq"] < intent["seq"] and
            child_freeze["body"].get("manifest_sha256") ==
            body["candidate_sha256"], "CHILD_CANDIDATE_SUPERSEDED")
    _freeze_operation(db, child_freeze,
                      grant_id=body["child_grant_id"],
                      task_id=body["child_task_id"],
                      manifest_sha256=body["candidate_sha256"])
    child_manifest_path = Path(child_freeze["body"]["manifest_path"])
    require(child_manifest_path.is_absolute() and
            state_dir in child_manifest_path.resolve(strict=True).parents,
            "CHILD_MANIFEST_LOCATION")
    verify_frozen_candidate(child_manifest_path,
                            expected_manifest_sha256=body["candidate_sha256"])
    child_manifest = strict_json(child_manifest_path.read_bytes())
    require(set(child_manifest["files"]) ==
            {item["source"] for item in body["files"]} and
            all(child_manifest["files"][item["source"]]["sha256"] ==
                item["sha256"] for item in body["files"]),
            "RETURN_CHILD_BYTES")
    return body, intent["body"]["signed_review"], child_manifest_path, row[6], effect


def _pre_release_evaluate(*, ledger_path, workspace, state_dir, root_pin_path,
                          expected_root_pin_sha256, reviewer_pin_path,
                          expected_reviewer_pin_sha256, child_reviewer_pin_path,
                          expected_child_reviewer_pin_sha256, ceo_pin_path,
                          expected_ceo_pin_sha256, grant_id, task_id,
                          task_revision, manifest_path, expected_manifest_sha256,
                          signed_review, signed_ceo_acceptance,
                          require_recorded):
    """Evaluate one coherent read snapshot, with optional durable CEO stage."""
    try:
        workspace = Path(workspace).resolve(strict=True)
        state_dir = Path(state_dir).resolve(strict=True)
        ledger_path = Path(ledger_path)
        manifest_path = Path(manifest_path)
        require(ledger_path == state_dir / "construction.sqlite3" and
                ledger_path.is_file() and
                ledger_path.resolve(strict=True) == ledger_path,
                "PRE_RELEASE_PATHS")
        require(manifest_path.is_absolute() and manifest_path.is_file() and
                state_dir in manifest_path.resolve(strict=True).parents,
                "PARENT_MANIFEST_LOCATION")
        for path in (root_pin_path, reviewer_pin_path, child_reviewer_pin_path):
            path = Path(path)
            require(path.is_absolute() and path.is_file() and
                    path.resolve(strict=True) == path and
                    state_dir not in path.parents and
                    workspace not in path.parents,
                    "PRE_RELEASE_EXTERNAL_PIN")
        verdict = local_adjudicate(
            ledger_path=ledger_path, workspace=workspace, state_dir=state_dir,
            root_pin_path=root_pin_path,
            expected_root_pin_sha256=expected_root_pin_sha256,
            reviewer_pin_path=reviewer_pin_path,
            expected_reviewer_pin_sha256=expected_reviewer_pin_sha256,
            grant_id=grant_id, task_id=task_id,
            task_revision=task_revision, manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha256,
            signed_review=signed_review)
        if verdict["status"] != "PASS":
            return {"status": verdict["status"],
                    "reason": "PARENT_" + verdict["reason"],
                    "dispatch_allowed": False}
        root_pin, _ = load_pin(root_pin_path, expected_root_pin_sha256, workspace)
        with closing(sqlite3.connect(ledger_path.as_uri() + "?mode=ro", uri=True,
                                     isolation_level=None, timeout=10)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            events = _read_events(db)
            head = (events[-1]["seq"], events[-1]["event_hash"])
            _scope(db, events, root_pin_path=root_pin_path,
                   expected_root_pin_sha256=expected_root_pin_sha256,
                   workspace=workspace, state_dir=state_dir,
                   grant_id=grant_id, task_id=task_id,
                   task_revision=task_revision)
            _require_latest_revision(
                db, events, root_pin_path=root_pin_path,
                expected_root_pin_sha256=expected_root_pin_sha256,
                workspace=workspace, state_dir=state_dir,
                task_id=task_id, task_revision=task_revision,
                code="PARENT_REVISION_SUPERSEDED")
            parent_manifest = strict_json(manifest_path.read_bytes())
            require(bytes_hash(manifest_path.read_bytes()) ==
                    expected_manifest_sha256, "PARENT_MANIFEST_CHANGED")
            parent_freeze, receipts = _freeze_and_receipts(
                events, grant_id=grant_id, task_id=task_id,
                task_revision=task_revision, manifest_path=manifest_path,
                manifest_sha256=expected_manifest_sha256,
                manifest=parent_manifest)
            _freeze_operation(db, parent_freeze, grant_id=grant_id,
                              task_id=task_id,
                              manifest_sha256=expected_manifest_sha256)
            author = _author(events, parent_freeze,
                             root_pin_path=root_pin_path,
                             expected_root_pin_sha256=expected_root_pin_sha256,
                             workspace=workspace, grant_id=grant_id,
                             task_id=task_id, task_revision=task_revision,
                             manifest_sha256=expected_manifest_sha256)
            review = verify_review_proof(
                signed_review, pin_path=reviewer_pin_path,
                expected_pin_sha256=expected_reviewer_pin_sha256,
                workspace=workspace,
                author_fingerprint=author["author_fingerprint"],
                grant_id=grant_id, task_id=task_id,
                task_revision=task_revision,
                manifest_sha256=expected_manifest_sha256,
                test_receipts=receipts,
                freeze_event_hash=parent_freeze["event_hash"])
            require(review["decision"] == "GO" and
                    review["review_sha256"] == verdict["review_sha256"],
                    "PARENT_REVIEW_CHANGED")
            verified = verify_frozen_candidate(
                manifest_path,
                expected_manifest_sha256=expected_manifest_sha256)
            require(verified["manifest_sha256"] ==
                    expected_manifest_sha256, "PARENT_MANIFEST_CHANGED")
            operation_id = signed_ceo_acceptance["body"][
                "internal_return_operation_id"]
            child_body, child_review, child_manifest_path, files_sha, consumed = (
                _return_provenance(
                    db, events, root_pin_path=root_pin_path,
                    expected_root_pin_sha256=expected_root_pin_sha256,
                    workspace=workspace, state_dir=state_dir,
                    parent_grant_id=grant_id, parent_task_id=task_id,
                    parent_task_revision=task_revision,
                    parent_freeze=parent_freeze,
                    parent_manifest=parent_manifest,
                    internal_return_operation_id=operation_id))
            _scope(db, events, root_pin_path=root_pin_path,
                   expected_root_pin_sha256=expected_root_pin_sha256,
                   workspace=workspace, state_dir=state_dir,
                   grant_id=child_body["child_grant_id"],
                   task_id=child_body["child_task_id"],
                   task_revision=child_body["child_task_revision"])
            _require_latest_revision(
                db, events, root_pin_path=root_pin_path,
                expected_root_pin_sha256=expected_root_pin_sha256,
                workspace=workspace, state_dir=state_dir,
                task_id=child_body["child_task_id"],
                task_revision=child_body["child_task_revision"],
                code="CHILD_REVISION_SUPERSEDED")
            child_verdict = local_adjudicate(
                ledger_path=ledger_path, workspace=workspace, state_dir=state_dir,
                root_pin_path=root_pin_path,
                expected_root_pin_sha256=expected_root_pin_sha256,
                reviewer_pin_path=child_reviewer_pin_path,
                expected_reviewer_pin_sha256=
                expected_child_reviewer_pin_sha256,
                grant_id=child_body["child_grant_id"],
                task_id=child_body["child_task_id"],
                task_revision=child_body["child_task_revision"],
                manifest_path=child_manifest_path,
                expected_manifest_sha256=child_body["candidate_sha256"],
                signed_review=child_review)
            require(child_verdict["status"] == "PASS" and
                    child_verdict["review_sha256"] ==
                    child_body["review_sha256"], "CHILD_VERDICT_REQUIRED")
            child_reviewer, _ = _public_pin(
                child_reviewer_pin_path,
                expected_child_reviewer_pin_sha256, workspace)
            expected = {
                "parent_grant_id": grant_id, "parent_task_id": task_id,
                "parent_task_revision": task_revision,
                "candidate_sha256": expected_manifest_sha256,
                "review_sha256": review["review_sha256"],
                "internal_return_operation_id": operation_id,
                "internal_return_files_sha256": files_sha,
                "internal_return_event_hash": consumed["event_hash"],
                "child_grant_id": child_body["child_grant_id"],
                "child_task_id": child_body["child_task_id"],
                "child_task_revision": child_body["child_task_revision"],
                "child_candidate_sha256": child_body["candidate_sha256"],
            }
            ceo = verify_signed_ceo_acceptance(
                signed_ceo_acceptance, pin_path=ceo_pin_path,
                expected_pin_sha256=expected_ceo_pin_sha256,
                root_pin_path=root_pin_path,
                expected_root_pin_sha256=expected_root_pin_sha256,
                parent_reviewer_fingerprint=review["reviewer_fingerprint"],
                workspace=workspace, state_dir=state_dir, expected=expected,
                excluded_fingerprints={
                    root_pin["fingerprint"], review["reviewer_fingerprint"],
                    child_reviewer["fingerprint"],
                    author["author_fingerprint"],
                    child_verdict["author_fingerprint"],
                })
            require(ceo["decision"] == "ACCEPT", "CEO_REJECTED")
            accepted_event = None
            if require_recorded:
                accepted = [entry for entry in events
                            if entry["body"].get("kind") == "CEO_ACCEPTED" and
                            entry["body"].get("grant_id") == grant_id and
                            entry["body"].get("task_id") == task_id and
                            entry["body"].get("task_revision") == task_revision and
                            entry["body"].get("manifest_sha256") ==
                            expected_manifest_sha256]
                require(len(accepted) == 1, "CEO_ACCEPTANCE_MISSING")
                accepted_event = accepted[0]
                recorded = accepted[0]["body"]
                require(recorded.get("signed_acceptance") ==
                        signed_ceo_acceptance and
                        recorded.get("ceo_acceptance_sha256") ==
                        ceo["ceo_acceptance_sha256"] and
                        recorded.get("review_sha256") == review["review_sha256"] and
                        recorded.get("internal_return_operation_id") ==
                        operation_id and
                        recorded.get("internal_return_files_sha256") ==
                        files_sha and
                        recorded.get("internal_return_event_hash") ==
                        consumed["event_hash"] and
                        consumed["seq"] < accepted[0]["seq"] and
                        parent_freeze["seq"] < accepted[0]["seq"],
                        "CEO_ACCEPTANCE_EVENT_CHANGED")
            parent_tests = [entry for entry in events
                            if entry["body"].get("kind") == "TEST_RECEIPT" and
                            entry["body"].get("grant_id") == grant_id and
                            entry["body"].get("task_id") == task_id and
                            entry["body"].get("task_revision") == task_revision and
                            entry["body"].get("operation_id") in
                            {ref["operation_id"] for ref in receipts}]
            require(len(parent_tests) == len(receipts) and
                    all(consumed["seq"] < item["seq"] < parent_freeze["seq"]
                        for item in parent_tests), "PARENT_TEST_ORDER")
            verify_frozen_candidate(
                manifest_path,
                expected_manifest_sha256=expected_manifest_sha256)
            verify_frozen_candidate(
                child_manifest_path,
                expected_manifest_sha256=child_body["candidate_sha256"])
        with closing(sqlite3.connect(ledger_path.as_uri() + "?mode=ro", uri=True,
                                     isolation_level=None, timeout=10)) as fresh:
            fresh.execute("PRAGMA query_only=ON")
            current = fresh.execute(
                "SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            require(current == head, "LEDGER_CHANGED")
        binding = {**expected,
                   "ceo_acceptance_sha256": ceo["ceo_acceptance_sha256"],
                   "ledger_head_seq": head[0],
                   "ledger_head_event_hash": head[1]}
        if accepted_event is not None:
            binding["ceo_accepted_event_hash"] = accepted_event["event_hash"]
            binding["ceo_accepted_event_seq"] = accepted_event["seq"]
        return {"status": "PASS", "reason": "PRE_RELEASE_EVIDENCE_CLOSED",
                "dispatch_allowed": False, **binding,
                "pre_release_sha256": digest({
                    "schema": "M2_CONSTRUCTION_PRE_RELEASE_BINDING_1",
                    **binding})}
    except (Denied, KeyError, IndexError, TypeError, ValueError, OSError,
            sqlite3.Error) as exc:
        code = str(exc) if isinstance(exc, Denied) else type(exc).__name__
        return {"status": "INDETERMINATE" if
                code in _INDETERMINATE or not isinstance(exc, Denied)
                else "FAIL", "reason": code, "dispatch_allowed": False}


def pre_release_readonly(*, ledger_path, workspace, state_dir, root_pin_path,
                         expected_root_pin_sha256, reviewer_pin_path,
                         expected_reviewer_pin_sha256, child_reviewer_pin_path,
                         expected_child_reviewer_pin_sha256, ceo_pin_path,
                         expected_ceo_pin_sha256, grant_id, task_id,
                         task_revision, manifest_path, expected_manifest_sha256,
                         signed_review, signed_ceo_acceptance):
    """Return PASS/FAIL/INDETERMINATE without a dispatch or ledger write."""
    return _pre_release_evaluate(
        ledger_path=ledger_path, workspace=workspace, state_dir=state_dir,
        root_pin_path=root_pin_path,
        expected_root_pin_sha256=expected_root_pin_sha256,
        reviewer_pin_path=reviewer_pin_path,
        expected_reviewer_pin_sha256=expected_reviewer_pin_sha256,
        child_reviewer_pin_path=child_reviewer_pin_path,
        expected_child_reviewer_pin_sha256=
        expected_child_reviewer_pin_sha256,
        ceo_pin_path=ceo_pin_path,
        expected_ceo_pin_sha256=expected_ceo_pin_sha256,
        grant_id=grant_id, task_id=task_id, task_revision=task_revision,
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        signed_review=signed_review,
        signed_ceo_acceptance=signed_ceo_acceptance,
        require_recorded=True)


def record_ceo_acceptance(controller, signed, *, reviewer_pin_path,
                          expected_reviewer_pin_sha256,
                          child_reviewer_pin_path,
                          expected_child_reviewer_pin_sha256, ceo_pin_path,
                          expected_ceo_pin_sha256, grant_id, task_id,
                          task_revision, manifest_path, expected_manifest_sha256,
                          signed_review):
    """Append one exact signed CEO acceptance after fresh read-only eligibility.

    This is an evidence event, never a release or dispatch. The Controller
    transaction rechecks the source head and frozen bytes before committing.
    """
    from .controller import Controller

    try:
        require(isinstance(controller, Controller), "CEO_CONTROLLER_REQUIRED")
        verdict = _pre_release_evaluate(
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
            grant_id=grant_id, task_id=task_id,
            task_revision=task_revision, manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha256,
            signed_review=signed_review, signed_ceo_acceptance=signed,
            require_recorded=False)
        if verdict["status"] != "PASS":
            return {"status": "DENIED", "reason": verdict["reason"],
                    "dispatch_allowed": False, "effect_executed": False}
        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            head = db.execute(
                "SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            require(head == (verdict["ledger_head_seq"],
                             verdict["ledger_head_event_hash"]),
                    "CEO_LEDGER_CHANGED")
            controller._current_scope(db, grant_id, task_id, task_revision)
            signed_body = signed["body"]
            controller._current_scope(
                db, signed_body["child_grant_id"],
                signed_body["child_task_id"],
                signed_body["child_task_revision"])
            events = _read_events(db)
            _require_latest_revision(
                db, events, root_pin_path=controller.pin_path,
                expected_root_pin_sha256=controller.expected_pin_sha256,
                workspace=controller.workspace, state_dir=controller.state_dir,
                task_id=task_id, task_revision=task_revision,
                code="PARENT_REVISION_SUPERSEDED")
            _require_latest_revision(
                db, events, root_pin_path=controller.pin_path,
                expected_root_pin_sha256=controller.expected_pin_sha256,
                workspace=controller.workspace, state_dir=controller.state_dir,
                task_id=signed_body["child_task_id"],
                task_revision=signed_body["child_task_revision"],
                code="CHILD_REVISION_SUPERSEDED")
            verify_frozen_candidate(
                Path(manifest_path),
                expected_manifest_sha256=expected_manifest_sha256)
            parent_freezes = [entry for entry in events
                              if entry["body"].get("kind") == "CANDIDATE_FROZEN" and
                              entry["body"].get("grant_id") == grant_id and
                              entry["body"].get("task_id") == task_id and
                              entry["body"].get("task_revision") == task_revision]
            require(parent_freezes and parent_freezes[-1]["body"].get(
                "manifest_sha256") == expected_manifest_sha256 and
                parent_freezes[-1]["seq"] <= head[0],
                "CEO_FREEZE_ORDER")
            child_freezes = [entry for entry in events
                             if entry["body"].get("kind") == "CANDIDATE_FROZEN" and
                             entry["body"].get("grant_id") ==
                             signed_body["child_grant_id"] and
                             entry["body"].get("task_id") ==
                             signed_body["child_task_id"] and
                             entry["body"].get("task_revision") ==
                             signed_body["child_task_revision"]]
            require(child_freezes and child_freezes[-1]["body"].get(
                "manifest_sha256") == signed_body["child_candidate_sha256"],
                "CHILD_CANDIDATE_SUPERSEDED")
            verify_frozen_candidate(
                Path(child_freezes[-1]["body"]["manifest_path"]),
                expected_manifest_sha256=
                signed_body["child_candidate_sha256"])
            prior = [entry for entry in events
                     if entry["body"].get("kind") == "CEO_ACCEPTED" and
                     entry["body"].get("grant_id") == grant_id and
                     entry["body"].get("task_id") == task_id and
                     entry["body"].get("task_revision") == task_revision and
                     entry["body"].get("manifest_sha256") ==
                     expected_manifest_sha256]
            if prior:
                require(len(prior) == 1 and
                        prior[0]["body"].get("signed_acceptance") == signed and
                        prior[0]["body"].get("ceo_acceptance_sha256") ==
                        verdict["ceo_acceptance_sha256"],
                        "CEO_ACCEPTANCE_CONFLICT")
                return {"status": "ACCEPTED", "dispatch_allowed": False,
                        "effect_executed": False,
                        "ceo_acceptance_sha256":
                        verdict["ceo_acceptance_sha256"],
                        "candidate_sha256": expected_manifest_sha256}
            controller.ledger.event(db, {
                "kind": "CEO_ACCEPTED", "grant_id": grant_id,
                "task_id": task_id, "task_revision": task_revision,
                "manifest_sha256": expected_manifest_sha256,
                "review_sha256": verdict["review_sha256"],
                "internal_return_operation_id":
                verdict["internal_return_operation_id"],
                "internal_return_files_sha256":
                verdict["internal_return_files_sha256"],
                "internal_return_event_hash":
                verdict["internal_return_event_hash"],
                "ceo_acceptance_sha256":
                verdict["ceo_acceptance_sha256"],
                "signed_acceptance": signed,
            })
            return {"status": "ACCEPTED", "dispatch_allowed": False,
                    "effect_executed": True,
                    "ceo_acceptance_sha256":
                    verdict["ceo_acceptance_sha256"],
                    "candidate_sha256": expected_manifest_sha256}
    except (Denied, KeyError, IndexError, TypeError, ValueError, OSError,
            sqlite3.Error) as exc:
        return {"status": "DENIED", "reason": str(exc),
                "dispatch_allowed": False, "effect_executed": False}
