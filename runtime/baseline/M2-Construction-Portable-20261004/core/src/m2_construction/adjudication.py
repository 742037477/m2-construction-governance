"""Local read-only eligibility verdict; this module never consumes an effect.

Controller records real TEST/BUILD receipts and CANDIDATE_FROZEN events. PASS also
requires a Test Root signed AUTHOR_ATTESTED event sourced from the actual
author identity; current production entry points do not supply that binding.
"""

from contextlib import closing
from pathlib import Path
import sqlite3
import time

from .artifacts import verify_frozen_candidate
from .contracts import (Denied, bytes_hash, canonical, digest, hash_text,
                        require, strict_json)
from .controller import Controller
from .ledger import Ledger
from .review import verify_author_attestation, verify_review_proof
from .trust import load_pin, verify_signed_scope


_FAIL_CODES = {"SCOPE_REVOKED", "SCOPE_EXPIRED", "CANDIDATE_SUPERSEDED",
               "REVIEW_NOT_INDEPENDENT", "REVIEW_ROOT_COLLISION",
               "FROZEN_BYTES_CHANGED", "FROZEN_SNAPSHOT_CHANGED",
               "TEST_LOG_CHANGED", "TEST_SOURCE_CHANGED", "TEST_PROGRAM_CHANGED"}


class _ReadOnlyScopePaths:
    """Supply only filesystem reads needed by Controller's shared scope checks."""

    __slots__ = ("workspace", "state_dir")
    _target = Controller._target
    _resource_key = Controller._resource_key

    def __init__(self, workspace, state_dir):
        self.workspace = workspace
        self.state_dir = state_dir


def _read_events(db):
    Ledger.verify_chain(db)
    return [{"seq": seq, "event_hash": event_hash, "body": strict_json(body_json)}
            for seq, event_hash, body_json in db.execute(
                "SELECT seq,event_hash,body_json FROM events ORDER BY seq")]


def _scope(db, events, *, root_pin_path, expected_root_pin_sha256, workspace,
           state_dir, grant_id, task_id, task_revision):
    row = db.execute("SELECT envelope_json,envelope_hash,revoked FROM grants WHERE grant_id=?",
                     (grant_id,)).fetchone()
    require(row is not None, "SCOPE_MISSING")
    signed = strict_json(row[0])
    require(canonical(signed).decode("utf-8") == row[0] and
            digest(signed) == row[1], "SCOPE_STORED_ENVELOPE_CHANGED")
    body = verify_signed_scope(signed, root_pin_path, expected_root_pin_sha256,
                               workspace)
    # Reuse the full v1/v2/v3 Controller contract without constructing a Controller
    # (whose initializer can create or migrate the ledger).
    Controller._validate_scope(_ReadOnlyScopePaths(workspace, state_dir), body)
    require((body["grant_id"], body["task_id"], body["task_revision"]) ==
            (grant_id, task_id, task_revision), "SCOPE_BINDING")
    grants = [event for event in events if event["body"].get("kind") == "SCOPE_GRANTED"
              and event["body"].get("grant_id") == grant_id]
    require(len(grants) == 1 and grants[0]["body"].get("scope_hash") == digest(body),
            "SCOPE_EVENT_MISSING")
    require(row[2] == 0 and not any(event["body"].get("kind") == "SCOPE_REVOKED"
                                        and event["body"].get("grant_id") == grant_id
                                        for event in events), "SCOPE_REVOKED")
    require(body["not_before"] <= int(time.time()) < body["expires_at"],
            "SCOPE_EXPIRED")
    return body


def _freeze_and_receipts(events, *, grant_id, task_id, task_revision,
                         manifest_path, manifest_sha256, manifest):
    freezes = [event for event in events
               if event["body"].get("kind") == "CANDIDATE_FROZEN"
               and event["body"].get("grant_id") == grant_id
               and event["body"].get("task_id") == task_id
               and event["body"].get("task_revision") == task_revision]
    require(freezes, "FREEZE_EVENT_MISSING")
    latest = freezes[-1]
    require(latest["body"].get("manifest_sha256") == manifest_sha256,
            "CANDIDATE_SUPERSEDED")
    require(latest["body"].get("manifest_path") == str(manifest_path),
            "FREEZE_EVENT_BINDING")
    refs = manifest["test_receipts"]
    require(type(refs) is list and refs, "TEST_RECEIPT_REQUIRED")
    receipts = []
    for ref in refs:
        receipt = {"operation_id": ref["operation_id"],
                   "receipt_sha256": ref["receipt_sha256"]}
        matches = [event for event in events
                   if event["seq"] < latest["seq"] and
                   event["body"].get("kind") == "TEST_RECEIPT" and
                   event["body"].get("grant_id") == grant_id and
                   event["body"].get("task_id") == task_id and
                   event["body"].get("task_revision") == task_revision and
                   event["body"].get("operation_id") == receipt["operation_id"] and
                   event["body"].get("receipt_sha256") == receipt["receipt_sha256"] and
                   event["body"].get("status") == "PASSED"]
        require(len(matches) == 1, "TEST_EVENT_MISSING")
        receipts.append(receipt)
    require(len({r["operation_id"] for r in receipts}) == len(receipts),
            "TEST_EVENT_DUPLICATE")
    if manifest["schema"] == "M2_CONSTRUCTION_FREEZE_2":
        build_refs = manifest["build_receipts"]
        require(type(build_refs) is list and build_refs, "BUILD_RECEIPT_REQUIRED")
        used_ids = {r["operation_id"] for r in receipts}
        for ref in build_refs:
            operation_id = ref["operation_id"]
            receipt_sha256 = ref["receipt_sha256"]
            require(type(operation_id) is str and hash_text(receipt_sha256) and
                    operation_id not in used_ids, "BUILD_EVENT_DUPLICATE")
            used_ids.add(operation_id)
            matches = [event for event in events
                       if event["seq"] < latest["seq"] and
                       event["body"].get("kind") == "BUILD_RECEIPT" and
                       event["body"].get("grant_id") == grant_id and
                       event["body"].get("task_id") == task_id and
                       event["body"].get("task_revision") == task_revision and
                       event["body"].get("operation_id") == operation_id and
                       event["body"].get("receipt_sha256") == receipt_sha256 and
                       event["body"].get("status") == "PASSED"]
            require(len(matches) == 1, "BUILD_EVENT_MISSING")
    return latest, receipts


def _author(events, freeze, *, root_pin_path, expected_root_pin_sha256,
            workspace, grant_id, task_id, task_revision, manifest_sha256):
    attestations = [event["body"]["authorship"] for event in events
                    if event["seq"] > freeze["seq"] and
                    event["body"].get("kind") == "AUTHOR_ATTESTED" and
                    "authorship" in event["body"]]
    matching = [signed for signed in attestations
                if type(signed) is dict and type(signed.get("body")) is dict and
                signed["body"].get("candidate_sha256") == manifest_sha256 and
                signed["body"].get("grant_id") == grant_id and
                signed["body"].get("task_id") == task_id and
                signed["body"].get("task_revision") == task_revision]
    require(len(matching) == 1, "AUTHOR_ATTESTATION_MISSING")
    return verify_author_attestation(
        matching[0], root_pin_path=root_pin_path,
        expected_root_pin_sha256=expected_root_pin_sha256,
        workspace=workspace, grant_id=grant_id, task_id=task_id,
        task_revision=task_revision, manifest_sha256=manifest_sha256)


def local_adjudicate(*, ledger_path, workspace, state_dir, root_pin_path,
                     expected_root_pin_sha256, reviewer_pin_path,
                     expected_reviewer_pin_sha256, grant_id, task_id,
                     task_revision, manifest_path, expected_manifest_sha256,
                     signed_review):
    """Return PASS/FAIL/INDETERMINATE from a consistent read-only DB snapshot.

    PASS is local internal-return eligibility evidence only. No ledger write,
    model call, dispatch, consumption, or release occurs here.
    """
    result = {"status": "INDETERMINATE", "reason": "UNVERIFIED",
              "dispatch_allowed": False}
    try:
        workspace = Path(workspace).resolve(strict=True)
        state_dir = Path(state_dir).resolve(strict=True)
        ledger_path = Path(ledger_path)
        manifest_path = Path(manifest_path)
        require(workspace.is_dir() and state_dir.is_dir() and
                ledger_path == state_dir / "construction.sqlite3" and
                ledger_path.is_file() and
                ledger_path.resolve(strict=True) == ledger_path,
                "ADJUDICATION_PATHS")
        for pin_path in (root_pin_path, reviewer_pin_path):
            pin = Path(pin_path)
            require(pin.is_absolute() and pin.is_file() and
                    pin.resolve(strict=True) == pin and
                    pin != state_dir and state_dir not in pin.parents,
                    "ADJUDICATION_EXTERNAL_PIN")
        require(hash_text(expected_manifest_sha256), "MANIFEST_HASH")
        require(type(task_revision) is int and task_revision > 0,
                "ADJUDICATION_REVISION")
        root_pin, _ = load_pin(root_pin_path, expected_root_pin_sha256, workspace)
        # URI mode=ro prevents the verdict from creating or updating the DB.
        with closing(sqlite3.connect(ledger_path.as_uri() + "?mode=ro", uri=True,
                                     isolation_level=None, timeout=10)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            events = _read_events(db)
            _scope(db, events, root_pin_path=root_pin_path,
                   expected_root_pin_sha256=expected_root_pin_sha256,
                   workspace=workspace, state_dir=state_dir,
                   grant_id=grant_id, task_id=task_id,
                   task_revision=task_revision)
            verified = verify_frozen_candidate(
                manifest_path, expected_manifest_sha256=expected_manifest_sha256)
            require(verified["manifest_sha256"] == expected_manifest_sha256,
                    "MANIFEST_HASH_CHANGED")
            manifest_raw = manifest_path.read_bytes()
            require(bytes_hash(manifest_raw) == expected_manifest_sha256,
                    "MANIFEST_HASH_CHANGED")
            manifest = strict_json(manifest_raw)
            freeze, receipts = _freeze_and_receipts(
                events, grant_id=grant_id, task_id=task_id,
                task_revision=task_revision, manifest_path=manifest_path,
                manifest_sha256=expected_manifest_sha256, manifest=manifest)
            author = _author(events, freeze, root_pin_path=root_pin_path,
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
                freeze_event_hash=freeze["event_hash"])
            require(review["reviewer_fingerprint"] != root_pin["fingerprint"],
                    "REVIEW_ROOT_COLLISION")
            # Recheck file evidence while the same SQL snapshot remains open.
            verify_frozen_candidate(
                manifest_path, expected_manifest_sha256=expected_manifest_sha256)
            if review["decision"] == "NO_GO":
                return {"status": "FAIL", "reason": "REVIEW_NO_GO",
                        "dispatch_allowed": False,
                        "candidate_sha256": expected_manifest_sha256,
                        "review_sha256": review["review_sha256"]}
            return {"status": "PASS", "reason": "LOCAL_EVIDENCE_CLOSED",
                    "dispatch_allowed": False,
                    "candidate_sha256": expected_manifest_sha256,
                    "review_sha256": review["review_sha256"],
                    "reviewer_fingerprint": review["reviewer_fingerprint"],
                    "author_fingerprint": author["author_fingerprint"]}
    except (Denied, KeyError, IndexError, TypeError, ValueError, OSError,
            sqlite3.Error) as exc:
        code = str(exc) if isinstance(exc, Denied) else type(exc).__name__
        result["status"] = "FAIL" if code in _FAIL_CODES else "INDETERMINATE"
        result["reason"] = code
        return result
