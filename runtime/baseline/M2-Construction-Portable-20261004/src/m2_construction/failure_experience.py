"""Explicit, bounded host overlay for historical failure advisories.

The immutable core owns permissions, task state and effects. This module owns
only JSON material and uses the existing project memory/projection APIs. It is
loaded outside the core33 inventory, after the host pins its source bytes.
"""
from copy import deepcopy
from pathlib import Path
import os
import sqlite3
import time
import uuid

from m2_construction.contracts import (Denied, bytes_hash, canonical, digest,
                                       exact_fields, hash_text, require, strict_json)
from m2_construction.controller import Controller
from m2_construction.context import build_hard_constraints_from_scope, context_bundle
from m2_construction.evidence_projection import EvidenceProjection
from m2_construction.memory import BINDING_FIELDS, MemoryStore, _binding
from m2_construction.orchestration import OrchestrationStore
from m2_construction.trust import verify_signed_scope


SESSION_FIELDS = ("schema binding grant_id node_id task_type history_root orchestration_path "
                  "memory_path dependencies premises read_roots historical_anchors lesson_proofs "
                  "revoked_lesson_ids revoked_proof_refs conflicting_lesson_ids rule_ids "
                  "max_candidates max_source_bytes max_items max_bytes expires_at")
LESSON_FIELDS = ("schema lesson_id version task_type origin historical_binding historical_session dependencies "
                 "premises effect_status cause observations supersedes")
TASK_TYPES = frozenset({"TEST", "BUILD", "CODE_CHANGE"})
NONPASS = frozenset({"FAILED", "TIMED_OUT", "LAUNCH_FAILED", "SOURCE_CHANGED",
                     "PROGRAM_CHANGED", "OUTPUT_MISSING", "OUTPUT_UNCHANGED", "OUTPUT_INVALID"})


def _path(value, root=None, *, existing=True):
    require(type(value) is str and len(value) <= 4096 and "\x00" not in value,
            "EXPERIENCE_PATH")
    p = Path(value)
    require(p.is_absolute() and p.resolve(strict=existing) == p, "EXPERIENCE_PATH_LINK")
    if root is not None:
        require(p == root or root in p.parents, "EXPERIENCE_PATH_OUTSIDE")
    for part in (p, *p.parents):
        if part.exists():
            require(not part.is_symlink() and not (
                getattr(part.stat(), "st_file_attributes", 0) & 0x400),
                "EXPERIENCE_PATH_LINK")
    return p


def _read(path, limit):
    p = _path(str(path))
    require(p.is_file() and p.stat().st_size <= limit, "EXPERIENCE_SOURCE_LIMIT")
    with p.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    require(len(raw) <= limit and (before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size,
             after.st_mtime_ns), "EXPERIENCE_SOURCE_CHANGED")
    require(p.stat().st_ino == before.st_ino, "EXPERIENCE_SOURCE_CHANGED")
    return raw


def _save(path, value):
    p = _path(str(path), existing=False)
    p.parent.mkdir(parents=True, exist_ok=True)
    _path(str(p.parent))
    raw = canonical(value)
    with p.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(p), "sha256": bytes_hash(raw), "bytes": len(raw)}


def _reference(path, raw):
    return {"path": str(path), "sha256": bytes_hash(raw), "bytes": len(raw)}


class Reader:
    """An explicit file allowlist policy; no glob contents enter model text."""
    def __init__(self, session):
        self.session = session
        self.roots = [_path(value) for value in session["read_roots"]]
        self.policy_hash = digest({"roots": session["read_roots"],
                                   "max_source_bytes": session["max_source_bytes"]})
        self.reads = []

    def raw(self, path, expected=None):
        p = _path(str(path))
        require(any(p == root or root in p.parents for root in self.roots),
                "EXPERIENCE_READ_DENIED")
        raw = _read(p, self.session["max_source_bytes"])
        ref = _reference(p, raw)
        self.reads.append(ref)
        if expected is not None:
            require(type(expected) is dict and set(expected) >= {"path", "sha256", "bytes"}
                    and str(p) == expected["path"] and ref["sha256"] == expected["sha256"]
                    and ref["bytes"] == expected["bytes"], "EXPERIENCE_SOURCE_HASH")
        return raw

    def json(self, ref):
        return strict_json(self.raw(ref["path"], ref))


def _session(path, expected, bridge_binding, config):
    require(hash_text(expected), "EXPERIENCE_DESCRIPTOR_HASH")
    raw = _read(path, 131072)
    require(bytes_hash(raw) == expected, "EXPERIENCE_DESCRIPTOR_CHANGED")
    s = strict_json(raw)
    exact_fields(s, SESSION_FIELDS, "EXPERIENCE_SESSION_FIELDS")
    require(s["schema"] == "CK_FAILURE_EXPERIENCE_SESSION_1", "EXPERIENCE_SESSION_SCHEMA")
    _binding(s["binding"])
    require(s["binding"]["task_id"] == bridge_binding["task_id"] and
            s["binding"]["task_revision"] == bridge_binding["task_revision"] and
            s["grant_id"] == bridge_binding["grant_id"], "EXPERIENCE_CURRENT_TASK")
    require(s["task_type"] in TASK_TYPES, "EXPERIENCE_TASK_TYPE")
    require(type(s["node_id"]) is str and 0 < len(s["node_id"]) <= 128,
            "EXPERIENCE_NODE")
    state, workspace = _path(config["state_root"]), _path(config["workspace_root"])
    for key in ("history_root", "orchestration_path", "memory_path"):
        _path(s[key], state, existing=key != "history_root")
    require(1 <= len(s["read_roots"]) <= 8, "EXPERIENCE_READ_ROOTS")
    input_root = _path(bridge_binding["cli_config_path"]).parent
    for value in s["read_roots"]:
        p = _path(value)
        require(p == state or state in p.parents or p == workspace or workspace in p.parents
                or p == input_root,
                "EXPERIENCE_READ_ROOTS")
    require(type(s["dependencies"]) is dict and 0 < len(s["dependencies"]) <= 32,
            "EXPERIENCE_DEPENDENCIES")
    for key, ref in s["dependencies"].items():
        require(type(key) is str and 0 < len(key) <= 128 and
                key.split(":", 1)[0] in {"module", "rule", "interface"},
                "EXPERIENCE_DEPENDENCY_KIND")
        exact_fields(ref, "path sha256 bytes", "EXPERIENCE_DEPENDENCY_REF")
        require(hash_text(ref["sha256"]) and type(ref["bytes"]) is int and ref["bytes"] >= 0,
                "EXPERIENCE_DEPENDENCY_REF")
    require(type(s["premises"]) is dict and len(s["premises"]) <= 32 and all(
        type(k) is str and 0 < len(k) <= 128 and type(v) is str and len(v) <= 256
        for k, v in s["premises"].items()), "EXPERIENCE_PREMISES")
    require(type(s["lesson_proofs"]) is dict and len(s["lesson_proofs"]) <= 64,
            "EXPERIENCE_PROOF_CATALOG")
    require(type(s["historical_anchors"]) is dict and len(s["historical_anchors"]) <= 64,
            "EXPERIENCE_HISTORY_ANCHORS")
    for key, ref in s["historical_anchors"].items():
        require(hash_text(key), "EXPERIENCE_HISTORY_ANCHOR_ID")
        exact_fields(ref, "path sha256 bytes", "EXPERIENCE_HISTORY_ANCHOR_REF")
        require(hash_text(ref["sha256"]) and type(ref["bytes"]) is int and ref["bytes"] > 0,
                "EXPERIENCE_HISTORY_ANCHOR_REF")
    for key in ("revoked_lesson_ids", "revoked_proof_refs", "conflicting_lesson_ids", "rule_ids"):
        require(type(s[key]) is list and len(s[key]) <= 64 and all(
            type(x) is str and 0 < len(x) <= 256 for x in s[key]), "EXPERIENCE_LIST")
    for key, minimum, maximum in (("max_candidates", 1, 64), ("max_source_bytes", 1024, 1048576),
                                 ("max_items", 1, 10000), ("max_bytes", 1024, 1048576)):
        require(type(s[key]) is int and minimum <= s[key] <= maximum, "EXPERIENCE_BUDGET")
    require(type(s["expires_at"]) is int and s["expires_at"] > int(time.time()),
            "EXPERIENCE_CURRENT_EXPIRED")
    return s


class FailureExperience:
    def __init__(self, bridge_binding, config, descriptor_path, descriptor_sha256):
        self.bridge = bridge_binding
        self.config = config
        self.descriptor_path = descriptor_path
        self.descriptor_sha256 = descriptor_sha256
        self.s = _session(descriptor_path, descriptor_sha256, bridge_binding, config)
        self.reader = Reader(self.s)
        self.controller = Controller(workspace=Path(config["workspace_root"]),
            state_dir=Path(config["state_root"]), pin_path=Path(config["pin_path"]),
            expected_pin_sha256=config["expected_pin_sha256"])

    def current(self):
        s = _session(self.descriptor_path, self.descriptor_sha256, self.bridge, self.config)
        with self.controller.ledger.transaction() as db:
            self.controller.ledger.verify_chain(db)
            scope = self.controller._current_scope(db, s["grant_id"], s["binding"]["task_id"],
                                                   s["binding"]["task_revision"])
        require(digest(scope) == s["binding"]["authority_hash"] and
                s["expires_at"] <= scope["expires_at"], "EXPERIENCE_CURRENT_GRANT")
        for ref in s["dependencies"].values():
            self.reader.raw(ref["path"], ref)
        return scope

    def origin(self, bridge_receipt):
        record = strict_json(self.reader.raw(bridge_receipt))
        require(record.get("schema") == "CK_NATIVE_B_BRIDGE_RECEIPT_1", "EXPERIENCE_BRIDGE_RECEIPT")
        native = record.get("native_result") or {}
        require(type(native) is dict, "EXPERIENCE_NATIVE_RESULT")
        op_id = record.get("operation_id")
        require(native.get("operation_id", op_id) == op_id, "EXPERIENCE_OPERATION")
        with self.controller.ledger.transaction() as db:
            self.controller.ledger.verify_chain(db)
            op = db.execute("SELECT kind,grant_id,task_id,status,result_json "
                            "FROM operations WHERE operation_id=?", (op_id,)).fetchone()
            require(op is not None and (op[1], op[2]) == (
                record["grant_id"], record["task_id"]),
                "EXPERIENCE_OPERATION_ORIGIN")
            require(op[0] in ("TEST", "BUILD"), "EXPERIENCE_OPERATION_KIND")
            grant = db.execute("SELECT envelope_json,envelope_hash FROM grants WHERE grant_id=?",
                               (op[1],)).fetchone()
            signed = strict_json(grant[0])
            require(digest(signed) == grant[1], "EXPERIENCE_HISTORICAL_GRANT")
            # Historical provenance checks the signature, never its current lease.
            historical_scope = verify_signed_scope(signed, self.controller.pin_path,
                                self.controller.expected_pin_sha256, self.controller.workspace)
            require((historical_scope["task_id"], historical_scope["task_revision"]) == (
                record["task_id"], record["task_revision"]), "EXPERIENCE_OPERATION_VERSION")
            if op[3] == "COMPLETED":
                require(op[4] is not None and strict_json(op[4]) == native,
                        "EXPERIENCE_NATIVE_RECEIPT_CONFLICT")
        braw = self.reader.raw(bridge_receipt)
        origin = {"run_id": record["run_id"], "task_id": record["task_id"],
                  "task_revision": record["task_revision"], "grant_id": record["grant_id"],
                  "operation_id": op_id, "kind": op[0], "candidate": "UNASSIGNED",
                  "authority_hash": digest(historical_scope),
                  "bridge_receipt": _reference(bridge_receipt, braw),
                  "native_receipt": None, "native_log": None,
                  "binding_source": {"path": record["binding_path"],
                                     "recorded_sha256": record["binding_sha256"]},
                  "request_source": {"path": record["request_path"],
                                     "recorded_sha256": record["request_sha256"]},
                  "started_utc": record.get("started_utc"),
                  "missing_sources": []}
        for field in ("binding_source", "request_source"):
            item = origin[field]
            try:
                data = self.reader.raw(item["path"])
                require(bytes_hash(data) == item["recorded_sha256"], "EXPERIENCE_ORIGINAL_INPUT_HASH")
                item.update(actual_sha256=bytes_hash(data), bytes=len(data))
            except (OSError, Denied):
                origin["missing_sources"].append(field)
        unresolved = (record["transport_status"] == "CLI_TIMEOUT_EFFECT_STATE_UNRESOLVED"
                      or op[3] in {"UNKNOWN", "IN_FLIGHT"})
        if unresolved:
            return origin, "UNKNOWN", {"status": "UNKNOWN", "exit_code": None}
        require(record["transport_status"] == "CLI_RETURNED" and
                record.get("post_call_inputs_unchanged") is True and op[3] == "COMPLETED",
                "EXPERIENCE_TRANSPORT_UNRESOLVED")
        receipt_ref = {"path": native.get("receipt_path"), "sha256": native.get("receipt_sha256")}
        require(hash_text(receipt_ref["sha256"]), "EXPERIENCE_NATIVE_RECEIPT_MISSING")
        praw = self.reader.raw(receipt_ref["path"])
        require(bytes_hash(praw) == receipt_ref["sha256"], "EXPERIENCE_NATIVE_RECEIPT_HASH")
        process = strict_json(praw)
        require(process.get("schema") == "M2_CONSTRUCTION_PROCESS_RECEIPT_1" and
                process["operation_id"] == op_id and process["status"] == native["status"]
                and process["exit_code"] == native.get("exit_code"), "EXPERIENCE_PROCESS_CONFLICT")
        origin["native_receipt"] = _reference(receipt_ref["path"], praw)
        log_raw = self.reader.raw(process["log_path"])
        require(bytes_hash(log_raw) == process["log_sha256"], "EXPERIENCE_LOG_HASH")
        origin["native_log"] = _reference(process["log_path"], log_raw)
        if process["status"] == "PASSED":
            return origin, "KNOWN_PASS", {"status": "PASSED", "exit_code": 0}
        require(process["status"] in NONPASS, "EXPERIENCE_PROCESS_STATUS")
        return origin, "KNOWN_NONPASS", {"status": process["status"],
                                        "exit_code": process["exit_code"]}

    def archive(self, receipt_path):
        self.current()
        origin, effect, observations = self.origin(receipt_path)
        require((origin["task_id"], origin["task_revision"], origin["grant_id"]) == (
            self.s["binding"]["task_id"], self.s["binding"]["task_revision"], self.s["grant_id"]),
            "EXPERIENCE_ARCHIVE_BINDING")
        if effect == "KNOWN_PASS":
            return {"status": "NOT_A_FAILURE", "dispatch_allowed": False}
        lesson_id = digest({"run": origin["run_id"], "operation": origin["operation_id"],
                            "receipt": origin["bridge_receipt"]["sha256"]})
        lesson = {"schema": "CK_FAILURE_LESSON_1", "lesson_id": lesson_id, "version": 1,
                  "task_type": self.s["task_type"], "origin": origin,
                  "historical_binding": self.s["binding"],
                  "historical_session": _reference(self.descriptor_path,
                      _read(self.descriptor_path, 131072)),
                  "dependencies": {key: ref["sha256"] for key, ref in self.s["dependencies"].items()},
                  "premises": self.s["premises"], "effect_status": effect,
                  "cause": {"status": "UNKNOWN", "hypotheses": []},
                  "observations": observations, "supersedes": None}
        path = Path(self.s["history_root"]) / (lesson_id + ".lesson.json")
        if path.exists():
            require(self.reader.raw(path) == canonical(lesson), "EXPERIENCE_IMMUTABLE_CONFLICT")
            ref = _reference(path, canonical(lesson))
        else:
            ref = _save(path, lesson)
        return {"status": "ARCHIVED", "lesson_path": ref["path"],
                "lesson_sha256": ref["sha256"], "effect_status": effect,
                "cause_status": "UNKNOWN", "dispatch_allowed": False,
                "reads": self.reader.reads}

    def checked_lesson(self, path, expected=None):
        raw = self.reader.raw(path, expected)
        lesson = strict_json(raw)
        exact_fields(lesson, LESSON_FIELDS, "EXPERIENCE_LESSON_FIELDS")
        require(lesson["schema"] == "CK_FAILURE_LESSON_1" and hash_text(lesson["lesson_id"])
                and type(lesson["version"]) is int and lesson["version"] >= 1,
                "EXPERIENCE_LESSON_ID")
        _binding(lesson["historical_binding"])
        anchor = self.s["historical_anchors"].get(lesson["lesson_id"])
        require(type(anchor) is dict, "INDEPENDENT_HISTORY_ANCHOR_MISSING")
        require(_reference(path, raw) == anchor, "INDEPENDENT_HISTORY_ANCHOR_CHANGED")
        historical = self.reader.json(lesson["historical_session"])
        # Check the old externally fixed descriptor as provenance, not as a
        # presently valid grant. It never supplies the new task's authority.
        require(historical.get("schema") == "CK_FAILURE_EXPERIENCE_SESSION_1" and
                historical.get("binding") == lesson["historical_binding"] and
                historical.get("task_type") == lesson["task_type"] and
                lesson["dependencies"] == {k: v["sha256"] for k, v in
                    historical.get("dependencies", {}).items()} and
                historical.get("premises") == lesson["premises"],
                "EXPERIENCE_HISTORY_SOURCE_CONFLICT")
        require(lesson["task_type"] in TASK_TYPES and lesson["effect_status"] in {
            "KNOWN_NONPASS", "UNKNOWN"}, "EXPERIENCE_LESSON_STATUS")
        require(type(lesson["dependencies"]) is dict and bool(lesson["dependencies"])
                and len(lesson["dependencies"]) <= 32 and all(hash_text(x)
                for x in lesson["dependencies"].values()), "EXPERIENCE_LESSON_DEPENDENCIES")
        origin, effect, observations = self.origin(lesson["origin"]["bridge_receipt"]["path"])
        require(origin == lesson["origin"] and effect == lesson["effect_status"] and
                observations == lesson["observations"], "EXPERIENCE_LESSON_ORIGIN_CHANGED")
        require((lesson["historical_binding"]["task_id"],
                 lesson["historical_binding"]["task_revision"],
                 lesson["historical_binding"]["authority_hash"]) == (
                    origin["task_id"], origin["task_revision"], origin["authority_hash"]),
                    "EXPERIENCE_HISTORY_BINDING")
        return lesson, _reference(path, raw)

    def match(self, lesson):
        key = lesson["lesson_id"]
        require(key not in self.s["revoked_lesson_ids"], "REVOKED_LESSON")
        require(key not in self.s["conflicting_lesson_ids"], "CONFLICTING_LESSON")
        require(lesson["task_type"] == self.s["task_type"], "OTHER_TASK_TYPE")
        for dep, value in lesson["dependencies"].items():
            require(dep in self.s["dependencies"], "APPLICABILITY_UNRESOLVED")
            ref = self.s["dependencies"][dep]
            self.reader.raw(ref["path"], ref)
            require(value == ref["sha256"], "NEEDS_REVIEW:" + dep)
        require(type(lesson["premises"]) is dict and all(
            self.s["premises"].get(k) == v for k, v in lesson["premises"].items()),
            "PREMISE_MISSING_OR_CHANGED")

    def confirmed_cause(self, lesson, lesson_ref):
        cause = lesson["cause"]
        require(type(cause) is dict and cause.get("status") in ("UNKNOWN", "CONFIRMED"),
                "EXPERIENCE_CAUSE")
        if cause["status"] == "UNKNOWN":
            return {"status": "UNKNOWN"}, None
        expected = self.s["lesson_proofs"].get(lesson["lesson_id"])
        require(type(expected) is dict, "INDEPENDENT_PROOF_MISSING")
        require(expected["path"] not in self.s["revoked_proof_refs"], "REVOKED_PROOF")
        proof = self.reader.json(expected)
        exact_fields(proof, "schema lesson_sha256 verifier_id author_id claims validation_scope supports",
                     "EXPERIENCE_HISTORY_PROOF_FIELDS")
        require(proof["schema"] == "CK_FAILURE_HISTORY_PROOF_1" and
                proof["lesson_sha256"] == lesson_ref["sha256"] and
                proof["verifier_id"] == expected["verifier_id"] and
                proof["verifier_id"] != proof["author_id"] and
                type(proof["claims"]) is list and 0 < len(proof["claims"]) <= 16 and
                all(type(x) is str and 0 < len(x) <= 1024 for x in proof["claims"]) and
                proof["claims"] == cause.get("claims") and
                type(proof["validation_scope"]) is str and 0 < len(proof["validation_scope"]) <= 1024 and
                type(proof["supports"]) is list and 2 <= len(proof["supports"]) <= 16,
                "INDEPENDENT_PROOF_CONFLICT")
        # The pinned independent review must identify a control and candidate,
        # not just an author supplied `verified` string or a hash catalogue.
        outcomes = {}
        support_paths, support_hashes = set(), set()
        for support in proof["supports"]:
            exact_fields(support, "role path sha256 bytes", "EXPERIENCE_PROOF_SUPPORT")
            role = support["role"]
            require(role in {"control", "candidate"} and role not in outcomes and
                    support["path"] not in support_paths and support["sha256"] not in support_hashes,
                    "INDEPENDENT_CONTROL_REQUIRED")
            support_paths.add(support["path"])
            support_hashes.add(support["sha256"])
            outcome = self.reader.json(support)
            exact_fields(outcome, "schema case_id input_source outcome bridge_receipt claims validation_scope",
                         "EXPERIENCE_COMPARISON_FIELDS")
            require(outcome["schema"] == "CK_FAILURE_CONTROL_RESULT_1" and
                    type(outcome["case_id"]) is str and 0 < len(outcome["case_id"]) <= 128 and
                    outcome["claims"] == proof["claims"] and
                    outcome["validation_scope"] == proof["validation_scope"],
                    "INDEPENDENT_COMPARISON_CONFLICT")
            iref = outcome["input_source"]
            self.reader.raw(iref["path"], iref)
            self.reader.raw(outcome["bridge_receipt"]["path"], outcome["bridge_receipt"])
            source_origin, effect, _ = self.origin(outcome["bridge_receipt"]["path"])
            require(source_origin["native_receipt"] is not None and effect in {
                    "KNOWN_NONPASS", "KNOWN_PASS"}, "INDEPENDENT_COMPARISON_UNRESOLVED")
            process = self.reader.json(source_origin["native_receipt"])
            input_path = Path(iref["path"])
            tracked_root = Path(process["tracked_root"])
            require(tracked_root in input_path.parents and process["tracked_files"].get(
                    input_path.relative_to(tracked_root).as_posix()) == iref["sha256"],
                    "INDEPENDENT_COMPARISON_INPUT")
            require(outcome["outcome"] == ("PASS" if effect == "KNOWN_PASS" else "NONPASS") and
                    ((role == "candidate" and effect == "KNOWN_PASS") or
                     (role == "control" and effect == "KNOWN_NONPASS")),
                    "INDEPENDENT_COMPARISON_RESULT")
            outcomes[role] = (outcome, process, source_origin)
        require(set(outcomes) == {"control", "candidate"}, "INDEPENDENT_CONTROL_REQUIRED")
        control, candidate = outcomes["control"], outcomes["candidate"]
        require(control[0]["case_id"] == candidate[0]["case_id"] and
                control[0]["input_source"]["sha256"] == candidate[0]["input_source"]["sha256"] and
                control[2]["operation_id"] != candidate[2]["operation_id"] and
                all(control[1][k] == candidate[1][k] for k in (
                    "actual_argv", "actual_env_sha256", "timeout_seconds", "program_sha256")),
                "INDEPENDENT_COMPARISON_CONDITIONS")
        return {"status": "CONFIRMED", "claims": proof["claims"],
                "validation_scope": proof["validation_scope"]}, expected

    def prepare(self):
        scope = self.current()
        binding = self.s["binding"]
        orch = OrchestrationStore(self.s["orchestration_path"], workspace=self.controller.workspace)
        restored = orch.restore(binding["task_id"], current_task_revision=binding["task_revision"],
            current_grant_digest=binding["authority_hash"], current_candidate_hash=binding["candidate_sha256"])
        require(restored["status"] not in {"STALE_BINDING", "LEASE_EXPIRED"},
                "EXPERIENCE_CURRENT_RESTORE")
        leases = [x for x in restored["leases"] if x["lease_id"] == binding["lease_id"]]
        require(len(leases) == 1 and leases[0]["node_id"] == self.s["node_id"] and
                self.s["expires_at"] <= leases[0]["expires_at"], "EXPERIENCE_CURRENT_LEASE")
        history = Path(self.s["history_root"])
        files = sorted(history.glob("*.lesson.json")) if history.exists() else []
        require(len(files) <= self.s["max_candidates"], "EXPERIENCE_DISCOVERY_LIMIT")
        folder = Path(self.config["state_root"]) / "failure-experience" / "preparations" / uuid.uuid4().hex
        folder.mkdir(parents=True)
        picked, excluded, materials, source_files = [], [], {}, {}
        for path in files:
            try:
                lesson, lref = self.checked_lesson(path)
                self.match(lesson)
                cause, historical_proof = self.confirmed_cause(lesson, lref)
                picked.append((lesson, lref, cause, historical_proof))
            except (Denied, OSError, ValueError, KeyError, TypeError) as exc:
                reason = str(exc) if isinstance(exc, Denied) else type(exc).__name__
                excluded.append({"path": str(path), "reason": reason})
        by_id = {}
        duplicates = set()
        for lesson, _, _, _ in picked:
            key = lesson["lesson_id"]
            if key in by_id:
                duplicates.add(key)
            by_id[key] = lesson
        superseded = set()
        invalid_corrections = set()
        for lesson, lref, _, _ in picked:
            if lesson["lesson_id"] in duplicates:
                invalid_corrections.add(lref["path"])
                excluded.append({"path": lref["path"], "reason": "DUPLICATE_LESSON_ID"})
                continue
            prior = lesson["supersedes"]
            if prior is not None:
                old = by_id.get(prior) if hash_text(prior) else None
                if not (old is not None and prior != lesson["lesson_id"] and
                        prior not in duplicates and old["supersedes"] is None and
                        lesson["version"] == old["version"] + 1 and
                        lesson["origin"] == old["origin"] and
                        lesson["historical_session"] == old["historical_session"]):
                    invalid_corrections.add(lref["path"])
                    excluded.append({"path": lref["path"], "reason": "INVALID_CORRECTION_RELATION"})
                else:
                    superseded.add(prior)
        active = []
        for item in picked:
            if item[1]["path"] in invalid_corrections:
                continue
            if item[0]["lesson_id"] in superseded:
                excluded.append({"path": item[1]["path"], "reason": "SUPERSEDED"})
            else:
                active.append(item)

        selection = {"schema": "CK_FAILURE_SELECTION_1", "current_binding": binding,
            "selected": [{"lesson_id": x[0]["lesson_id"], "lesson_ref": x[1]} for x in active],
            "excluded": excluded, "dispatch_allowed": False}
        matched_ref = _save(folder / "matched-selection.json", {
            **selection, "phase": "MATCHED_NOT_YET_CORE_VALIDATED"})
        try:
            return self._prepare_matched(scope, binding, orch, restored, folder,
                                         active, materials, source_files, selection, matched_ref)
        except BaseException as exc:
            # Preserve the original core refusal. Diagnostic persistence must
            # never turn it into an authorization or mask it with an IO error.
            try:
                _save(folder / "preparation-failure.json", {
                    "schema": "CK_FAILURE_PREPARATION_FAILURE_1",
                    "phase": "AFTER_MATCHING_BEFORE_PREPARED",
                    "error_type": type(exc).__name__,
                    "matched_selection": matched_ref, "dispatch_allowed": False})
                _save(folder / "failure-reads.json", {
                    "pid": os.getpid(), "reads": self.reader.reads,
                    "dispatch_allowed": False})
            except BaseException:
                pass
            raise

    def _prepare_matched(self, scope, binding, orch, restored, folder, active,
                         materials, source_files, selection, matched_ref):

        def verify_material(entry, verifier, verification_source):
            require(verifier == "host-evidence-reader", "EXPERIENCE_VERIFIER")
            material = materials.get(entry["entry_id"])
            require(material is not None and entry["binding"] == binding and
                    entry["source"] == material["source"] and
                    verification_source == material["verification_source"], "EXPERIENCE_CURRENT_PROOF")
            self.current()
            lesson, lref = self.checked_lesson(material["lesson_ref"]["path"], material["lesson_ref"])
            self.match(lesson)
            cause, _ = self.confirmed_cause(lesson, lref)
            reference = self.reader.json(material["reference_ref"])
            proof = self.reader.json(material["proof_ref"])
            require(reference == material["reference"] and proof == material["proof"] and
                    reference["current_binding"] == binding and reference["cause"] == cause and
                    proof["reference_sha256"] == entry["source"]["sha256"] and
                    proof["lesson_sha256"] == lref["sha256"], "EXPERIENCE_CURRENT_PROOF")
            require(entry["text"] == canonical(reference["advisory"]).decode("utf-8"),
                    "EXPERIENCE_ADVISORY_TEXT")
            return True

        memory = MemoryStore(self.s["memory_path"], verification_check=verify_material)
        for lesson, lref, cause, _ in active:
            entry_id = "failure-" + uuid.uuid4().hex
            advisory = {"authority": "ADVISORY_ONLY", "historical_origin": {
                k: lesson["origin"][k] for k in ("run_id", "task_id", "task_revision", "operation_id")},
                "effect_status": lesson["effect_status"], "observations": lesson["observations"],
                "cause": cause, "applicability": {"dependencies": lesson["dependencies"],
                                                 "premises": lesson["premises"]},
                "replay_authorized": False, "current_authority_required": True}
            reference = {"schema": "CK_FAILURE_CURRENT_REFERENCE_1", "entry_id": entry_id,
                         "current_binding": binding, "lesson_ref": lref,
                         "cause": cause, "advisory": advisory}
            proof = {"schema": "CK_FAILURE_CURRENT_PROOF_1", "current_binding": binding,
                     "reference_sha256": digest(reference), "lesson_sha256": lref["sha256"],
                     "verifier_id": "host-evidence-reader", "author_id": "failure-reference-adapter",
                     "validation_scope": "Current applicability and real receipt only; no new cause claim"}
            rref = _save(folder / (entry_id + ".reference.json"), reference)
            pref = _save(folder / (entry_id + ".proof.json"), proof)
            source = {"id": entry_id + "-source", "version": "1", "sha256": rref["sha256"],
                      "evidence_refs": ["public/memory-sources/" + entry_id + ".json"]}
            vsource = {"id": entry_id + "-proof", "version": "1", "sha256": pref["sha256"],
                       "evidence_refs": ["public/proofs/" + entry_id + ".json"]}
            materials[entry_id] = {"source": source, "verification_source": vsource,
                "lesson_ref": lref, "reference_ref": rref, "proof_ref": pref,
                "reference": reference, "proof": proof}
            for src, ref in ((source, rref), (vsource, pref)):
                source_files[src["id"]] = (src, ref, entry_id)
            memory.propose(entry_id=entry_id, kind="COGNITION",
                text=canonical(advisory).decode("utf-8"), source=source,
                proposed_by="failure-reference-adapter", binding=binding, expires_at=self.s["expires_at"])
            memory.verify(entry_id, verifier_id="host-evidence-reader", verification_source=vsource)

        def read_file_evidence(current_binding, source):
            require(current_binding == binding and source["id"] in source_files,
                    "EXPERIENCE_FILE_SOURCE")
            registered, ref, eid = source_files[source["id"]]
            require(registered == source, "EXPERIENCE_FILE_SOURCE")
            m = materials[eid]
            verify_material({"entry_id": eid, "binding": binding, "source": m["source"],
                             "text": canonical(m["reference"]["advisory"]).decode("utf-8")},
                            "host-evidence-reader", m["verification_source"])
            return {"binding": deepcopy(binding), "source": deepcopy(source),
                    "ref": source["evidence_refs"][0], "content": self.reader.raw(ref["path"], ref),
                    "read_policy_sha256": self.reader.policy_hash}

        def read_advisory_current():
            self.current()
            current_sources = {}
            for src, ref, eid in source_files.values():
                m = materials[eid]
                verify_material({"entry_id": eid, "binding": binding, "source": m["source"],
                                 "text": canonical(m["reference"]["advisory"]).decode("utf-8")},
                                "host-evidence-reader", m["verification_source"])
                self.reader.raw(ref["path"], ref)
                current_sources[src["id"]] = {"version": src["version"], "sha256": ref["sha256"]}
            return {"current_sources": current_sources, "current_skill_versions": {},
                    "revoked_source_ids": [], "revoked_entry_ids": [], "conflicting_entry_ids": []}

        service = EvidenceProjection(self.controller, orch, memory, read_file_evidence=read_file_evidence)
        service.rebuild_index()
        view = service.context_inputs(binding, read_advisory_current=read_advisory_current)
        source = {**view, "verified_scope": scope, "rule_ids": self.s["rule_ids"],
                  "hard_constraints": build_hard_constraints_from_scope(scope,
                    rules_version=binding["rules_version"], rule_ids=self.s["rule_ids"]),
                  "orchestration": restored}
        loads = []

        def read_projection_current(phash, current_binding):
            observed = service.load_projection(phash, current_binding,
                                              read_advisory_current=read_advisory_current)
            loads.append({"pid": os.getpid(), "projection_hash": phash,
                          "binding": deepcopy(current_binding), "load": len(loads) + 1})
            return observed

        def read_current():
            self.current()
            return {"task_binding": binding, "heads": service.current_heads(
                binding, read_advisory_current=read_advisory_current)}

        context = context_bundle(binding, view["heads"], self.s["max_items"], self.s["max_bytes"],
            capture_sources=lambda: deepcopy(source), read_current=read_current,
            read_projection_current=read_projection_current)
        sref = _save(folder / "selection.json", selection)
        cref = _save(folder / "context.json", context)
        rref = _save(folder / "reads.json", {"pid": os.getpid(), "reads": self.reader.reads,
                                             "projection_loads": loads})
        return {"status": "PREPARED" if context.get("capsule") is not None else "NOT_PREPARED",
                "current_binding": binding, "selection_path": sref["path"],
                "matched_selection_path": matched_ref["path"],
                "context_path": cref["path"], "reads_path": rref["path"], "context": context,
                "restore": restored, "dispatch_allowed": False, "model_usage": "N/A"}


def archive_receipt(receipt_path, *, bridge_binding, config, descriptor_path, descriptor_sha256):
    return FailureExperience(bridge_binding, config, descriptor_path, descriptor_sha256).archive(receipt_path)


def prepare_context(*, bridge_binding, config, descriptor_path, descriptor_sha256):
    return FailureExperience(bridge_binding, config, descriptor_path, descriptor_sha256).prepare()
