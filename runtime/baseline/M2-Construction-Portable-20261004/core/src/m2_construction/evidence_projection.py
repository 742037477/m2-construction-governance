"""Read-only atomic evidence snapshots and rebuildable advisory projections.

The index and projection tables are disposable caches. Ledger events, signed
grants, operations, orchestration state, and memory events remain the sources.
No result from this module grants dispatch or changes an operation's status.
"""

from pathlib import Path, PurePosixPath
from copy import deepcopy
import sqlite3
import time

from .contracts import canonical, bytes_hash, digest, hash_text, require, strict_json
from .controller import Controller
from .artifacts import verify_frozen_candidate
from .memory import MemoryStore, _binding
from .orchestration import OrchestrationStore
from .trust import load_pin, verify_signed_scope


_ZERO = "0" * 64
_SELECTORS = frozenset({"project_id", "ledger_id", "operation_id", "candidate_sha256",
                        "kind", "evidence_id", "event_hash", "file_sha256"})
_INDEX_FIELDS = ("project_id", "ledger_id", "event_seq", "event_hash", "body_hash",
                 "task_id", "task_revision", "authority_hash", "operation_id",
                 "candidate_sha256", "kind", "evidence_id", "file_path", "file_sha256")
_ADVISORY_FIELDS = frozenset({"current_sources", "current_skill_versions",
                              "revoked_source_ids", "revoked_entry_ids",
                              "conflicting_entry_ids"})


def _head(rows):
    return {"seq": rows[-1][0], "event_hash": rows[-1][3]} if rows else {
        "seq": 0, "event_hash": _ZERO}


def _file_bytes(path, directory, expected_name, expected_hash):
    """Read a fixed evidence filename without accepting a link or path escape."""
    require(hash_text(expected_hash), "EVIDENCE_FILE_HASH")
    require(type(path) is str, "EVIDENCE_FILE_PATH")
    actual = Path(path)
    require(actual == directory / expected_name, "EVIDENCE_FILE_PATH")
    require(actual.is_file(), "EVIDENCE_FILE_MISSING")
    require(not actual.is_symlink() and not directory.is_symlink() and
            actual.resolve(strict=True) == actual, "EVIDENCE_FILE_LINK")
    raw = actual.read_bytes()
    require(bytes_hash(raw) == expected_hash, "EVIDENCE_FILE_TAMPERED")
    return raw


def _advisory_state(*, current_sources, current_skill_versions,
                    revoked_source_ids, revoked_entry_ids, conflicting_entry_ids):
    require(type(current_sources) is dict and type(current_skill_versions) is dict,
            "ADVISORY_CURRENT_MANIFEST")
    state = {"current_sources": current_sources,
             "current_skill_versions": current_skill_versions}
    for name, values in (("revoked_source_ids", revoked_source_ids),
                         ("revoked_entry_ids", revoked_entry_ids),
                         ("conflicting_entry_ids", conflicting_entry_ids)):
        require(type(values) in (set, frozenset, list, tuple) and
                all(type(value) is str and value for value in values),
                "ADVISORY_CURRENT_MANIFEST")
        state[name] = sorted(set(values))
    return strict_json(canonical(state))


def _read_advisory_current(reader):
    state = reader()
    require(type(state) is dict and set(state) == _ADVISORY_FIELDS,
            "ADVISORY_CURRENT_MANIFEST")
    return _advisory_state(**state)


class EvidenceProjection:
    """Trusted host adapter for exact evidence lookup and source-bound projections.

    `Controller` supplies verified project, state, and Test Root identity. A
    caller-supplied project ID or task label is never used for attribution.
    Candidate attribution requires an explicit historical binding event; the
    present ledger does not have one, so its existing events stay UNASSIGNED.
    """

    def __init__(self, controller: Controller, orchestration: OrchestrationStore,
                 memory: MemoryStore, *, read_file_evidence=None):
        require(type(controller) is Controller and type(orchestration) is OrchestrationStore
                and type(memory) is MemoryStore, "EVIDENCE_TRUSTED_SOURCES")
        self.controller = controller
        self.orchestration = orchestration
        self.memory = memory
        require(read_file_evidence is None or callable(read_file_evidence),
                "FILE_EVIDENCE_TRUSTED_READER")
        self._read_file_evidence = read_file_evidence
        self.project_id = digest({"schema": "M2_PROJECT_ID_1",
                                  "workspace": str(controller.workspace),
                                  "pin_sha256": controller.expected_pin_sha256})
        self.ledger_id = digest({"schema": "M2_LEDGER_ID_1", "project_id": self.project_id,
                                 "state_root": str(controller.state_dir),
                                 "ledger_path": str(controller.ledger.path)})
        with self.controller.ledger.transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS evidence_index(
                project_id TEXT NOT NULL, ledger_id TEXT NOT NULL,
                event_seq INTEGER PRIMARY KEY, event_hash TEXT NOT NULL,
                body_hash TEXT NOT NULL, task_id TEXT, task_revision INTEGER,
                authority_hash TEXT, operation_id TEXT, candidate_sha256 TEXT,
                kind TEXT, evidence_id TEXT NOT NULL UNIQUE,
                file_path TEXT, file_sha256 TEXT)""")
            db.execute("""CREATE INDEX IF NOT EXISTS evidence_exact_lookup ON evidence_index(
                project_id,ledger_id,task_id,task_revision,authority_hash,
                operation_id,kind,event_seq)""")
            db.execute("""CREATE TABLE IF NOT EXISTS evidence_index_head(
                project_id TEXT NOT NULL, ledger_id TEXT NOT NULL,
                event_seq INTEGER NOT NULL, event_hash TEXT NOT NULL,
                PRIMARY KEY(project_id,ledger_id))""")
        with self.memory._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS evidence_projections(
                projection_hash TEXT PRIMARY KEY, payload_json TEXT NOT NULL)""")

    def _grant_scopes(self, db):
        load_pin(self.controller.pin_path, self.controller.expected_pin_sha256,
                 self.controller.workspace)
        scopes = {}
        for grant_id, raw, envelope_hash, revoked in db.execute(
                "SELECT grant_id,envelope_json,envelope_hash,revoked FROM grants"):
            signed = strict_json(raw)
            require(canonical(signed).decode("utf-8") == raw and
                    digest(signed) == envelope_hash and revoked in (0, 1),
                    "EVIDENCE_GRANT_TAMPERED")
            scope = verify_signed_scope(signed, self.controller.pin_path,
                                        self.controller.expected_pin_sha256,
                                        self.controller.workspace)
            self.controller._validate_scope(scope)
            require(scope["grant_id"] == grant_id, "EVIDENCE_GRANT_CONFLICT")
            scopes[grant_id] = (scope, revoked)
        return scopes

    def _receipt_file(self, event, operation_id, operation, intent):
        result = strict_json(operation["result_json"])
        require(result.get("operation_id") == operation_id and
                result.get("effect_executed") is True,
                "EVIDENCE_RECEIPT_CONFLICT")
        if operation["kind"] == "PATCH":
            require(result.get("status") == "COMPLETED" and
                    result.get("before_sha256") == operation["before_sha256"] and
                    result.get("after_sha256") == operation["after_sha256"] ==
                    event.get("actual_sha256") and
                    event.get("request_hash") == operation["request_hash"],
                    "EVIDENCE_RECEIPT_CONFLICT")
            return None, None, operation["after_sha256"]
        if operation["kind"] == "CREATE":
            expected = operation["after_sha256"]
            require(result.get("status") == "COMPLETED" and
                    result.get("before_state") == "ABSENT" and
                    result.get("after_sha256") == expected ==
                    intent.get("after_sha256") == event.get("actual_sha256") and
                    event.get("request_hash") == operation["request_hash"],
                    "EVIDENCE_RECEIPT_CONFLICT")
            # The receipt proves the original effect. A later governed PATCH
            # may replace those bytes; current-file verification follows the
            # ordered receipt chain after every event has been checked.
            return None, None, expected
        require(operation["kind"] in ("TEST", "BUILD") and
                result.get("receipt_sha256") == operation["after_sha256"] ==
                event.get("receipt_sha256") and
                result.get("status") == event.get("status") and
                event.get("request_hash") == operation["request_hash"],
                "EVIDENCE_RECEIPT_CONFLICT")
        directory = self.controller.state_dir / "evidence"
        receipt_path = result.get("receipt_path")
        raw = _file_bytes(receipt_path, directory,
                          operation_id + ".receipt.json", result["receipt_sha256"])
        receipt = strict_json(raw)
        require(canonical(receipt) == raw and receipt.get("operation_id") == operation_id
                and receipt.get("status") == result["status"] and
                receipt.get("exit_code") == result.get("exit_code"),
                "EVIDENCE_RECEIPT_CONFLICT")
        _file_bytes(receipt.get("log_path"), directory, operation_id + ".log",
                    receipt.get("log_sha256"))
        return str(receipt_path), result["receipt_sha256"], None

    def _frozen_file(self, event, operation_id, operation, intents, operations,
                     typed_receipts, scopes):
        """Bind a frozen manifest to the original FREEZE and passing TEST IDs."""
        require(operation["kind"] == "FREEZE" and operation["status"] == "COMPLETED" and
                operation_id in intents, "EVIDENCE_FREEZE_CONFLICT")
        result = strict_json(operation["result_json"])
        candidate = operation["after_sha256"]
        path = self.controller.state_dir / "evidence" / "candidates" / (
            operation_id + ".manifest.json")
        require(hash_text(candidate) and operation["path"] == str(path) and
                result.get("operation_id") == operation_id and
                result.get("status") == "FROZEN" and
                result.get("effect_executed") is True and
                result.get("manifest_path") == event.get("manifest_path") == str(path) and
                result.get("manifest_sha256") == event.get("manifest_sha256") == candidate and
                result.get("candidate_sha256") == candidate,
                "EVIDENCE_FREEZE_CONFLICT")
        raw = _file_bytes(str(path), path.parent, path.name, candidate)
        manifest = strict_json(raw)
        require(canonical(manifest) == raw and
                manifest.get("root") == str(self.controller.workspace) and
                type(manifest.get("files")) is dict and
                set(manifest["files"]) <= set(
                    scopes[operation["grant_id"]][0]["allowed_files"]),
                "EVIDENCE_FREEZE_CONFLICT")
        refs = manifest.get("test_receipts")
        intent_ids = intents[operation_id].get("test_operation_ids")
        require(type(refs) is list and bool(refs) and
                type(intent_ids) is list and len(intent_ids) == len(set(intent_ids)) and
                set(intent_ids) == {ref.get("operation_id") for ref in refs
                                    if type(ref) is dict} and
                len(refs) == len(intent_ids), "EVIDENCE_FREEZE_TEST_CONFLICT")
        scope = scopes[operation["grant_id"]][0]
        for ref in refs:
            test_id = ref["operation_id"]
            test_op = operations.get(test_id)
            typed = typed_receipts.get(test_id)
            test_result = (strict_json(test_op["result_json"])
                           if test_op is not None and test_op["result_json"] is not None
                           else {})
            require(test_op is not None and test_op["kind"] == "TEST" and
                    test_op["grant_id"] == operation["grant_id"] and
                    test_op["task_id"] == scope["task_id"] and
                    test_op["status"] == "COMPLETED" and typed is not None and
                    typed["kind"] == "TEST_RECEIPT" and
                    typed["status"] == "PASSED" and
                    typed["receipt_sha256"] == ref["receipt_sha256"] ==
                    test_op["after_sha256"] and
                    ref.get("receipt_path") == test_result.get("receipt_path"),
                    "EVIDENCE_FREEZE_TEST_CONFLICT")
        verified = verify_frozen_candidate(
            path, expected_manifest_sha256=candidate,
            require_workspace_current=False)
        require(result.get("file_count") == verified["file_count"],
                "EVIDENCE_FREEZE_CONFLICT")
        return str(path), candidate, candidate

    def _source_records(self, db):
        self.controller.ledger.verify_chain(db)
        rows = db.execute("SELECT seq,prev_hash,body_hash,event_hash,body_json "
                          "FROM events ORDER BY seq").fetchall()
        scopes = self._grant_scopes(db)
        operations = {}
        for row in db.execute("SELECT operation_id,grant_id,task_id,kind,path,request_hash,"
                              "status,before_sha256,after_sha256,result_json FROM operations"):
            (operation_id, grant_id, task_id, kind, path, request_hash, status,
             before_hash, after_hash, raw) = row
            require(grant_id in scopes and kind in ("PATCH", "CREATE", "TEST", "BUILD", "FREEZE") and
                    status in ("INTENT", "COMPLETED", "UNKNOWN") and
                    hash_text(request_hash) and
                    (before_hash == "ABSENT" if kind == "CREATE" else
                     hash_text(before_hash)),
                    "EVIDENCE_OPERATION_CONFLICT")
            scope = scopes[grant_id][0]
            require(task_id == scope["task_id"], "EVIDENCE_OPERATION_CONFLICT")
            if kind == "CREATE":
                require(scope["schema"] == "M2_CONSTRUCTION_SCOPE_3" and
                        "CREATE" in scope["allowed_effects"] and
                        path in scope["creatable_files"] and
                        scope["baseline_files"][path] is None and
                        (hash_text(after_hash) and raw is not None
                         if status == "COMPLETED" else
                         after_hash is None and raw is None),
                        "EVIDENCE_OPERATION_CONFLICT")
            operations[operation_id] = {"grant_id": grant_id, "task_id": task_id,
                                        "kind": kind, "path": path,
                                        "request_hash": request_hash, "status": status,
                                        "before_sha256": before_hash,
                                        "after_sha256": after_hash, "result_json": raw}
        counts = {}
        granted = set()
        revoked = set()
        intents = {}
        typed_receipts = {}
        frozen = {}
        records = []
        for seq, _, body_hash, event_hash, raw in rows:
            body = strict_json(raw)
            kind = body.get("kind")
            grant_id = body.get("grant_id")
            operation_id = body.get("operation_id")
            file_path = file_sha256 = effect_sha256 = None
            scope = None
            if kind in ("SCOPE_GRANTED", "SCOPE_REVOKED"):
                require(grant_id in scopes, "EVIDENCE_GRANT_MISSING")
                scope = scopes[grant_id][0]
                if kind == "SCOPE_GRANTED":
                    require(grant_id not in granted and body.get("scope_hash") == digest(scope)
                            and body.get("root_domain") == "TEST_ONLY",
                            "EVIDENCE_GRANT_CONFLICT")
                    granted.add(grant_id)
                else:
                    require(grant_id in granted and grant_id not in revoked,
                            "EVIDENCE_GRANT_CONFLICT")
                    revoked.add(grant_id)
            elif kind in ("GATE_ALLOW", "INTENT", "RECEIPT", "TEST_RECEIPT",
                          "BUILD_RECEIPT", "CANDIDATE_FROZEN", "UNKNOWN"):
                require(operation_id in operations, "EVIDENCE_OPERATION_MISSING")
                operation = operations[operation_id]
                grant_id = operation["grant_id"]
                scope = scopes[grant_id][0]
                count = counts.setdefault(operation_id, {})
                count[kind] = count.get(kind, 0) + 1
                require(count[kind] == 1, "EVIDENCE_OPERATION_CONFLICT")
                if kind == "GATE_ALLOW":
                    require(grant_id in granted and body.get("grant_id") == grant_id and
                            body.get("request_hash") == operation["request_hash"],
                            "EVIDENCE_OPERATION_CONFLICT")
                else:
                    require(count.get("GATE_ALLOW") == 1, "EVIDENCE_OPERATION_CONFLICT")
                if kind == "INTENT":
                    if operation["kind"] == "PATCH":
                        require(body.get("path") == operation["path"] and
                                body.get("before_sha256") == operation["before_sha256"],
                                "EVIDENCE_OPERATION_CONFLICT")
                    elif operation["kind"] == "CREATE":
                        expected = body.get("after_sha256")
                        require(body.get("path") == operation["path"] and
                                body.get("before_state") == "ABSENT" and
                                hash_text(expected) and
                                operation["request_hash"] == digest({
                                    "schema": "M2_CONSTRUCTION_CREATE_1",
                                    "grant_id": grant_id,
                                    "task_id": operation["task_id"],
                                    "task_revision": scope["task_revision"],
                                    "operation_id": operation_id,
                                    "path": operation["path"],
                                    "content_sha256": expected}),
                                "EVIDENCE_OPERATION_CONFLICT")
                    elif operation["kind"] in ("TEST", "BUILD"):
                        require(body.get("command_id") == operation["path"] and
                                body.get("source_hash") == operation["before_sha256"],
                                "EVIDENCE_OPERATION_CONFLICT")
                    else:
                        require(body.get("source_hash") == operation["before_sha256"] and
                                type(body.get("test_operation_ids")) is list and
                                bool(body["test_operation_ids"]),
                                "EVIDENCE_FREEZE_CONFLICT")
                    intents[operation_id] = body
                elif kind == "RECEIPT":
                    require(count.get("INTENT") == 1 and operation["status"] == "COMPLETED" and
                            operation["kind"] != "FREEZE",
                            "EVIDENCE_RECEIPT_CONFLICT")
                    file_path, file_sha256, effect_sha256 = self._receipt_file(
                        body, operation_id, operation, intents[operation_id])
                elif kind in ("TEST_RECEIPT", "BUILD_RECEIPT"):
                    require(count.get("RECEIPT") == 1 and
                            operation["kind"] == kind.split("_")[0] and
                            body.get("grant_id") == grant_id and
                            body.get("task_id") == scope["task_id"] and
                            body.get("task_revision") == scope["task_revision"] and
                            body.get("receipt_sha256") == operation["after_sha256"],
                            "EVIDENCE_RECEIPT_CONFLICT")
                    result = strict_json(operation["result_json"])
                    require(body.get("status") == result.get("status"),
                            "EVIDENCE_RECEIPT_CONFLICT")
                    typed_receipts[operation_id] = body
                    file_path = result["receipt_path"]
                    file_sha256 = body["receipt_sha256"]
                elif kind == "CANDIDATE_FROZEN":
                    require(count.get("INTENT") == 1 and
                            body.get("grant_id") == grant_id and
                            body.get("task_id") == scope["task_id"] and
                            body.get("task_revision") == scope["task_revision"],
                            "EVIDENCE_FREEZE_CONFLICT")
                    file_path, file_sha256, effect_sha256 = self._frozen_file(
                        body, operation_id, operation, intents, operations,
                        typed_receipts, scopes)
                    frozen[operation_id] = file_sha256
                elif kind == "UNKNOWN":
                    require(count.get("INTENT") == 1, "EVIDENCE_OPERATION_CONFLICT")
            # OBS and AUTHOR_ATTESTED remain unattributed here: signed author
            # provenance does not itself bind an event to current Gate authority.
            # Other unknown events likewise cannot use their own task_id text.
            evidence_id = digest({"schema": "M2_EVIDENCE_ID_1", "ledger_id": self.ledger_id,
                                  "seq": seq, "event_hash": event_hash})
            records.append({"project_id": self.project_id, "ledger_id": self.ledger_id,
                            "event_seq": seq, "event_hash": event_hash,
                            "body_hash": body_hash, "body": body,
                            "task_id": scope["task_id"] if scope else None,
                            "task_revision": scope["task_revision"] if scope else None,
                            "authority_hash": digest(scope) if scope else None,
                            "operation_id": operation_id if scope else None,
                            "candidate_sha256": frozen.get(operation_id),
                            "candidate_status": ("FROZEN" if operation_id in frozen else
                                                 "UNASSIGNED"),
                            "kind": kind, "evidence_id": evidence_id,
                            "file_path": file_path, "file_sha256": file_sha256,
                            "effect_sha256": effect_sha256})
        require(granted == set(scopes) and
                revoked == {grant_id for grant_id, (_, flag) in scopes.items() if flag},
                "EVIDENCE_GRANT_CONFLICT")
        for operation_id, operation in operations.items():
            count = counts.get(operation_id, {})
            require(count.get("GATE_ALLOW") == 1 and count.get("INTENT") == 1,
                    "EVIDENCE_OPERATION_CONFLICT")
            if operation["status"] == "COMPLETED":
                if operation["kind"] == "FREEZE":
                    require(count.get("CANDIDATE_FROZEN") == 1 and
                            not count.get("RECEIPT"), "EVIDENCE_FREEZE_MISSING")
                else:
                    require(count.get("RECEIPT") == 1 and
                            count.get(operation["kind"] + "_RECEIPT", 1 if
                                      operation["kind"] in ("PATCH", "CREATE") else 0) == 1,
                            "EVIDENCE_RECEIPT_MISSING")
            if operation["status"] == "UNKNOWN":
                require(count.get("UNKNOWN") == 1, "EVIDENCE_UNKNOWN_MISSING")
            if operation["kind"] == "CREATE":
                require((not count.get("UNKNOWN") if operation["status"] == "COMPLETED"
                         else not count.get("RECEIPT")),
                        "EVIDENCE_OPERATION_CONFLICT")
        mutations = [(record, operations[record["operation_id"]])
                     for record in records if record["kind"] == "RECEIPT" and
                     operations[record["operation_id"]]["kind"] in ("CREATE", "PATCH")]
        for index, (record, operation) in enumerate(mutations):
            if operation["kind"] != "CREATE":
                continue
            resource = self.controller._resource_key(operation["path"])
            expected = operation["after_sha256"]
            latest_record = record
            for later, successor in mutations[index + 1:]:
                if self.controller._resource_key(successor["path"]) != resource:
                    continue
                require(successor["kind"] == "PATCH" and
                        successor["before_sha256"] == expected,
                        "EVIDENCE_EFFECT_CHAIN_CONFLICT")
                expected = successor["after_sha256"]
                latest_record = later
            target = self.controller._target(operation["path"])
            _file_bytes(str(target), target.parent, target.name, expected)
            latest_record["file_path"] = str(target)
            latest_record["file_sha256"] = expected
        # A valid freeze explicitly binds its own earlier GATE_ALLOW and INTENT
        # events to this manifest. TEST receipts can serve multiple candidates,
        # so they retain UNASSIGNED candidate status.
        for record in records:
            candidate = frozen.get(record["operation_id"])
            if candidate is not None:
                record["candidate_sha256"] = candidate
                record["candidate_status"] = "FROZEN"
        return records, _head(rows), scopes

    @staticmethod
    def _index_row(record):
        return tuple(record[key] for key in _INDEX_FIELDS)

    def rebuild_index(self):
        """Atomically replace only disposable index rows after verifying sources."""
        with self.controller.ledger.transaction() as db:
            records, head, _ = self._source_records(db)
            db.execute("DELETE FROM evidence_index")
            placeholders = ",".join("?" for _ in _INDEX_FIELDS)
            db.executemany("INSERT INTO evidence_index(" + ",".join(_INDEX_FIELDS) +
                           ") VALUES(" + placeholders + ")",
                           [self._index_row(record) for record in records])
            db.execute("INSERT INTO evidence_index_head VALUES(?,?,?,?) ON CONFLICT(" 
                       "project_id,ledger_id) DO UPDATE SET event_seq=excluded.event_seq,"
                       "event_hash=excluded.event_hash",
                       (self.project_id, self.ledger_id, head["seq"], head["event_hash"]))
        return {"status": "REBUILT", "head": head, "indexed_count": len(records),
                "authority": False}

    def _check_index(self, db, records, head):
        stored = db.execute("SELECT event_seq,event_hash FROM evidence_index_head "
                            "WHERE project_id=? AND ledger_id=?",
                            (self.project_id, self.ledger_id)).fetchone()
        require(stored == (head["seq"], head["event_hash"]), "STALE_INDEX")
        rows = db.execute("SELECT " + ",".join(_INDEX_FIELDS) +
                          " FROM evidence_index ORDER BY event_seq").fetchall()
        require(rows == [self._index_row(record) for record in records],
                "EVIDENCE_INDEX_TAMPERED")

    def _current_scope(self, db, binding, scopes):
        matching = [(grant_id, scope) for grant_id, (scope, _) in scopes.items()
                    if scope["task_id"] == binding["task_id"] and
                    scope["task_revision"] == binding["task_revision"] and
                    digest(scope) == binding["authority_hash"]]
        require(len(matching) == 1, "UNRESOLVED_GRANT")
        grant_id, scope = matching[0]
        self.controller._current_scope(db, grant_id, binding["task_id"],
                                       binding["task_revision"])
        return scope

    def evidence_snapshot(self, binding, selectors, expected_head=None, limit=100):
        """Exact, bounded lookup under a stable verified ledger snapshot."""
        _binding(binding)
        require(type(selectors) is dict and set(selectors) <= _SELECTORS and
                type(limit) is int and 0 < limit <= 1000, "EVIDENCE_SELECTORS")
        for key in ("event_hash", "evidence_id", "file_sha256", "candidate_sha256"):
            if key in selectors:
                require(hash_text(selectors[key]), "EVIDENCE_SELECTOR_HASH")
        if "project_id" in selectors:
            require(selectors["project_id"] == self.project_id, "PROJECT_ID_MISMATCH")
        if "ledger_id" in selectors:
            require(selectors["ledger_id"] == self.ledger_id, "LEDGER_ID_MISMATCH")
        with sqlite3.connect(self.controller.ledger.path) as db:
            db.execute("BEGIN")
            records, head, scopes = self._source_records(db)
            if expected_head is not None:
                require(expected_head == head, "STALE_SNAPSHOT")
            self._check_index(db, records, head)
            self._current_scope(db, binding, scopes)
            base = [record for record in records
                    if record["task_id"] == binding["task_id"] and
                    record["task_revision"] == binding["task_revision"] and
                    record["authority_hash"] == binding["authority_hash"]]
            if "candidate_sha256" in selectors:
                # Historical operation-to-candidate attribution is absent in
                # the current ledger contract; never infer it from today's plan.
                other = [record for record in base if all(
                    key == "candidate_sha256" or key in ("project_id", "ledger_id") or
                    record.get(key) == value for key, value in selectors.items())]
                require(not other or all(record["candidate_sha256"] is not None
                                         for record in other), "UNRESOLVED_CANDIDATE")
            clauses = ["project_id=?", "ledger_id=?", "task_id=?", "task_revision=?",
                       "authority_hash=?"]
            args = [self.project_id, self.ledger_id, binding["task_id"],
                    binding["task_revision"], binding["authority_hash"]]
            for key, value in selectors.items():
                if key not in ("project_id", "ledger_id"):
                    clauses.append(key + "=?")
                    args.append(value)
            query = ("SELECT event_seq FROM evidence_index WHERE " + " AND ".join(clauses) +
                     " ORDER BY event_seq LIMIT ?")
            selected_seqs = [row[0] for row in db.execute(query, (*args, limit + 1))]
            require(len(selected_seqs) <= limit, "EVIDENCE_LIMIT_EXCEEDED")
            by_seq = {record["event_seq"]: record for record in records}
            selected = [by_seq[seq] for seq in selected_seqs]
            return {"status": "OK" if selected else "MISSING", "authority": False,
                    "project_id": self.project_id, "ledger_id": self.ledger_id,
                    "head": head, "indexed_through": head,
                    "snapshot_id": digest({"schema": "M2_EVIDENCE_SNAPSHOT_1",
                                           "ledger_id": self.ledger_id, "head": head,
                                           "binding": binding, "selectors": selectors,
                                           "evidence_ids": [r["evidence_id"] for r in selected]}),
                    "records": selected}

    def _orchestration_snapshot(self, binding):
        with sqlite3.connect(self.orchestration.path) as db:
            db.execute("BEGIN")
            state, revision, event_hash = self.orchestration._load(db, binding["task_id"])
        require(state["task_revision"] == binding["task_revision"] and
                state["grant_digest"] == binding["authority_hash"] and
                state["candidate_hash"] == binding["candidate_sha256"],
                "STALE_BINDING")
        lease = next((item for item in state["leases"]
                      if item["lease_id"] == binding["lease_id"]), None)
        open_on_lease = any(item["lease_id"] == binding["lease_id"]
                            for item in state["open_operations"])
        require(lease is not None and
                (lease["expires_at"] > int(time.time()) or open_on_lease),
                "STALE_LEASE")
        return {"state": state, "head": {"revision": revision,
                                         "state_hash": digest(state),
                                         "event_hash": event_hash}, "lease": lease,
                "open_on_lease": open_on_lease}

    def _memory_content(self):
        with sqlite3.connect(self.memory.path) as db:
            db.execute("BEGIN")
            entries, _ = self.memory._replay(db)
            head = {"seq": 0, "event_hash": _ZERO}
            for seq, event_hash, raw in db.execute(
                    "SELECT seq,event_hash,body_json FROM events ORDER BY seq"):
                if strict_json(raw)["type"] != "RETRIEVE":
                    head = {"seq": seq, "event_hash": event_hash}
        return entries, head

    def _heads(self, binding):
        with sqlite3.connect(self.controller.ledger.path) as db:
            db.execute("BEGIN")
            records, ledger_head, scopes = self._source_records(db)
            self._check_index(db, records, ledger_head)
            scope = self._current_scope(db, binding, scopes)
        orchestration = self._orchestration_snapshot(binding)
        entries, content_head = self._memory_content()
        return ({"ledger": ledger_head, "orchestration": orchestration["head"],
                 "memory_content": content_head}, scope, orchestration, entries)

    def _file_proofs(self, binding, entries, advisory, visible):
        """Validate bytes returned by a host-installed, permission-enforcing reader.

        No caller-supplied visible IDs or verified flag is accepted. Only a single
        file whose raw bytes hash is the registered source hash is supported.
        Opaque/multi-file source manifests need a separate explicit contract.
        """
        if self._read_file_evidence is None:
            return []
        proofs = {}
        for entry in entries.values():
            if (entry["binding"] != binding or entry["status"] != "VERIFIED" or
                    int(time.time()) >= entry["expires_at"] or
                    entry["entry_id"] in advisory["revoked_entry_ids"] or
                    entry["entry_id"] in advisory["conflicting_entry_ids"]):
                continue
            sources = [entry[key] for key in ("source", "verification_source", "activation_source")
                       if entry[key] is not None]
            if any(source["id"] in advisory["revoked_source_ids"] or
                   advisory["current_sources"].get(source["id"]) != {
                       "version": source["version"], "sha256": source["sha256"]}
                   for source in sources):
                continue
            for source in sources:
                if set(source["evidence_refs"]) <= visible:
                    continue
                require(len(source["evidence_refs"]) == 1,
                        "FILE_EVIDENCE_SINGLE_SOURCE_REQUIRED")
                ref = source["evidence_refs"][0]
                path = PurePosixPath(ref)
                require(not path.is_absolute() and ".." not in path.parts and
                        str(path) == ref and ":" not in ref and "\\" not in ref,
                        "FILE_EVIDENCE_REFERENCE")
                try:
                    observed = self._read_file_evidence(deepcopy(binding), deepcopy(source))
                except Exception:
                    require(False, "FILE_EVIDENCE_READ_FAILED")
                require(type(observed) is dict and set(observed) == {
                    "binding", "source", "ref", "content", "read_policy_sha256"},
                    "FILE_EVIDENCE_OBSERVATION")
                _binding(observed["binding"])
                require(observed["binding"] == binding and observed["source"] == source and
                        observed["ref"] == ref, "FILE_EVIDENCE_BINDING")
                require(type(observed["content"]) is bytes and
                        bytes_hash(observed["content"]) == source["sha256"],
                        "FILE_EVIDENCE_HASH")
                require(hash_text(observed["read_policy_sha256"]), "FILE_EVIDENCE_READ_POLICY")
                proof = {"binding": deepcopy(binding), "source": deepcopy(source), "ref": ref,
                         "content_sha256": source["sha256"],
                         "read_policy_sha256": observed["read_policy_sha256"]}
                key = digest({"source": source, "ref": ref})
                require(key not in proofs or proofs[key] == proof, "STALE_FILE_EVIDENCE")
                proofs[key] = proof
        return [proofs[key] for key in sorted(proofs)]

    def project_memory(self, binding, *, mode="refresh", limit=100,
                       current_sources=None, current_skill_versions=None,
                       revoked_source_ids=(), revoked_entry_ids=(),
                       conflicting_entry_ids=()):
        """Persist a deterministic projection; RETRIEVE audit stays outside its head."""
        _binding(binding)
        require(mode in ("refresh", "rebuild"), "PROJECTION_MODE")
        current_sources = {} if current_sources is None else current_sources
        current_skill_versions = {} if current_skill_versions is None else current_skill_versions
        advisory_state = _advisory_state(
            current_sources=current_sources,
            current_skill_versions=current_skill_versions,
            revoked_source_ids=revoked_source_ids,
            revoked_entry_ids=revoked_entry_ids,
            conflicting_entry_ids=conflicting_entry_ids)
        for _ in range(2):
            snapshot = self.evidence_snapshot(binding, {}, limit=limit)
            before, scope, orchestration, entries = self._heads(binding)
            if before["ledger"] != snapshot["head"]:
                continue
            visible = {record["evidence_id"] for record in snapshot["records"]}
            file_proofs = self._file_proofs(binding, entries, advisory_state, visible)
            retrieval_started = int(time.time())
            retrieval = self.memory.retrieve(
                binding=binding, current_sources=advisory_state["current_sources"],
                visible_evidence=visible | {proof["ref"] for proof in file_proofs},
                current_skill_versions=advisory_state["current_skill_versions"],
                revoked_source_ids=advisory_state["revoked_source_ids"],
                revoked_entry_ids=advisory_state["revoked_entry_ids"],
                conflicting_entry_ids=advisory_state["conflicting_entry_ids"])
            retrieval_finished = int(time.time())
            after, _, _, _ = self._heads(binding)
            if before != after or any(
                    retrieval_started < entry["expires_at"] <= retrieval_finished
                    for entry in entries.values()):
                continue
            require(self._file_proofs(binding, entries, advisory_state, visible) == file_proofs,
                    "STALE_FILE_EVIDENCE")
            facts = []
            for record in snapshot["records"]:
                kind = record["kind"]
                semantics = {"INTENT": "INTENT_REGISTERED",
                             "RECEIPT": "EFFECT_RECEIPT",
                             "TEST_RECEIPT": "TEST_RESULT",
                             "BUILD_RECEIPT": "BUILD_RESULT",
                             "CANDIDATE_FROZEN": "CANDIDATE_FROZEN",
                             "UNKNOWN": "UNKNOWN_RECORDED",
                             "GATE_ALLOW": "GATE_DECISION_RECORDED",
                             "SCOPE_GRANTED": "GRANT_RECORDED",
                             "SCOPE_REVOKED": "REVOCATION_RECORDED"}.get(
                                 kind, "OBSERVED_ONLY")
                fact = {"kind": kind, "semantics": semantics,
                        "evidence_id": record["evidence_id"],
                        "event_hash": record["event_hash"],
                        "event_seq": record["event_seq"],
                        "body_hash": record["body_hash"],
                        "operation_id": record["operation_id"],
                        "candidate_sha256": record["candidate_sha256"],
                        "effect_sha256": record["effect_sha256"],
                        "file_sha256": record["file_sha256"],
                        "receipt_status": (record["body"].get("status") if kind in
                                           ("RECEIPT", "TEST_RECEIPT", "BUILD_RECEIPT")
                                           else None)}
                fact_hash = digest(fact)
                facts.append({**fact, "fact_id": fact_hash, "fact_hash": fact_hash})
            # A registered open effect remains UNKNOWN even when a ledger
            # receipt exists but Controller reconciliation has not closed it.
            for item in orchestration["state"]["open_operations"]:
                fact = {"kind": "ORCHESTRATION_OPEN_OPERATION", "semantics": "UNKNOWN",
                        "status": "UNKNOWN",
                        "operation_id": item["operation_id"],
                        "state_hash": orchestration["head"]["state_hash"]}
                fact_hash = digest(fact)
                facts.append({**fact, "fact_id": fact_hash, "fact_hash": fact_hash})
            lease_until = orchestration["lease"]["expires_at"]
            if orchestration["open_on_lease"] and lease_until <= retrieval_finished:
                lease_until = scope["expires_at"]
            valid_until = min([scope["expires_at"], lease_until] +
                              [entry["expires_at"] for entry in entries.values()
                               if entry["expires_at"] > retrieval_finished])
            payload = {"projection_schema": "M2_ATOMIC_MEMORY_PROJECTION_1",
                       "authority": False, "scope_binding": binding,
                       "source_heads": before,
                       "indexed_through": snapshot["indexed_through"],
                       "orchestration_snapshot": orchestration["state"],
                       "facts": facts,
                       "adopted_refs": [{"evidence_id": record["evidence_id"],
                                         "event_hash": record["event_hash"]}
                                        for record in snapshot["records"]],
                       "advisory_entries": retrieval["adopted"],
                       "file_evidence": file_proofs,
                       "excluded_refs": retrieval["excluded"],
                       "advisory_state": advisory_state,
                       "requires_advisory_current": bool(entries) or any((
                           advisory_state["current_sources"],
                           advisory_state["current_skill_versions"],
                           advisory_state["revoked_source_ids"],
                           advisory_state["revoked_entry_ids"],
                           advisory_state["conflicting_entry_ids"])),
                       "valid_until": valid_until}
            projection_hash = digest(payload)
            result = {**payload, "projection_id": projection_hash,
                      "projection_hash": projection_hash}
            with self.memory._transaction() as db:
                row = db.execute("SELECT payload_json FROM evidence_projections WHERE "
                                 "projection_hash=?", (projection_hash,)).fetchone()
                raw = canonical(result).decode("utf-8")
                if row is None:
                    db.execute("INSERT INTO evidence_projections VALUES(?,?)",
                               (projection_hash, raw))
                elif row[0] != raw:
                    require(mode == "rebuild", "PROJECTION_CACHE_CONFLICT")
                    db.execute("UPDATE evidence_projections SET payload_json=? WHERE "
                               "projection_hash=?", (raw, projection_hash))
            return result
        require(False, "STALE_SNAPSHOT")

    def load_projection(self, projection_hash, binding, *, read_advisory_current=None):
        """Recheck current sources before serving a cached advisory projection."""
        _binding(binding)
        require(hash_text(projection_hash), "PROJECTION_HASH")
        with sqlite3.connect(self.memory.path) as db:
            row = db.execute("SELECT payload_json FROM evidence_projections WHERE "
                             "projection_hash=?", (projection_hash,)).fetchone()
        require(row is not None, "PROJECTION_MISSING")
        payload = strict_json(row[0])
        require(canonical(payload).decode("utf-8") == row[0] and
                payload.get("projection_hash") == projection_hash and
                payload.get("projection_id") == projection_hash and
                digest({key: value for key, value in payload.items()
                        if key not in ("projection_hash", "projection_id")}) == projection_hash,
                "PROJECTION_CACHE_TAMPERED")
        require(payload["scope_binding"] == binding and
                int(time.time()) < payload["valid_until"], "STALE_PROJECTION")
        if payload["requires_advisory_current"]:
            require(callable(read_advisory_current), "ADVISORY_CURRENTNESS_REQUIRED")
        if read_advisory_current is None:
            current_advisory = _advisory_state(
                current_sources={}, current_skill_versions={}, revoked_source_ids=(),
                revoked_entry_ids=(), conflicting_entry_ids=())
        else:
            current_advisory = _read_advisory_current(read_advisory_current)
        require(payload["advisory_state"] == current_advisory, "STALE_PROJECTION")
        with sqlite3.connect(self.controller.ledger.path) as db:
            db.execute("BEGIN")
            self.controller.ledger.verify_chain(db)
            current = _head(db.execute(
                "SELECT seq,prev_hash,body_hash,event_hash,body_json FROM events "
                "ORDER BY seq").fetchall())
        require(payload["source_heads"]["ledger"] == current, "STALE_PROJECTION")
        heads, _, _, entries = self._heads(binding)
        require(payload["source_heads"] == heads and
                payload["indexed_through"] == heads["ledger"],
                "STALE_PROJECTION")
        if payload.get("file_evidence"):
            require(self._read_file_evidence is not None, "FILE_EVIDENCE_READER_REQUIRED")
            visible = {item["evidence_id"] for item in payload["adopted_refs"]}
            require(self._file_proofs(binding, entries, current_advisory, visible) == payload["file_evidence"],
                    "STALE_FILE_EVIDENCE")
        if read_advisory_current is not None:
            require(_read_advisory_current(read_advisory_current) == current_advisory,
                    "STALE_PROJECTION")
        if payload.get("file_evidence"):
            require(self._file_proofs(binding, entries, current_advisory, visible) == payload["file_evidence"],
                    "STALE_FILE_EVIDENCE")
        return payload

    def current_heads(self, binding, *, read_advisory_current=None):
        """Public current head vector for a trusted context read callback."""
        _binding(binding)
        before = (_read_advisory_current(read_advisory_current)
                  if read_advisory_current is not None else None)
        heads, _, _, entries = self._heads(binding)
        require(not entries or read_advisory_current is not None,
                "ADVISORY_CURRENTNESS_REQUIRED")
        advisory = before if before is not None else _advisory_state(
            current_sources={}, current_skill_versions={}, revoked_source_ids=(),
            revoked_entry_ids=(), conflicting_entry_ids=())
        if read_advisory_current is not None:
            require(_read_advisory_current(read_advisory_current) == advisory,
                    "STALE_SNAPSHOT")
        return {"project_id": self.project_id, "ledger_id": self.ledger_id,
                **heads, "index": heads["ledger"],
                "skill_versions": advisory["current_skill_versions"],
                "advisory_state": {"sha256": digest(advisory)}}

    def context_inputs(self, binding, *, read_advisory_current=None, limit=100):
        """Verified evidence, facts, and heads for `context_bundle` callers.

        The caller supplies current hard constraints and OrchestrationStore
        restore state separately. This method never returns an authority token.
        """
        _binding(binding)
        advisory = (_read_advisory_current(read_advisory_current)
                    if read_advisory_current is not None else _advisory_state(
                        current_sources={}, current_skill_versions={},
                        revoked_source_ids=(), revoked_entry_ids=(),
                        conflicting_entry_ids=()))
        projection = self.project_memory(
            binding, limit=limit, **advisory)
        self.load_projection(projection["projection_hash"], binding,
                             read_advisory_current=read_advisory_current)
        evidence = self.evidence_snapshot(
            binding, {}, expected_head=projection["source_heads"]["ledger"],
            limit=limit)
        heads = self.current_heads(binding,
                                   read_advisory_current=read_advisory_current)
        require(projection["source_heads"] == {
                    key: heads[key] for key in ("ledger", "orchestration",
                                                "memory_content")} and
                projection["indexed_through"] == heads["index"],
                "STALE_SNAPSHOT")
        return {"task_binding": binding, "heads": heads,
                "projection": projection, "evidence": evidence,
                "authority": False}
