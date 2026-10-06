"""Durable advisory task orchestration; all effects still require Controller Gate.

This store remembers work and refuses unsafe restart suggestions. Its checkpoints,
leases and text are not grants, receipts, or authority to execute an effect.
"""

from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import time

from .contracts import canonical, digest, hash_text, require, strict_json


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _identifier(value):
    require(type(value) is str and _IDENTIFIER.fullmatch(value) is not None,
            "INVALID_IDENTIFIER")


def _file(value):
    require(type(value) is str and value and "\\" not in value and ":" not in value and
            not value.startswith("/") and "\x00" not in value, "INVALID_FILE_LEASE")
    pure = PurePosixPath(value)
    require(str(pure) == value and all(part not in ("", ".", "..") for part in value.split("/")),
            "INVALID_FILE_LEASE")


def _graph(value):
    require(type(value) is dict and 0 < len(value) <= 500, "GRAPH_REQUIRED")
    for node, deps in value.items():
        _identifier(node)
        require(type(deps) is list and
                all(type(dep) is str and dep in value and dep != node for dep in deps),
                "GRAPH_DEPENDENCIES")
        require(len(deps) == len(set(deps)), "GRAPH_DEPENDENCIES")
    visiting = set()
    visited = set()

    def walk(node):
        require(node not in visiting, "GRAPH_CYCLE")
        if node in visited:
            return
        visiting.add(node)
        for dep in value[node]:
            walk(dep)
        visiting.remove(node)
        visited.add(node)

    for node in value:
        walk(node)
    return {node: list(deps) for node, deps in value.items()}


class OrchestrationStore:
    """SQLite checkpoints and leases for one or more task IDs.

    The caller supplies the trusted Controller workspace on every open. The
    persisted binding prevents a lease database from being reused for another root.
    ``restore`` takes current bindings obtained by the caller from the trusted
    Controller/candidate snapshot. It has no executor and never replays an ID.
    An open ID requires an explicit Controller reconciliation outside this store.
    """

    def __init__(self, path, *, workspace):
        root = Path(workspace)
        require(root.is_absolute(), "WORKSPACE_REQUIRED")
        self.workspace = root.resolve(strict=True)
        require(self.workspace.is_dir(), "WORKSPACE_REQUIRED")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS plans(
                task_id TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                state_json TEXT NOT NULL, state_hash TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS events(
                task_id TEXT NOT NULL, revision INTEGER NOT NULL,
                previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
                state_hash TEXT NOT NULL, kind TEXT NOT NULL,
                PRIMARY KEY(task_id, revision))""")
            db.execute("""CREATE TABLE IF NOT EXISTS operation_ids(
                operation_id TEXT PRIMARY KEY, task_id TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS lease_ids(
                lease_id TEXT PRIMARY KEY, task_id TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS workspace_binding(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                workspace TEXT NOT NULL)""")
            row = db.execute("SELECT workspace FROM workspace_binding WHERE singleton=1").fetchone()
            if row is None:
                require(db.execute("SELECT 1 FROM plans LIMIT 1").fetchone() is None,
                        "WORKSPACE_BINDING_REQUIRED")
                db.execute("INSERT INTO workspace_binding(singleton,workspace) VALUES(1,?)",
                           (str(self.workspace),))
            else:
                require(row[0] == str(self.workspace), "WORKSPACE_MISMATCH")

    def _file_identity(self, value):
        """Resolve a lease spelling against the bound workspace, as Controller does."""
        _file(value)
        parts = PurePosixPath(value).parts
        current = self.workspace
        for index, part in enumerate(parts):
            current = current / part
            if not (current.exists() or current.is_symlink()):
                require(index == len(parts) - 1, "PATH_NOT_FOUND")
                if os.name == "nt":
                    require(part.rstrip(" .") == part and not os.path.isreserved(part),
                            "PATH_AMBIGUOUS")
                parent = current.parent.resolve(strict=True)
                require(parent.is_dir() and
                        (parent == self.workspace or self.workspace in parent.parents),
                        "PATH_OUTSIDE_WORKSPACE")
                target = parent / part
                break
            info = current.lstat()
            require(not stat.S_ISLNK(info.st_mode) and
                    not (getattr(info, "st_file_attributes", 0) &
                         getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)), "PATH_LINK")
        else:
            require(current.is_file(), "PATH_OUTSIDE_WORKSPACE")
            target = current
        relative = target.resolve(strict=target.exists()).relative_to(self.workspace).as_posix()
        key = relative.casefold() if os.name == "nt" else relative
        return key, target

    @staticmethod
    def _same_file(left, right):
        return left[0] == right[0] or (left[1].exists() and right[1].exists() and
                                      os.path.samefile(left[1], right[1]))

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.execute("COMMIT")
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    @staticmethod
    def _load(db, task_id):
        row = db.execute("SELECT revision,state_json,state_hash FROM plans WHERE task_id=?",
                         (task_id,)).fetchone()
        require(row is not None, "PLAN_NOT_FOUND")
        revision, raw, state_hash = row
        state = strict_json(raw)
        require(canonical(state).decode("utf-8") == raw and digest(state) == state_hash,
                "PLAN_TAMPERED")
        previous = "0" * 64
        expected_revision = 1
        last_state_hash = None
        for event_revision, event_previous, event_hash, event_state_hash, kind in db.execute(
                "SELECT revision,previous_hash,event_hash,state_hash,kind FROM events "
                "WHERE task_id=? ORDER BY revision", (task_id,)):
            expected_hash = digest({"schema": "M2_ORCHESTRATION_EVENT_1", "task_id": task_id,
                                    "revision": event_revision, "previous_hash": event_previous,
                                    "state_hash": event_state_hash, "kind": kind})
            require(event_revision == expected_revision and event_previous == previous and
                    event_hash == expected_hash, "PLAN_EVENT_CHAIN")
            previous = event_hash
            last_state_hash = event_state_hash
            expected_revision += 1
        require(revision == expected_revision - 1 and last_state_hash == state_hash and
                state["task_id"] == task_id, "PLAN_EVENT_CHAIN")
        return state, revision, previous

    @staticmethod
    def _write(db, state, revision, previous_hash, kind):
        task_id = state["task_id"]
        state_json = canonical(state).decode("utf-8")
        state_hash = digest(state)
        event_hash = digest({"schema": "M2_ORCHESTRATION_EVENT_1", "task_id": task_id,
                             "revision": revision, "previous_hash": previous_hash,
                             "state_hash": state_hash, "kind": kind})
        db.execute("INSERT INTO events(task_id,revision,previous_hash,event_hash,state_hash,kind) "
                   "VALUES(?,?,?,?,?,?)", (task_id, revision, previous_hash, event_hash,
                                            state_hash, kind))
        db.execute("INSERT INTO plans(task_id,revision,state_json,state_hash) VALUES(?,?,?,?) "
                   "ON CONFLICT(task_id) DO UPDATE SET revision=excluded.revision, "
                   "state_json=excluded.state_json,state_hash=excluded.state_hash",
                   (task_id, revision, state_json, state_hash))

    def create_plan(self, *, task_id, task_revision, grant_digest, candidate_hash,
                    graph, attempt_budget):
        _identifier(task_id)
        require(type(task_revision) is int and task_revision > 0, "TASK_REVISION")
        require(hash_text(grant_digest), "GRANT_DIGEST")
        require(hash_text(candidate_hash), "CANDIDATE_HASH")
        require(type(attempt_budget) is int and 0 < attempt_budget <= 10_000,
                "ATTEMPT_BUDGET")
        graph = _graph(graph)
        state = {"schema": "M2_ORCHESTRATION_1", "task_id": task_id,
                 "task_revision": task_revision, "grant_digest": grant_digest,
                 "candidate_hash": candidate_hash, "graph": graph,
                 "nodes": {node: "PENDING" for node in graph},
                 "leases": [], "expired_leases": [], "failed_leases": [],
                 "checkpoints": [], "candidate_history": [],
                 "open_operations": [],
                 "resolved_operations": [],
                 "attempt_budget": attempt_budget, "attempts_used": 0}
        with self._transaction() as db:
            require(db.execute("SELECT 1 FROM plans WHERE task_id=?", (task_id,)).fetchone()
                    is None, "PLAN_ALREADY_EXISTS")
            self._write(db, state, 1, "0" * 64, "CREATE")
        return {"status": "CREATED", "task_id": task_id, "authority": False}

    def _change(self, task_id, kind, transform):
        _identifier(task_id)
        with self._transaction() as db:
            state, revision, previous = self._load(db, task_id)
            result = transform(db, state)
            self._write(db, state, revision + 1, previous, kind)
            return result

    @staticmethod
    def _lease(state, node_id, lease_id, now):
        lease = next((item for item in state["leases"] if item["node_id"] == node_id and
                      item["lease_id"] == lease_id), None)
        require(lease is not None and now < lease["expires_at"], "LEASE_NOT_CURRENT")
        return lease

    @staticmethod
    def _pending_review_ids(state, node_id):
        pending = []
        for index, item in enumerate(state["checkpoints"], 1):
            if item["node_id"] != node_id or item["candidate_hash"] != state["candidate_hash"]:
                continue
            reviewed = item.get("reviewed_checkpoint_id")
            if reviewed in pending:
                pending.remove(reviewed)
            if item["pending_review"]:
                pending.append(item.get("checkpoint_id", f"checkpoint-{index}"))
        return pending

    def begin_attempt(self, task_id, node_id, *, role, files, lease_id, expires_at,
                      now=None):
        _identifier(node_id)
        _identifier(role)
        _identifier(lease_id)
        require(type(files) is list and len(files) > 0, "FILES_REQUIRED")
        for item in files:
            _file(item)
        now = int(time.time()) if now is None else now
        require(type(now) is int and type(expires_at) is int and expires_at > now,
                "LEASE_TIME")

        def change(db, state):
            identities = [self._file_identity(item) for item in files]
            require(not any(self._same_file(left, right)
                            for index, left in enumerate(identities)
                            for right in identities[index + 1:]), "FILES_REQUIRED")
            require(node_id in state["graph"], "NODE_NOT_FOUND")
            require(not state["open_operations"], "OPERATION_UNRESOLVED")
            require(state["attempts_used"] < state["attempt_budget"], "ATTEMPT_BUDGET")
            require(state["nodes"][node_id] == "PENDING", "NODE_ALREADY_RUNNING")
            require(all(state["nodes"][dep] == "DONE" for dep in state["graph"][node_id]),
                    "DEPENDENCIES_UNMET")
            all_leases = list(state["leases"])
            for (other_task,) in db.execute("SELECT task_id FROM plans WHERE task_id<>?",
                                            (task_id,)):
                other_state, _, _ = self._load(db, other_task)
                all_leases.extend(other_state["leases"])
            require(all(item["role"] != role for item in all_leases),
                    "ROLE_LEASE_BUSY")
            occupied = [self._file_identity(path)
                        for lease in all_leases for path in lease["files"]]
            require(not any(self._same_file(left, right)
                            for left in occupied for right in identities),
                    "FILE_LEASE_BUSY")
            require(db.execute("SELECT 1 FROM lease_ids WHERE lease_id=?",
                               (lease_id,)).fetchone() is None, "LEASE_ID_USED")
            db.execute("INSERT INTO lease_ids(lease_id,task_id) VALUES(?,?)",
                       (lease_id, task_id))
            state["leases"].append({"node_id": node_id, "role": role,
                                    "files": list(files), "lease_id": lease_id,
                                    "expires_at": expires_at})
            state["nodes"][node_id] = "RUNNING"
            state["attempts_used"] += 1
            return {"status": "STARTED", "attempts_used": state["attempts_used"],
                    "authority": False}

        return self._change(task_id, "BEGIN_ATTEMPT", change)

    def reassign_expired_lease(self, task_id, node_id, old_lease_id, *,
                               new_lease_id, role, expires_at, now=None):
        """Explicitly spend another attempt after an expired, effect-free lease.

        This never runs the node. Any open effect remains a hard stop.
        """
        _identifier(node_id)
        _identifier(old_lease_id)
        _identifier(new_lease_id)
        _identifier(role)
        now = int(time.time()) if now is None else now
        require(type(now) is int and type(expires_at) is int and expires_at > now,
                "LEASE_TIME")

        def change(db, state):
            require(not state["open_operations"], "OPERATION_UNRESOLVED")
            require(state["attempts_used"] < state["attempt_budget"], "ATTEMPT_BUDGET")
            old = next((item for item in state["leases"]
                        if item["node_id"] == node_id and
                        item["lease_id"] == old_lease_id), None)
            require(old is not None and old["expires_at"] <= now and
                    state["nodes"][node_id] == "RUNNING", "LEASE_NOT_EXPIRED")
            require(db.execute("SELECT 1 FROM lease_ids WHERE lease_id=?",
                               (new_lease_id,)).fetchone() is None, "LEASE_ID_USED")
            reassigned = [self._file_identity(path) for path in old["files"]]
            for (other_task,) in db.execute("SELECT task_id FROM plans"):
                other_state = state if other_task == task_id else self._load(db, other_task)[0]
                for lease in other_state["leases"]:
                    if other_task == task_id and lease["lease_id"] == old_lease_id:
                        continue
                    require(lease["role"] != role, "ROLE_LEASE_BUSY")
                    occupied = [self._file_identity(path) for path in lease["files"]]
                    require(not any(self._same_file(left, right)
                                    for left in occupied for right in reassigned),
                            "FILE_LEASE_BUSY")
            db.execute("INSERT INTO lease_ids(lease_id,task_id) VALUES(?,?)",
                       (new_lease_id, task_id))
            state["leases"].remove(old)
            state["expired_leases"].append(old)
            state["leases"].append({"node_id": node_id, "role": role,
                                    "files": list(old["files"]),
                                    "lease_id": new_lease_id,
                                    "expires_at": expires_at})
            state["attempts_used"] += 1
            return {"status": "REASSIGNED", "attempts_used": state["attempts_used"],
                    "authority": False}

        return self._change(task_id, "REASSIGN_EXPIRED", change)

    def record_failed_attempt(self, task_id, node_id, lease_id, *, reason, now=None):
        """Close a failed advisory attempt without refunding its budget."""
        _identifier(node_id)
        _identifier(lease_id)
        require(type(reason) is str and 0 < len(reason) <= 4096, "FAILURE_REASON")
        now = int(time.time()) if now is None else now
        require(type(now) is int, "FAILURE_TIME")

        def change(db, state):
            lease = self._lease(state, node_id, lease_id, now)
            require(not state["open_operations"], "OPERATION_UNRESOLVED")
            state["leases"].remove(lease)
            state["failed_leases"].append({**lease, "failed_at": now, "reason": reason})
            state["nodes"][node_id] = "PENDING"
            state["checkpoints"].append(
                {"checkpoint_id": f"checkpoint-{len(state['checkpoints']) + 1}",
                 "node_id": node_id, "lease_id": lease_id, "stage": "FAILED",
                 "next_step": reason, "pending_review": False,
                 "reviewed_checkpoint_id": None,
                 "candidate_hash": state["candidate_hash"], "at": now})
            return {"status": "ATTEMPT_FAILED", "attempts_used": state["attempts_used"],
                    "authority": False}

        return self._change(task_id, "ATTEMPT_FAILED", change)

    def supersede_candidate(self, task_id, new_candidate_hash):
        """Start a new candidate explicitly; retain consumed attempts and history."""
        require(hash_text(new_candidate_hash), "CANDIDATE_HASH")

        def change(db, state):
            require(not state["open_operations"], "OPERATION_UNRESOLVED")
            require(not state["leases"], "LEASE_ACTIVE")
            require(state["candidate_hash"] != new_candidate_hash,
                    "CANDIDATE_UNCHANGED")
            state["candidate_history"].append(state["candidate_hash"])
            state["candidate_hash"] = new_candidate_hash
            state["nodes"] = {node: "PENDING" for node in state["graph"]}
            return {"status": "NEW_CANDIDATE", "candidate_hash": new_candidate_hash,
                    "attempts_used": state["attempts_used"], "authority": False}

        return self._change(task_id, "NEW_CANDIDATE", change)

    def save_checkpoint(self, task_id, node_id, lease_id, *, stage, next_step,
                        pending_review, reviewed_checkpoint_id=None, now=None):
        _identifier(node_id)
        _identifier(lease_id)
        require(type(stage) is str and 0 < len(stage) <= 128 and
                type(next_step) is str and len(next_step) <= 4096 and
                type(pending_review) is bool, "CHECKPOINT_FIELDS")
        if reviewed_checkpoint_id is not None:
            _identifier(reviewed_checkpoint_id)
            require(not pending_review, "REVIEW_RESOLUTION_FIELDS")
        now = int(time.time()) if now is None else now
        require(type(now) is int, "CHECKPOINT_TIME")

        def change(db, state):
            self._lease(state, node_id, lease_id, now)
            if reviewed_checkpoint_id is not None:
                require(reviewed_checkpoint_id in self._pending_review_ids(state, node_id),
                        "REVIEW_CHECKPOINT_NOT_PENDING")
            item = {"checkpoint_id": f"checkpoint-{len(state['checkpoints']) + 1}",
                    "node_id": node_id, "lease_id": lease_id, "stage": stage,
                    "next_step": next_step, "pending_review": pending_review,
                    "reviewed_checkpoint_id": reviewed_checkpoint_id,
                    "candidate_hash": state["candidate_hash"], "at": now}
            state["checkpoints"].append(item)
            return {"status": "SAVED", "checkpoint": item, "authority": False}

        return self._change(task_id, "CHECKPOINT", change)

    def register_open_operation(self, task_id, node_id, lease_id, operation_id, *, now=None):
        _identifier(node_id)
        _identifier(lease_id)
        _identifier(operation_id)
        now = int(time.time()) if now is None else now
        require(type(now) is int, "OPERATION_TIME")

        def change(db, state):
            self._lease(state, node_id, lease_id, now)
            require(db.execute("SELECT 1 FROM operation_ids WHERE operation_id=?",
                               (operation_id,)).fetchone() is None, "OPERATION_ID_USED")
            require(not state["open_operations"], "OPERATION_UNRESOLVED")
            db.execute("INSERT INTO operation_ids(operation_id,task_id) VALUES(?,?)",
                       (operation_id, task_id))
            state["open_operations"].append({"operation_id": operation_id,
                                             "node_id": node_id,
                                             "lease_id": lease_id})
            return {"status": "RECORDED_UNKNOWN", "operation_id": operation_id,
                    "authority": False}

        return self._change(task_id, "OPEN_OPERATION", change)

    def reconcile_completed_operation(self, task_id, operation_id, controller):
        """Clear an open ID only after the actual Controller ledger has a receipt.

        An absent or in-flight operation stays UNKNOWN. This method never calls
        the effect again. The Controller's current signed grant is rechecked.
        """
        from .controller import Controller

        _identifier(task_id)
        _identifier(operation_id)
        require(type(controller) is Controller, "CONTROLLER_REQUIRED")
        require(controller.workspace == self.workspace, "WORKSPACE_MISMATCH")
        with self._transaction() as db:
            state, _, _ = self._load(db, task_id)
            open_item = next((item for item in state["open_operations"]
                              if item["operation_id"] == operation_id), None)
            require(open_item is not None, "OPERATION_NOT_OPEN")
            lease = next((item for item in state["leases"]
                          if item["node_id"] == open_item["node_id"] and
                          item["lease_id"] == open_item["lease_id"]), None)
            require(lease is not None, "OPERATION_LEASE_MISSING")
        with controller.ledger.transaction() as db:
            controller.ledger.verify_chain(db)
            row = db.execute("SELECT grant_id,task_id,kind,path,status,after_sha256,result_json,"
                             "request_hash "
                             "FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row[4] != "COMPLETED":
                return {"status": "UNKNOWN", "operation_id": operation_id,
                        "authority": False}
            grant_id, operation_task, kind, path, _, after_hash, result_json, request_hash = row
            require(operation_task == task_id, "OPERATION_TASK_MISMATCH")
            scope = controller._current_scope(db, grant_id, task_id,
                                              state["task_revision"])
            require(digest(scope) == state["grant_digest"], "GRANT_DIGEST_MISMATCH")
            result = strict_json(result_json)
            events = [strict_json(item[0]) for item in db.execute(
                "SELECT body_json FROM events ORDER BY seq")]
            if kind in ("PATCH", "CREATE"):
                receipt_file = self._file_identity(path)
                require(any(self._same_file(receipt_file, self._file_identity(item))
                            for item in lease["files"]),
                        "OPERATION_FILE_NOT_LEASED")
                require(result["status"] == "COMPLETED" and
                        result["operation_id"] == operation_id and
                        result["after_sha256"] == after_hash and
                        result["effect_executed"] is True and hash_text(after_hash),
                        "OPERATION_RECEIPT_INVALID")
                require(any(event.get("kind") == "RECEIPT" and
                            event.get("operation_id") == operation_id and
                            event.get("request_hash") == request_hash and
                            event.get("actual_sha256") == after_hash for event in events),
                        "OPERATION_RECEIPT_EVENT_MISSING")
            else:
                require(kind in ("TEST", "BUILD"), "OPERATION_KIND_UNSUPPORTED")
                require(any(command["command_id"] == path and command["kind"] == kind
                            for command in scope.get("allowed_commands", [])),
                        "OPERATION_COMMAND_NOT_AUTHORIZED")
                require(any(event.get("kind") == "INTENT" and
                            event.get("operation_id") == operation_id and
                            event.get("command_id") == path for event in events),
                        "OPERATION_COMMAND_INTENT_MISSING")
                require(result["operation_id"] == operation_id and
                        result["effect_executed"] is True and
                        type(result["status"]) is str and result["status"] and
                        result["receipt_sha256"] == after_hash and
                        hash_text(after_hash), "OPERATION_RECEIPT_INVALID")
                require(any(event.get("kind") == "RECEIPT" and
                            event.get("operation_id") == operation_id and
                            event.get("request_hash") == request_hash and
                            event.get("receipt_sha256") == after_hash and
                            event.get("status") == result["status"] for event in events) and
                        any(event.get("kind") == kind + "_RECEIPT" and
                            event.get("grant_id") == grant_id and
                            event.get("task_id") == task_id and
                            event.get("task_revision") == state["task_revision"] and
                            event.get("operation_id") == operation_id and
                            event.get("receipt_sha256") == after_hash and
                            event.get("status") == result["status"] for event in events),
                        "OPERATION_RECEIPT_EVENT_MISSING")
            receipt_hash = digest(result)

        def change(db, state):
            open_item = next((item for item in state["open_operations"]
                              if item["operation_id"] == operation_id), None)
            require(open_item is not None, "OPERATION_NOT_OPEN")
            state["open_operations"].remove(open_item)
            state["resolved_operations"].append(
                {"operation_id": operation_id, "receipt_hash": receipt_hash,
                 "after_sha256": after_hash})
            return {"status": "RECONCILED_COMPLETED", "operation_id": operation_id,
                    "receipt_hash": receipt_hash, "authority": False}

        return self._change(task_id, "RECONCILE_COMPLETED", change)

    def mark_complete(self, task_id, node_id, lease_id, *, now=None):
        _identifier(node_id)
        _identifier(lease_id)
        now = int(time.time()) if now is None else now
        require(type(now) is int, "COMPLETION_TIME")

        def change(db, state):
            self._lease(state, node_id, lease_id, now)
            require(not state["open_operations"], "OPERATION_UNRESOLVED")
            require(not self._pending_review_ids(state, node_id), "REVIEW_PENDING")
            last_checkpoint = next((item for item in reversed(state["checkpoints"])
                                    if item["node_id"] == node_id and
                                    item["candidate_hash"] == state["candidate_hash"]), None)
            require(last_checkpoint is None or last_checkpoint["lease_id"] == lease_id,
                    "CHECKPOINT_STALE")
            require(last_checkpoint is None or not last_checkpoint["pending_review"],
                    "REVIEW_PENDING")
            state["nodes"][node_id] = "DONE"
            state["leases"] = [item for item in state["leases"]
                               if item["lease_id"] != lease_id]
            return {"status": "NODE_RECORDED_DONE", "authority": False}

        return self._change(task_id, "NODE_DONE", change)

    def restore(self, task_id, *, current_task_revision, current_grant_digest,
                current_candidate_hash, now=None):
        _identifier(task_id)
        require(current_task_revision is None or
                (type(current_task_revision) is int and current_task_revision > 0),
                "TASK_REVISION")
        require(current_grant_digest is None or hash_text(current_grant_digest),
                "GRANT_DIGEST")
        require(current_candidate_hash is None or hash_text(current_candidate_hash),
                "CANDIDATE_HASH")
        now = int(time.time()) if now is None else now
        require(type(now) is int, "RESTORE_TIME")
        with self._transaction() as db:
            state, _, _ = self._load(db, task_id)
        stale = []
        for field, current in (("task_revision", current_task_revision),
                               ("grant_digest", current_grant_digest),
                               ("candidate_hash", current_candidate_hash)):
            if state[field] != current:
                stale.append(field)
        if stale:
            status = "STALE_BINDING"
        elif state["open_operations"]:
            status = "BLOCKED_UNKNOWN"
        elif any(lease["expires_at"] <= now for lease in state["leases"]):
            status = "LEASE_EXPIRED"
        elif state["attempts_used"] >= state["attempt_budget"] and any(
                node == "PENDING" for node in state["nodes"].values()):
            status = "ATTEMPT_BUDGET_EXHAUSTED"
        else:
            status = "RESUMABLE"
        ready = sorted(node for node, deps in state["graph"].items()
                       if state["nodes"][node] == "PENDING" and
                       all(state["nodes"][dep] == "DONE" for dep in deps)) if status == "RESUMABLE" else []
        active_lease_ids = {item["lease_id"] for item in state["leases"]}
        current_checkpoints = []
        excluded_checkpoints = []
        for index, stored_item in enumerate(state["checkpoints"], 1):
            item = {"checkpoint_id": f"checkpoint-{index}",
                    "reviewed_checkpoint_id": None, **stored_item}
            if stale:
                reason = "BINDING_STALE"
            elif item["candidate_hash"] != state["candidate_hash"]:
                reason = "CANDIDATE_CHANGED"
            elif item["lease_id"] not in active_lease_ids:
                reason = "LEASE_NOT_CURRENT"
            elif state["nodes"][item["node_id"]] != "RUNNING":
                reason = "NODE_NOT_RUNNING"
            else:
                reason = None
            if reason is None:
                current_checkpoints.append(item)
            else:
                excluded_checkpoints.append(
                    {"checkpoint_id": item["checkpoint_id"],
                     "node_id": item["node_id"], "lease_id": item["lease_id"],
                     "reason": reason})
        pending_review = [checkpoint_id for node in state["graph"]
                          for checkpoint_id in self._pending_review_ids(state, node)]
        return {"status": status, "authority": False, "stale_fields": stale,
                "task_id": task_id, "task_revision": state["task_revision"],
                "grant_digest": state["grant_digest"],
                "candidate_hash": state["candidate_hash"],
                "graph": state["graph"], "nodes": state["nodes"],
                "leases": state["leases"],
                "expired_leases": state["expired_leases"],
                "failed_leases": state["failed_leases"],
                "candidate_history": state["candidate_history"],
                "ready_nodes": ready,
                "attempt_budget": state["attempt_budget"],
                "attempts_used": state["attempts_used"],
                "checkpoint": current_checkpoints[-1] if current_checkpoints else None,
                "excluded_checkpoints": excluded_checkpoints,
                "pending_review_checkpoint_ids": pending_review,
                "open_operation_ids": [item["operation_id"]
                                       for item in state["open_operations"]],
                "resolved_operations": list(state["resolved_operations"])}
