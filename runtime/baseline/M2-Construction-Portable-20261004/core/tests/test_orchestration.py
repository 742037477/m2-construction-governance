"""Task 4 orchestration persistence and conservative restart behavior."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest

from m2_construction.contracts import Denied
from m2_construction.orchestration import OrchestrationStore
from test_execution import (_new_file_scope, fixture as controller_fixture,
                            resign, sha)


GRANT = "a" * 64
CANDIDATE = "b" * 64


def make_store(path, *, workspace=None):
    path = Path(path)
    workspace = path.parent / "workspace" if workspace is None else Path(workspace)
    for relative in ("sample.py", "src/demo.py", "src/Report.py",
                     "docs/guide.md", "other.py"):
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_text("value = 1\n", encoding="utf-8")
    return OrchestrationStore(path, workspace=workspace)


def plan(store, **changes):
    values = dict(
        task_id="task-01", task_revision=3, grant_digest=GRANT,
        candidate_hash=CANDIDATE,
        graph={"edit": [], "review": ["edit"], "merge": ["review"]},
        attempt_budget=2,
    )
    values.update(changes)
    return store.create_plan(**values)


def restore(store, **changes):
    values = dict(task_id="task-01", current_task_revision=3,
                  current_grant_digest=GRANT, current_candidate_hash=CANDIDATE,
                  now=100)
    values.update(changes)
    return store.restore(**values)


def test_restart_retains_dag_role_file_lease_checkpoint_and_budget(tmp_path):
    path = tmp_path / "orchestration.sqlite3"
    store = make_store(path)
    plan(store)
    assert restore(store)["ready_nodes"] == ["edit"]
    assert store.begin_attempt("task-01", "edit", role="author-a",
                               files=["src/demo.py"], lease_id="lease-a",
                               expires_at=200, now=100)["attempts_used"] == 1
    store.save_checkpoint("task-01", "edit", "lease-a", stage="PATCHED",
                          next_step="Run actual tests", pending_review=True, now=101)

    reopened = make_store(path)
    state = restore(reopened)
    assert state["status"] == "RESUMABLE"
    assert state["authority"] is False
    assert state["graph"] == {"edit": [], "review": ["edit"], "merge": ["review"]}
    assert state["leases"] == [{"node_id": "edit", "role": "author-a",
                                "files": ["src/demo.py"], "lease_id": "lease-a",
                                "expires_at": 200}]
    assert state["attempts_used"] == 1 and state["attempt_budget"] == 2
    assert state["checkpoint"]["next_step"] == "Run actual tests"
    assert state["checkpoint"]["pending_review"] is True
    assert state["ready_nodes"] == []


def test_checkpoint_restores_after_actual_process_exit(tmp_path):
    path = tmp_path / "orchestration.sqlite3"
    store = make_store(path)
    plan(store)
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.save_checkpoint("task-01", "edit", "lease-a", stage="PAUSED",
                          next_step="Verify current Controller grant", pending_review=True,
                          now=101)
    script = ("import json,sys; from m2_construction.orchestration import OrchestrationStore; "
              "s=OrchestrationStore(sys.argv[1],workspace=sys.argv[2]).restore('task-01', "
              "current_task_revision=3,current_grant_digest='a'*64,"
              "current_candidate_hash='b'*64,now=102); "
              "print(json.dumps({'status':s['status'],'checkpoint':s['checkpoint'],"
              "'attempts':s['attempts_used']}))")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    completed = subprocess.run([sys.executable, "-c", script, str(path), str(store.workspace)],
                               env=env, capture_output=True, text=True, check=True)
    state = json.loads(completed.stdout)
    assert state["status"] == "RESUMABLE"
    assert state["checkpoint"]["next_step"] == "Verify current Controller grant"
    assert state["attempts"] == 1


@pytest.mark.parametrize("changed", [
    {"current_task_revision": 4},
    {"current_grant_digest": "c" * 64},
    {"current_candidate_hash": "d" * 64},
    {"current_grant_digest": None},
])
def test_restore_rejects_each_stale_binding(tmp_path, changed):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store)
    state = restore(make_store(store.path), **changed)
    assert state["status"] == "STALE_BINDING"
    assert state["ready_nodes"] == []
    assert state["authority"] is False


def test_unknown_operation_survives_restart_and_cannot_be_replayed(tmp_path):
    path = tmp_path / "state.sqlite3"
    store = make_store(path)
    plan(store)
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.register_open_operation("task-01", "edit", "lease-a", "op-01", now=101)
    store.save_checkpoint("task-01", "edit", "lease-a", stage="WAITING_EFFECT",
                          next_step="Inspect Controller receipt", pending_review=False,
                          now=102)

    reopened = make_store(path)
    state = restore(reopened)
    assert state["status"] == "BLOCKED_UNKNOWN"
    assert state["open_operation_ids"] == ["op-01"]
    assert state["ready_nodes"] == []
    assert state["attempts_used"] == 1
    with pytest.raises(Denied, match="OPERATION_UNRESOLVED"):
        reopened.mark_complete("task-01", "edit", "lease-a", now=103)
    with pytest.raises(Denied, match="OPERATION_UNRESOLVED"):
        reopened.begin_attempt("task-01", "review", role="reviewer-b",
                               files=["src/demo.py"], lease_id="lease-b",
                               expires_at=220, now=103)
    with pytest.raises(Denied, match="OPERATION_ID_USED"):
        reopened.register_open_operation("task-01", "edit", "lease-a", "op-01", now=104)


def test_dependencies_lease_exclusivity_and_attempt_budget(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store)
    with pytest.raises(Denied, match="DEPENDENCIES_UNMET"):
        store.begin_attempt("task-01", "review", role="reviewer-b", files=["src/demo.py"],
                            lease_id="lease-b", expires_at=200, now=100)
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with pytest.raises(Denied, match="NODE_ALREADY_RUNNING"):
        store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                            lease_id="lease-b", expires_at=200, now=100)
    assert restore(store, now=201)["status"] == "LEASE_EXPIRED"
    store.mark_complete("task-01", "edit", "lease-a", now=101)
    assert restore(store)["ready_nodes"] == ["review"]
    store.begin_attempt("task-01", "review", role="reviewer-b", files=["src/demo.py"],
                        lease_id="lease-b", expires_at=200, now=100)
    with pytest.raises(Denied, match="ATTEMPT_BUDGET"):
        store.begin_attempt("task-01", "merge", role="integrator-c", files=["other.py"],
                            lease_id="lease-c", expires_at=200, now=100)


def test_expired_lease_requires_explicit_budgeted_reassignment(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=150, now=100)
    assert restore(store, now=151)["status"] == "LEASE_EXPIRED"
    result = store.reassign_expired_lease("task-01", "edit", "lease-a",
                                          new_lease_id="lease-b", role="author-b",
                                          expires_at=300, now=151)
    assert result["attempts_used"] == 2
    state = restore(make_store(store.path), now=152)
    assert state["status"] == "RESUMABLE"
    assert state["leases"][0]["lease_id"] == "lease-b"
    assert state["expired_leases"][0]["lease_id"] == "lease-a"
    with pytest.raises(Denied, match="ATTEMPT_BUDGET"):
        store.reassign_expired_lease("task-01", "edit", "lease-b",
                                      new_lease_id="lease-c", role="author-c",
                                      expires_at=400, now=301)


def test_reassigned_lease_excludes_old_checkpoint_until_new_record(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=150, now=100)
    store.save_checkpoint("task-01", "edit", "lease-a", stage="TESTED",
                          next_step="Continue from old attempt", pending_review=False,
                          now=101)
    store.reassign_expired_lease("task-01", "edit", "lease-a",
                                  new_lease_id="lease-b", role="author-b",
                                  expires_at=300, now=151)
    state = restore(make_store(store.path), now=152)
    assert state["status"] == "RESUMABLE"
    assert state["checkpoint"] is None
    assert any(item["reason"] == "LEASE_NOT_CURRENT" and
               item["lease_id"] == "lease-a" for item in state["excluded_checkpoints"])
    with pytest.raises(Denied, match="CHECKPOINT_STALE"):
        store.mark_complete("task-01", "edit", "lease-b", now=152)
    store.save_checkpoint("task-01", "edit", "lease-b", stage="REVALIDATED",
                          next_step="Finish current attempt", pending_review=False,
                          now=153)
    assert store.mark_complete("task-01", "edit", "lease-b", now=154)["status"] == "NODE_RECORDED_DONE"


def test_pending_review_survives_lease_change_until_explicit_resolution(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=150, now=100)
    old = store.save_checkpoint("task-01", "edit", "lease-a", stage="WAITING_REVIEW",
                                next_step="Independent review", pending_review=True,
                                now=101)["checkpoint"]
    store.reassign_expired_lease("task-01", "edit", "lease-a",
                                  new_lease_id="lease-b", role="author-b",
                                  expires_at=300, now=151)
    state = restore(store, now=152)
    assert state["checkpoint"] is None
    assert state["pending_review_checkpoint_ids"] == [old["checkpoint_id"]]
    with pytest.raises(Denied, match="REVIEW_PENDING"):
        store.mark_complete("task-01", "edit", "lease-b", now=152)
    store.save_checkpoint("task-01", "edit", "lease-b", stage="RECHECKED",
                          next_step="Review still pending", pending_review=False,
                          now=153)
    with pytest.raises(Denied, match="REVIEW_PENDING"):
        store.mark_complete("task-01", "edit", "lease-b", now=154)
    store.save_checkpoint("task-01", "edit", "lease-b", stage="REVIEW_RECORDED",
                          next_step="Continue after review", pending_review=False,
                          reviewed_checkpoint_id=old["checkpoint_id"], now=155)
    assert restore(store, now=155)["pending_review_checkpoint_ids"] == []
    assert store.mark_complete("task-01", "edit", "lease-b", now=156)["status"] == "NODE_RECORDED_DONE"


def test_failed_attempt_checkpoint_cannot_complete_same_candidate_retry(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.save_checkpoint("task-01", "edit", "lease-a", stage="TESTED",
                          next_step="Old attempt result", pending_review=False, now=101)
    store.record_failed_attempt("task-01", "edit", "lease-a",
                                reason="Actual test failed", now=102)
    store.begin_attempt("task-01", "edit", role="author-b", files=["src/demo.py"],
                        lease_id="lease-b", expires_at=250, now=103)
    state = restore(make_store(store.path), now=104)
    assert state["checkpoint"] is None
    assert all(item["reason"] == "LEASE_NOT_CURRENT" for item in state["excluded_checkpoints"])
    with pytest.raises(Denied, match="CHECKPOINT_STALE"):
        store.mark_complete("task-01", "edit", "lease-b", now=104)
    store.save_checkpoint("task-01", "edit", "lease-b", stage="RETESTED",
                          next_step="Continue current attempt", pending_review=False, now=105)
    assert store.mark_complete("task-01", "edit", "lease-b", now=106)["status"] == "NODE_RECORDED_DONE"


def test_failed_attempt_and_new_candidate_keep_bounded_budget(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.record_failed_attempt("task-01", "edit", "lease-a",
                                reason="Actual test failed", now=101)
    failed = restore(store)
    assert failed["checkpoint"] is None
    assert failed["excluded_checkpoints"][-1]["reason"] == "LEASE_NOT_CURRENT"
    assert store.supersede_candidate("task-01", "c" * 64)["status"] == "NEW_CANDIDATE"
    state = restore(make_store(store.path), current_candidate_hash="c" * 64)
    assert state["status"] == "RESUMABLE"
    assert state["ready_nodes"] == ["edit"]
    assert state["checkpoint"] is None
    assert state["candidate_history"] == [CANDIDATE]
    assert state["attempts_used"] == 1
    store.begin_attempt("task-01", "edit", role="author-b", files=["src/demo.py"],
                        lease_id="lease-b", expires_at=200, now=102)
    store.record_failed_attempt("task-01", "edit", "lease-b",
                                reason="Second actual test failed", now=103)
    exhausted = restore(store, current_candidate_hash="c" * 64)
    assert exhausted["status"] == "ATTEMPT_BUDGET_EXHAUSTED"
    assert exhausted["ready_nodes"] == []
    with pytest.raises(Denied, match="ATTEMPT_BUDGET"):
        store.begin_attempt("task-01", "edit", role="author-c", files=["src/demo.py"],
                            lease_id="lease-c", expires_at=200, now=104)


def test_unknown_operation_blocks_candidate_supersession(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.register_open_operation("task-01", "edit", "lease-a", "op-01", now=101)
    with pytest.raises(Denied, match="OPERATION_UNRESOLVED"):
        store.supersede_candidate("task-01", "c" * 64)


def test_pending_review_checkpoint_blocks_advisory_node_completion(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.save_checkpoint("task-01", "edit", "lease-a", stage="WAITING_REVIEW",
                          next_step="Independent review", pending_review=True, now=101)
    with pytest.raises(Denied, match="REVIEW_PENDING"):
        store.mark_complete("task-01", "edit", "lease-a", now=102)
    assert restore(store)["checkpoint"]["pending_review"] is True


def test_changed_persisted_state_is_rejected(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE plans SET state_json='{}' WHERE task_id='task-01'")
    with pytest.raises(Denied, match="PLAN_TAMPERED"):
        restore(make_store(store.path))


def test_graph_cycles_and_overlapping_active_leases_are_rejected(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    with pytest.raises(Denied, match="GRAPH_CYCLE"):
        plan(store, graph={"edit": ["review"], "review": ["edit"]})
    plan(store, graph={"edit": [], "docs": []}, attempt_budget=3)
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with pytest.raises(Denied, match="FILE_LEASE_BUSY"):
        store.begin_attempt("task-01", "docs", role="author-b", files=["src/demo.py"],
                            lease_id="lease-b", expires_at=200, now=100)
    with pytest.raises(Denied, match="ROLE_LEASE_BUSY"):
        store.begin_attempt("task-01", "docs", role="author-a", files=["docs/guide.md"],
                            lease_id="lease-b", expires_at=200, now=100)


def test_file_lease_is_exclusive_across_tasks_in_one_workspace_store(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    plan(store, task_id="task-02", graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with pytest.raises(Denied, match="FILE_LEASE_BUSY"):
        store.begin_attempt("task-02", "edit", role="author-b", files=["src/demo.py"],
                            lease_id="lease-b", expires_at=200, now=100)


def test_windows_case_alias_of_real_file_cannot_hold_two_leases(tmp_path):
    workspace = tmp_path / "workspace"
    target = workspace / "src" / "Report.py"
    target.parent.mkdir(parents=True)
    target.write_text("value = 1\n", encoding="utf-8")
    alias = workspace / "SRC" / "report.PY"
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("case-sensitive test filesystem")
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    plan(store, task_id="task-02", graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/Report.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with pytest.raises(Denied, match="FILE_LEASE_BUSY"):
        store.begin_attempt("task-02", "edit", role="author-b", files=["SRC/report.PY"],
                            lease_id="lease-b", expires_at=200, now=100)


def test_windows_trailing_dot_alias_of_real_file_cannot_hold_two_leases(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "sample.py"
    target.write_text("value = 1\n", encoding="utf-8")
    alias = workspace / "sample.py."
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("filesystem does not resolve the trailing-dot alias")
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    plan(store, task_id="task-02", graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with pytest.raises(Denied, match="FILE_LEASE_BUSY"):
        store.begin_attempt("task-02", "edit", role="author-b", files=["sample.py."],
                            lease_id="lease-b", expires_at=200, now=100)
    with sqlite3.connect(store.path) as db:
        leases = {task: json.loads(raw)["leases"] for task, raw in db.execute(
            "SELECT task_id,state_json FROM plans")}
        lease_ids = db.execute("SELECT lease_id FROM lease_ids").fetchall()
    assert leases["task-01"][0]["files"] == ["sample.py"]
    assert leases["task-02"] == [] and lease_ids == [("lease-a",)]


def test_same_lease_rejects_trailing_dot_alias_duplicate(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    alias = store.workspace / "sample.py."
    if not alias.exists() or not os.path.samefile(store.workspace / "sample.py", alias):
        pytest.skip("filesystem does not resolve the trailing-dot alias")
    plan(store, graph={"edit": []})
    with pytest.raises(Denied, match="FILES_REQUIRED"):
        store.begin_attempt("task-01", "edit", role="author-a",
                            files=["sample.py", "sample.py."],
                            lease_id="lease-a", expires_at=200, now=100)


def test_hardlink_alias_of_real_file_cannot_hold_two_leases(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    try:
        os.link(store.workspace / "sample.py", store.workspace / "linked.py")
    except OSError:
        pytest.skip("filesystem does not support hard links")
    plan(store, graph={"edit": []})
    plan(store, task_id="task-02", graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with pytest.raises(Denied, match="FILE_LEASE_BUSY"):
        store.begin_attempt("task-02", "edit", role="author-b", files=["linked.py"],
                            lease_id="lease-b", expires_at=200, now=100)


def test_store_cannot_rebind_existing_leases_to_another_workspace(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    other = tmp_path / "other-workspace"
    other.mkdir()
    with pytest.raises(Denied, match="WORKSPACE_MISMATCH"):
        OrchestrationStore(store.path, workspace=other)


def test_unbound_existing_lease_store_is_not_silently_adopted(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    with sqlite3.connect(store.path) as db:
        db.execute("DELETE FROM workspace_binding")
    with pytest.raises(Denied, match="WORKSPACE_BINDING_REQUIRED"):
        OrchestrationStore(store.path, workspace=store.workspace)


def test_reassignment_rechecks_actual_file_ownership(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store, graph={"edit": []})
    plan(store, task_id="task-02", graph={"edit": []})
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=150, now=100)
    store.begin_attempt("task-02", "edit", role="author-b", files=["other.py"],
                        lease_id="lease-b", expires_at=300, now=100)
    other = store.workspace / "other.py"
    other.unlink()
    try:
        os.link(store.workspace / "sample.py", other)
    except OSError:
        pytest.skip("filesystem does not support hard links")
    with pytest.raises(Denied, match="FILE_LEASE_BUSY"):
        store.reassign_expired_lease("task-01", "edit", "lease-a",
                                      new_lease_id="lease-c", role="author-c",
                                      expires_at=400, now=151)
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT lease_id FROM lease_ids ORDER BY lease_id").fetchall() == [
            ("lease-a",), ("lease-b",)]


def test_same_lease_rejects_case_alias_duplicates(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    alias = store.workspace / "SRC/report.PY"
    if not alias.exists() or not os.path.samefile(store.workspace / "src/Report.py", alias):
        pytest.skip("case-sensitive test filesystem")
    plan(store, graph={"edit": []})
    with pytest.raises(Denied, match="FILES_REQUIRED"):
        store.begin_attempt("task-01", "edit", role="author-a",
                            files=["src/Report.py", "SRC/report.PY"],
                            lease_id="lease-a", expires_at=200, now=100)


def test_only_verified_controller_receipt_reconciles_open_operation(tmp_path):
    controller, target, signed = controller_fixture(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    store = make_store(tmp_path / "orchestration.sqlite3")
    plan(store, task_revision=1, grant_digest=controller.register_grant(signed)["scope_hash"],
         graph={"edit": []})
    now = int(time.time())
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=now + 300, now=now)
    store.register_open_operation("task-01", "edit", "lease-a", "op-01", now=now)
    assert store.reconcile_completed_operation("task-01", "op-01", controller)["status"] == "UNKNOWN"
    assert store.restore("task-01", current_task_revision=1,
                         current_grant_digest=controller.register_grant(signed)["scope_hash"],
                         current_candidate_hash=CANDIDATE, now=now)["status"] == "BLOCKED_UNKNOWN"

    result = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-01", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n")
    assert result["status"] == "COMPLETED"
    receipt = store.reconcile_completed_operation("task-01", "op-01", controller)
    assert receipt["status"] == "RECONCILED_COMPLETED"
    assert store.restore("task-01", current_task_revision=1,
                         current_grant_digest=controller.register_grant(signed)["scope_hash"],
                         current_candidate_hash=CANDIDATE, now=now)["open_operation_ids"] == []
    assert store.mark_complete("task-01", "edit", "lease-a", now=now)["status"] == "NODE_RECORDED_DONE"
    assert target.read_bytes() == b"value = 2\n"


def test_real_governed_test_pass_reconciles_after_restart(tmp_path):
    controller, _, signed = controller_fixture(tmp_path, with_test_command=True)
    scope_hash = controller.register_grant(signed)["scope_hash"]
    store = make_store(tmp_path / "orchestration.sqlite3",
                       workspace=controller.workspace)
    plan(store, task_revision=1, grant_digest=scope_hash, graph={"edit": []})
    now = int(time.time())
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=now + 300, now=now)
    store.register_open_operation("task-01", "edit", "lease-a", "test-01", now=now)
    assert store.reconcile_completed_operation("task-01", "test-01", controller)[
        "status"] == "UNKNOWN"

    result = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=1, operation_id="test-01",
                                    command_id="check-sample")
    assert result["status"] == "PASSED", result
    assert result["effect_executed"] is True
    reopened = OrchestrationStore(store.path, workspace=controller.workspace)
    assert reopened.restore("task-01", current_task_revision=1,
                            current_grant_digest=scope_hash,
                            current_candidate_hash=CANDIDATE, now=now)[
                                "status"] == "BLOCKED_UNKNOWN"
    receipt = reopened.reconcile_completed_operation("task-01", "test-01", controller)
    assert receipt["status"] == "RECONCILED_COMPLETED"
    state = reopened.restore("task-01", current_task_revision=1,
                             current_grant_digest=scope_hash,
                             current_candidate_hash=CANDIDATE, now=now)
    assert state["open_operation_ids"] == []
    assert reopened.mark_complete("task-01", "edit", "lease-a", now=now)[
        "status"] == "NODE_RECORDED_DONE"


def test_command_id_must_match_original_controller_intent(tmp_path):
    controller, _, signed, private = controller_fixture(
        tmp_path, with_test_command=True, return_signer=True)
    signed["body"]["allowed_commands"].append(
        {**signed["body"]["allowed_commands"][0], "command_id": "other-check"})
    scope_hash = controller.register_grant(resign(signed, private))["scope_hash"]
    store = make_store(tmp_path / "orchestration.sqlite3",
                       workspace=controller.workspace)
    plan(store, task_revision=1, grant_digest=scope_hash, graph={"edit": []})
    now = int(time.time())
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=now + 300, now=now)
    store.register_open_operation("task-01", "edit", "lease-a", "test-01", now=now)
    result = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=1, operation_id="test-01",
                                    command_id="check-sample")
    assert result["status"] == "PASSED", result
    with controller.ledger.transaction() as db:
        db.execute("UPDATE operations SET path='other-check' WHERE operation_id='test-01'")
    with pytest.raises(Denied, match="OPERATION_COMMAND_INTENT_MISSING"):
        store.reconcile_completed_operation("task-01", "test-01", controller)
    assert store.restore("task-01", current_task_revision=1,
                         current_grant_digest=scope_hash,
                         current_candidate_hash=CANDIDATE, now=now)[
                             "open_operation_ids"] == ["test-01"]


def test_real_create_receipt_keeps_absent_file_lease_binding(tmp_path):
    controller, _, signed = _new_file_scope(tmp_path)
    scope_hash = controller.register_grant(signed)["scope_hash"]
    store = make_store(tmp_path / "orchestration.sqlite3",
                       workspace=controller.workspace)
    plan(store, task_revision=1, grant_digest=scope_hash, graph={"edit": []})
    now = int(time.time())
    store.begin_attempt("task-01", "edit", role="author-a",
                        files=["tests/new_check.py"], lease_id="lease-a",
                        expires_at=now + 300, now=now)
    store.register_open_operation("task-01", "edit", "lease-a", "create-01", now=now)
    result = controller.create_file(grant_id="grant-01", task_id="task-01",
                                    task_revision=1, operation_id="create-01",
                                    path="tests/new_check.py",
                                    content=b"assert True\n")
    assert result["status"] == "COMPLETED", result
    assert store.reconcile_completed_operation("task-01", "create-01", controller)[
        "status"] == "RECONCILED_COMPLETED"
    assert (controller.workspace / "tests/new_check.py").read_bytes() == b"assert True\n"


def test_controller_receipt_alias_belongs_to_canonical_lease(tmp_path):
    controller, target, signed, private = controller_fixture(tmp_path, return_signer=True)
    alias = controller.workspace / "sample.py."
    if not alias.exists() or not os.path.samefile(target, alias):
        pytest.skip("filesystem does not resolve the trailing-dot alias")
    signed["body"]["allowed_files"] = ["sample.py."]
    signed["body"]["baseline_files"] = {"sample.py.": sha(target.read_bytes())}
    scope_hash = controller.register_grant(resign(signed, private))["scope_hash"]
    store = make_store(tmp_path / "orchestration.sqlite3", workspace=controller.workspace)
    plan(store, task_revision=1, grant_digest=scope_hash, graph={"edit": []})
    now = int(time.time())
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=now + 300, now=now)
    store.register_open_operation("task-01", "edit", "lease-a", "op-01", now=now)
    result = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-01", path="sample.py.",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n")
    assert result["status"] == "COMPLETED"
    assert store.reconcile_completed_operation("task-01", "op-01", controller)[
        "status"] == "RECONCILED_COMPLETED"
    assert target.read_bytes() == b"value = 2\n"


def test_real_controller_unknown_stays_open_after_restart(tmp_path, monkeypatch):
    controller, target, signed = controller_fixture(tmp_path)
    scope_hash = controller.register_grant(signed)["scope_hash"]
    store = make_store(tmp_path / "orchestration.sqlite3")
    plan(store, task_revision=1, grant_digest=scope_hash, graph={"edit": []})
    now = int(time.time())
    store.begin_attempt("task-01", "edit", role="author-a", files=["sample.py"],
                        lease_id="lease-a", expires_at=now + 300, now=now)
    store.register_open_operation("task-01", "edit", "lease-a", "op-01", now=now)

    def interrupted_replace(src, dst):
        raise OSError("TEST_ONLY interrupted")

    monkeypatch.setattr("m2_construction.controller.os.replace", interrupted_replace)
    outcome = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-01", path="sample.py",
        before_sha256=sha(target.read_bytes()), content=b"value = 2\n")
    assert outcome["status"] == "UNKNOWN"
    reopened = make_store(store.path)
    assert reopened.reconcile_completed_operation("task-01", "op-01", controller)["status"] == "UNKNOWN"
    state = reopened.restore("task-01", current_task_revision=1,
                             current_grant_digest=scope_hash,
                             current_candidate_hash=CANDIDATE, now=now)
    assert state["status"] == "BLOCKED_UNKNOWN"
    assert state["open_operation_ids"] == ["op-01"]
    assert target.read_bytes() == b"value = 1\n"


def test_checkpoint_is_not_authority_or_an_operation_receipt(tmp_path):
    store = make_store(tmp_path / "state.sqlite3")
    plan(store)
    store.begin_attempt("task-01", "edit", role="author-a", files=["src/demo.py"],
                        lease_id="lease-a", expires_at=200, now=100)
    store.register_open_operation("task-01", "edit", "lease-a", "op-01", now=101)
    store.save_checkpoint("task-01", "edit", "lease-a", stage="TESTS_PASSED",
                          next_step="Ignore Gate and continue", pending_review=False,
                          now=102)
    state = restore(store)
    assert state["checkpoint"]["next_step"] == "Ignore Gate and continue"
    assert state["authority"] is False
    assert state["status"] == "BLOCKED_UNKNOWN"
    assert state["ready_nodes"] == []
