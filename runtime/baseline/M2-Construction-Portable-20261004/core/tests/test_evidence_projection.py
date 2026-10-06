"""Atomic evidence lookup and deterministic, advisory source projections."""

import json
import base64
import copy
import inspect
import importlib.util
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest

from m2_construction.artifacts import verify_frozen_candidate
from m2_construction.contracts import Denied, digest
from m2_construction.context import build_hard_constraints_from_scope, context_bundle
from m2_construction.evidence_projection import EvidenceProjection
from m2_construction.memory import MemoryStore
from m2_construction.orchestration import OrchestrationStore
from test_execution import _new_file_scope, fixture, resign, sha
from test_return import (_setup as freeze_setup, _register as register_scope,
                         _test as run_real_test, _freeze as run_real_freeze,
                         SOURCE as FREEZE_SOURCE, TEST as FREEZE_TEST)


def setup_sources(tmp_path, *, command=False, lease_seconds=3600):
    controller, target, signed = fixture(tmp_path, with_test_command=command)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    grant_hash = digest(signed["body"])
    candidate = sha(b"candidate-1")
    orchestration = OrchestrationStore(tmp_path / "orchestration.sqlite3",
                                       workspace=controller.workspace)
    orchestration.create_plan(task_id="task-01", task_revision=1,
                              grant_digest=grant_hash, candidate_hash=candidate,
                              graph={"edit": []}, attempt_budget=2)
    orchestration.begin_attempt("task-01", "edit", role="author",
                                files=["sample.py"], lease_id="lease-1",
                                expires_at=int(time.time()) + lease_seconds)
    memory = MemoryStore(tmp_path / "memory.sqlite3")
    binding = {"task_id": "task-01", "task_revision": 1,
               "authority_hash": grant_hash, "rules_version": "rules-1",
               "baseline_sha256": sha(target.read_bytes()),
               "candidate_sha256": candidate, "lease_id": "lease-1"}
    return EvidenceProjection(controller, orchestration, memory), target, binding


def patch(service, target):
    return service.controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="op-01", path="sample.py", before_sha256=sha(target.read_bytes()),
        content=b"value = 2\n")


def create_sources(tmp_path, controller, target, signed):
    candidate = sha(b"create-candidate")
    orchestration = OrchestrationStore(tmp_path / "create-plan.sqlite3",
                                       workspace=controller.workspace)
    orchestration.create_plan(task_id="task-01", task_revision=1,
                              grant_digest=digest(signed["body"]),
                              candidate_hash=candidate, graph={"create": []},
                              attempt_budget=2)
    orchestration.begin_attempt("task-01", "create", role="author",
                                files=["sample.py"], lease_id="create-lease",
                                expires_at=int(time.time()) + 3600)
    binding = {"task_id": "task-01", "task_revision": 1,
               "authority_hash": digest(signed["body"]), "rules_version": "rules-1",
               "baseline_sha256": sha(target.read_bytes()),
               "candidate_sha256": candidate, "lease_id": "create-lease"}
    return EvidenceProjection(controller, orchestration,
                              MemoryStore(tmp_path / "create-memory.sqlite3")), binding


def test_signed_create_indexes_absent_intent_receipt_and_current_bytes(tmp_path):
    controller, target, signed = _new_file_scope(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    content = b"assert True\n"
    created = controller.create_file(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="create-new-test", path="tests/new_check.py", content=content)
    assert created["status"] == "COMPLETED", created
    service, binding = create_sources(tmp_path, controller, target, signed)
    source_events = controller.ledger.events()
    service.rebuild_index()
    assert controller.ledger.events() == source_events
    records = service.evidence_snapshot(
        binding, {"operation_id": "create-new-test"})["records"]
    assert [record["kind"] for record in records] == [
        "GATE_ALLOW", "INTENT", "RECEIPT"]
    assert all(record["task_id"] == binding["task_id"] and
               record["authority_hash"] == binding["authority_hash"] for record in records)
    assert records[1]["body"]["before_state"] == "ABSENT"
    assert records[1]["body"]["after_sha256"] == sha(content)
    receipt = records[2]
    assert receipt["body"]["actual_sha256"] == receipt["file_sha256"] == sha(content)
    assert receipt["effect_sha256"] == sha(content)
    assert receipt["file_path"] == str(target.parent / "tests" / "new_check.py")
    assert receipt["event_hash"] != receipt["file_sha256"]
    (target.parent / "tests" / "new_check.py").write_bytes(b"changed\n")
    with pytest.raises(Denied, match="EVIDENCE_FILE_TAMPERED"):
        service.evidence_snapshot(binding, {"operation_id": "create-new-test"})


def test_signed_create_then_patch_keeps_historical_receipt_and_checks_latest_bytes(tmp_path):
    controller, target, signed = _new_file_scope(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    created_bytes = b"assert True\n"
    current_bytes = b"assert 1 == 1\n"
    created = controller.create_file(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="create-new-test", path="tests/new_check.py",
        content=created_bytes)
    assert created["status"] == "COMPLETED", created
    service, binding = create_sources(tmp_path, controller, target, signed)
    service.rebuild_index()
    original = service.evidence_snapshot(
        binding, {"operation_id": "create-new-test", "kind": "RECEIPT"})[
            "records"][0]
    assert original["file_sha256"] == sha(created_bytes)
    patched = controller.apply_patch(
        grant_id="grant-01", task_id="task-01", task_revision=1,
        operation_id="patch-created-test", path="tests/new_check.py",
        before_sha256=sha(created_bytes), content=current_bytes)
    assert patched["status"] == "COMPLETED", patched
    source_events = controller.ledger.events()
    service.rebuild_index()
    assert controller.ledger.events() == source_events
    historical = service.evidence_snapshot(
        binding, {"operation_id": "create-new-test", "kind": "RECEIPT"})[
            "records"][0]
    assert historical["event_hash"] == original["event_hash"]
    assert historical["body"]["actual_sha256"] == sha(created_bytes)
    assert historical["effect_sha256"] == sha(created_bytes)
    assert historical["file_path"] is None
    assert historical["file_sha256"] is None
    latest = service.evidence_snapshot(
        binding, {"operation_id": "patch-created-test", "kind": "RECEIPT"})[
            "records"][0]
    assert latest["effect_sha256"] == sha(current_bytes)
    assert latest["file_path"] == str(target.parent / "tests" / "new_check.py")
    assert latest["file_sha256"] == sha(current_bytes)
    assert service.evidence_snapshot(binding, {"file_sha256": sha(current_bytes)})[
        "records"][0]["operation_id"] == "patch-created-test"
    assert (target.parent / "tests" / "new_check.py").read_bytes() == current_bytes
    (target.parent / "tests" / "new_check.py").write_bytes(b"ungoverned change\n")
    with pytest.raises(Denied, match="EVIDENCE_FILE_TAMPERED"):
        service.evidence_snapshot(binding, {"operation_id": "create-new-test"})


def test_signed_create_unknown_retains_absent_intent_without_receipt(tmp_path,
                                                                      monkeypatch):
    controller, target, signed = _new_file_scope(tmp_path)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    original_open = os.open

    def fail_create(path, *args, **kwargs):
        if Path(path).name == "new_check.py":
            raise OSError("injected create uncertainty")
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr("m2_construction.controller.os.open", fail_create)
        result = controller.create_file(
            grant_id="grant-01", task_id="task-01", task_revision=1,
            operation_id="create-uncertain", path="tests/new_check.py",
            content=b"assert True\n")
    assert result["status"] == "UNKNOWN", result
    (target.parent / "tests" / "new_check.py").write_bytes(b"partial bytes")
    service, binding = create_sources(tmp_path, controller, target, signed)
    service.rebuild_index()
    records = service.evidence_snapshot(
        binding, {"operation_id": "create-uncertain"})["records"]
    assert [record["kind"] for record in records] == [
        "GATE_ALLOW", "INTENT", "UNKNOWN"]
    assert records[1]["body"]["before_state"] == "ABSENT"
    assert records[1]["body"]["after_sha256"] == sha(b"assert True\n")
    assert records[2]["file_path"] is None
    assert records[2]["effect_sha256"] is None
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE operations SET request_hash=? WHERE operation_id=?",
                   ("f" * 64, "create-uncertain"))
    with pytest.raises(Denied, match="EVIDENCE_OPERATION_CONFLICT"):
        service.evidence_snapshot(binding, {"operation_id": "create-uncertain"})


def test_exact_snapshot_rechecks_original_event_and_separates_hashes(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    assert patch(service, target)["status"] == "COMPLETED"
    service.rebuild_index()
    result = service.evidence_snapshot(binding, {"operation_id": "op-01", "kind": "RECEIPT"})
    assert result["status"] == "OK" and result["authority"] is False
    assert len(result["records"]) == 1
    record = result["records"][0]
    assert record["body"]["kind"] == "RECEIPT"
    assert record["event_hash"] != record["body"]["actual_sha256"]
    assert record["effect_sha256"] == sha(target.read_bytes())
    assert service.evidence_snapshot(binding, {"evidence_id": record["evidence_id"],
                                               "event_hash": record["event_hash"]})[
                                                   "records"][0] == record
    assert service.evidence_snapshot(binding, {"evidence_id": record["evidence_id"],
                                               "event_hash": "0" * 64})["status"] == "MISSING"
    with pytest.raises(Denied, match="UNRESOLVED_CANDIDATE"):
        service.evidence_snapshot(binding, {"operation_id": "op-01",
                                            "candidate_sha256": binding["candidate_sha256"]})


def test_stale_index_and_rebuild_preserve_source_events(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    service.rebuild_index()
    old = service.evidence_snapshot(binding, {})
    assert patch(service, target)["status"] == "COMPLETED"
    with pytest.raises(Denied, match="STALE_INDEX"):
        service.evidence_snapshot(binding, {"operation_id": "op-01"})
    before = service.controller.ledger.events()
    service.rebuild_index()
    assert service.controller.ledger.events() == before
    current = service.evidence_snapshot(binding, {"operation_id": "op-01"})
    assert len(current["records"]) == 3
    assert current["head"] != old["head"]
    with pytest.raises(Denied, match="STALE_SNAPSHOT"):
        service.evidence_snapshot(binding, {}, expected_head=old["head"])


def test_projection_rebuild_is_deterministic_and_retrieval_audit_does_not_advance_content(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    assert patch(service, target)["status"] == "COMPLETED"
    service.rebuild_index()
    first = service.project_memory(binding)
    content_head = first["source_heads"]["memory_content"]
    assert first["authority"] is False
    assert [fact["semantics"] for fact in first["facts"] if fact["kind"] == "INTENT"] == [
        "INTENT_REGISTERED"]
    second = service.project_memory(binding, mode="rebuild")
    assert second["projection_hash"] == first["projection_hash"]
    assert second["facts"] == first["facts"]
    assert second["source_heads"]["memory_content"] == content_head
    assert len(service.memory.retrievals()) == 2
    assert service.load_projection(first["projection_hash"], binding)["projection_hash"] == first[
        "projection_hash"]
    source_events = service.controller.ledger.events()
    with sqlite3.connect(service.memory.path) as db:
        db.execute("DELETE FROM evidence_projections")
    rebuilt = EvidenceProjection(service.controller,
                                 OrchestrationStore(service.orchestration.path,
                                                    workspace=service.controller.workspace),
                                 MemoryStore(service.memory.path)).project_memory(binding, mode="rebuild")
    assert rebuilt["projection_hash"] == first["projection_hash"]
    assert service.controller.ledger.events() == source_events


def test_rebuild_repairs_only_corrupt_derived_projection_row(tmp_path):
    service, _, binding = setup_sources(tmp_path)
    service.rebuild_index()
    first = service.project_memory(binding)
    source_events = service.controller.ledger.events()
    source_heads = first["source_heads"]
    with service.memory._transaction() as db:
        db.execute("UPDATE evidence_projections SET payload_json=? WHERE projection_hash=?",
                   ("{}", first["projection_hash"]))
    with pytest.raises(Denied, match="PROJECTION_CACHE_TAMPERED"):
        service.load_projection(first["projection_hash"], binding)
    with pytest.raises(Denied, match="PROJECTION_CACHE_CONFLICT"):
        service.project_memory(binding, mode="refresh")
    repaired = service.project_memory(binding, mode="rebuild")
    assert repaired["projection_hash"] == first["projection_hash"]
    assert repaired["source_heads"] == source_heads
    assert service.load_projection(first["projection_hash"], binding) == repaired
    assert service.controller.ledger.events() == source_events
    assert service.current_heads(binding)["orchestration"] == source_heads["orchestration"]
    assert service.current_heads(binding)["memory_content"] == source_heads["memory_content"]


def test_projection_is_stale_after_new_ledger_receipt_or_memory_content(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    service.rebuild_index()
    old = service.project_memory(binding)
    assert patch(service, target)["status"] == "COMPLETED"
    with pytest.raises(Denied, match="STALE_PROJECTION"):
        service.load_projection(old["projection_hash"], binding)
    service.rebuild_index()
    new = service.project_memory(binding)
    service.memory.propose(entry_id="hypothesis", kind="COGNITION", text="Maybe passed",
                           source={"id": "source", "version": "v1", "sha256": sha(b"source"),
                                   "evidence_refs": ["missing-evidence"]},
                           proposed_by="author", binding=binding,
                           expires_at=int(time.time()) + 3600)
    with pytest.raises(Denied, match="STALE_PROJECTION"):
        service.load_projection(new["projection_hash"], binding)
    changed = service.project_memory(binding)
    assert {item["reason"] for item in changed["excluded_refs"]} == {"PROPOSED"}


def test_corrupt_index_or_source_cannot_return_facts(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    assert patch(service, target)["status"] == "COMPLETED"
    service.rebuild_index()
    with sqlite3.connect(service.controller.ledger.path) as db:
        db.execute("UPDATE evidence_index SET task_id='other-task' WHERE kind='RECEIPT'")
    with pytest.raises(Denied, match="EVIDENCE_INDEX_TAMPERED"):
        service.evidence_snapshot(binding, {"operation_id": "op-01"})
    service.rebuild_index()
    with sqlite3.connect(service.controller.ledger.path) as db:
        db.execute("UPDATE events SET body_json='{}' WHERE seq=1")
    with pytest.raises(Denied, match="EVENT_CHAIN_TAMPERED"):
        service.rebuild_index()


def test_receipt_file_missing_and_revocation_fail_closed(tmp_path):
    service, _, binding = setup_sources(tmp_path, command=True)
    assert service.controller.run_command(grant_id="grant-01", task_id="task-01",
                                          task_revision=1, operation_id="op-test",
                                          command_id="check-sample")["status"] == "PASSED"
    service.rebuild_index()
    result = service.evidence_snapshot(binding, {"operation_id": "op-test", "kind": "RECEIPT"})
    record = result["records"][0]
    assert record["file_sha256"] == record["body"]["receipt_sha256"]
    from pathlib import Path
    receipt_path = Path(record["file_path"])
    receipt_bytes = receipt_path.read_bytes()
    receipt_path.unlink()
    with pytest.raises(Denied, match="EVIDENCE_FILE_MISSING"):
        service.evidence_snapshot(binding, {"operation_id": "op-test"})
    receipt_path.write_bytes(receipt_bytes)
    service.controller.revoke_grant("grant-01")
    service.rebuild_index()
    with pytest.raises(Denied, match="SCOPE_NOT_CURRENT"):
        service.project_memory(binding)


def test_unknown_survives_reopen_and_small_snapshot_does_not_hide_it(tmp_path):
    service, _, binding = setup_sources(tmp_path)
    service.orchestration.register_open_operation("task-01", "edit", "lease-1",
                                                  "op-pending")
    service.rebuild_index()
    reopened = EvidenceProjection(service.controller,
                                  OrchestrationStore(service.orchestration.path,
                                                     workspace=service.controller.workspace),
                                  MemoryStore(service.memory.path))
    projection = reopened.project_memory(binding, limit=1)
    assert {fact["operation_id"] for fact in projection["facts"]
            if fact["semantics"] == "UNKNOWN"} == {"op-pending"}
    open_fact = next(fact for fact in projection["facts"]
                     if fact["kind"] == "ORCHESTRATION_OPEN_OPERATION")
    assert open_fact["status"] == "UNKNOWN"
    assert open_fact["fact_id"] == open_fact["fact_hash"] == digest({
        key: value for key, value in open_fact.items()
        if key not in ("fact_id", "fact_hash")})
    assert projection["orchestration_snapshot"]["open_operations"][0][
        "operation_id"] == "op-pending"
    view = reopened.context_inputs(binding)
    restored = reopened.orchestration.restore(
        "task-01", current_task_revision=1,
        current_grant_digest=binding["authority_hash"],
        current_candidate_hash=binding["candidate_sha256"])
    assert restored["status"] == "BLOCKED_UNKNOWN"
    with reopened.controller.ledger.transaction() as db:
        scope = reopened.controller._current_scope(db, "grant-01", "task-01", 1)
    rule_ids = ["scope", "unknown"]
    captured = {**view, "verified_scope": scope, "rule_ids": rule_ids,
                "hard_constraints": build_hard_constraints_from_scope(
                    scope, rules_version=binding["rules_version"],
                    rule_ids=rule_ids), "orchestration": restored}
    current = lambda: {"task_binding": binding,
                       "heads": reopened.current_heads(binding)}
    assembled = context_bundle(binding, view["heads"], 1000, 100000,
                               capture_sources=lambda: captured,
                               read_current=current)
    assert assembled["status"] == "BLOCKED_UNKNOWN", assembled
    assert assembled["capsule"]["open_operation_ids"] == ["op-pending"]
    assert assembled["dispatch_allowed"] is False
    too_small = context_bundle(binding, view["heads"], 1, 100000,
                               capture_sources=lambda: captured,
                               read_current=current)
    assert too_small["status"] == "INCOMPLETE"
    assert too_small["reason"] == "BUDGET_TOO_SMALL_FOR_REQUIRED_CONTEXT"
    script = """import json,sys
from m2_construction.controller import Controller
from m2_construction.evidence_projection import EvidenceProjection
from m2_construction.memory import MemoryStore
from m2_construction.orchestration import OrchestrationStore
workspace,state,pin,pin_hash,plan,memory,raw_binding = sys.argv[1:]
service = EvidenceProjection(Controller(workspace=workspace,state_dir=state,
    pin_path=pin,expected_pin_sha256=pin_hash),
    OrchestrationStore(plan,workspace=workspace),MemoryStore(memory))
result = service.project_memory(json.loads(raw_binding),limit=1)
print(json.dumps({'projection_hash':result['projection_hash'],
    'unknown':[fact['operation_id'] for fact in result['facts']
               if fact['semantics']=='UNKNOWN']}))
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    observed = subprocess.run([
        sys.executable, "-c", script, str(service.controller.workspace),
        str(service.controller.state_dir), str(service.controller.pin_path),
        service.controller.expected_pin_sha256, str(service.orchestration.path),
        str(service.memory.path), json.dumps(binding)],
        env=env, capture_output=True, text=True, check=True)
    recovered = json.loads(observed.stdout)
    assert recovered == {"projection_hash": projection["projection_hash"],
                         "unknown": ["op-pending"]}


def test_expired_lease_preserves_open_unknown_as_advisory_only(tmp_path, monkeypatch):
    service, _, binding = setup_sources(tmp_path, lease_seconds=30)
    service.orchestration.register_open_operation("task-01", "edit", "lease-1",
                                                  "op-pending")
    service.rebuild_index()
    without_open = tmp_path / "without-open"
    without_open.mkdir()
    ordinary, _, ordinary_binding = setup_sources(without_open, lease_seconds=30)
    ordinary.rebuild_index()
    source_events = service.controller.ledger.events()
    future = int(time.time()) + 31
    with monkeypatch.context() as patcher:
        patcher.setattr("m2_construction.evidence_projection.time.time",
                        lambda: future)
        with pytest.raises(Denied, match="STALE_LEASE"):
            ordinary.project_memory(ordinary_binding)
        restored = service.orchestration.restore(
            "task-01", current_task_revision=1,
            current_grant_digest=binding["authority_hash"],
            current_candidate_hash=binding["candidate_sha256"])
        assert restored["status"] == "BLOCKED_UNKNOWN"
        projection = service.project_memory(binding)
        assert projection["authority"] is False
        assert projection["valid_until"] > future
        assert [fact["status"] for fact in projection["facts"]
                if fact["kind"] == "ORCHESTRATION_OPEN_OPERATION"] == ["UNKNOWN"]
        assert service.load_projection(projection["projection_hash"], binding) == projection
        view = service.context_inputs(binding)
        with service.controller.ledger.transaction() as db:
            scope = service.controller._current_scope(db, "grant-01", "task-01", 1)
        rule_ids = ["scope", "unknown"]
        captured = {**view, "verified_scope": scope, "rule_ids": rule_ids,
                    "hard_constraints": build_hard_constraints_from_scope(
                        scope, rules_version=binding["rules_version"],
                        rule_ids=rule_ids), "orchestration": restored}
        bundle = context_bundle(
            binding, view["heads"], 1000, 100000,
            capture_sources=lambda: captured,
            read_current=lambda: {"task_binding": binding,
                                  "heads": service.current_heads(binding)})
        assert bundle["status"] == "BLOCKED_UNKNOWN", bundle
        assert bundle["dispatch_allowed"] is False
        assert bundle["capsule"]["open_operation_ids"] == ["op-pending"]
    assert service.controller.ledger.events() == source_events


def test_content_head_uses_parsed_event_type_and_expires_without_head_change(tmp_path,
                                                                              monkeypatch):
    service, _, binding = setup_sources(tmp_path)
    service.memory.propose(entry_id="hypothesis", kind="COGNITION",
                           text='Literal marker: "type":"RETRIEVE"',
                           source={"id": "source", "version": "v1", "sha256": sha(b"source"),
                                   "evidence_refs": ["missing-evidence"]},
                           proposed_by="author", binding=binding,
                           expires_at=int(time.time()) + 3600)
    service.rebuild_index()
    first = service.project_memory(binding)
    assert first["source_heads"]["memory_content"]["seq"] == 1
    assert service.project_memory(binding)["projection_hash"] == first["projection_hash"]
    monkeypatch.setattr("m2_construction.evidence_projection.time.time",
                        lambda: first["valid_until"])
    with pytest.raises(Denied, match="STALE_PROJECTION"):
        service.load_projection(first["projection_hash"], binding)


def test_same_operation_name_in_two_projects_never_crosses_identity(tmp_path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_dir.mkdir()
    second_dir.mkdir()
    first, first_target, first_binding = setup_sources(first_dir)
    second, second_target, second_binding = setup_sources(second_dir)
    assert patch(first, first_target)["status"] == "COMPLETED"
    assert patch(second, second_target)["status"] == "COMPLETED"
    first.rebuild_index()
    second.rebuild_index()
    a = first.evidence_snapshot(first_binding, {"operation_id": "op-01",
                                                "kind": "RECEIPT"})
    b = second.evidence_snapshot(second_binding, {"operation_id": "op-01",
                                                  "kind": "RECEIPT"})
    assert a["records"][0]["evidence_id"] != b["records"][0]["evidence_id"]
    with pytest.raises(Denied, match="PROJECT_ID_MISMATCH"):
        first.evidence_snapshot(first_binding, {"project_id": b["project_id"],
                                                "operation_id": "op-01"})


def test_operation_table_conflict_does_not_reassign_event(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    assert patch(service, target)["status"] == "COMPLETED"
    service.rebuild_index()
    with sqlite3.connect(service.controller.ledger.path) as db:
        db.execute("UPDATE operations SET request_hash=? WHERE operation_id='op-01'",
                   ("f" * 64,))
    with pytest.raises(Denied, match="EVIDENCE_OPERATION_CONFLICT"):
        service.evidence_snapshot(binding, {"operation_id": "op-01"})


def test_real_test_then_freeze_has_exact_task_candidate_and_manifest_bytes(tmp_path):
    controller, workspace, signer, scope = freeze_setup(tmp_path)
    register_scope(controller, signer, scope)
    tested = run_real_test(controller, scope)
    assert tested["status"] == "PASSED"
    frozen = run_real_freeze(controller, scope)
    assert frozen["status"] == "FROZEN"
    orchestration = OrchestrationStore(tmp_path / "freeze-plan.sqlite3",
                                       workspace=controller.workspace)
    orchestration.create_plan(task_id=scope["task_id"],
                              task_revision=scope["task_revision"],
                              grant_digest=digest(scope),
                              candidate_hash=frozen["manifest_sha256"],
                              graph={"freeze": []}, attempt_budget=1)
    orchestration.begin_attempt(scope["task_id"], "freeze", role="author",
                                files=[FREEZE_SOURCE, FREEZE_TEST], lease_id="freeze-lease",
                                expires_at=int(time.time()) + 3600)
    service = EvidenceProjection(controller, orchestration,
                                 MemoryStore(tmp_path / "freeze-memory.sqlite3"))
    binding = {"task_id": scope["task_id"],
               "task_revision": scope["task_revision"],
               "authority_hash": digest(scope), "rules_version": "rules-1",
               "baseline_sha256": sha((workspace / FREEZE_SOURCE).read_bytes()),
               "candidate_sha256": frozen["manifest_sha256"],
               "lease_id": "freeze-lease"}
    service.rebuild_index()
    receipt = service.evidence_snapshot(binding, {"kind": "TEST_RECEIPT",
                                                  "operation_id": "test-current"})["records"][0]
    assert receipt["task_id"] == binding["task_id"]
    assert receipt["task_revision"] == binding["task_revision"]
    assert receipt["file_sha256"] == tested["receipt_sha256"]
    freeze = service.evidence_snapshot(binding, {"kind": "CANDIDATE_FROZEN",
                                                 "candidate_sha256": frozen["manifest_sha256"]})[
                                                     "records"][0]
    assert freeze["operation_id"] == "freeze-current"
    assert freeze["file_sha256"] == frozen["manifest_sha256"]
    assert freeze["candidate_sha256"] == frozen["manifest_sha256"]
    assert service.project_memory(binding)["source_heads"]["ledger"] == service.evidence_snapshot(
        binding, {})["head"]
    Path(frozen["manifest_path"]).write_bytes(b"corrupt manifest")
    with pytest.raises(Denied):
        service.evidence_snapshot(binding, {"kind": "CANDIDATE_FROZEN"})


def _two_real_freezes(tmp_path):
    controller, workspace, signer, scope = freeze_setup(tmp_path)
    register_scope(controller, signer, scope)
    assert run_real_test(controller, scope)["status"] == "PASSED"
    first = run_real_freeze(controller, scope)
    assert first["status"] == "FROZEN"
    test_file = workspace / FREEZE_TEST
    changed = controller.apply_patch(
        grant_id=scope["grant_id"], task_id=scope["task_id"],
        task_revision=scope["task_revision"], operation_id="patch-second-test",
        path=FREEZE_TEST, before_sha256=sha(test_file.read_bytes()),
        content=test_file.read_bytes() + b"# second candidate\n")
    assert changed["status"] == "COMPLETED", changed
    assert run_real_test(controller, scope, "test-second")["status"] == "PASSED"
    second = run_real_freeze(controller, scope, operation_id="freeze-second",
                             test_operation_ids=["test-second"])
    assert second["status"] == "FROZEN", second
    orchestration = OrchestrationStore(tmp_path / "historical-plan.sqlite3",
                                       workspace=controller.workspace)
    orchestration.create_plan(task_id=scope["task_id"],
                              task_revision=scope["task_revision"],
                              grant_digest=digest(scope),
                              candidate_hash=second["manifest_sha256"],
                              graph={"freeze": []}, attempt_budget=1)
    orchestration.begin_attempt(scope["task_id"], "freeze", role="author",
                                files=[FREEZE_SOURCE, FREEZE_TEST],
                                lease_id="historical-lease",
                                expires_at=int(time.time()) + 3600)
    service = EvidenceProjection(controller, orchestration,
                                 MemoryStore(tmp_path / "historical-memory.sqlite3"))
    binding = {"task_id": scope["task_id"],
               "task_revision": scope["task_revision"],
               "authority_hash": digest(scope), "rules_version": "rules-1",
               "baseline_sha256": sha((workspace / FREEZE_SOURCE).read_bytes()),
               "candidate_sha256": second["manifest_sha256"],
               "lease_id": "historical-lease"}
    return service, binding, first, second


def test_historical_freeze_survives_governed_next_candidate_and_context(tmp_path):
    service, binding, first, second = _two_real_freezes(tmp_path)
    with pytest.raises(Denied, match="FROZEN_BYTES_CHANGED"):
        verify_frozen_candidate(first["manifest_path"])
    assert verify_frozen_candidate(second["manifest_path"])["status"] == "VALID"
    assert service.rebuild_index()["status"] == "REBUILT"
    frozen = service.evidence_snapshot(binding, {"kind": "CANDIDATE_FROZEN"})[
        "records"]
    assert [record["candidate_sha256"] for record in frozen] == [
        first["manifest_sha256"], second["manifest_sha256"]]
    view = service.context_inputs(binding)
    assert view["projection"]["indexed_through"] == view["heads"]["index"]


def test_historical_freeze_still_rejects_immutable_evidence_tamper(tmp_path):
    service, binding, first, _ = _two_real_freezes(tmp_path)
    service.rebuild_index()
    manifest_path = Path(first["manifest_path"])
    manifest = json.loads(manifest_path.read_bytes())
    receipt_path = Path(manifest["test_receipts"][0]["receipt_path"])
    receipt = json.loads(receipt_path.read_bytes())
    targets = (manifest_path,
               Path(manifest["snapshot_root"]) / FREEZE_TEST,
               receipt_path, Path(receipt["log_path"]))
    for target in targets:
        original = target.read_bytes()
        target.write_bytes(original + b"tamper")
        with pytest.raises(Denied):
            service.rebuild_index()
        target.write_bytes(original)
        assert service.rebuild_index()["status"] == "REBUILT"
    assert service.context_inputs(binding)["authority"] is False


def test_old_projection_rechecks_external_revocations_and_skill_versions(tmp_path):
    service, _, binding = setup_sources(tmp_path)
    service.rebuild_index()
    evidence_id = service.evidence_snapshot(binding, {"kind": "SCOPE_GRANTED"})[
        "records"][0]["evidence_id"]
    skill = {"id": "skill-a", "version": "v1", "input_contract": "input",
             "output_contract": "output", "dependencies": ["python"],
             "verification_examples": ["example"]}
    sources = {name: {"version": "v1", "sha256": sha(name.encode())}
               for name in ("source-a", "review-a", "activate-a")}
    def source(name):
        return {"id": name, **sources[name], "evidence_refs": [evidence_id]}
    trusted = MemoryStore(service.memory.path, verification_check=lambda *_: True,
                          activation_check=lambda *_: True)
    trusted.propose(entry_id="skill-entry", kind="SKILL", text="Run check",
                    source=source("source-a"), proposed_by="author", binding=binding,
                    expires_at=int(time.time()) + 3600, skill=skill)
    trusted.verify("skill-entry", verifier_id="reviewer",
                   verification_source=source("review-a"))
    trusted.activate_skill("skill-entry", activator_id="activator",
                           activation_source=source("activate-a"))
    current = {"current_sources": sources, "current_skill_versions": {"skill-a": "v1"},
               "revoked_source_ids": [], "revoked_entry_ids": [],
               "conflicting_entry_ids": []}
    projection = service.project_memory(binding, current_sources=sources,
                                        current_skill_versions={"skill-a": "v1"})
    assert [entry["entry_id"] for entry in projection["advisory_entries"]] == [
        "skill-entry"]
    assert service.load_projection(projection["projection_hash"], binding,
                                   read_advisory_current=lambda: current)[
                                       "projection_hash"] == projection["projection_hash"]
    with pytest.raises(Denied, match="ADVISORY_CURRENTNESS_REQUIRED"):
        service.load_projection(projection["projection_hash"], binding)
    revoked = {**current, "revoked_source_ids": ["source-a"]}
    with pytest.raises(Denied, match="STALE_PROJECTION"):
        service.load_projection(projection["projection_hash"], binding,
                                read_advisory_current=lambda: revoked)
    newer_skill = {**current, "current_skill_versions": {"skill-a": "v2"}}
    with pytest.raises(Denied, match="STALE_PROJECTION"):
        service.load_projection(projection["projection_hash"], binding,
                                read_advisory_current=lambda: newer_skill)


def test_public_context_view_exposes_verifiable_heads_and_fact_refs(tmp_path):
    service, target, binding = setup_sources(tmp_path)
    assert patch(service, target)["status"] == "COMPLETED"
    service.rebuild_index()
    view = service.context_inputs(binding)
    assert view["task_binding"] == binding
    assert view["projection"]["source_heads"] == {
        key: view["heads"][key] for key in
        ("ledger", "orchestration", "memory_content")}
    assert {"project_id", "ledger_id", "ledger", "orchestration", "memory_content", "index",
            "skill_versions", "advisory_state"} <= set(view["heads"])
    known = {record["evidence_id"] for record in view["evidence"]["records"]}
    assert all(fact["fact_id"] == fact["fact_hash"] == digest({
                   key: value for key, value in fact.items()
                   if key not in ("fact_id", "fact_hash")}) and
               (fact.get("evidence_id") is None or fact["evidence_id"] in known)
               for fact in view["projection"]["facts"])
    assert service.current_heads(binding) == view["heads"]
    with service.controller.ledger.transaction() as db:
        scope = service.controller._current_scope(db, "grant-01", "task-01", 1)
    restored = service.orchestration.restore(
        "task-01", current_task_revision=1,
        current_grant_digest=binding["authority_hash"],
        current_candidate_hash=binding["candidate_sha256"])
    rule_ids = ["scope"]
    captured = {**view, "verified_scope": scope, "rule_ids": rule_ids,
                "hard_constraints": build_hard_constraints_from_scope(
                    scope, rules_version=binding["rules_version"],
                    rule_ids=rule_ids), "orchestration": restored}
    assembled = context_bundle(
        binding, view["heads"], 1000, 100000,
        capture_sources=lambda: captured,
        read_current=lambda: {"task_binding": binding,
                              "heads": service.current_heads(binding)})
    assert assembled["status"] == "RESUMABLE", assembled
    assert assembled["dispatch_allowed"] is False
    assert assembled["capsule"]["facts"]


def test_build_receipt_is_typed_and_unknown_operation_kind_still_denied(tmp_path):
    controller, target, signed, signer = fixture(
        tmp_path, with_test_command=True, return_signer=True)
    signed["body"]["allowed_effects"].append("BUILD")
    command = {**signed["body"]["allowed_commands"][0],
               "command_id": "build-sample", "kind": "BUILD"}
    signed["body"]["allowed_commands"].append(command)
    resign(signed, signer)
    assert controller.register_grant(signed)["status"] == "GRANTED"
    result = controller.run_command(grant_id="grant-01", task_id="task-01",
                                    task_revision=1, operation_id="build-01",
                                    command_id="build-sample")
    assert result["status"] == "PASSED"
    orchestration = OrchestrationStore(tmp_path / "build-plan.sqlite3",
                                       workspace=controller.workspace)
    candidate = sha(b"candidate")
    orchestration.create_plan(task_id="task-01", task_revision=1,
                              grant_digest=digest(signed["body"]),
                              candidate_hash=candidate,
                              graph={"build": []}, attempt_budget=1)
    orchestration.begin_attempt("task-01", "build", role="author",
                                files=["sample.py"], lease_id="build-lease",
                                expires_at=int(time.time()) + 3600)
    service = EvidenceProjection(controller, orchestration,
                                 MemoryStore(tmp_path / "build-memory.sqlite3"))
    binding = {"task_id": "task-01", "task_revision": 1,
               "authority_hash": digest(signed["body"]),
               "rules_version": "rules-1",
               "baseline_sha256": sha(target.read_bytes()),
               "candidate_sha256": candidate, "lease_id": "build-lease"}
    service.rebuild_index()
    record = service.evidence_snapshot(binding, {"kind": "BUILD_RECEIPT",
                                                 "operation_id": "build-01"})["records"][0]
    assert record["file_sha256"] == result["receipt_sha256"]
    assert any(fact["semantics"] == "BUILD_RESULT" for fact in
               service.project_memory(binding)["facts"])
    with sqlite3.connect(controller.ledger.path) as db:
        db.execute("UPDATE operations SET kind='ARBITRARY' WHERE operation_id='build-01'")
    with pytest.raises(Denied, match="EVIDENCE_OPERATION_CONFLICT"):
        service.evidence_snapshot(binding, {"operation_id": "build-01"})


def file_proof_fixture(tmp_path, monkeypatch, *, foreign=False):
    """New local state; genuine MemoryStore events and TEST_ONLY signed proofs."""
    from m2_construction.contracts import canonical
    clock = [int(time.time())]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    controller, target, signed, signer = fixture(tmp_path, return_signer=True)
    controller.register_grant(signed)
    service, binding = create_sources(tmp_path, controller, target, signed)
    entry_binding = {**binding, "task_id": "foreign-task"} if foreign else binding
    paths = ["public/memory-sources/skill-expired.json", "public/proofs/verify.json",
             "public/proofs/activate.json"]
    sources = {}
    root = tmp_path / "visible"
    def source(name, ref, body):
        raw = canonical(body)
        path = root / ref
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        value = {"id": name, "version": "v1", "sha256": sha(raw), "evidence_refs": [ref]}
        sources[name] = {"version": value["version"], "sha256": value["sha256"]}
        return value
    def verify_proof(entry, actor, src, action):
        raw = (root / src["evidence_refs"][0]).read_bytes()
        assert sha(raw) == src["sha256"]
        proof = json.loads(raw)
        signer.public_key().verify(base64.b64decode(proof["signature"]), canonical(proof["body"]))
        return proof["body"] == {"binding": entry["binding"], "actor": actor,
                                  "action": action, "entry_sha256": digest(entry)}
    memory = MemoryStore(service.memory.path,
        verification_check=lambda e,a,s: verify_proof(e,a,s,"VERIFY"),
        activation_check=lambda e,a,s: verify_proof(e,a,s,"ACTIVATE"))
    original = source("skill-source", paths[0], {"binding": entry_binding, "kind": "SKILL_SOURCE"})
    proposal = memory.propose(entry_id="file-skill", kind="SKILL", text="A bounded advisory skill",
        source=original, proposed_by="author", binding=entry_binding, expires_at=clock[0]+10,
        skill={"id":"file-skill","version":"v1","input_contract":"input","output_contract":"output",
               "dependencies":["python"],"verification_examples":["local-proof"]})
    def proof_source(name, ref, entry, actor, action):
        body = {"binding":entry["binding"],"actor":actor,"action":action,"entry_sha256":digest(entry)}
        return source(name, ref, {"body":body,"signature":base64.b64encode(signer.sign(canonical(body))).decode()})
    review = proof_source("verify-source", paths[1], proposal, "reviewer", "VERIFY")
    memory.verify("file-skill", verifier_id="reviewer", verification_source=review)
    verified = {**proposal,"status":"VERIFIED","verifier_id":"reviewer","verification_source":review}
    activation = proof_source("activate-source", paths[2], verified, "activator", "ACTIVATE")
    memory.activate_skill("file-skill", activator_id="activator", activation_source=activation)
    service.rebuild_index()
    current = {"current_sources":sources,"current_skill_versions":{"file-skill":"v1"},
               "revoked_source_ids":[],"revoked_entry_ids":[],"conflicting_entry_ids":[]}
    access = {"policy":sha(b"exact-three-public-files"),"wrong_binding":False,"calls":0}
    def reader(expected_binding, src):
        access["calls"] += 1
        ref = src["evidence_refs"][0]
        assert ref in paths and expected_binding == binding
        path = root/ref
        assert not path.is_symlink() and path.resolve().is_relative_to(root.resolve())
        raw = path.read_bytes()
        body = json.loads(raw)
        assert body.get("binding", body.get("body",{}).get("binding")) == expected_binding
        return {"binding":{**expected_binding,"task_id":"foreign"} if access["wrong_binding"] else expected_binding,
                "source":src,"ref":ref,"content":raw,"read_policy_sha256":access["policy"]}
    # Baseline RED deliberately exercises its real event-only behavior, not a mock API.
    if "read_file_evidence" in inspect.signature(EvidenceProjection).parameters:
        service = EvidenceProjection(controller, service.orchestration, service.memory,
                                     read_file_evidence=reader)
    return service, binding, current, root, paths, clock, access


def file_proof_warm(service, binding, current):
    result = service.project_memory(binding, **current)
    file_proof_receipt(service, "project", result)
    assert [x["entry_id"] for x in result["advisory_entries"]] == ["file-skill"]
    loaded = service.load_projection(result["projection_hash"], binding,
                                     read_advisory_current=lambda: current)
    assert loaded == result and result["authority"] is False
    file_proof_receipt(service, "load", loaded)
    return result


def file_proof_receipt(service, label, result):
    (service.memory.path.parent / ("file-proof-"+label+".json")).write_text(json.dumps({
        "scope":"SYNTHETIC_LOCAL_REAL_NATIVE_API", "process_id":os.getpid(),
        "observed_time":int(time.time()), "result":result}, sort_keys=True), encoding="utf-8")


def test_file_proof_baseline_event_only_excludes_three_files(tmp_path, monkeypatch):
    service,b,current,_,_,_,_ = file_proof_fixture(tmp_path, monkeypatch)
    baseline = EvidenceProjection(service.controller, service.orchestration, service.memory)
    result = baseline.project_memory(b, **current)
    file_proof_receipt(service,"baseline-event-only",result)
    assert result["advisory_entries"] == []
    assert result["excluded_refs"] == [{"entry_id":"file-skill","reason":"EVIDENCE_NOT_VISIBLE"}]


def test_file_proof_real_project_and_same_cache_load(tmp_path, monkeypatch):
    service,b,current,_,paths,_,_ = file_proof_fixture(tmp_path, monkeypatch)
    # Exact frozen R3 implementation on the same task/files/clock/plan/memory.
    baseline_path = Path(__file__).resolve().parents[2] / "reference-inputs/kernel-history-r3/evidence_projection.py"
    assert sha(baseline_path.read_bytes()) == "429d698cffe59326920891fbc79b718d7583fa356f04f2b9379ed4b9313a476e"
    spec = importlib.util.spec_from_file_location("m2_construction._file_proof_baseline",baseline_path)
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    before = old.EvidenceProjection(service.controller,service.orchestration,service.memory).project_memory(b,**current)
    file_proof_receipt(service,"exact-r3-baseline",before)
    assert before["advisory_entries"] == []
    assert before["excluded_refs"] == [{"entry_id":"file-skill","reason":"EVIDENCE_NOT_VISIBLE"}]
    result = file_proof_warm(service,b,current)
    assert result["source_heads"] == before["source_heads"]
    assert {x["ref"] for x in result["file_evidence"]} == set(paths)
    native = service.memory.retrievals()[-1]
    assert native["adopted_ids"] == ["file-skill"]
    without_reader = EvidenceProjection(service.controller,service.orchestration,service.memory)
    with pytest.raises(Denied, match="FILE_EVIDENCE_READER_REQUIRED") as denied:
        without_reader.load_projection(result["projection_hash"], b, read_advisory_current=lambda:current)
    file_proof_receipt(service,"missing-reader",{"projection_hash":result["projection_hash"],"error":str(denied.value)})


@pytest.mark.parametrize("change", ["missing","hash","binding","policy","version","revoked","expired"])
def test_file_proof_same_cache_rechecks_change(tmp_path, monkeypatch, change):
    service,b,current,root,paths,clock,access = file_proof_fixture(tmp_path,monkeypatch)
    result = file_proof_warm(service,b,current)
    if change == "missing": (root/paths[0]).unlink()
    elif change == "hash":
        value=json.loads((root/paths[0]).read_bytes());value["extra"]="changed"
        (root/paths[0]).write_text(json.dumps(value),encoding="utf-8")
    elif change == "binding": access["wrong_binding"] = True
    elif change == "policy": access["policy"] = sha(b"new-read-policy")
    elif change == "version": current["current_sources"]["skill-source"]["version"] = "v2"
    elif change == "revoked": current["revoked_source_ids"].append("skill-source")
    elif change == "expired": clock[0] += 11
    with pytest.raises(Denied) as denied:
        service.load_projection(result["projection_hash"],b,read_advisory_current=lambda:current)
    file_proof_receipt(service,"changed-cache",{"change":change,"projection_hash":result["projection_hash"],"error":str(denied.value)})
    if change in ("revoked","expired"):
        refreshed=service.project_memory(b,**current)
        file_proof_receipt(service,"refresh-after-change",refreshed)
        assert refreshed["advisory_entries"] == []
        assert refreshed["excluded_refs"][0]["reason"] == {"revoked":"SOURCE_REVOKED","expired":"EXPIRED"}[change]
    if change in ("missing","hash","binding"):
        with pytest.raises(Denied): service.project_memory(b,**current)


def test_file_proof_foreign_task_stays_native_excluded(tmp_path, monkeypatch):
    service,b,current,_,_,_,access = file_proof_fixture(tmp_path,monkeypatch,foreign=True)
    result=service.project_memory(b,**current)
    assert result["advisory_entries"] == []
    assert result["excluded_refs"][0]["reason"] == "BINDING_CHANGED:task_id"
    assert access["calls"] == 0
    file_proof_receipt(service,"foreign-task",result)


@pytest.mark.parametrize("shape", ["strings_only","verified_claim","wrong_version","bool_revision"])
def test_file_proof_does_not_accept_asserted_visibility(tmp_path, monkeypatch, shape):
    service,b,current,_,paths,_,_ = file_proof_fixture(tmp_path,monkeypatch)
    warm=file_proof_warm(service,b,current)
    original=service._read_file_evidence
    def invalid(binding,source):
        if shape == "strings_only": return paths
        observed=original(binding,source)
        if shape == "verified_claim": observed["verified"] = True
        elif shape == "bool_revision": observed["binding"] = {**binding,"task_revision":True}
        else: observed["source"] = {**source,"version":"unbound-version"}
        return observed
    guarded=EvidenceProjection(service.controller,service.orchestration,service.memory,
                               read_file_evidence=invalid)
    with pytest.raises(Denied) as denied:
        guarded.load_projection(warm["projection_hash"],b,read_advisory_current=lambda:current)
    file_proof_receipt(service,"asserted-visibility",{"shape":shape,"error":str(denied.value)})
