"""Bounded, source-bound advisory context for one construction task.

The caller supplies trusted source readers. This module copies a fixed snapshot,
checks the live binding and source heads before and after assembly, and never
offers a Gate or an effect API. A capsule is evidence for planning at its recorded
heads only; the Controller must check current authorization for every effect.
"""

from copy import deepcopy
from pathlib import PurePosixPath
import time

from .contracts import Denied, canonical, digest, hash_text, require


_BINDING = frozenset({
    "task_id", "task_revision", "authority_hash", "rules_version",
    "baseline_sha256", "candidate_sha256", "lease_id",
})
_HEADS = frozenset({"project_id", "ledger_id", "ledger", "orchestration",
                    "memory_content", "index", "skill_versions",
                    "advisory_state"})
_PROJECTION_HEADS = ("ledger", "orchestration", "memory_content")
_SCOPE_FIELDS = frozenset({
    "schema", "trust_domain", "grant_id", "task_id", "task_revision",
    "workspace_root", "state_root", "baseline_files", "allowed_files",
    "allowed_effects", "not_before", "expires_at", "max_operations",
    "max_patch_bytes",
})


def build_hard_constraints_from_scope(scope, *, rules_version, rule_ids):
    """Copy constraints from a Controller-verified current signed scope body.

    This pure transform does not verify a signature or grant effects. Its caller
    must obtain ``scope`` through Controller's current-scope read and supply
    trusted rule IDs; context_bundle binds the resulting digest to current heads.
    Command environment values are represented by a hash, not copied into the
    advisory capsule.
    """
    require(type(scope) is dict, "CONTEXT_VERIFIED_SCOPE")
    schema = scope.get("schema")
    require(schema in ("M2_CONSTRUCTION_SCOPE_1", "M2_CONSTRUCTION_SCOPE_2",
                       "M2_CONSTRUCTION_SCOPE_3"), "CONTEXT_SCOPE_SCHEMA")
    fields = set(_SCOPE_FIELDS)
    if schema in ("M2_CONSTRUCTION_SCOPE_2", "M2_CONSTRUCTION_SCOPE_3"):
        fields.add("allowed_commands")
    if schema == "M2_CONSTRUCTION_SCOPE_3":
        fields.add("creatable_files")
    require(set(scope) == fields and scope["trust_domain"] == "TEST_ONLY",
            "CONTEXT_VERIFIED_SCOPE")
    require(type(rules_version) is str and rules_version and
            type(rule_ids) is list and rule_ids and
            all(type(item) is str and item for item in rule_ids),
            "CONTEXT_RULE_SOURCE")
    require(type(scope["allowed_files"]) is list and scope["allowed_files"] and
            all(type(path) is str and path for path in scope["allowed_files"]) and
            len(set(scope["allowed_files"])) == len(scope["allowed_files"]) and
            type(scope["allowed_effects"]) is list and scope["allowed_effects"] and
            all(type(effect) is str and effect for effect in scope["allowed_effects"]) and
            len(set(scope["allowed_effects"])) == len(scope["allowed_effects"]) and
            type(scope["baseline_files"]) is dict and
            set(scope["baseline_files"]) == set(scope["allowed_files"]),
            "CONTEXT_SCOPE_BOUNDARIES")
    commands = scope.get("allowed_commands", [])
    creatable = scope.get("creatable_files", [])
    require(type(commands) is list and type(creatable) is list and
            type(scope["max_operations"]) is int and scope["max_operations"] > 0 and
            type(scope["max_patch_bytes"]) is int and scope["max_patch_bytes"] > 0 and
            type(scope["not_before"]) is int and type(scope["expires_at"]) is int and
            scope["not_before"] < scope["expires_at"],
            "CONTEXT_SCOPE_BUDGET")
    safe_commands = []
    for command in commands:
        command_fields = {"command_id", "kind", "argv", "cwd", "env",
                          "timeout_seconds", "program_sha256", "tracked_paths"}
        if schema == "M2_CONSTRUCTION_SCOPE_3":
            command_fields.add("output_files")
        require(type(command) is dict and set(command) == command_fields and
                type(command.get("env")) is dict and
                type(command.get("command_id")) is str and
                type(command.get("kind")) is str and
                type(command.get("argv")) is list and
                type(command.get("tracked_paths")) is list,
                "CONTEXT_SCOPE_COMMAND")
        safe = {key: deepcopy(command[key]) for key in (
            "command_id", "kind", "argv", "cwd", "timeout_seconds",
            "program_sha256", "tracked_paths")}
        if "output_files" in command:
            safe["output_files"] = deepcopy(command["output_files"])
        safe["env_keys"] = sorted(command["env"])
        safe["env_sha256"] = digest(command["env"])
        safe_commands.append(safe)
    return {
        "source": "CONTROLLER_SCOPE_DERIVED_1",
        "grant_ref": {"id": scope["grant_id"], "sha256": digest(scope)},
        "scope_schema": schema, "trust_domain": scope["trust_domain"],
        "task_id": scope["task_id"], "task_revision": scope["task_revision"],
        "workspace_root": scope["workspace_root"],
        "state_root": scope["state_root"],
        "baseline_files": deepcopy(scope["baseline_files"]),
        "allowed_files": deepcopy(scope["allowed_files"]),
        "allowed_effects": deepcopy(scope["allowed_effects"]),
        "allowed_commands": safe_commands, "creatable_files": deepcopy(creatable),
        "not_before": scope["not_before"], "expires_at": scope["expires_at"],
        "max_operations": scope["max_operations"],
        "max_patch_bytes": scope["max_patch_bytes"],
        "rules_version": rules_version, "rule_ids": deepcopy(rule_ids),
        "grant_active": True,
    }


def _failure(status, reason):
    return {"status": status, "reason": reason, "can_continue": False,
            "dispatch_allowed": False, "capsule": None}


def _valid_binding(binding):
    require(type(binding) is dict and set(binding) == _BINDING,
            "CONTEXT_BINDING_FIELDS")
    require(type(binding["task_id"]) is str and binding["task_id"] and
            type(binding["rules_version"]) is str and binding["rules_version"],
            "CONTEXT_BINDING_ID")
    require(type(binding["task_revision"]) is int and binding["task_revision"] > 0,
            "CONTEXT_TASK_REVISION")
    require(binding["lease_id"] is None or
            (type(binding["lease_id"]) is str and binding["lease_id"]),
            "CONTEXT_LEASE")
    for key in ("authority_hash", "baseline_sha256", "candidate_sha256"):
        require(hash_text(binding[key]), "CONTEXT_BINDING_HASH")


def _valid_heads(heads):
    require(type(heads) is dict and _HEADS <= set(heads), "CONTEXT_HEADS")
    for key in ("project_id", "ledger_id"):
        require(hash_text(heads[key]), "CONTEXT_SOURCE_ID")
    for key in _HEADS - {"project_id", "ledger_id"}:
        require(type(heads[key]) is dict and
                (heads[key] or key == "skill_versions"), "CONTEXT_HEADS")
    require(hash_text(heads["advisory_state"].get("sha256")),
            "CONTEXT_ADVISORY_HEAD")
    canonical(heads)


def _item_count(value):
    """Count nested mandatory leaves so a small item limit cannot hide one."""
    if type(value) is dict:
        return sum(_item_count(item) for item in value.values()) or 1
    if type(value) is list:
        return sum(_item_count(item) for item in value) or 1
    return 1


def _evidence_ref(record):
    require(type(record) is dict and hash_text(record.get("evidence_id")) and
            hash_text(record.get("event_hash")) and
            hash_text(record.get("body_hash")) and
            type(record.get("kind")) is str, "CONTEXT_EVIDENCE_REF")
    ref = {key: record[key] for key in (
        "project_id", "ledger_id", "authority_hash", "evidence_id",
        "event_hash", "body_hash", "kind", "task_id", "task_revision")}
    for key in ("file_sha256", "effect_sha256", "operation_id",
                "candidate_sha256", "candidate_status", "event_seq"):
        if key in record:
            ref[key] = record[key]
    return ref


def _file_commitments(projection, binding):
    """Validate typed commitments; current bytes still require a trusted load."""
    values = projection.get("file_evidence", [])
    require(type(values) is list, "CONTEXT_FILE_COMMITMENTS")
    proofs = {}
    for proof in values:
        require(type(proof) is dict and set(proof) == {
            "binding", "source", "ref", "content_sha256", "read_policy_sha256"},
            "CONTEXT_FILE_COMMITMENTS")
        _valid_binding(proof["binding"])
        require(canonical(proof["binding"]) == canonical(binding),
                "CONTEXT_FILE_BINDING")
        source, ref = proof["source"], proof["ref"]
        require(type(source) is dict and set(source) == {
            "id", "version", "sha256", "evidence_refs"} and
            all(type(source[key]) is str and source[key] for key in ("id", "version")) and
            hash_text(source["sha256"]) and type(ref) is str and ref and
            source["evidence_refs"] == [ref], "CONTEXT_FILE_SOURCE")
        path = PurePosixPath(ref)
        require(not path.is_absolute() and str(path) == ref and
                ".." not in path.parts and ":" not in ref and
                "\\" not in ref and "\x00" not in ref,
                "CONTEXT_FILE_REFERENCE")
        require(proof["content_sha256"] == source["sha256"] and
                hash_text(proof["read_policy_sha256"]), "CONTEXT_FILE_HASH_POLICY")
        key = digest({"source": source, "ref": ref})
        require(key not in proofs, "CONTEXT_DUPLICATE_FILE_COMMITMENT")
        proofs[key] = {"type": "FILE_EVIDENCE_1", **deepcopy(proof)}
    return proofs


def _read_file_projection(reader, projection, binding):
    """The host must use load_projection, never just current_heads or a flag."""
    observed = reader(projection["projection_hash"], deepcopy(binding))
    require(type(observed) is dict and canonical(observed) == canonical(projection),
            "CONTEXT_FILE_CURRENTNESS_MISMATCH")


def _advisory(entry, fact_refs, file_proofs, binding):
    if type(entry) is not dict or entry.get("status") != "VERIFIED" or \
            type(entry.get("verification_source")) is not dict:
        return None, "NOT_VERIFIED_OR_ACTIVATED"
    kind = entry.get("kind")
    if kind not in ("COGNITION", "SKILL") or (
            kind == "SKILL" and entry.get("activation_source") is None):
        return None, "NOT_VERIFIED_OR_ACTIVATED"
    if not all(type(entry.get(key)) is str and entry[key]
               for key in ("entry_id", "text")):
        return None, "NOT_VERIFIED_OR_ACTIVATED"
    refs, files = [], {}
    for key in ("source", "verification_source", "activation_source"):
        source = entry.get(key)
        if source is None:
            continue
        if type(source) is not dict or type(source.get("evidence_refs")) is not list:
            return None, "ADVISORY_EVIDENCE_UNRESOLVED"
        for ref in source["evidence_refs"]:
            if type(ref) is not str:
                return None, "ADVISORY_EVIDENCE_UNRESOLVED"
            if ref in fact_refs:
                refs.append(ref)
            else:
                key = digest({"source": source, "ref": ref})
                proof = file_proofs.get(key)
                if proof is None:
                    return None, "ADVISORY_EVIDENCE_UNRESOLVED"
                files[key] = proof
    if not refs and not files:
        return None, "ADVISORY_EVIDENCE_UNRESOLVED"
    safe = {"entry_id": entry["entry_id"], "kind": kind, "text": entry["text"],
            "evidence_refs": list(dict.fromkeys(refs)), "authority": "ADVISORY_ONLY"}
    if files:
        _valid_binding(entry.get("binding"))
        require(canonical(entry["binding"]) == canonical(binding), "CONTEXT_FILE_ENTRY_BINDING")
        safe["file_evidence"] = [deepcopy(files[key]) for key in sorted(files)]
    return safe, None


def context_bundle(task_binding, expected_heads, max_items, max_bytes, *,
                   capture_sources, read_current, read_projection_current=None, now=None):
    """Build a bounded capsule from trusted snapshots and live read callbacks.

    ``capture_sources()`` returns task_binding, heads, a Controller-verified
    current ``verified_scope`` body, trusted ``rule_ids``, the complete
    ``hard_constraints`` derived from those inputs, orchestration restore,
    projection, and evidence. ``read_current()`` returns live task_binding and
    heads. Both callbacks are trusted read entry points, never model-provided
    summaries. File-backed projections additionally require the trusted
    ``read_projection_current(hash, binding)`` callback to return the exact
    projection after a live ``EvidenceProjection.load_projection``. It runs
    before and after assembly; a cached object or current_heads alone is not
    sufficient. Event-only callers need no new callback.
    """
    _valid_binding(task_binding)
    _valid_heads(expected_heads)
    require(type(max_items) is int and max_items >= 0 and
            type(max_bytes) is int and max_bytes >= 0, "CONTEXT_BUDGET")
    require(callable(capture_sources) and callable(read_current),
            "CONTEXT_SOURCE_READER")
    now = int(time.time()) if now is None else now
    require(type(now) is int and now >= 0, "CONTEXT_TIME")

    current = read_current()
    require(type(current) is dict, "CONTEXT_CURRENT")
    if current.get("task_binding") != task_binding:
        return _failure("STALE_BINDING", "CURRENT_BINDING_CHANGED")
    if current.get("heads") != expected_heads:
        return _failure("STALE_SNAPSHOT", "CURRENT_HEAD_CHANGED")

    source = deepcopy(capture_sources())
    require(type(source) is dict, "CONTEXT_SOURCE")
    if source.get("task_binding") != task_binding:
        return _failure("STALE_BINDING", "SOURCE_BINDING_CHANGED")
    if source.get("heads") != expected_heads:
        return _failure("STALE_SNAPSHOT", "SOURCE_HEAD_CHANGED")
    projection = source.get("projection")
    if type(projection) is not dict or not hash_text(projection.get("projection_hash")):
        return _failure("INCOMPLETE", "PROJECTION_UNAVAILABLE")
    if projection.get("scope_binding") != task_binding:
        return _failure("STALE_BINDING", "PROJECTION_BINDING_CHANGED")
    projected_heads = {key: expected_heads[key] for key in _PROJECTION_HEADS}
    if projection.get("source_heads") != projected_heads or \
            projection.get("indexed_through") != expected_heads["index"]:
        return _failure("STALE_SNAPSHOT", "PROJECTION_HEAD_CHANGED")
    if digest(projection.get("advisory_state")) != expected_heads[
            "advisory_state"]["sha256"]:
        return _failure("STALE_SNAPSHOT", "ADVISORY_STATE_CHANGED")
    if projection.get("projection_schema") != "M2_ATOMIC_MEMORY_PROJECTION_1" or \
            projection.get("authority") is not False or \
            projection.get("projection_id") != projection["projection_hash"]:
        return _failure("INCOMPLETE", "PROJECTION_CONTRACT_MISMATCH")
    payload = {key: value for key, value in projection.items()
               if key not in ("projection_id", "projection_hash")}
    if digest(payload) != projection["projection_hash"]:
        return _failure("INCOMPLETE", "PROJECTION_HASH_MISMATCH")
    if type(projection.get("valid_until")) is not int or \
            projection["valid_until"] <= now:
        return _failure("STALE_SNAPSHOT", "PROJECTION_EXPIRED")
    file_proofs = _file_commitments(projection, task_binding)
    if file_proofs:
        if not callable(read_projection_current):
            return _failure("INCOMPLETE", "FILE_EVIDENCE_CURRENTNESS_REQUIRED")
        _read_file_projection(read_projection_current, projection, task_binding)
    evidence = source.get("evidence")
    if type(evidence) is dict and evidence.get("status") == "STALE_INDEX":
        return _failure("STALE_INDEX", "EVIDENCE_INDEX_STALE")
    if type(evidence) is not dict or evidence.get("status") != "OK":
        return _failure("INCOMPLETE", "EVIDENCE_UNAVAILABLE")
    if evidence.get("project_id") != expected_heads["project_id"] or \
            evidence.get("ledger_id") != expected_heads["ledger_id"]:
        return _failure("INCOMPLETE", "EVIDENCE_IDENTITY_MISMATCH")
    if evidence.get("head") != expected_heads["ledger"] or \
            evidence.get("indexed_through") != expected_heads["index"]:
        return _failure("STALE_SNAPSHOT", "EVIDENCE_HEAD_CHANGED")
    records = evidence.get("records")
    facts = projection.get("facts")
    if type(records) is not list or type(facts) is not list:
        return _failure("INCOMPLETE", "SOURCE_ITEMS_UNAVAILABLE")

    trusted_scope = source.get("verified_scope")
    rules = source.get("rule_ids")
    if type(trusted_scope) is not dict or type(rules) is not list:
        return _failure("INCOMPLETE", "VERIFIED_SCOPE_MISSING")
    try:
        expected_constraints = build_hard_constraints_from_scope(
            trusted_scope, rules_version=task_binding["rules_version"],
            rule_ids=rules)
    except Denied:
        return _failure("INCOMPLETE", "HARD_CONSTRAINTS_MISSING")
    constraints = source.get("hard_constraints")
    if constraints != expected_constraints:
        return _failure("INCOMPLETE", "HARD_CONSTRAINTS_MISSING")
    grant_ref = constraints["grant_ref"]
    if grant_ref["sha256"] != task_binding["authority_hash"] or \
            constraints["task_id"] != task_binding["task_id"] or \
            constraints["task_revision"] != task_binding["task_revision"]:
        return _failure("STALE_BINDING", "GRANT_REF_CHANGED")
    if constraints["not_before"] > now or constraints["expires_at"] <= now:
        return _failure("STALE_BINDING", "GRANT_EXPIRED")

    state = source.get("orchestration")
    if type(state) is not dict:
        return _failure("INCOMPLETE", "ORCHESTRATION_UNAVAILABLE")
    for state_key, binding_key in (("task_id", "task_id"),
                                   ("task_revision", "task_revision"),
                                   ("grant_digest", "authority_hash"),
                                   ("candidate_hash", "candidate_sha256")):
        if state.get(state_key) != task_binding[binding_key]:
            return _failure("STALE_BINDING", "ORCHESTRATION_BINDING_CHANGED")
    if state.get("status") == "STALE_BINDING":
        return _failure("STALE_BINDING", "ORCHESTRATION_BINDING_CHANGED")
    required_state = ("status", "graph", "nodes", "leases", "attempt_budget",
                      "attempts_used", "checkpoint", "pending_review_checkpoint_ids",
                      "open_operation_ids", "ready_nodes")
    if any(key not in state for key in required_state):
        return _failure("INCOMPLETE", "ORCHESTRATION_FIELDS_MISSING")
    leases = state["leases"]
    if type(leases) is not list or any(type(item) is not dict for item in leases):
        return _failure("INCOMPLETE", "LEASES_UNAVAILABLE")
    lease_id = task_binding["lease_id"]
    if lease_id is not None and lease_id not in {
            item.get("lease_id") for item in leases}:
        return _failure("STALE_BINDING", "LEASE_CHANGED")
    if any(type(item.get("expires_at")) is int and
           item["expires_at"] <= now for item in leases):
        if state["status"] == "RESUMABLE":
            return _failure("STALE_SNAPSHOT", "LEASE_EXPIRED")
    for key in ("pending_review_checkpoint_ids", "open_operation_ids"):
        if type(state[key]) is not list:
            return _failure("INCOMPLETE", "ORCHESTRATION_FIELDS_MISSING")
    raw_state = projection.get("orchestration_snapshot")
    if type(raw_state) is not dict or \
            digest(raw_state) != expected_heads["orchestration"].get("state_hash") or \
            raw_state.get("task_id") != task_binding["task_id"] or \
            raw_state.get("task_revision") != task_binding["task_revision"] or \
            raw_state.get("grant_digest") != task_binding["authority_hash"] or \
            raw_state.get("candidate_hash") != task_binding["candidate_sha256"]:
        return _failure("STALE_SNAPSHOT", "ORCHESTRATION_SOURCE_MISMATCH")
    raw_open = raw_state.get("open_operations")
    if type(raw_open) is not list or \
            sorted(item.get("operation_id") for item in raw_open
                   if type(item) is dict) != sorted(state["open_operation_ids"]):
        return _failure("STALE_SNAPSHOT", "UNKNOWN_SOURCE_MISMATCH")

    refs = []
    for record in records:
        if type(record) is not dict or record.get("task_id") != task_binding["task_id"] or \
                record.get("task_revision") != task_binding["task_revision"] or \
                record.get("project_id") != expected_heads["project_id"] or \
                record.get("ledger_id") != expected_heads["ledger_id"] or \
                record.get("authority_hash") != task_binding["authority_hash"]:
            return _failure("INCOMPLETE", "EVIDENCE_SCOPE_UNRESOLVED")
        refs.append(_evidence_ref(record))
    by_evidence = {item["evidence_id"]: item for item in refs}
    if len(by_evidence) != len(refs):
        return _failure("INCOMPLETE", "DUPLICATE_EVIDENCE_ID")
    adopted_refs = projection.get("adopted_refs")
    if type(adopted_refs) is not list or adopted_refs != [
            {"evidence_id": item["evidence_id"], "event_hash": item["event_hash"]}
            for item in refs]:
        return _failure("INCOMPLETE", "PROJECTION_EVIDENCE_MISMATCH")
    safe_facts = []
    fact_refs = set()
    for fact in facts:
        if type(fact) is not dict or not hash_text(fact.get("fact_hash")) or \
                fact.get("fact_id") != fact["fact_hash"] or \
                digest({key: value for key, value in fact.items()
                        if key not in ("fact_hash", "fact_id")}) != fact["fact_hash"]:
            return _failure("INCOMPLETE", "FACT_HASH_MISMATCH")
        evidence_id = fact.get("evidence_id")
        if evidence_id is None:
            if fact.get("kind") != "ORCHESTRATION_OPEN_OPERATION" or \
                    fact.get("semantics") != "UNKNOWN" or \
                    fact.get("status") != "UNKNOWN" or \
                    fact.get("evidence_refs", []) != [] or \
                    fact.get("operation_id") not in state["open_operation_ids"] or \
                    fact.get("state_hash") != expected_heads["orchestration"].get(
                        "state_hash"):
                return _failure("INCOMPLETE", "FACT_EVIDENCE_UNRESOLVED")
        else:
            record = by_evidence.get(evidence_id)
            if record is None:
                return _failure("INCOMPLETE", "FACT_EVIDENCE_UNRESOLVED")
            if fact.get("evidence_refs", [evidence_id]) != [evidence_id] or any(
                    fact.get(field) != record.get(field) for field in (
                        "kind", "event_hash", "event_seq", "body_hash",
                        "operation_id", "candidate_sha256", "effect_sha256",
                        "file_sha256")):
                return _failure("INCOMPLETE", "FACT_SOURCE_MISMATCH")
            fact_refs.add(evidence_id)
        safe = {key: fact[key] for key in (
            "fact_id", "fact_hash", "kind", "semantics", "status",
            "evidence_refs", "evidence_id", "event_hash", "event_seq",
            "body_hash", "operation_id", "effect_sha256", "file_sha256",
            "receipt_status", "candidate_sha256", "state_hash", "value")
                if key in fact}
        safe_facts.append(safe)

    entries = projection.get("advisory_entries")
    if type(entries) is not list or type(projection.get("excluded_refs")) is not list:
        return _failure("INCOMPLETE", "MEMORY_PROJECTION_UNAVAILABLE")
    advisory = []
    excluded = deepcopy(projection.get("excluded_refs", []))
    for entry in entries:
        safe, reason = _advisory(entry, fact_refs, file_proofs, task_binding)
        if reason is not None:
            excluded.append({"entry_id": entry.get("entry_id", "UNKNOWN") if
                             type(entry) is dict else "UNKNOWN",
                             "reason": reason})
        else:
            advisory.append(safe)

    capsule = {
        "schema": "M2_CONTEXT_CAPSULE_1", "task_binding": deepcopy(task_binding),
        "heads": deepcopy(expected_heads),
        "projection_hash": projection["projection_hash"],
        "hard_constraints": deepcopy(constraints),
        "workflow_status": state["status"], "graph": deepcopy(state["graph"]),
        "nodes": deepcopy(state["nodes"]), "leases": deepcopy(leases),
        "attempt_budget": state["attempt_budget"],
        "attempts_used": state["attempts_used"],
        "checkpoint": deepcopy(state["checkpoint"]),
        "pending_review_checkpoint_ids": deepcopy(state["pending_review_checkpoint_ids"]),
        "open_operation_ids": deepcopy(state["open_operation_ids"]),
        "ready_nodes": deepcopy(state["ready_nodes"]),
        "excluded_refs": excluded, "evidence_refs": [], "facts": [],
        "advisory_memory": [], "omitted_items": [],
        "dispatch_allowed": False,
    }
    capsule["mandatory_item_count"] = _item_count({
        key: value for key, value in capsule.items()
        if key not in ("mandatory_item_count", "evidence_refs", "facts",
                       "advisory_memory", "omitted_items")})
    if capsule["mandatory_item_count"] > max_items or len(canonical(capsule)) > max_bytes:
        return _failure("INCOMPLETE", "BUDGET_TOO_SMALL_FOR_REQUIRED_CONTEXT")

    optional = [(field, item, id_key)
                for field, items, id_key in (
                    ("evidence_refs", sorted(refs, key=lambda x: x["evidence_id"]),
                     "evidence_id"),
                    ("facts", sorted(safe_facts, key=lambda x: x["fact_hash"]),
                     "fact_hash"),
                    ("advisory_memory", sorted(advisory,
                                               key=lambda x: x["entry_id"]),
                     "entry_id"))
                for item in items]
    capsule["omitted_items"] = [
        {"id": item[id_key], "kind": field, "reason": "BUDGET_LIMIT"}
        for field, item, id_key in optional]
    if len(canonical(capsule)) > max_bytes:
        return _failure("INCOMPLETE", "BUDGET_TOO_SMALL_FOR_EXCLUSIONS")
    selected_count = capsule["mandatory_item_count"]
    omitted_cursor = 0
    for field, item, _ in optional:
        trial = deepcopy(capsule)
        trial[field].append(item)
        # This position belongs to the current item even when IDs repeat.
        del trial["omitted_items"][omitted_cursor]
        if selected_count + 1 <= max_items and len(canonical(trial)) <= max_bytes:
            capsule = trial
            selected_count += 1
        else:
            omitted_cursor += 1

    latest = read_current()
    require(type(latest) is dict, "CONTEXT_CURRENT")
    if latest.get("task_binding") != task_binding:
        return _failure("STALE_BINDING", "CURRENT_BINDING_CHANGED")
    if latest.get("heads") != expected_heads:
        return _failure("STALE_SNAPSHOT", "CURRENT_HEAD_CHANGED")
    if file_proofs:
        _read_file_projection(read_projection_current, projection, task_binding)
    status = state["status"]
    return {"status": status, "reason": None,
            "can_continue": status == "RESUMABLE", "dispatch_allowed": False,
            "capsule": capsule, "capsule_hash": digest(capsule),
            "actual_bytes": len(canonical(capsule))}
