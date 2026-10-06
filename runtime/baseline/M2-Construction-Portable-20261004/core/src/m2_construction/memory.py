"""Project-local, event-sourced advisory memory.

This store has no grant, policy, effect, or execution API. A trusted caller must
check evidence before verification/activation, and the Controller remains the
sole authority for effects. Retrieval is an auditable context suggestion.
"""

from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
import sqlite3
import time

from .contracts import canonical, digest, exact_fields, hash_text, require, strict_json


BINDING_FIELDS = (
    "task_id", "task_revision", "authority_hash", "rules_version",
    "baseline_sha256", "candidate_sha256", "lease_id",
)
STATUS = frozenset({"PROPOSED", "VERIFIED", "REJECTED", "SUPERSEDED", "EXPIRED"})
_TERMINAL = frozenset({"REJECTED", "SUPERSEDED", "EXPIRED"})


def _name(value, code):
    require(type(value) is str and 0 < len(value) <= 256 and "\x00" not in value, code)


def _text(value):
    require(type(value) is str and 0 < len(value) <= 16_384 and "\x00" not in value,
            "MEMORY_TEXT")


def _source(value):
    exact_fields(value, "id version sha256 evidence_refs", "MEMORY_SOURCE_FIELDS")
    _name(value["id"], "MEMORY_SOURCE_ID")
    _name(value["version"], "MEMORY_SOURCE_VERSION")
    require(hash_text(value["sha256"]), "MEMORY_SOURCE_HASH")
    refs = value["evidence_refs"]
    require(type(refs) is list and 0 < len(refs) <= 100, "MEMORY_EVIDENCE_REFS")
    for ref in refs:
        _name(ref, "MEMORY_EVIDENCE_REF")
    require(len(set(refs)) == len(refs), "MEMORY_EVIDENCE_DUPLICATE")


def _binding(value):
    require(type(value) is dict and set(value) == set(BINDING_FIELDS), "MEMORY_BINDING_FIELDS")
    for key in ("task_id", "rules_version", "lease_id"):
        _name(value[key], "MEMORY_BINDING_" + key.upper())
    require(type(value["task_revision"]) is int and value["task_revision"] > 0,
            "MEMORY_TASK_REVISION")
    for key in ("authority_hash", "baseline_sha256", "candidate_sha256"):
        require(hash_text(value[key]), "MEMORY_BINDING_" + key.upper())


def _skill(value):
    exact_fields(value, "id version input_contract output_contract dependencies verification_examples",
                 "MEMORY_SKILL_FIELDS")
    for key in ("id", "version", "input_contract", "output_contract"):
        _name(value[key], "MEMORY_SKILL_" + key.upper())
    for key in ("dependencies", "verification_examples"):
        items = value[key]
        require(type(items) is list and 0 < len(items) <= 100, "MEMORY_SKILL_" + key.upper())
        for item in items:
            _name(item, "MEMORY_SKILL_" + key.upper())
        require(len(set(items)) == len(items), "MEMORY_SKILL_DUPLICATE")


class MemoryStore:
    """One SQLite file per project; trusted proof checks are supplied by the host.

    `verification_check(proposal, verifier_id, verification_source)` and
    `activation_check(proposal, activator_id, activation_source)` must validate
    their independent evidence. Without them, promotion and activation deny.
    They grant no execution permission; only the Controller can do that.
    """

    def __init__(self, path, *, verification_check=None, activation_check=None):
        self.path = Path(path)
        self.verification_check = verification_check
        self.activation_check = activation_check
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS events(
                seq INTEGER PRIMARY KEY AUTOINCREMENT, prev_hash TEXT NOT NULL,
                body_hash TEXT NOT NULL, event_hash TEXT NOT NULL, body_json TEXT NOT NULL)""")
            self._replay(db)

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
    def _append(db, body):
        last = db.execute("SELECT seq,event_hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq = 1 if last is None else last[0] + 1
        previous = "0" * 64 if last is None else last[1]
        body_hash = digest(body)
        event_hash = digest({"schema": "M2_MEMORY_EVENT_1", "seq": seq,
                             "prev_hash": previous, "body_hash": body_hash})
        db.execute("INSERT INTO events(seq,prev_hash,body_hash,event_hash,body_json) "
                   "VALUES(?,?,?,?,?)", (seq, previous, body_hash, event_hash,
                                           canonical(body).decode("utf-8")))
        return event_hash

    @staticmethod
    def _replay(db):
        entries = {}
        retrievals = []
        previous = "0" * 64
        expected_seq = 1
        for seq, prev, body_hash, event_hash, body_json in db.execute(
                "SELECT seq,prev_hash,body_hash,event_hash,body_json FROM events ORDER BY seq"):
            body = strict_json(body_json)
            require(seq == expected_seq and prev == previous and
                    canonical(body).decode("utf-8") == body_json and digest(body) == body_hash and
                    event_hash == digest({"schema": "M2_MEMORY_EVENT_1", "seq": seq,
                                          "prev_hash": prev, "body_hash": body_hash}),
                    "MEMORY_EVENT_CHAIN_TAMPERED")
            event_type = body.get("type")
            if event_type == "PROPOSE":
                exact_fields(body, "type entry", "MEMORY_EVENT_FIELDS")
                entry = body["entry"]
                exact_fields(entry, "entry_id kind text source proposed_by binding expires_at "
                                   "invalidation status verification_source verifier_id "
                                   "activation_source activator_id skill", "MEMORY_ENTRY_FIELDS")
                require(entry["entry_id"] not in entries and entry["status"] == "PROPOSED" and
                        entry["verification_source"] is None and entry["verifier_id"] is None and
                        entry["activation_source"] is None and entry["activator_id"] is None,
                        "MEMORY_PROPOSAL_EVENT")
                _validate_entry(entry)
                entries[entry["entry_id"]] = entry
            elif event_type == "VERIFY":
                exact_fields(body, "type entry_id verifier_id verification_source",
                             "MEMORY_EVENT_FIELDS")
                entry = _entry(entries, body["entry_id"], "PROPOSED")
                _name(body["verifier_id"], "MEMORY_VERIFIER")
                _source(body["verification_source"])
                require(body["verifier_id"] != entry["proposed_by"] and
                        body["verification_source"]["id"] != entry["source"]["id"],
                        "MEMORY_INDEPENDENT_VERIFICATION")
                entry["status"] = "VERIFIED"
                entry["verifier_id"] = body["verifier_id"]
                entry["verification_source"] = body["verification_source"]
            elif event_type == "ACTIVATE":
                exact_fields(body, "type entry_id activator_id activation_source",
                             "MEMORY_EVENT_FIELDS")
                entry = _entry(entries, body["entry_id"], "VERIFIED")
                require(entry["kind"] == "SKILL" and entry["activation_source"] is None,
                        "MEMORY_SKILL_ACTIVATION_STATE")
                _name(body["activator_id"], "MEMORY_ACTIVATOR")
                _source(body["activation_source"])
                require(body["activator_id"] != entry["proposed_by"] and
                        body["activation_source"]["id"] not in
                        (entry["source"]["id"], entry["verification_source"]["id"]),
                        "MEMORY_INDEPENDENT_ACTIVATION")
                entry["activator_id"] = body["activator_id"]
                entry["activation_source"] = body["activation_source"]
            elif event_type in ("REJECT", "SUPERSEDE", "EXPIRE"):
                exact_fields(body, "type entry_id actor_id reason", "MEMORY_EVENT_FIELDS")
                entry = _entry(entries, body["entry_id"])
                require(entry["status"] in ("PROPOSED", "VERIFIED"), "MEMORY_TERMINAL_STATE")
                _name(body["actor_id"], "MEMORY_STATUS_ACTOR")
                _name(body["reason"], "MEMORY_STATUS_REASON")
                entry["status"] = {"REJECT": "REJECTED", "SUPERSEDE": "SUPERSEDED",
                                   "EXPIRE": "EXPIRED"}[event_type]
            elif event_type == "RETRIEVE":
                exact_fields(body, "type query_hash adopted_ids excluded retrieval_hash",
                             "MEMORY_EVENT_FIELDS")
                require(hash_text(body["query_hash"]) and hash_text(body["retrieval_hash"]) and
                        type(body["adopted_ids"]) is list and type(body["excluded"]) is list,
                        "MEMORY_RETRIEVAL_EVENT")
                retrievals.append({key: value for key, value in body.items() if key != "type"})
            else:
                require(False, "MEMORY_EVENT_TYPE")
            expected_seq += 1
            previous = event_hash
        return entries, retrievals

    def propose(self, *, entry_id, kind, text, source, proposed_by, binding, expires_at,
                skill=None):
        _name(entry_id, "MEMORY_ENTRY_ID")
        _name(proposed_by, "MEMORY_AUTHOR")
        _text(text)
        _source(source)
        _binding(binding)
        require(kind in ("COGNITION", "SKILL"), "MEMORY_KIND")
        if kind == "SKILL":
            _skill(skill)
        else:
            require(skill is None, "MEMORY_COGNITION_SKILL")
        require(type(expires_at) is int and int(time.time()) < expires_at <= 9_007_199_254_740_991,
                "MEMORY_EXPIRY")
        entry = {"entry_id": entry_id, "kind": kind, "text": text, "source": source,
                 "proposed_by": proposed_by, "binding": binding, "expires_at": expires_at,
                 "invalidation": {"binding_keys": list(BINDING_FIELDS), "source_change": True,
                                  "revocation": True, "conflict": True, "expiry": True},
                 "status": "PROPOSED", "verification_source": None, "verifier_id": None,
                 "activation_source": None, "activator_id": None, "skill": skill}
        _validate_entry(entry)
        with self._transaction() as db:
            entries, _ = self._replay(db)
            require(entry_id not in entries, "MEMORY_ENTRY_ID_CONFLICT")
            self._append(db, {"type": "PROPOSE", "entry": entry})
        return deepcopy(entry)

    def verify(self, entry_id, *, verifier_id, verification_source):
        _name(verifier_id, "MEMORY_VERIFIER")
        _source(verification_source)
        with self._transaction() as db:
            entries, _ = self._replay(db)
            entry = _entry(entries, entry_id, "PROPOSED")
            require(verifier_id != entry["proposed_by"] and
                    verification_source["id"] != entry["source"]["id"],
                    "MEMORY_INDEPENDENT_VERIFICATION")
            require(self.verification_check is not None and
                    self.verification_check(deepcopy(entry), verifier_id,
                                            deepcopy(verification_source)) is True,
                    "MEMORY_VERIFICATION_NOT_TRUSTED")
            self._append(db, {"type": "VERIFY", "entry_id": entry_id,
                              "verifier_id": verifier_id,
                              "verification_source": verification_source})

    def activate_skill(self, entry_id, *, activator_id, activation_source):
        _name(activator_id, "MEMORY_ACTIVATOR")
        _source(activation_source)
        with self._transaction() as db:
            entries, _ = self._replay(db)
            entry = _entry(entries, entry_id, "VERIFIED")
            require(entry["kind"] == "SKILL" and entry["activation_source"] is None,
                    "MEMORY_SKILL_ACTIVATION_STATE")
            require(activator_id != entry["proposed_by"] and
                    activation_source["id"] not in
                    (entry["source"]["id"], entry["verification_source"]["id"]),
                    "MEMORY_INDEPENDENT_ACTIVATION")
            require(self.activation_check is not None and
                    self.activation_check(deepcopy(entry), activator_id,
                                          deepcopy(activation_source)) is True,
                    "MEMORY_ACTIVATION_NOT_TRUSTED")
            self._append(db, {"type": "ACTIVATE", "entry_id": entry_id,
                              "activator_id": activator_id,
                              "activation_source": activation_source})

    def _terminal(self, event_type, entry_id, *, actor_id, reason):
        _name(actor_id, "MEMORY_STATUS_ACTOR")
        _name(reason, "MEMORY_STATUS_REASON")
        with self._transaction() as db:
            entries, _ = self._replay(db)
            entry = _entry(entries, entry_id)
            require(entry["status"] not in _TERMINAL, "MEMORY_TERMINAL_STATE")
            self._append(db, {"type": event_type, "entry_id": entry_id,
                              "actor_id": actor_id, "reason": reason})

    def reject(self, entry_id, *, actor_id, reason):
        self._terminal("REJECT", entry_id, actor_id=actor_id, reason=reason)

    def supersede(self, entry_id, *, actor_id, reason):
        self._terminal("SUPERSEDE", entry_id, actor_id=actor_id, reason=reason)

    def expire(self, entry_id, *, actor_id, reason):
        self._terminal("EXPIRE", entry_id, actor_id=actor_id, reason=reason)

    def retrieve(self, *, binding, current_sources, visible_evidence,
                 current_skill_versions, revoked_source_ids, revoked_entry_ids,
                 conflicting_entry_ids):
        _binding(binding)
        require(type(current_sources) is dict and type(current_skill_versions) is dict,
                "MEMORY_CURRENT_MANIFEST")
        for source_id, version in current_sources.items():
            _name(source_id, "MEMORY_CURRENT_SOURCE_ID")
            exact_fields(version, "version sha256", "MEMORY_CURRENT_SOURCE_FIELDS")
            _name(version["version"], "MEMORY_CURRENT_SOURCE_VERSION")
            require(hash_text(version["sha256"]), "MEMORY_CURRENT_SOURCE_HASH")
        for skill_id, version in current_skill_versions.items():
            _name(skill_id, "MEMORY_CURRENT_SKILL_ID")
            _name(version, "MEMORY_CURRENT_SKILL_VERSION")
        visible = _ids(visible_evidence, "MEMORY_VISIBLE_EVIDENCE")
        revoked_sources = _ids(revoked_source_ids, "MEMORY_REVOKED_SOURCE")
        revoked_entries = _ids(revoked_entry_ids, "MEMORY_REVOKED_ENTRY")
        conflicting = _ids(conflicting_entry_ids, "MEMORY_CONFLICT_ID")
        query = {"binding": binding, "current_sources": current_sources,
                 "visible_evidence": sorted(visible),
                 "current_skill_versions": current_skill_versions,
                 "revoked_source_ids": sorted(revoked_sources),
                 "revoked_entry_ids": sorted(revoked_entries),
                 "conflicting_entry_ids": sorted(conflicting)}
        with self._transaction() as db:
            entries, _ = self._replay(db)
            adopted = []
            excluded = []
            now = int(time.time())
            for entry in entries.values():
                reason = _exclusion(entry, binding, current_sources, visible,
                                    current_skill_versions, revoked_sources,
                                    revoked_entries, conflicting, now)
                if reason is None:
                    adopted.append(deepcopy(entry))
                else:
                    excluded.append({"entry_id": entry["entry_id"], "reason": reason})
            record = {"query_hash": digest(query),
                      "adopted_ids": [item["entry_id"] for item in adopted],
                      "excluded": excluded}
            retrieval_hash = digest({"schema": "M2_MEMORY_RETRIEVAL_1", **record})
            self._append(db, {"type": "RETRIEVE", **record,
                              "retrieval_hash": retrieval_hash})
        return {"authority": "ADVISORY_ONLY", "adopted": adopted, "excluded": excluded,
                "retrieval_hash": retrieval_hash, "missing": not adopted}

    def retrievals(self):
        with self._transaction() as db:
            _, retrievals = self._replay(db)
            return deepcopy(retrievals)


def _entry(entries, entry_id, expected=None):
    _name(entry_id, "MEMORY_ENTRY_ID")
    require(entry_id in entries, "MEMORY_ENTRY_NOT_FOUND")
    entry = entries[entry_id]
    if expected is not None:
        require(entry["status"] == expected, "MEMORY_STATUS_TRANSITION")
    return entry


def _validate_entry(entry):
    _name(entry["entry_id"], "MEMORY_ENTRY_ID")
    _text(entry["text"])
    _name(entry["proposed_by"], "MEMORY_AUTHOR")
    _source(entry["source"])
    _binding(entry["binding"])
    require(entry["kind"] in ("COGNITION", "SKILL") and entry["status"] in STATUS,
            "MEMORY_ENTRY_KIND_STATUS")
    require(type(entry["expires_at"]) is int and entry["expires_at"] > 0,
            "MEMORY_EXPIRY")
    require(entry["invalidation"] == {"binding_keys": list(BINDING_FIELDS),
                                      "source_change": True, "revocation": True,
                                      "conflict": True, "expiry": True},
            "MEMORY_INVALIDATION")
    if entry["kind"] == "SKILL":
        _skill(entry["skill"])
    else:
        require(entry["skill"] is None, "MEMORY_COGNITION_SKILL")


def _ids(values, code):
    require(type(values) in (set, frozenset, list, tuple), code)
    result = set()
    for value in values:
        _name(value, code)
        result.add(value)
    return result


def _exclusion(entry, binding, sources, visible, skills, revoked_sources,
               revoked_entries, conflicting, now):
    if entry["status"] != "VERIFIED":
        return entry["status"]
    if entry["entry_id"] in revoked_entries:
        return "ENTRY_REVOKED"
    if entry["entry_id"] in conflicting:
        return "CONFLICT"
    if now >= entry["expires_at"]:
        return "EXPIRED"
    for key in BINDING_FIELDS:
        if entry["binding"][key] != binding[key]:
            return "BINDING_CHANGED:" + key
    refs = []
    for source in (entry["source"], entry["verification_source"],
                   entry["activation_source"]):
        if source is None:
            continue
        if source["id"] in revoked_sources:
            return "SOURCE_REVOKED"
        current = sources.get(source["id"])
        if current is None:
            return "SOURCE_UNAVAILABLE"
        if current != {"version": source["version"], "sha256": source["sha256"]}:
            return "SOURCE_CHANGED"
        refs.extend(source["evidence_refs"])
    if not set(refs) <= visible:
        return "EVIDENCE_NOT_VISIBLE"
    if entry["kind"] == "SKILL":
        if entry["activation_source"] is None:
            return "SKILL_NOT_ACTIVATED"
        skill = entry["skill"]
        if skills.get(skill["id"]) != skill["version"]:
            return "SKILL_VERSION_CHANGED"
    return None
