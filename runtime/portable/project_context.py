"""Explicit, bounded project reference loading. Python 3.11+, standard library.

Schema ``portable-project-context-v1`` stores project_root relative to the
config directory, goal, project_id, sources and not_applicable [{kind, reason}].
Each source has id/kind/path/sha256/revision/status/applicability, optionally
claim_type (reference, assumption, unverified_report), critical, conflicts and
supersedes (source IDs). Applicability is {conditions: [str], limitations: [str]}.
No metadata, hash match or ready-for-review state verifies a project's claims.
No source content is executed, evaluated, scanned for instructions, or written
to the governance kernel MemoryStore. No execution authorization is produced.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Any

SCHEMA_VERSION = "portable-project-context-v1"
ROLES = ("requirements", "design", "code", "tests", "decisions", "known_issues", "memory", "evidence")
MAX_SOURCE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 128 * 1024
MAX_SOURCES = 128
MAX_GOAL_CHARS = 8192
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_PRIVATE_KEY = re.compile(br"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_SOURCE_FIELDS = ("id", "kind", "path", "sha256", "revision", "status", "applicability",
                  "claim_type", "critical", "conflicts", "supersedes")


class ProjectError(ValueError):
    """A stable machine-readable reason; no file content is embedded in errors."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, limit: int = 1024, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise ProjectError("INVALID_METADATA")
    if not allow_empty and not value.strip():
        raise ProjectError("INVALID_METADATA")
    return value


def _sensitive(part: str) -> bool:
    name = part.casefold().rstrip(" .")
    return (name in {".git", ".ssh", ".aws", ".azure", ".gnupg", ".netrc", ".npmrc", "credentials", "secrets"}
            or name.startswith((".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials.", "secret.", "secrets.", "private_key"))
            or name.endswith((".key", ".pem", ".p12", ".pfx", ".keystore"))
            or re.search(r"(?:^|[-_.])credentials?(?:[-_.]|$)", name) is not None)


def _relative_source(value: Any) -> Path:
    value = _text(value).replace("\\", "/")
    posix, windows = PurePosixPath(value), PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise ProjectError("SOURCE_OUTSIDE_ROOT")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or ":" in part or part != part.rstrip(" .") for part in parts):
        raise ProjectError("SOURCE_OUTSIDE_ROOT")
    if any(_sensitive(part) for part in parts):
        raise ProjectError("SENSITIVE_PATH")
    if any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part) for part in parts):
        raise ProjectError("UNSAFE_PATH")
    return Path(*parts)


def _no_links(path: Path) -> None:
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProjectError("LINK_NOT_ALLOWED")
        if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
            raise ProjectError("LINK_NOT_ALLOWED")


def _absolute(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if str(path).startswith(("\\\\", "//")):
        raise ProjectError("NETWORK_PATH_NOT_ALLOWED")
    try:
        _no_links(path)
    except OSError as error:
        raise ProjectError("PATH_UNREADABLE") from error
    return path


def _read(path: Path, limit: int, category: str = "SOURCE") -> bytes:
    try:
        _no_links(path)
        if any(_sensitive(part) for part in path.parts):
            raise ProjectError("SENSITIVE_PATH")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ProjectError(category + "_NOT_REGULAR_FILE")
        if before.st_size > limit:
            raise ProjectError(category + "_TOO_LARGE")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_nlink > 1:
                raise ProjectError("SOURCE_CHANGED_DURING_READ")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        _no_links(path)
        final = path.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if signature(before) != signature(after) or signature(after) != signature(final):
            raise ProjectError("SOURCE_CHANGED_DURING_READ")
        if len(data) > limit:
            raise ProjectError(category + "_TOO_LARGE")
        if _PRIVATE_KEY.search(data):
            raise ProjectError("PRIVATE_KEY_CONTENT")
        return data
    except FileNotFoundError as error:
        raise ProjectError(category + "_MISSING") from error
    except OSError as error:
        raise ProjectError(category + "_UNREADABLE") from error


def _decode(data: bytes) -> str:
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProjectError("SOURCE_NOT_UTF8") from error
    if "\x00" in value:
        raise ProjectError("SOURCE_BINARY_CONTENT")
    return value


def _read_source(path: Path, remaining: int) -> bytes:
    if remaining <= 0:
        raise ProjectError("TOTAL_SOURCE_LIMIT_EXCEEDED")
    try:
        return _read(path, min(MAX_SOURCE_BYTES, remaining))
    except ProjectError as error:
        if error.reason == "SOURCE_TOO_LARGE" and remaining < MAX_SOURCE_BYTES:
            raise ProjectError("TOTAL_SOURCE_LIMIT_EXCEEDED") from error
        raise


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProjectError("CONFIG_DUPLICATE_KEY")
        result[key] = value
    return result


def _root(config: Path, relative: Any) -> Path:
    value = _text(relative, 4096).replace("\\", "/")
    if PureWindowsPath(value).drive or PureWindowsPath(value).root or PurePosixPath(value).is_absolute():
        raise ProjectError("PROJECT_ROOT_MUST_BE_RELATIVE")
    root = _absolute(config.parent / value)
    if not root.is_dir():
        raise ProjectError("PROJECT_ROOT_MISSING")
    return root


def _source_metadata(item: Any) -> dict:
    if not isinstance(item, dict):
        raise ProjectError("INVALID_SOURCE_METADATA")
    source = {key: item[key] for key in _SOURCE_FIELDS if key in item}
    _text(source.get("id"), 128)
    if source.get("kind") not in ROLES:
        raise ProjectError("INVALID_SOURCE_KIND")
    _text(source.get("path"))
    if not isinstance(source.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", source["sha256"]):
        raise ProjectError("INVALID_SOURCE_HASH")
    _text(source.get("revision"), 256)
    if source.get("status") not in ("current", "draft", "expired", "superseded"):
        raise ProjectError("INVALID_SOURCE_STATUS")
    applicability = source.get("applicability")
    if not isinstance(applicability, dict) or set(applicability) != {"conditions", "limitations"}:
        raise ProjectError("INVALID_APPLICABILITY")
    for entries in applicability.values():
        if not isinstance(entries, list) or len(entries) > 32:
            raise ProjectError("INVALID_APPLICABILITY")
        for entry in entries:
            _text(entry, 2048)
    source.setdefault("claim_type", "reference")
    if source["claim_type"] not in ("reference", "assumption", "unverified_report"):
        raise ProjectError("INVALID_CLAIM_TYPE")
    source.setdefault("critical", False)
    if type(source["critical"]) is not bool:
        raise ProjectError("INVALID_CRITICAL_FLAG")
    for field in ("conflicts", "supersedes"):
        source.setdefault(field, [])
        if not isinstance(source[field], list) or len(source[field]) > MAX_SOURCES:
            raise ProjectError("INVALID_SOURCE_RELATION")
        for target in source[field]:
            _text(target, 128)
        if len(set(source[field])) != len(source[field]) or source["id"] in source[field]:
            raise ProjectError("INVALID_SOURCE_RELATION")
    return source


def _identity(project_id: Any, goal: Any) -> None:
    _text(project_id, 128)
    _text(goal, MAX_GOAL_CHARS)


def init_project(root: Path, config: Path, goal: str, sources: list[str], project_id: str = "project") -> dict:
    """Create a new external config; read only the explicitly named UTF-8 files.

    Unsafe input, duplicate paths, size excess or existing output raises
    ProjectError(reason). The returned result uses the load_context schema.
    Config parents must already exist. This function does not scan directories.
    """
    _identity(project_id, goal)
    root, config = _absolute(Path(root)), _absolute(Path(config))
    if not root.is_dir():
        raise ProjectError("PROJECT_ROOT_MISSING")
    if config.is_relative_to(PACKAGE_ROOT):
        raise ProjectError("CONFIG_INSIDE_PACKAGE")
    if any(_sensitive(part) for part in config.parts):
        raise ProjectError("SENSITIVE_PATH")
    if config.exists():
        raise ProjectError("CONFIG_ALREADY_EXISTS")
    if not config.parent.is_dir():
        raise ProjectError("CONFIG_DIRECTORY_MISSING")
    if not isinstance(sources, list) or len(sources) > MAX_SOURCES:
        raise ProjectError("TOO_MANY_SOURCES")
    entries, seen, total = [], set(), 0
    for index, spec in enumerate(sources, 1):
        _text(spec, 1200)
        role, separator, relative = spec.partition("=")
        if not separator or role not in ROLES:
            raise ProjectError("INVALID_SOURCE_SPEC")
        relative_path = _relative_source(relative)
        path_key = os.path.normcase(str(relative_path))
        if path_key in seen:
            raise ProjectError("DUPLICATE_SOURCE_PATH")
        seen.add(path_key)
        data = _read_source(root / relative_path, MAX_TOTAL_BYTES - total)
        _decode(data)
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ProjectError("TOTAL_SOURCE_LIMIT_EXCEEDED")
        digest = hashlib.sha256(data).hexdigest()
        entries.append({"id": role + "-" + str(index), "kind": role,
                        "path": relative_path.as_posix(), "sha256": digest,
                        "revision": "sha256:" + digest, "status": "current",
                        "applicability": {"conditions": [], "limitations": []},
                        "claim_type": "reference", "critical": False,
                        "conflicts": [], "supersedes": []})
    try:
        relative_root = os.path.relpath(root, config.parent).replace("\\", "/")
    except ValueError as error:
        raise ProjectError("CONFIG_ROOT_DIFFERENT_VOLUME") from error
    document = {"schema_version": SCHEMA_VERSION, "project_id": project_id,
                "project_root": relative_root, "goal": goal, "sources": entries,
                "not_applicable": [], "execution_authority": False,
                "human_acceptance": "NOT_CLAIMED"}
    encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ProjectError("CONFIG_TOO_LARGE")
    try:
        _no_links(config.parent)
        with config.open("xb") as stream:
            stream.write(encoded)
    except FileExistsError as error:
        raise ProjectError("CONFIG_ALREADY_EXISTS") from error
    except OSError as error:
        raise ProjectError("CONFIG_WRITE_FAILED") from error
    result = load_context(config)
    result["config_path"] = str(config)
    return result


def load_context(config: Path) -> dict:
    """Read a config and its explicit sources without modifying either.

    Source failures are issues and exclusions, including critical hash failures;
    invalid config/schema raises ProjectError(reason). Every issue makes the
    overall status PROJECT_CONTEXT_INCOMPLETE, even if another file fills the
    same role. Expired/superseded references are intentionally excluded and do
    not themselves make a covered context incomplete. Relations are explicit
    only: no clock, repository HEAD or model-based semantic inference is used.
    """
    config = _absolute(Path(config))
    try:
        document = json.loads(_read(config, MAX_CONFIG_BYTES, "CONFIG").decode("utf-8"), object_pairs_hook=_unique_keys)
    except ProjectError:
        raise
    except (ValueError, RecursionError) as error:
        raise ProjectError("CONFIG_INVALID_JSON") from error
    if not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION:
        raise ProjectError("CONFIG_SCHEMA_UNSUPPORTED")
    _identity(document.get("project_id"), document.get("goal"))
    root = _root(config, document.get("project_root"))
    raw_sources = document.get("sources")
    if not isinstance(raw_sources, list) or len(raw_sources) > MAX_SOURCES:
        raise ProjectError("INVALID_SOURCES")
    sources = [_source_metadata(item) for item in raw_sources]
    by_id = {source["id"]: source for source in sources}
    if len(by_id) != len(sources):
        raise ProjectError("DUPLICATE_SOURCE_ID")
    exemptions = document.get("not_applicable", [])
    if not isinstance(exemptions, list) or len(exemptions) > len(ROLES):
        raise ProjectError("INVALID_NOT_APPLICABLE")
    exempt_roles = set()
    for item in exemptions:
        if not isinstance(item, dict) or set(item) != {"kind", "reason"} or item["kind"] not in ROLES:
            raise ProjectError("INVALID_NOT_APPLICABLE")
        _text(item["reason"], 2048)
        if item["kind"] in exempt_roles:
            raise ProjectError("DUPLICATE_NOT_APPLICABLE")
        exempt_roles.add(item["kind"])
    exclusions = {source["id"]: [] for source in sources}
    issues = []

    def exclude(source_id: str, reason: str, issue: bool = True):
        if reason not in exclusions[source_id]:
            exclusions[source_id].append(reason)
            if issue:
                issues.append({"source_id": source_id, "reason": reason,
                               "critical": by_id[source_id]["critical"]})

    seen_paths = {}
    for source in sources:
        source_id = source["id"]
        if source["kind"] in exempt_roles:
            exclude(source_id, "NOT_APPLICABLE_WITH_SOURCE")
        if source["status"] in {"expired", "superseded"}:
            exclude(source_id, "SOURCE_" + source["status"].upper(), False)
        for field in ("conflicts", "supersedes"):
            for target in source[field]:
                if target not in by_id:
                    exclude(source_id, "UNKNOWN_RELATION_TARGET")
                elif field == "conflicts":
                    exclude(source_id, "EXPLICIT_CONFLICT")
                    exclude(target, "EXPLICIT_CONFLICT")
                else:
                    exclude(target, "EXPLICITLY_SUPERSEDED", False)
        try:
            relative = _relative_source(source["path"])
            key = os.path.normcase(str(relative))
            if key in seen_paths:
                exclude(source_id, "DUPLICATE_SOURCE_PATH")
                exclude(seen_paths[key], "DUPLICATE_SOURCE_PATH")
            else:
                seen_paths[key] = source_id
        except ProjectError as error:
            exclude(source_id, error.reason)
    output, included_roles, total = [], set(), 0
    for source in sources:
        source_id = source["id"]
        result = dict(source, included=False, hash_status="NOT_CHECKED",
                      verification="UNTRUSTED_PROJECT_REFERENCE")
        content = None
        if not exclusions[source_id]:
            try:
                relative = _relative_source(source["path"])
                path = _absolute(root / relative)
                if not path.is_relative_to(root):
                    raise ProjectError("SOURCE_OUTSIDE_ROOT")
                data = _read_source(path, MAX_TOTAL_BYTES - total)
                total += len(data)
                if total > MAX_TOTAL_BYTES:
                    raise ProjectError("TOTAL_SOURCE_LIMIT_EXCEEDED")
                actual = hashlib.sha256(data).hexdigest()
                result["observed_sha256"] = actual
                result["hash_status"] = "MATCH" if actual == source["sha256"] else "MISMATCH"
                if actual != source["sha256"]:
                    raise ProjectError("HASH_MISMATCH")
                content = _decode(data)
            except ProjectError as error:
                exclude(source_id, error.reason)
        if not exclusions[source_id]:
            result.update(included=True, content=content)
            included_roles.add(source["kind"])
        result["exclusion_reasons"] = exclusions[source_id]
        output.append(result)
    missing = [role for role in ROLES if role not in included_roles and role not in exempt_roles]
    return {"schema_version": SCHEMA_VERSION, "project_id": document["project_id"],
            "project_root": str(root), "goal": document["goal"], "sources": output,
            "not_applicable": exemptions, "missing_roles": missing, "issues": issues,
            "status": "PROJECT_CONTEXT_INCOMPLETE" if missing or issues else "CONTEXT_READY_FOR_REVIEW",
            "execution_authority": False, "human_acceptance": "NOT_CLAIMED"}
