"""Freeze actual source, test and build bytes with passing process evidence.

These functions validate bytes; the Controller must supply trusted receipt IDs
from its ledger and pin the returned manifest SHA before an effect is consumed.
"""

from pathlib import Path

from .adapters import (_absolute_directory, _evidence_directory, _file_sha256,
                       _no_link, _relative_file, _write_exclusive)
from .contracts import (Denied, bytes_hash, canonical, exact_fields, hash_text,
                        require, strict_json)


def _load_canonical_json(path, code):
    try:
        raw = path.read_bytes()
        value = strict_json(raw)
        require(canonical(value) == raw, code)
        return value, bytes_hash(raw)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        raise Denied(code) from exc


def _receipt(path, expected_sha256):
    require(hash_text(expected_sha256), "RECEIPT_HASH")
    path = Path(path)
    require(path.is_absolute() and path.is_file(), "RECEIPT_MISSING")
    _no_link(path)
    require(path.resolve(strict=True) == path, "RECEIPT_LINK")
    value, actual_hash = _load_canonical_json(path, "RECEIPT_INVALID")
    require(actual_hash == expected_sha256, "RECEIPT_CHANGED")
    require(type(value) is dict and
            value.get("schema") == "M2_CONSTRUCTION_PROCESS_RECEIPT_1",
            "RECEIPT_SCHEMA")
    log_path = Path(value["log_path"])
    require(log_path.is_absolute() and log_path.is_file(), "TEST_LOG_MISSING")
    _no_link(log_path)
    require(log_path.resolve(strict=True) == log_path and
            _file_sha256(log_path) == value["log_sha256"], "TEST_LOG_CHANGED")
    return value


def _passing_receipt(root, source_test_hashes, receipt, *, require_workspace_current=True):
    require(receipt["status"] == "PASSED" and receipt["exit_code"] == 0 and
            receipt["timed_out"] is False, "TEST_NOT_PASSED")
    require(receipt["tracked_root"] == str(root), "TEST_ROOT_MISMATCH")
    tracked = receipt["tracked_files"]
    require(type(tracked) is dict and set(source_test_hashes) <= set(tracked),
            "TEST_COVERAGE")
    require(receipt["tracked_after"] == tracked and
            all(tracked[name] == value for name, value in source_test_hashes.items()),
            "TEST_SOURCE_CHANGED")
    if require_workspace_current:
        for name, expected in tracked.items():
            require(_file_sha256(_relative_file(root, name)) == expected,
                    "TEST_SOURCE_CHANGED")
        program = Path(receipt["program_path"])
        require(program.is_absolute() and program.is_file(), "TEST_PROGRAM_MISSING")
        _no_link(program)
        require(program.resolve(strict=True) == program and
                receipt["program_sha256"] == receipt["program_sha256_after"] and
                _file_sha256(program) == receipt["program_sha256"],
                "TEST_PROGRAM_CHANGED")
    else:
        # The pinned receipt attests to the original program and any extra
        # tracked inputs. Frozen inputs are independently checked in the
        # immutable snapshot; later legitimate workspace/runtime updates must
        # not rewrite the meaning of this historical receipt.
        require(receipt["program_sha256"] == receipt["program_sha256_after"],
                "TEST_PROGRAM_CHANGED")


def _file_groups(root, source_files, test_files, build_files):
    groups = (("source", source_files), ("test", test_files), ("build", build_files))
    require(all(type(names) in (list, tuple) for _, names in groups) and
            len(source_files) > 0 and len(test_files) > 0, "FREEZE_FILES")
    kinds = {}
    for kind, names in groups:
        for name in names:
            require(type(name) is str and name not in kinds, "FREEZE_FILES")
            _relative_file(root, name)
            kinds[name] = kind
    return kinds


def freeze_candidate(*, root, source_files, test_files, build_files,
                     test_receipts, manifest_path, build_receipts=()):
    """Store a byte snapshot and a canonical manifest for one tested candidate.

    Source and test files match every passing TEST receipt. In schema 2, build
    bytes must additionally match passing BUILD output receipts and TEST inputs.
    Legacy schema 1 is a byte snapshot only; it makes no build-origin claim.
    The returned manifest hash is the candidate identity to pin in the ledger.
    """
    root = _absolute_directory(root)
    kinds = _file_groups(root, source_files, test_files, build_files)
    require(type(test_receipts) in (list, tuple) and len(test_receipts) > 0,
            "TEST_RECEIPT_REQUIRED")
    actual = {name: _file_sha256(_relative_file(root, name)) for name in kinds}
    source_test_hashes = {name: actual[name] for name, kind in kinds.items()
                          if kind in ("source", "test")}
    require(type(build_receipts) in (list, tuple) and
            (not build_receipts or bool(build_files)), "BUILD_RECEIPTS")
    refs = []
    for item in test_receipts:
        require(type(item) is dict and "receipt_path" in item and
                "receipt_sha256" in item, "RECEIPT_REFERENCE")
        loaded = _receipt(item["receipt_path"], item["receipt_sha256"])
        require(item == {**loaded, "receipt_path": item["receipt_path"],
                         "receipt_sha256": item["receipt_sha256"]},
                "RECEIPT_ARGUMENT_CHANGED")
        _passing_receipt(root, actual if build_receipts else source_test_hashes, loaded)
        refs.append({"operation_id": loaded["operation_id"],
                     "receipt_path": item["receipt_path"],
                     "receipt_sha256": item["receipt_sha256"],
                     "log_sha256": loaded["log_sha256"],
                     "program_sha256": loaded["program_sha256"],
                     "exit_code": loaded["exit_code"]})
    require(len({ref["operation_id"] for ref in refs}) == len(refs),
            "TEST_RECEIPT_DUPLICATE")

    build_refs = []
    build_covered = set()
    for item in build_receipts:
        require(type(item) is dict and "receipt_path" in item and
                "receipt_sha256" in item, "BUILD_RECEIPT_REFERENCE")
        loaded = _receipt(item["receipt_path"], item["receipt_sha256"])
        require(item == {**loaded, "receipt_path": item["receipt_path"],
                         "receipt_sha256": item["receipt_sha256"]},
                "BUILD_RECEIPT_ARGUMENT_CHANGED")
        _passing_receipt(root,
                         {name: actual[name] for name in source_files}, loaded)
        outputs = loaded.get("output_after")
        require(type(outputs) is dict and outputs and
                set(outputs) <= set(build_files), "BUILD_OUTPUT_PROOF")
        for name, record in outputs.items():
            require(name not in build_covered and type(record) is dict and
                    record.get("sha256") == actual[name] and
                    record.get("size") == _relative_file(root, name).stat().st_size,
                    "BUILD_OUTPUT_PROOF")
            build_covered.add(name)
        build_refs.append({"operation_id": loaded["operation_id"],
                           "receipt_path": item["receipt_path"],
                           "receipt_sha256": item["receipt_sha256"],
                           "log_sha256": loaded["log_sha256"],
                           "program_sha256": loaded["program_sha256"],
                           "exit_code": loaded["exit_code"]})
    if build_receipts:
        require(build_covered == set(build_files) and
                len({ref["operation_id"] for ref in build_refs}) == len(build_refs),
                "BUILD_OUTPUT_PROOF")

    manifest_path = Path(manifest_path)
    require(manifest_path.is_absolute(), "MANIFEST_PATH")
    evidence = _evidence_directory(manifest_path.parent, root)
    manifest_path = evidence / manifest_path.name
    snapshot_root = evidence / f"{manifest_path.stem}.snapshot"
    require(not manifest_path.exists() and not snapshot_root.exists(),
            "CANDIDATE_ID_USED")
    snapshot_root.mkdir()
    files = {}
    for name, kind in sorted(kinds.items()):
        raw = _relative_file(root, name).read_bytes()
        require(bytes_hash(raw) == actual[name], "FROZEN_BYTES_CHANGED")
        destination = snapshot_root.joinpath(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        _write_exclusive(destination, raw)
        files[name] = {"kind": kind, "sha256": bytes_hash(raw), "size": len(raw)}
    for name, record in files.items():
        require(_file_sha256(_relative_file(root, name)) == record["sha256"],
                "FROZEN_BYTES_CHANGED")
    manifest = {
        "schema": ("M2_CONSTRUCTION_FREEZE_2" if build_receipts else
                   "M2_CONSTRUCTION_FREEZE_1"),
        "root": str(root),
        "snapshot_root": str(snapshot_root),
        "files": files,
        "test_receipts": refs,
    }
    if build_receipts:
        manifest["build_receipts"] = build_refs
    raw_manifest = canonical(manifest)
    _write_exclusive(manifest_path, raw_manifest)
    manifest_sha256 = bytes_hash(raw_manifest)
    verify_frozen_candidate(manifest_path, expected_manifest_sha256=manifest_sha256)
    return {"status": "FROZEN", "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_sha256,
            "candidate_sha256": manifest_sha256, "file_count": len(files)}


def verify_frozen_candidate(manifest_path, *, expected_manifest_sha256=None,
                            require_workspace_current=True):
    """Recheck a pin; only historical evidence may omit live-byte currentness."""
    manifest_path = Path(manifest_path)
    require(manifest_path.is_absolute() and manifest_path.is_file(), "MANIFEST_MISSING")
    _no_link(manifest_path)
    manifest, actual_hash = _load_canonical_json(manifest_path, "MANIFEST_INVALID")
    if expected_manifest_sha256 is not None:
        require(hash_text(expected_manifest_sha256) and
                actual_hash == expected_manifest_sha256, "MANIFEST_HASH_CHANGED")
    require(type(manifest) is dict and
            manifest.get("schema") in ("M2_CONSTRUCTION_FREEZE_1",
                                       "M2_CONSTRUCTION_FREEZE_2"),
            "MANIFEST_SCHEMA")
    root = _absolute_directory(manifest["root"])
    snapshot_root = _absolute_directory(manifest["snapshot_root"])
    require(root not in snapshot_root.parents and snapshot_root != root,
            "EVIDENCE_INSIDE_SOURCE")
    require(type(manifest["files"]) is dict and manifest["files"],
            "MANIFEST_FILES")
    source_test_hashes = {}
    all_hashes = {}
    build_hashes = {}
    for name, record in manifest["files"].items():
        exact_fields(record, "kind sha256 size", "MANIFEST_FILE_FIELDS")
        require(record["kind"] in ("source", "test", "build") and
                hash_text(record["sha256"]) and type(record["size"]) is int and
                record["size"] >= 0, "MANIFEST_FILE")
        if require_workspace_current:
            target = _relative_file(root, name)
            require(_file_sha256(target) == record["sha256"] and
                    target.stat().st_size == record["size"], "FROZEN_BYTES_CHANGED")
        snapshot = _relative_file(snapshot_root, name)
        require(_file_sha256(snapshot) == record["sha256"] and
                snapshot.stat().st_size == record["size"],
                "FROZEN_SNAPSHOT_CHANGED")
        if record["kind"] in ("source", "test"):
            source_test_hashes[name] = record["sha256"]
        if record["kind"] == "build":
            build_hashes[name] = record["sha256"]
        all_hashes[name] = record["sha256"]
    require(type(manifest["test_receipts"]) is list and
            manifest["test_receipts"], "TEST_RECEIPT_REQUIRED")
    for ref in manifest["test_receipts"]:
        exact_fields(ref,
                     "operation_id receipt_path receipt_sha256 log_sha256 program_sha256 exit_code",
                     "TEST_REFERENCE_FIELDS")
        receipt = _receipt(ref["receipt_path"], ref["receipt_sha256"])
        require(receipt["operation_id"] == ref["operation_id"] and
                receipt["log_sha256"] == ref["log_sha256"] and
                receipt["program_sha256"] == ref["program_sha256"] and
                receipt["exit_code"] == ref["exit_code"], "TEST_REFERENCE_CHANGED")
        _passing_receipt(root,
                         all_hashes if manifest["schema"] == "M2_CONSTRUCTION_FREEZE_2"
                         else source_test_hashes, receipt,
                         require_workspace_current=require_workspace_current)
    if manifest["schema"] == "M2_CONSTRUCTION_FREEZE_2":
        require(build_hashes and type(manifest.get("build_receipts")) is list and
                manifest["build_receipts"], "BUILD_RECEIPTS")
        covered = set()
        for ref in manifest["build_receipts"]:
            exact_fields(ref,
                         "operation_id receipt_path receipt_sha256 log_sha256 program_sha256 exit_code",
                         "BUILD_REFERENCE_FIELDS")
            receipt = _receipt(ref["receipt_path"], ref["receipt_sha256"])
            require(receipt["operation_id"] == ref["operation_id"] and
                    receipt["log_sha256"] == ref["log_sha256"] and
                    receipt["program_sha256"] == ref["program_sha256"] and
                    receipt["exit_code"] == ref["exit_code"],
                    "BUILD_REFERENCE_CHANGED")
            _passing_receipt(root,
                             {name: value for name, value in source_test_hashes.items()
                              if manifest["files"][name]["kind"] == "source"},
                             receipt,
                             require_workspace_current=require_workspace_current)
            outputs = receipt.get("output_after")
            require(type(outputs) is dict and outputs and
                    set(outputs) <= set(build_hashes), "BUILD_OUTPUT_PROOF")
            for name, record in outputs.items():
                require(name not in covered and type(record) is dict and
                        record.get("sha256") == build_hashes[name] and
                        record.get("size") == manifest["files"][name]["size"],
                        "BUILD_OUTPUT_PROOF")
                covered.add(name)
        require(covered == set(build_hashes), "BUILD_OUTPUT_PROOF")
    return {"status": "VALID", "manifest_path": str(manifest_path),
            "manifest_sha256": actual_hash, "candidate_sha256": actual_hash,
            "file_count": len(manifest["files"])}
