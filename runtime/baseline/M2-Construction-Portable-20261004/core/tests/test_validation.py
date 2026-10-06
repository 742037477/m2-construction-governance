"""Real process and byte-bound candidate validation, without mocked receipts."""

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import m2_construction.adapters as adapters
from m2_construction.adapters import run_fixed_command
from m2_construction.artifacts import freeze_candidate, verify_frozen_candidate
from m2_construction.contracts import Denied


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def files_under(root, *paths):
    return {name: sha((root / name).read_bytes()) for name in paths}


def command(tmp_path, script, *, operation_id="test-01", timeout_seconds=5,
            output_files=None):
    workspace = tmp_path / "workspace"
    kwargs = {"output_files": output_files} if output_files is not None else {}
    return run_fixed_command(
        argv=[sys.executable, str(workspace / script), "fixed-argument"],
        cwd=workspace,
        env={"M2_EXACT": "only-test"},
        timeout_seconds=timeout_seconds,
        expected_program_sha256=sha(Path(sys.executable).read_bytes()),
        log_dir=tmp_path / "evidence" / "tests",
        operation_id=operation_id,
        tracked_root=workspace,
        tracked_files=files_under(workspace, "src/algorithm.py", script),
        **kwargs,
    )


def workspace_with_script(tmp_path, code):
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "tests").mkdir()
    (workspace / "dist").mkdir()
    (workspace / "src" / "algorithm.py").write_bytes(b"value = 1\n")
    (workspace / "tests" / "check.py").write_text(code, encoding="utf-8")
    (workspace / "dist" / "package.bin").write_bytes(b"built-actual-bytes\x00")
    return workspace


def freeze(tmp_path, receipt):
    return freeze_candidate(
        root=tmp_path / "workspace",
        source_files=["src/algorithm.py"],
        test_files=["tests/check.py"],
        build_files=["dist/package.bin"],
        test_receipts=[receipt],
        manifest_path=tmp_path / "evidence" / "candidate" / "manifest.json",
    )


def test_real_nonzero_exit_and_fixed_process_inputs_are_recorded(tmp_path, monkeypatch):
    workspace = workspace_with_script(tmp_path, """
import json, os, sys
print(json.dumps({"cwd": os.getcwd(), "env": dict(os.environ), "argv": sys.argv}))
raise SystemExit(7)
""")
    monkeypatch.setenv("PARENT_SENTINEL", "must-not-be-inherited")
    receipt = command(tmp_path, "tests/check.py")
    assert receipt["status"] == "FAILED"
    assert receipt["exit_code"] == 7
    assert receipt["actual_argv"] == [sys.executable, str(workspace / "tests" / "check.py"), "fixed-argument"]
    assert receipt["actual_cwd"] == str(workspace)
    assert receipt["program_sha256"] == sha(Path(sys.executable).read_bytes())
    raw_log = Path(receipt["log_path"]).read_bytes()
    assert receipt["log_sha256"] == sha(raw_log)
    assert b'"M2_EXACT": "only-test"' in raw_log
    assert b"PARENT_SENTINEL" not in raw_log
    assert b"fixed-argument" in raw_log
    assert Path(receipt["receipt_path"]).is_file()
    assert receipt["schema"] == "M2_CONSTRUCTION_PROCESS_RECEIPT_1"
    assert not {"output_files", "output_after", "output_error"} & receipt.keys()


def test_program_hash_mismatch_denies_before_dispatch(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('unexpected-effect').write_text('ran')
""")
    with pytest.raises(Denied, match="PROGRAM_HASH_MISMATCH"):
        run_fixed_command(
            argv=[sys.executable, str(workspace / "tests" / "check.py")],
            cwd=workspace, env={}, timeout_seconds=5,
            expected_program_sha256="0" * 64,
            log_dir=tmp_path / "evidence" / "tests", operation_id="wrong-program",
            tracked_root=workspace,
            tracked_files=files_under(workspace, "src/algorithm.py", "tests/check.py"),
        )
    assert not (workspace / "unexpected-effect").exists()


def test_timeout_is_not_a_passing_exit(tmp_path):
    workspace_with_script(tmp_path, """
import sys, time
print('started', flush=True)
time.sleep(5)
""")
    receipt = command(tmp_path, "tests/check.py", timeout_seconds=1)
    assert receipt["status"] == "TIMED_OUT"
    assert receipt["exit_code"] is None
    assert receipt["timed_out"] is True
    assert b"started" in Path(receipt["log_path"]).read_bytes()


def test_failed_test_cannot_freeze_candidate(tmp_path):
    workspace_with_script(tmp_path, "raise SystemExit(3)\n")
    receipt = command(tmp_path, "tests/check.py")
    assert receipt["exit_code"] == 3
    with pytest.raises(Denied, match="TEST_NOT_PASSED"):
        freeze(tmp_path, receipt)
    assert not (tmp_path / "evidence" / "candidate" / "manifest.json").exists()


def test_mutation_during_test_invalidates_its_receipt(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('src/algorithm.py').write_bytes(b'value = 2\\n')
""")
    receipt = command(tmp_path, "tests/check.py")
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "SOURCE_CHANGED"
    assert (workspace / "src" / "algorithm.py").read_bytes() == b"value = 2\n"
    with pytest.raises(Denied, match="TEST_NOT_PASSED"):
        freeze(tmp_path, receipt)


def test_freeze_records_real_bytes_and_rejects_later_mutation(tmp_path):
    workspace = workspace_with_script(tmp_path, "print('passed')\n")
    receipt = command(tmp_path, "tests/check.py")
    assert receipt["status"] == "PASSED" and receipt["exit_code"] == 0
    frozen = freeze(tmp_path, receipt)
    manifest_path = Path(frozen["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert frozen["manifest_sha256"] == sha(manifest_path.read_bytes())
    for name in ("src/algorithm.py", "tests/check.py", "dist/package.bin"):
        assert manifest["files"][name]["sha256"] == sha((workspace / name).read_bytes())
        assert (Path(manifest["snapshot_root"]) / name).read_bytes() == (workspace / name).read_bytes()
    assert verify_frozen_candidate(
        manifest_path, expected_manifest_sha256=frozen["manifest_sha256"]
    )["status"] == "VALID"
    (workspace / "src" / "algorithm.py").write_bytes(b"value = 9\n")
    with pytest.raises(Denied, match="FROZEN_BYTES_CHANGED"):
        verify_frozen_candidate(manifest_path)


def test_source_changed_after_test_cannot_be_frozen(tmp_path):
    workspace = workspace_with_script(tmp_path, "print('passed')\n")
    receipt = command(tmp_path, "tests/check.py")
    (workspace / "src" / "algorithm.py").write_bytes(b"value = 4\n")
    with pytest.raises(Denied, match="TEST_SOURCE_CHANGED"):
        freeze(tmp_path, receipt)


def test_snapshot_mutation_invalidates_frozen_candidate(tmp_path):
    workspace_with_script(tmp_path, "print('passed')\n")
    frozen = freeze(tmp_path, command(tmp_path, "tests/check.py"))
    manifest = json.loads(Path(frozen["manifest_path"]).read_text(encoding="utf-8"))
    (Path(manifest["snapshot_root"]) / "dist" / "package.bin").write_bytes(b"altered")
    with pytest.raises(Denied, match="FROZEN_SNAPSHOT_CHANGED"):
        verify_frozen_candidate(frozen["manifest_path"])


def test_log_mutation_invalidates_frozen_candidate(tmp_path):
    workspace_with_script(tmp_path, "print('passed')\n")
    receipt = command(tmp_path, "tests/check.py")
    frozen = freeze(tmp_path, receipt)
    Path(receipt["log_path"]).write_bytes(b"changed log")
    with pytest.raises(Denied, match="TEST_LOG_CHANGED"):
        verify_frozen_candidate(
            frozen["manifest_path"],
            expected_manifest_sha256=frozen["manifest_sha256"],
        )


def test_real_build_records_exact_new_output_bytes_in_canonical_receipt(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/fresh.bin').write_bytes(b'\\x00built\\n\\xff')
""")
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/fresh.bin": None})
    raw = (workspace / "dist" / "fresh.bin").read_bytes()
    assert raw == b"\x00built\n\xff"
    assert receipt["status"] == "PASSED" and receipt["exit_code"] == 0
    assert receipt["output_files"] == {"dist/fresh.bin": None}
    assert receipt["output_after"] == {
        "dist/fresh.bin": {"sha256": sha(raw), "size": len(raw)}}
    persisted = Path(receipt["receipt_path"]).read_bytes()
    assert receipt["receipt_sha256"] == sha(persisted)
    assert json.loads(persisted)["output_after"] == receipt["output_after"]


def test_real_build_can_replace_a_pinned_preexisting_output(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/package.bin').write_bytes(b'new-package\\x00')
""")
    before = sha((workspace / "dist" / "package.bin").read_bytes())
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/package.bin": before})
    raw = (workspace / "dist" / "package.bin").read_bytes()
    assert receipt["status"] == "PASSED", receipt["output_error"]
    assert receipt["output_files"] == {"dist/package.bin": before}
    assert receipt["output_after"]["dist/package.bin"] == {
        "sha256": sha(raw), "size": len(raw)}


@pytest.mark.parametrize("code,expected_status", [
    ("print('zero exit without file')\n", "OUTPUT_MISSING"),
    ("from pathlib import Path\nPath('dist/fresh.bin').mkdir()\n", "OUTPUT_INVALID"),
])
def test_zero_exit_without_regular_output_fails_closed(tmp_path, code, expected_status):
    workspace_with_script(tmp_path, code)
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/fresh.bin": None})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == expected_status
    assert receipt["output_after"] == {"dist/fresh.bin": None}


def test_unchanged_preexisting_output_does_not_prove_a_build(tmp_path):
    workspace = workspace_with_script(tmp_path, "print('no build')\n")
    before = sha((workspace / "dist" / "package.bin").read_bytes())
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/package.bin": before})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "OUTPUT_UNCHANGED"


def test_empty_output_declaration_denies_before_dispatch(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('unexpected-effect').write_bytes(b'ran')
""")
    with pytest.raises(Denied, match="OUTPUT_FILES"):
        command(tmp_path, "tests/check.py", output_files={})
    assert not (workspace / "unexpected-effect").exists()


@pytest.mark.parametrize("output_files", [
    {"dist/package.bin": None},
    {"dist/package.bin": "0" * 64},
])
def test_output_precondition_mismatch_denies_before_dispatch(tmp_path, output_files):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('unexpected-effect').write_bytes(b'ran')
""")
    with pytest.raises(Denied, match="OUTPUT_BEFORE_CHANGED"):
        command(tmp_path, "tests/check.py", output_files=output_files)
    assert not (workspace / "unexpected-effect").exists()


@pytest.mark.parametrize("name", [
    "../outside.bin", "dist/../outside.bin", "/outside.bin",
    str(Path(Path.cwd().anchor) / "outside.bin"), "dist\\outside.bin",
])
def test_output_path_outside_workspace_denies_before_dispatch(tmp_path, name):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('unexpected-effect').write_bytes(b'ran')
""")
    with pytest.raises(Denied, match="OUTPUT_PATH_SCOPE"):
        command(tmp_path, "tests/check.py", output_files={name: None})
    assert not (workspace / "unexpected-effect").exists()


def test_output_case_alias_denies_before_dispatch(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('unexpected-effect').write_bytes(b'ran')
""")
    with pytest.raises(Denied, match="OUTPUT_PATH_ALIAS"):
        command(tmp_path, "tests/check.py", output_files={
            "dist/FRESH.bin": None, "dist/fresh.bin": None})
    assert not (workspace / "unexpected-effect").exists()


def test_output_link_denies_before_dispatch(tmp_path):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('unexpected-effect').write_bytes(b'ran')
""")
    try:
        (workspace / "dist" / "linked.bin").symlink_to(workspace / "dist" / "package.bin")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(Denied, match="OUTPUT_PATH_LINK"):
        command(tmp_path, "tests/check.py", output_files={"dist/linked.bin": None})
    assert not (workspace / "unexpected-effect").exists()


def test_hardlinked_output_after_dispatch_fails_closed(tmp_path):
    workspace_with_script(tmp_path, """
import os
os.link('dist/package.bin', 'dist/fresh.bin')
""")
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/fresh.bin": None})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "OUTPUT_INVALID"
    assert receipt["output_after"] == {"dist/fresh.bin": None}
    assert receipt["output_error"] == "OUTPUT_PATH_LINK"


def test_output_mutation_during_receipt_assembly_fails_closed(tmp_path, monkeypatch):
    workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/fresh.bin').write_bytes(b'build-version')
""")
    observe = adapters._output_bytes
    observations = 0

    def mutate_after_first_observation(root, name):
        nonlocal observations
        found = observe(root, name)
        observations += 1
        if observations == 1:
            (root / name).write_bytes(b'other-version')
        return found

    monkeypatch.setattr(adapters, "_output_bytes", mutate_after_first_observation)
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/fresh.bin": None})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "OUTPUT_INVALID"
    assert receipt["output_error"] == "OUTPUT_CHANGED"
    assert receipt["output_after"]["dist/fresh.bin"] == {
        "sha256": sha(b"build-version"), "size": len(b"build-version")}


def test_in_read_path_swap_cannot_sign_decoy_bytes(tmp_path, monkeypatch):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/fresh.bin').write_bytes(b'AAAA')
""")
    artifact = workspace / "dist" / "fresh.bin"
    decoy = workspace / "dist" / "decoy.bin"
    parked = workspace / "dist" / "parked.bin"
    decoy.write_bytes(b"BBBB")
    original_read = Path.read_bytes
    swaps = 0

    def swapped_read(path):
        nonlocal swaps
        if path != artifact:
            return original_read(path)
        os.replace(artifact, parked)
        os.replace(decoy, artifact)
        try:
            raw = original_read(path)
        finally:
            os.replace(artifact, decoy)
            os.replace(parked, artifact)
        swaps += 1
        return raw

    with monkeypatch.context() as patcher:
        patcher.setattr(Path, "read_bytes", swapped_read)
        receipt = command(tmp_path, "tests/check.py",
                          output_files={"dist/fresh.bin": None})
    current = sha(artifact.read_bytes())
    recorded = receipt["output_after"]["dist/fresh.bin"]
    assert receipt["status"] != "PASSED" or recorded == {
        "sha256": current, "size": artifact.stat().st_size}
    assert json.loads(Path(receipt["receipt_path"]).read_bytes())[
        "output_after"] == receipt["output_after"]


def test_output_handle_for_a_different_file_fails_closed(tmp_path, monkeypatch):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/fresh.bin').write_bytes(b'AAAA')
""")
    artifact = workspace / "dist" / "fresh.bin"
    decoy = workspace / "dist" / "decoy.bin"
    decoy.write_bytes(b"BBBB")
    open_file = os.open

    def substituted_open(path, flags, *args, **kwargs):
        if Path(path) == artifact:
            return open_file(decoy, flags, *args, **kwargs)
        return open_file(path, flags, *args, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(adapters.os, "open", substituted_open)
        receipt = command(tmp_path, "tests/check.py",
                          output_files={"dist/fresh.bin": None})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "OUTPUT_INVALID"
    assert receipt["output_error"] == "OUTPUT_CHANGED"
    assert receipt["output_after"] == {"dist/fresh.bin": None}


def test_same_bytes_replacement_between_observations_fails_closed(tmp_path, monkeypatch):
    workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/fresh.bin').write_bytes(b'AAAA')
""")
    observe = adapters._output_bytes
    observations = 0

    def replace_after_first_observation(root, name):
        nonlocal observations
        found = observe(root, name)
        observations += 1
        if observations == 1:
            replacement = root / "dist" / "replacement.bin"
            replacement.write_bytes(b"AAAA")
            os.replace(replacement, root / name)
        return found

    monkeypatch.setattr(adapters, "_output_bytes", replace_after_first_observation)
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/fresh.bin": None})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "OUTPUT_INVALID"
    assert receipt["output_error"] == "OUTPUT_CHANGED"


def test_output_changed_while_receipt_is_written_cannot_return_passed(tmp_path,
                                                                     monkeypatch):
    workspace = workspace_with_script(tmp_path, """
from pathlib import Path
Path('dist/fresh.bin').write_bytes(b'AAAA')
""")
    write = adapters._write_exclusive

    def mutate_after_receipt_write(path, raw):
        write(path, raw)
        if path.name.endswith(".receipt.json"):
            (workspace / "dist" / "fresh.bin").write_bytes(b"BBBB")

    monkeypatch.setattr(adapters, "_write_exclusive", mutate_after_receipt_write)
    with pytest.raises(Denied, match="OUTPUT_CHANGED_AFTER_RECEIPT"):
        command(tmp_path, "tests/check.py",
                output_files={"dist/fresh.bin": None})
    receipt_path = tmp_path / "evidence" / "tests" / "test-01.receipt.json"
    assert receipt_path.is_file()
    assert json.loads(receipt_path.read_bytes())["status"] == "PASSED"


def test_source_mutation_stays_source_changed_with_successful_output(tmp_path):
    workspace_with_script(tmp_path, """
from pathlib import Path
Path('src/algorithm.py').write_bytes(b'value = 2\\n')
Path('dist/fresh.bin').write_bytes(b'built')
""")
    receipt = command(tmp_path, "tests/check.py",
                      output_files={"dist/fresh.bin": None})
    assert receipt["exit_code"] == 0
    assert receipt["status"] == "SOURCE_CHANGED"
    assert receipt["output_after"]["dist/fresh.bin"] == {
        "sha256": sha(b"built"), "size": 5}
