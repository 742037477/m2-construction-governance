"""Real fixed-command adapter for the TEST_ONLY construction Controller.

The caller must gate and reserve each operation before invoking this adapter.
Fixed argv, cwd, environment and timeout constrain this entry only; they do
not provide an operating-system filesystem, process or network sandbox.
"""

from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time

from .contracts import Denied, bytes_hash, canonical, digest, hash_text, require


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _no_link(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and
            not (getattr(info, "st_file_attributes", 0) &
                 getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)), "PATH_LINK")


def _absolute_directory(value):
    path = Path(value)
    require(path.is_absolute() and path.is_dir(), "DIRECTORY_REQUIRED")
    _no_link(path)
    require(path.resolve(strict=True) == path, "DIRECTORY_LINK")
    return path


def _absolute_file(value):
    path = Path(value)
    require(path.is_absolute() and path.is_file(), "PROGRAM_REQUIRED")
    _no_link(path)
    require(path.resolve(strict=True) == path, "PROGRAM_LINK")
    return path


def _relative_file(root, name):
    require(type(name) is str and name and "\\" not in name and ":" not in name and
            "\x00" not in name and not name.startswith("/"), "PATH_SCOPE")
    relative = PurePosixPath(name)
    require(str(relative) == name and
            all(part not in ("", ".", "..") for part in name.split("/")), "PATH_SCOPE")
    current = root
    for part in relative.parts:
        current = current / part
        require(current.exists() or current.is_symlink(), "PATH_NOT_FOUND")
        _no_link(current)
    require(current.is_file() and root in current.resolve(strict=True).parents,
            "PATH_OUTSIDE_ROOT")
    return current


def _file_sha256(path):
    hashed = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hashed.update(block)
    return hashed.hexdigest()


def _tracked_hashes(root, names, *, missing_as_none=False):
    observed = {}
    for name in sorted(names):
        try:
            observed[name] = _file_sha256(_relative_file(root, name))
        except (Denied, OSError):
            if not missing_as_none:
                raise
            observed[name] = None
    return observed


def _relative_output_file(root, name):
    """Resolve a workspace output without following links at any existing step."""
    require(type(name) is str and name and "\\" not in name and ":" not in name and
            "\x00" not in name and not name.startswith("/"), "OUTPUT_PATH_SCOPE")
    relative = PurePosixPath(name)
    require(str(relative) == name and
            all(part not in ("", ".", "..") for part in name.split("/")),
            "OUTPUT_PATH_SCOPE")
    current = root
    missing = False
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            missing = True
            continue
        require(not missing, "OUTPUT_PATH_CHANGED")
        require(not stat.S_ISLNK(info.st_mode) and
                not (getattr(info, "st_file_attributes", 0) &
                     getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
                "OUTPUT_PATH_LINK")
        if index < len(relative.parts) - 1:
            require(stat.S_ISDIR(info.st_mode), "OUTPUT_PATH_TYPE")
        else:
            require(stat.S_ISREG(info.st_mode), "OUTPUT_PATH_TYPE")
            require(info.st_nlink == 1, "OUTPUT_PATH_LINK")
    require(root in current.resolve(strict=False).parents, "OUTPUT_PATH_SCOPE")
    return current, not missing


def _output_bytes(root, name):
    """Hash an opened file, matching its identity to the workspace path."""
    path, exists = _relative_output_file(root, name)
    require(exists, "OUTPUT_MISSING")
    before = path.lstat()
    require(before.st_ino != 0, "OUTPUT_IDENTITY_UNAVAILABLE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                not (getattr(opened, "st_file_attributes", 0) &
                     getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
                "OUTPUT_PATH_LINK")
        identity = (opened.st_dev, opened.st_ino)
        require(identity == (before.st_dev, before.st_ino), "OUTPUT_CHANGED")
        hashed = sha256()
        size = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hashed.update(block)
            size += len(block)
        completed = os.fstat(stream.fileno())
    path_after, still_exists = _relative_output_file(root, name)
    require(still_exists and path_after == path, "OUTPUT_CHANGED")
    after = path.lstat()
    require(identity == (completed.st_dev, completed.st_ino) ==
            (after.st_dev, after.st_ino) and
            (before.st_size, before.st_mtime_ns) ==
            (opened.st_size, opened.st_mtime_ns) ==
            (completed.st_size, completed.st_mtime_ns) ==
            (after.st_size, after.st_mtime_ns) and
            before.st_ctime_ns == after.st_ctime_ns and
            opened.st_ctime_ns == completed.st_ctime_ns and
            size == completed.st_size, "OUTPUT_CHANGED")
    return {"sha256": hashed.hexdigest(), "size": size}, identity


def _evidence_directory(value, protected_root):
    path = Path(value)
    require(path.is_absolute(), "EVIDENCE_DIRECTORY")
    require(path != protected_root and protected_root not in path.parents,
            "EVIDENCE_INSIDE_SOURCE")
    # Resolve existing ancestors before creating anything: an evidence path
    # through a junction/symlink must not create files under the source root.
    destination = path.resolve(strict=False)
    require(destination == path, "EVIDENCE_PATH_LINK")
    require(destination != protected_root and
            protected_root not in destination.parents, "EVIDENCE_INSIDE_SOURCE")
    path.mkdir(parents=True, exist_ok=True)
    return _absolute_directory(path)


def _write_exclusive(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def run_fixed_command(*, argv, cwd, env, timeout_seconds, expected_program_sha256,
                      log_dir, operation_id, tracked_root=None, tracked_files=None,
                      output_files=None):
    """Execute one already-authorized command and persist its real process receipt.

    argv[0] is an absolute executable whose bytes must match the pinned hash.
    env is the entire child environment, with no implicit parent inheritance.
    tracked_files maps relative source/test paths to hashes expected before the
    run; a passing receipt requires those same bytes after the run. A Controller
    may pass output_files as relative workspace paths mapped to their expected
    pre-run SHA-256, or None if absent. A passing output receipt requires each
    output to exist as a changed regular file, bound to its actual SHA and size.
    Legacy calls omit this argument and retain the original receipt fields.
    Handle identity and final reads narrow path races, but a mutable ordinary
    filesystem cannot bind the path atomically through return. Consumers must
    recheck current output bytes when using the receipt.
    A Controller must bind this receipt to its reserved operation and treat any
    post-dispatch receipt-write failure as UNKNOWN, never as a retryable failure.
    """
    require(type(operation_id) is str and _IDENTIFIER.fullmatch(operation_id) is not None,
            "OPERATION_ID")
    require(type(argv) in (list, tuple) and len(argv) > 0 and
            all(type(arg) is str and "\x00" not in arg for arg in argv), "COMMAND_ARGV")
    require(type(env) is dict and all(type(key) is str and type(value) is str and
            key and "=" not in key and "\x00" not in key and "\x00" not in value
            for key, value in env.items()), "COMMAND_ENV")
    require(type(timeout_seconds) is int and 0 < timeout_seconds <= 3600,
            "COMMAND_TIMEOUT")
    require(hash_text(expected_program_sha256), "PROGRAM_HASH")
    actual_cwd = _absolute_directory(cwd)
    program = _absolute_file(argv[0])
    actual_program_sha256 = _file_sha256(program)
    require(actual_program_sha256 == expected_program_sha256, "PROGRAM_HASH_MISMATCH")
    if tracked_files is None:
        tracked_files = {}
    require(type(tracked_files) is dict and
            all(type(name) is str and hash_text(value)
                for name, value in tracked_files.items()), "TRACKED_FILES")
    root = _absolute_directory(tracked_root) if tracked_root is not None else actual_cwd
    before = _tracked_hashes(root, tracked_files)
    require(before == tracked_files, "TRACKED_BEFORE_CHANGED")
    output_requested = output_files is not None
    if output_requested:
        require(type(output_files) is dict and bool(output_files) and
                all(type(name) is str and (value is None or hash_text(value))
                    for name, value in output_files.items()), "OUTPUT_FILES")
        require(set(output_files).isdisjoint(tracked_files), "OUTPUT_TRACKED_OVERLAP")
        output_identities = set()
        for name, expected in sorted(output_files.items()):
            path, exists = _relative_output_file(root, name)
            identity = os.path.normcase(str(path))
            require(identity not in output_identities, "OUTPUT_PATH_ALIAS")
            output_identities.add(identity)
            observed = _file_sha256(path) if exists else None
            require(observed == expected, "OUTPUT_BEFORE_CHANGED")
    evidence = _evidence_directory(log_dir, root)
    log_path = evidence / f"{operation_id}.log"
    receipt_path = evidence / f"{operation_id}.receipt.json"
    require(not log_path.exists() and not receipt_path.exists(), "EVIDENCE_ID_USED")

    started = time.perf_counter()
    stdout = b""
    stderr = b""
    exit_code = None
    timed_out = False
    launch_error = None
    try:
        completed = subprocess.run(
            list(argv), cwd=str(actual_cwd), env=dict(env),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout_seconds, shell=False, check=False,
        )
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        launch_error = f"{type(exc).__name__}: {exc}"
        stderr = launch_error.encode("utf-8", errors="replace")

    duration_ms = int((time.perf_counter() - started) * 1000)
    after = _tracked_hashes(root, tracked_files, missing_as_none=True)
    try:
        program_after = _file_sha256(_absolute_file(program))
    except (Denied, OSError):
        program_after = None
    output_after = {}
    output_identities = {}
    output_error = None
    if output_requested:
        for name in sorted(output_files):
            try:
                output_after[name], output_identities[name] = _output_bytes(root, name)
            except (Denied, OSError) as exc:
                output_after[name] = None
                if output_error is None:
                    output_error = (str(exc) if isinstance(exc, Denied)
                                    else "OUTPUT_INVALID")
        for name in sorted(output_files):
            if (output_after[name] is not None and
                    output_after[name]["sha256"] == output_files[name] and
                    output_error is None):
                output_error = "OUTPUT_UNCHANGED"
    # Length framing preserves the exact bytes and channel identity of both
    # captured streams; their relative interleaving is not observable here.
    log = (b"M2_PROCESS_LOG_1\n" + len(stdout).to_bytes(8, "big") + stdout +
           len(stderr).to_bytes(8, "big") + stderr)
    _write_exclusive(log_path, log)
    if output_requested:
        # Re-read immediately before sealing the receipt. Later consumers
        # must also compare the current output bytes to the receipt.
        for name, observed in output_after.items():
            if observed is None:
                continue
            try:
                require(_output_bytes(root, name) ==
                        (observed, output_identities[name]), "OUTPUT_CHANGED")
            except (Denied, OSError):
                output_error = "OUTPUT_CHANGED"
    if launch_error is not None:
        status = "LAUNCH_FAILED"
    elif timed_out:
        status = "TIMED_OUT"
    elif program_after != expected_program_sha256:
        status = "PROGRAM_CHANGED"
    elif after != before:
        status = "SOURCE_CHANGED"
    elif exit_code != 0:
        status = "FAILED"
    elif output_error is not None:
        status = ("OUTPUT_MISSING" if output_error == "OUTPUT_MISSING" else
                  "OUTPUT_UNCHANGED" if output_error == "OUTPUT_UNCHANGED" else
                  "OUTPUT_INVALID")
    else:
        status = "PASSED"

    receipt = {
        "schema": "M2_CONSTRUCTION_PROCESS_RECEIPT_1",
        "operation_id": operation_id,
        "status": status,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "launch_error": launch_error,
        "actual_argv": list(argv),
        "actual_cwd": str(actual_cwd),
        "actual_env_sha256": digest(env),
        "timeout_seconds": timeout_seconds,
        "program_path": str(program),
        "program_sha256": actual_program_sha256,
        "program_sha256_after": program_after,
        "tracked_root": str(root),
        "tracked_files": dict(sorted(tracked_files.items())),
        "tracked_after": after,
        "stdout_sha256": bytes_hash(stdout),
        "stderr_sha256": bytes_hash(stderr),
        "log_path": str(log_path),
        "log_sha256": bytes_hash(log),
        "duration_ms": duration_ms,
        "execution_boundary": "CWD_ENV_TIMEOUT_ONLY_NO_OS_SANDBOX",
    }
    if output_requested:
        receipt["output_files"] = dict(sorted(output_files.items()))
        receipt["output_after"] = output_after
        receipt["output_error"] = output_error
    raw_receipt = canonical(receipt)
    _write_exclusive(receipt_path, raw_receipt)
    if output_requested and status == "PASSED":
        # A change during receipt persistence cannot return a passing proof.
        # The caller must mark this post-dispatch exception UNKNOWN; a later
        # consumer still has to verify current bytes before using the receipt.
        for name, observed in output_after.items():
            try:
                require(_output_bytes(root, name) ==
                        (observed, output_identities[name]),
                        "OUTPUT_CHANGED_AFTER_RECEIPT")
            except (Denied, OSError) as exc:
                raise Denied("OUTPUT_CHANGED_AFTER_RECEIPT") from exc
    return {**receipt, "receipt_path": str(receipt_path),
            "receipt_sha256": bytes_hash(raw_receipt)}
