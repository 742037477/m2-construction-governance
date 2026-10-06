"""Real-file contract checks for the independent project-context wrapper.

Config schema: portable-project-context-v1; project_root is relative to the
configuration directory. Source fields: id, kind, path, sha256, revision,
status, applicability {conditions, limitations}, claim_type, critical,
conflicts, supersedes. All eight roles need an included source or explicit
not_applicable [{kind, reason}]. load_context returns sources with included,
hash_status, verification, exclusion_reasons and content only when included.
"""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PACKAGE = Path(__file__).resolve().parents[1]
WORK = PACKAGE.parent / "work" / "context-tests"
sys.path.insert(0, str(PACKAGE))

from portable.project_context import (  # noqa: E402
    MAX_SOURCE_BYTES, MAX_TOTAL_BYTES, ProjectError, init_project, load_context,
)

ROLES = ("requirements", "design", "code", "tests", "decisions", "known_issues", "memory", "evidence")


class ProjectContextTests(unittest.TestCase):
    def setUp(self):
        WORK.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="case-", dir=WORK)
        self.base = Path(self.temp.name).resolve()
        self.assertTrue(self.base.is_relative_to(WORK.resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = self.base / "project"
        self.root.mkdir()
        self.config = self.base / "project.json"

    def write_config(self, config):
        self.config.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

    def initialize(self, roles=ROLES):
        specs = []
        for role in roles:
            (self.root / (role + ".txt")).write_text("明确来源：" + role, encoding="utf-8")
            specs.append(role + "=" + role + ".txt")
        return init_project(self.root, self.config, "核对项目入场资料", specs)

    def test_complete_real_files_survive_process_restart_and_relative_move(self):
        result = self.initialize()
        self.assertFalse(result["execution_authority"])
        saved = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(saved["project_root"], "project")
        self.assertEqual(len(saved["sources"]), 8)
        script = "from pathlib import Path; import json,sys; from portable.project_context import load_context; print(json.dumps(load_context(Path(sys.argv[1]))))"
        proc = subprocess.run([sys.executable, "-B", "-c", script, str(self.config)], cwd=PACKAGE,
                              capture_output=True, text=True, check=True)
        loaded = json.loads(proc.stdout)
        self.assertEqual(loaded["status"], "CONTEXT_READY_FOR_REVIEW")
        self.assertEqual(loaded["human_acceptance"], "NOT_CLAIMED")
        self.assertEqual(loaded["missing_roles"], [])
        for source in loaded["sources"]:
            self.assertTrue(source["included"])
            self.assertEqual(source["hash_status"], "MATCH")
            self.assertEqual(source["verification"], "UNTRUSTED_PROJECT_REFERENCE")
            self.assertEqual(source["content"], "明确来源：" + source["kind"])
        moved = self.base / "moved"
        moved.mkdir()
        self.root.rename(moved / "project")
        self.config.rename(moved / "project.json")
        self.assertEqual(load_context(moved / "project.json")["status"], "CONTEXT_READY_FOR_REVIEW")

    def test_empty_template_requires_all_roles_then_explicit_nonapplicability(self):
        init_project(self.root, self.config, "新项目", [])
        self.assertEqual(load_context(self.config)["missing_roles"], list(ROLES))
        config = json.loads(self.config.read_text(encoding="utf-8"))
        config["not_applicable"] = [{"kind": role, "reason": "人工限定：本项目此阶段不适用"} for role in ROLES]
        self.write_config(config)
        self.assertEqual(load_context(self.config)["status"], "CONTEXT_READY_FOR_REVIEW")

    def test_drive_rooted_project_path_is_rejected_before_reading(self):
        self.initialize()
        config = json.loads(self.config.read_text(encoding="utf-8"))
        config["project_root"] = str(self.root)[2:] if os.name == "nt" else "\\project"
        self.write_config(config)
        with self.assertRaises(ProjectError) as raised:
            load_context(self.config)
        self.assertEqual(raised.exception.reason, "PROJECT_ROOT_MUST_BE_RELATIVE")

    def test_modified_and_missing_sources_are_excluded_without_rehash(self):
        self.initialize()
        original = self.config.read_bytes()
        (self.root / "requirements.txt").write_text("不同需求", encoding="utf-8")
        (self.root / "evidence.txt").unlink()
        result = load_context(self.config)
        self.assertEqual(result["status"], "PROJECT_CONTEXT_INCOMPLETE")
        self.assertEqual(result["missing_roles"], ["requirements", "evidence"])
        by_kind = {s["kind"]: s for s in result["sources"]}
        self.assertIn("HASH_MISMATCH", by_kind["requirements"]["exclusion_reasons"])
        self.assertIn("SOURCE_MISSING", by_kind["evidence"]["exclusion_reasons"])
        self.assertNotIn("content", by_kind["requirements"])
        self.assertNotIn("content", by_kind["evidence"])
        self.assertEqual(original, self.config.read_bytes())

    def test_explicit_conflicts_expiry_and_supersession_preserve_metadata(self):
        self.initialize()
        config = json.loads(self.config.read_text(encoding="utf-8"))
        sources = config["sources"]
        sources[0]["conflicts"] = [sources[1]["id"]]
        sources[2]["status"] = "expired"
        sources[3]["supersedes"] = [sources[4]["id"]]
        sources[5]["status"] = "superseded"
        sources[6]["claim_type"] = "assumption"
        sources[6]["revision"] = "old-reviewed-reference"
        sources[6]["applicability"] = {"conditions": ["仅适用旧接口仍兼容时"], "limitations": ["原因尚未证实"]}
        self.write_config(config)
        result = load_context(self.config)
        by_kind = {s["kind"]: s for s in result["sources"]}
        for role in ("requirements", "design", "code", "decisions", "known_issues"):
            self.assertFalse(by_kind[role]["included"])
            self.assertNotIn("content", by_kind[role])
        memory = by_kind["memory"]
        self.assertTrue(memory["included"])
        self.assertEqual(memory["claim_type"], "assumption")
        self.assertEqual(memory["revision"], "old-reviewed-reference")
        self.assertEqual(memory["applicability"], sources[6]["applicability"])
        self.assertEqual(memory["verification"], "UNTRUSTED_PROJECT_REFERENCE")

    def test_sensitive_traversal_and_private_key_sources_never_return_content(self):
        init_project(self.root, self.config, "安全检查", [])
        saved = json.loads(self.config.read_text(encoding="utf-8"))
        paths = ["../outside.txt", ".env", ".git/config", "credentials.json", "keys/id_rsa", "private.pem"]
        for relative in paths:
            with self.subTest(path=relative):
                candidate = self.root / relative
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("SECRET_MARKER", encoding="utf-8")
                saved["sources"] = [{"id": "blocked", "kind": "evidence", "path": relative,
                    "sha256": "0" * 64, "revision": "test", "status": "current",
                    "applicability": {"conditions": [], "limitations": []}}]
                self.write_config(saved)
                result = load_context(self.config)
                self.assertFalse(result["sources"][0]["included"])
                self.assertNotIn("SECRET_MARKER", json.dumps(result))
        pem = self.root / "notes.txt"
        pem.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_MARKER", encoding="utf-8")
        with self.assertRaises(ProjectError):
            init_project(self.root, self.base / "private-key.json", "测试", ["evidence=notes.txt"])

    def test_source_and_aggregate_limits_do_not_truncate(self):
        (self.root / "too-large.txt").write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
        with self.assertRaises(ProjectError):
            init_project(self.root, self.config, "检查长度", ["code=too-large.txt"])
        specs = []
        for index in range(MAX_TOTAL_BYTES // MAX_SOURCE_BYTES + 1):
            name = "large-" + str(index) + ".txt"
            (self.root / name).write_bytes(b"x" * MAX_SOURCE_BYTES)
            specs.append("code=" + name)
        with self.assertRaises(ProjectError):
            init_project(self.root, self.config, "检查总量", specs)
        self.assertFalse(self.config.exists())

    def test_new_config_only_and_package_write_prohibited(self):
        self.initialize()
        original = self.config.read_bytes()
        with self.assertRaises(ProjectError):
            init_project(self.root, self.config, "覆盖", [])
        self.assertEqual(original, self.config.read_bytes())
        with self.assertRaises(ProjectError):
            init_project(self.root, PACKAGE / "blocked-project.json", "包内配置拒绝", [])
        self.assertFalse((PACKAGE / "blocked-project.json").exists())

    def test_load_total_limit_and_binary_sources_fail_closed(self):
        self.initialize()
        config = json.loads(self.config.read_text(encoding="utf-8"))
        for source in config["sources"]:
            data = b"x" * (MAX_TOTAL_BYTES // 7)
            (self.root / source["path"]).write_bytes(data)
            source["sha256"] = hashlib.sha256(data).hexdigest()
        self.write_config(config)
        result = load_context(self.config)
        self.assertEqual(result["status"], "PROJECT_CONTEXT_INCOMPLETE")
        self.assertLessEqual(sum(len(s.get("content", "").encode("utf-8")) for s in result["sources"]), MAX_TOTAL_BYTES)
        self.assertIn("TOTAL_SOURCE_LIMIT_EXCEEDED", result["sources"][-1]["exclusion_reasons"])
        binary = b"\xff\xfe\x00"
        (self.root / "requirements.txt").write_bytes(binary)
        config["sources"][0]["sha256"] = hashlib.sha256(binary).hexdigest()
        self.write_config(config)
        invalid = load_context(self.config)["sources"][0]
        self.assertFalse(invalid["included"])
        self.assertIn("SOURCE_NOT_UTF8", invalid["exclusion_reasons"])
        self.assertNotIn("content", invalid)

    def test_ambiguous_json_and_invalid_metadata_have_stable_errors(self):
        self.initialize()
        config = json.loads(self.config.read_text(encoding="utf-8"))
        config["sources"][0]["status"] = []
        self.write_config(config)
        with self.assertRaises(ProjectError):
            load_context(self.config)
        self.config.write_text('{"schema_version":"portable-project-context-v1","schema_version":"other"}', encoding="utf-8")
        with self.assertRaises(ProjectError) as raised:
            load_context(self.config)
        self.assertEqual(raised.exception.reason, "CONFIG_DUPLICATE_KEY")

    def test_hardlinks_are_rejected(self):
        source = self.root / "original.txt"
        source.write_text("should not enter context through link", encoding="utf-8")
        linked = self.root / "linked.txt"
        os.link(source, linked)
        with self.assertRaises(ProjectError):
            init_project(self.root, self.config, "链接拒绝", ["evidence=linked.txt"])

    def test_symlinks_are_rejected_if_supported(self):
        source = self.root / "original.txt"
        source.write_text("should not enter context through link", encoding="utf-8")
        linked = self.root / "linked.txt"
        try:
            linked.symlink_to(source)
        except OSError as error:
            self.skipTest("OS denied creation of test symlink: " + str(error))
        with self.assertRaises(ProjectError):
            init_project(self.root, self.config, "链接拒绝", ["evidence=linked.txt"])


if __name__ == "__main__":
    unittest.main()
