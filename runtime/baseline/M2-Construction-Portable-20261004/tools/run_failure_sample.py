"""Portable derivative entry for the existing TEST_ONLY GM flow; no pytest dependency."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

TEST_SHA = '44b3a440e4c3cc375e79e48ac6e91e6f5dc47098f7cc9d66cc5bc135774d85f3'
CAPTURE_SHA = '2f28a427c699da5fff2353f09be635b71970a313cd48b0fd60b377ef19262ad7'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def plain(path):
    require(path.is_absolute() and path.resolve() == path, 'CANONICAL_ABSOLUTE_PATH_REQUIRED')
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            require(not item.is_symlink() and not (getattr(item.lstat(), 'st_file_attributes', 0) & 0x400),
                    'LINK_OR_REPARSE_POINT')
    return path


def pinned(path, expected):
    raw = plain(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected, 'PINNED_INPUT_CHANGED')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(sys.flags.optimize == 0, 'ORIGINAL_ASSERTIONS_MUST_BE_ENABLED')
    root = plain(Path(__file__).absolute()).parents[1]
    test = root / 'tests/test_failure_experience.py'
    capture = root / 'CORE_CAPTURE.json'
    pinned(test, TEST_SHA)
    members = json.loads(pinned(capture, CAPTURE_SHA))['members']
    core = plain(root / 'core')
    require(len(members) == 33 and {x['path'] for x in members} ==
            {p.relative_to(core).as_posix() for p in core.rglob('*') if p.is_file()}, 'EXACT_CORE_33')
    for member in members:
        require(len(pinned(core / member['path'], member['sha256'])) == member['bytes'], 'CORE_BYTES')
    output = plain(args.output)
    require(not output.exists() and output != root and root not in output.parents and output not in root.parents,
            'FRESH_EXTERNAL_OUTPUT_REQUIRED')
    # The original test's environment overrides must not redirect output or replace its fixed pins.
    for name in ('FAILURE_REUSE_TEST_EVIDENCE_ROOT', 'FAILURE_REUSE_ADAPTER_SHA256',
                 'FAILURE_REUSE_BRIDGE_SHA256', 'PYTHONOPTIMIZE'):
        os.environ.pop(name, None)
    os.environ.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('ck_delivery_fixed_failure_sample', test)
    require(spec is not None and spec.loader is not None, 'ORIGINAL_TEST_IMPORT_SPEC')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # Pins describe this portable derivative; original core runtime, assertions and flow are retained.
    module.TRUSTED_CAPTURE = capture
    require(module.ROOT == root and module.CORE == core, 'ORIGINAL_PACKAGE_LAYOUT')
    output.mkdir(parents=True, exist_ok=False)
    module.test_flow01_real_failure_cross_process_new_binding(output)
    report = output / 'flow01/flow-result.json'
    print(json.dumps({'portable_flow_result': str(report),
                      'sha256': hashlib.sha256(report.read_bytes()).hexdigest(),
                      'test_source_sha256': TEST_SHA, 'capture_sha256': CAPTURE_SHA,
                      'independent_acceptance': 'NOT_CLAIMED', 'human_acceptance': 'NOT_CLAIMED'}))


if __name__ == '__main__':
    main()
