#!/usr/bin/env python3
"""M2 portable entry: inspect environment, load project references, call existing gates.

This wrapper does not issue grants, invoke models, start an autonomous CEO,
or certify project acceptance. Current signed inputs remain mandatory.
"""
import sys
sys.dont_write_bytecode=True
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import runpy
import stat
import subprocess

ROOT=Path(__file__).resolve().parent
BASELINE=ROOT/'baseline'/'M2-Construction-Portable-20261004'
BASELINE_MANIFEST_SHA='e50cc71c4e43cbe9f36c08f789bdc3a31f5c88c994d88685bb00256898f74423'
VERSION='CK-PORTABLE-START-20261006-01'

class EntryError(ValueError):pass

def need(ok,reason):
    if not ok:raise EntryError(reason)

def digest(raw):return hashlib.sha256(raw).hexdigest()

def read_json(path):
    def pairs(items):
        obj={}
        for k,v in items:
            need(k not in obj,'DUPLICATE_JSON_KEY')
            obj[k]=v
        return obj
    return json.loads(path.read_text(encoding='utf-8-sig'),object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(EntryError('INVALID_JSON_CONSTANT')))

def plain(path):
    path=Path(os.path.abspath(path))
    for p in (path,*path.parents):
        if p.exists() or p.is_symlink():
            info=p.lstat()
            need(not stat.S_ISLNK(info.st_mode) and not(getattr(info,'st_file_attributes',0)&0x400),'LINK_OR_REPARSE_POINT')
    return path

def package_file(name):
    need(isinstance(name,str) and name and '\\' not in name and ':' not in name and
         not name.startswith('/') and all(s not in ('','.','..') for s in name.split('/')),'PACKAGE_MANIFEST_PATH')
    p=plain(ROOT.joinpath(*PurePosixPath(name).parts))
    need(p.is_file(),'PACKAGE_FILE_MISSING')
    return p

def verify_package():
    plain(ROOT)
    index=ROOT/'BASELINE_FILES.json'
    need(index.is_file() and digest(index.read_bytes())==BASELINE_MANIFEST_SHA,'BASELINE_INDEX_CHANGED')
    baseline=read_json(index)['files']
    actual={p.relative_to(ROOT/'baseline').as_posix() for p in (ROOT/'baseline').rglob('*') if p.is_file()}
    need(actual==set(baseline),'BASELINE_FILE_SET_CHANGED')
    for name,item in baseline.items():
        raw=package_file('baseline/'+name).read_bytes()
        need(digest(raw)==item['sha256'] and len(raw)==item['bytes'],'BASELINE_FILE_CHANGED')
    seal=ROOT/'WRAPPER_FILES.json'
    need(seal.is_file(),'PACKAGE_NOT_SEALED')
    entries=read_json(seal)['files']
    need('m2.py' in entries and 'portable/project_context.py' in entries,'WRAPPER_MANIFEST_INCOMPLETE')
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and
            'baseline'!=p.relative_to(ROOT).parts[0] and p!=seal}
    need(actual==set(entries),'WRAPPER_FILE_SET_CHANGED')
    for name,item in entries.items():
        raw=package_file(name).read_bytes()
        need(digest(raw)==item['sha256'] and len(raw)==item['bytes'],'WRAPPER_FILE_CHANGED')
    return len(baseline),len(entries)

def report(status,**values):
    return dict(status=status,package_version=VERSION,execution_authority=False,
                governance_status='NOT_STARTED',human_acceptance='NOT_CLAIMED',**values)

def doctor():
    need(sys.version_info>=(3,11),'PYTHON_3_11_OR_NEWER_REQUIRED')
    need(sys.flags.optimize==0,'ASSERTIONS_MUST_BE_ENABLED')
    base,extra=verify_package()
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise EntryError('DEPENDENCY_CRYPTOGRAPHY_MISSING') from None
    return report('STARTUP_READY',baseline_members_verified=base,wrapper_members_verified=extra,
        python_version=platform.python_version(),cryptography_version=cryptography.__version__,
        platform=platform.system(),platform_validation='WINDOWS_ONLY_RECORDED_MAC_LINUX_NOT_TESTED',
        integrity_scope='LOCAL_PACKAGE_CONSISTENCY_NOT_SIGNATURE_OR_OS_SANDBOX',
        next_steps=['project-init','context','readiness','workflow'],
        message='入口可用；尚未加载项目、签发授权、执行任务或完成独立审查。')

STAGES=[
 ('PROJECT_CONTEXT','核对需求、设计、代码、测试、决策、问题、记忆与证据；缺失或冲突先澄清'),
 ('TRUSTED_BOOTSTRAP','由宿主固定解释器、配置与公钥；区分作者、独审和 CEO 身份'),
 ('CURRENT_SCOPE','建立本任务签名范围和累计预算；保留旧失败和未决操作 ID'),
 ('GATED_WORK','每次 create/patch/command 经过当前授权及意图/回执检查'),
 ('REAL_TEST_BUILD','真实命令验证实际候选；核对 Maven 等工具真正读取的项目位置'),
 ('FROZEN_CANDIDATE','绑定真实 TEST/BUILD 回执与最终字节，记录外部作者证明'),
 ('INDEPENDENT_AUDIT','非作者核对要求、源码、调用方与覆盖；提供绑定候选的签名证明'),
 ('LOCAL_RETURN','局部只读裁决与独立签名回交指令，INTERNAL_PARENT_ONLY 单次消费'),
 ('PARENT_INTEGRATION','父集成后 TEST、冻结、独立 AUDIT；子任务通过不替代父验证'),
 ('CEO_ACCEPTANCE','核验独立签名的 CEO 接受材料并登记接受'),
 ('PRE_RELEASE','全链只读裁决；PASS 本身不授予发布权限'),
 ('RELEASE_POST','独立签名发布租约、单次发布、POST 只读复核及复验后登记'),
 ('HUMAN_ACCEPTANCE','向用户交付证据与未覆盖项；仅用户明确接受才登记人工 PASS')]

def workflow():
    return report('GUIDANCE_ONLY',stages=[dict(id=k,description=v) for k,v in STAGES],
        orchestrator='EXTERNAL_HOST_REQUIRED',
        note='全链由宿主组织；本入口不会自动调用模型、签发证明或把 TEST 提升为整体 PASS。',
        guide='docs/WORKFLOW.md')

def core_imports():
    # Package consistency is verified before this function is reached.
    sys.path.insert(0,str(BASELINE/'core/src'))

def readiness(config,expected):
    core_imports()
    from m2_construction.cli import _bootstrap
    cfg=_bootstrap(plain(config),expected)
    schema=cfg['schema']
    status={'M2_CONSTRUCTION_CLI_CONFIG_1':'EXECUTION_ONLY_CONFIGURATION',
            'M2_CONSTRUCTION_CLI_CONFIG_2':'INTERNAL_RETURN_CONFIGURATION',
            'M2_CONSTRUCTION_CLI_CONFIG_3':'FULL_CHAIN_CONFIGURATION_PRESENT'}[schema]
    missing=(['INDEPENDENT_AUDIT','CEO_ACCEPTANCE','RELEASE'] if schema.endswith('_1') else
             ['CEO_ACCEPTANCE','RELEASE'] if schema.endswith('_2') else [])
    return report(status,configuration_schema=schema,missing_capabilities=missing,
        identity_status='PIN_BYTES_VALIDATED_NOT_LIVE_ACTOR_IDENTITY',
        approval_status='CURRENT_SCOPE_AND_REVIEW_PROOFS_NOT_EVALUATED',
        state_effect='NONE',note='配置等级检查，不证明独审发生、授权有效或任务已经完成。')

def external_new(path):
    p=plain(path)
    need(p!=ROOT and ROOT not in p.parents and p not in ROOT.parents,'OUTPUT_MUST_BE_OUTSIDE_PACKAGE')
    need(not p.exists(),'NEW_OUTPUT_REQUIRED')
    return p

def emit(value,output=None):
    raw=json.dumps(value,ensure_ascii=False,indent=2)+'\n'
    if output is not None:
        p=external_new(output)
        need(p.parent.is_dir(),'OUTPUT_PARENT_MISSING')
        with p.open('x',encoding='utf-8') as f:f.write(raw)
    print(raw,end='')

class Parser(argparse.ArgumentParser):
    def error(self,message):raise EntryError('ARGUMENTS_INVALID_USE_HELP')

def parser():
    p=Parser(description=__doc__)
    s=p.add_subparsers(dest='command',parser_class=Parser)
    s.add_parser('doctor',help='检查环境及包字节，不启动任务')
    a=s.add_parser('start',help='统一启动检查；可加载指定项目上下文');a.add_argument('--project',type=Path)
    s.add_parser('workflow',help='查看完整治理链及宿主职责')
    a=s.add_parser('project-init',help='建立明确文件来源的项目知识配置')
    a.add_argument('--root',required=True,type=Path);a.add_argument('--config',required=True,type=Path)
    a.add_argument('--goal',required=True);a.add_argument('--project-id',default='project')
    a.add_argument('--source',action='append',default=[],help='requirements=docs/requirements.md，可重复')
    a=s.add_parser('context',help='逐项核对并输出项目参考；不授予权限')
    a.add_argument('--config',required=True,type=Path);a.add_argument('--output',type=Path)
    a=s.add_parser('readiness',help='只读识别真实配置等级；不创建状态账本')
    a.add_argument('--config',required=True,type=Path);a.add_argument('--config-sha256',required=True)
    a=s.add_parser('sample',help='原失败经验 TEST_ONLY 样例；不是项目验收')
    a.add_argument('--output',required=True,type=Path)
    s.add_parser('kernel',help='转接完整原生治理 CLI（用 kernel --help 查看）')
    s.add_parser('tool',help='转接原生工具桥（用 tool --help 查看）')
    return p

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if not args:
        parser().print_help();return 0
    try:
        if args[0] in ('kernel','tool'):
            doctor()
            forwarded=args[1:]
            if forwarded[:1]==['--']:forwarded=forwarded[1:]
            if args[0]=='kernel':
                core_imports()
                from m2_construction.cli import main as kernel_main
                return kernel_main(forwarded)
            sys.argv=[str(BASELINE/'tools/native_b_runtime.py'),*forwarded]
            runpy.run_path(sys.argv[0],run_name='__main__')
            return 0
        parsed=parser().parse_args(args)
        if parsed.command=='workflow':
            emit(workflow());return 0
        check=doctor()
        if parsed.command=='doctor':emit(check);return 0
        if parsed.command=='readiness':
            result=readiness(parsed.config,parsed.config_sha256)
            emit(result);return 0 if result['status']=='FULL_CHAIN_CONFIGURATION_PRESENT' else 3
        if parsed.command=='sample':
            out=external_new(parsed.output)
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
            r=subprocess.run([sys.executable,'-I','-B',str(BASELINE/'tools/run_failure_sample.py'),
                '--output',str(out)],capture_output=True,text=True,encoding='utf-8',errors='replace',env=env)
            if r.returncode!=0:
                emit(report('DEMO_FAILED',exit_code=r.returncode,
                    reason='ORIGINAL_SAMPLE_FAILED',evidence_directory=str(out),
                    diagnostic=r.stderr[-4000:],independent_acceptance='NOT_CLAIMED'));return 2
            sample=json.loads(r.stdout)
            emit(report('DEMO_COMPLETED',sample=sample,independent_acceptance='NOT_CLAIMED',
                        message='样例包含预期失败；不代表真实项目、独审或发布验收。'));return 0
        sys.path.insert(0,str(ROOT))
        from portable.project_context import init_project,load_context
        if parsed.command=='project-init':
            result=init_project(parsed.root,parsed.config,parsed.goal,parsed.source,project_id=parsed.project_id)
            emit(result);return 0
        if parsed.command=='context':
            result=load_context(parsed.config);emit(result,parsed.output)
            return 0 if result['status']=='CONTEXT_READY_FOR_REVIEW' else 3
        if parsed.command=='start':
            if parsed.project is None:
                emit(report('NEEDS_PROJECT_CONFIGURATION',environment=check,
                    next_step='project-init --root <project> --config <new-config.json> --goal <goal>',
                    help='START_HERE.md',note='入口已启动检查；此程序不是网页服务或自动 Agent 主控。'));return 0
            context=load_context(parsed.project)
            emit(report('PROJECT_CONTEXT_READY' if context['status']=='CONTEXT_READY_FOR_REVIEW' else
                        'PROJECT_CONTEXT_INCOMPLETE',environment=check,project_context=context,
                        next_step='核对项目知识，然后 readiness / workflow；执行需要当前签名授权。'))
            return 0 if context['status']=='CONTEXT_READY_FOR_REVIEW' else 3
    except (ValueError,OSError,KeyError,TypeError,ImportError) as exc:
        # Never echo arbitrary input contents, secret paths or tracebacks.
        from re import fullmatch
        reason=getattr(exc,'reason',str(exc))
        if not isinstance(reason,str) or not fullmatch(r'[A-Z][A-Z0-9_]{0,99}',reason):reason='PORTABLE_INPUT_OR_IO_ERROR'
        emit(report('BLOCKED',reason=reason,help='docs/TROUBLESHOOTING.md'));return 2
    return 2

if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr,'reconfigure'):sys.stderr.reconfigure(encoding='utf-8')
    raise SystemExit(main())
