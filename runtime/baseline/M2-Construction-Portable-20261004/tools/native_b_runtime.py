"""Thin shell-to-native-CLI bridge. No signing, grant or publication commands.

The supervisor fixes --binding and its independently recorded SHA-256. Inline
payloads become native request envelopes outside the product workspace. Product
effects are performed only by the pinned m2_construction.cli process.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


BINDING_FIELDS=set('schema run_id task_id task_revision grant_id cli_config_path cli_config_sha256 kernel_capture_path kernel_capture_sha256 kernel_root python_path python_sha256 control_plane_root phase max_request_bytes cli_timeout_seconds'.split())
PHASES={'PLAN_READ_ONLY','CHECKPOINT_ONLY','WORK','RESTORE_READ_ONLY'}
DISPATCH_ATTEMPTED=False


class Refused(ValueError):pass


def require(ok,reason):
    if not ok:raise Refused(reason)


def canonical(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def digest(raw):return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'BRIDGE_DUPLICATE_JSON_KEY');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Refused('BRIDGE_NONFINITE_JSON')))


def fixed_hash(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None


def identifier(value):
    require(isinstance(value,str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,119}',value) is not None,'BRIDGE_IDENTIFIER')
    return value


def canonical_path(value):
    require(isinstance(value,str),'BRIDGE_PATH')
    path=Path(value)
    require(path.is_absolute() and path.resolve()==path,'BRIDGE_PATH_NOT_CANONICAL')
    for ancestor in [path,*path.parents]:
        if ancestor.exists() or ancestor.is_symlink():
            require(not ancestor.is_symlink() and not (getattr(ancestor.lstat(),'st_file_attributes',0)&0x400),'BRIDGE_PATH_LINK')
    return path


def read_fixed(path,expected,reason):
    require(fixed_hash(expected),'BRIDGE_EXPECTED_HASH_REQUIRED')
    raw=path.read_bytes();require(digest(raw)==expected,reason);return raw


def verify_capture(binding):
    capture=canonical_path(binding['kernel_capture_path']);root=canonical_path(binding['kernel_root'])
    value=strict(read_fixed(capture,binding['kernel_capture_sha256'],'BRIDGE_CAPTURE_CHANGED'))
    members=value.get('members');require(isinstance(members,list) and len(members)==33,'BRIDGE_CAPTURE_MEMBERS')
    names=set()
    for entry in members:
        relative=entry['path'];p=Path(relative)
        require(isinstance(relative,str) and relative and not p.is_absolute() and '\\' not in relative and ':' not in relative and '..' not in p.parts,'BRIDGE_CAPTURE_PATH')
        require(relative not in names,'BRIDGE_DUPLICATE_CAPTURE_MEMBER');names.add(relative)
        target=canonical_path(str(root/p));raw=read_fixed(target,entry['sha256'],'BRIDGE_KERNEL_CHANGED')
        require(len(raw)==entry['bytes'],'BRIDGE_KERNEL_SIZE')
    require('src/m2_construction/cli.py' in names and 'src/m2_construction/controller.py' in names,'BRIDGE_CLI_MISSING')
    actual=set()
    for target in root.rglob('*'):
        canonical_path(str(target))
        if target.is_file():actual.add(target.relative_to(root).as_posix())
    # Extra Python modules or cached bytecode must not change the pinned import.
    require(actual==names,'BRIDGE_KERNEL_INVENTORY_CHANGED')
    return root


def load_binding(path,expected):
    path=canonical_path(str(path));binding=strict(read_fixed(path,expected,'BRIDGE_BINDING_CHANGED'))
    require(type(binding) is dict and set(binding)==BINDING_FIELDS and binding['schema']=='CK_NATIVE_B_BRIDGE_BINDING_1','BRIDGE_BINDING_FIELDS')
    for key in ('run_id','task_id','grant_id'):identifier(binding[key])
    require(type(binding['task_revision']) is int and binding['task_revision']>0,'BRIDGE_TASK_REVISION')
    require(binding['phase'] in PHASES and type(binding['max_request_bytes']) is int and 1<=binding['max_request_bytes']<=1048576 and
            type(binding['cli_timeout_seconds']) is int and 1<=binding['cli_timeout_seconds']<=600,'BRIDGE_LIMITS')
    configpath=canonical_path(binding['cli_config_path'])
    config=strict(read_fixed(configpath,binding['cli_config_sha256'],'BRIDGE_CONFIG_CHANGED'))
    workspace=canonical_path(config['workspace_root']);state=canonical_path(config['state_root'])
    require(workspace.is_dir() and state.is_dir() and state!=workspace and not state.is_relative_to(workspace),'BRIDGE_EXTERNAL_STATE_REQUIRED')
    require(not path.is_relative_to(workspace) and not configpath.is_relative_to(workspace),'BRIDGE_CONFIG_IN_PRODUCT')
    control=canonical_path(binding['control_plane_root'])
    require(control==state/'control-plane'/binding['run_id'],'BRIDGE_CONTROL_PLANE_LOCATION')
    kernel=verify_capture(binding)
    python=canonical_path(binding['python_path']);read_fixed(python,binding['python_sha256'],'BRIDGE_PYTHON_CHANGED')
    return binding,config,control,kernel,python


class Parser(argparse.ArgumentParser):
    def error(self,message):raise Refused('BRIDGE_ARGUMENTS')


def _experience_options(p,required=False):
    p.add_argument('--experience-descriptor',required=required,type=Path)
    p.add_argument('--experience-descriptor-sha256',required=required)
    p.add_argument('--experience-adapter-sha256',required=required)


def _experience_requested(args):
    fields=('experience_descriptor','experience_descriptor_sha256','experience_adapter_sha256')
    present=[getattr(args,field,None) is not None for field in fields]
    require(not any(present) or all(present),'BRIDGE_EXPERIENCE_OPTIONS_REQUIRED_TOGETHER')
    if not any(present):return False
    require(fixed_hash(args.experience_descriptor_sha256) and fixed_hash(args.experience_adapter_sha256),
            'BRIDGE_EXPERIENCE_EXPECTED_HASH_REQUIRED')
    return True


def parser():
    p=Parser(description=__doc__)
    p.add_argument('--binding',required=True,type=Path);p.add_argument('--binding-sha256',required=True)
    subs=p.add_subparsers(dest='verb',required=True,parser_class=Parser)
    for verb in ('create','patch','command','freeze','status'):
        s=subs.add_parser(verb);s.add_argument('--operation-id',required=verb!='status')
        _experience_options(s)
        if verb in ('create','patch'):
            s.add_argument('--path',required=True)
            content=s.add_mutually_exclusive_group(required=True)
            content.add_argument('--content-text');content.add_argument('--content-b64');content.add_argument('--content-stdin',action='store_true')
            if verb=='patch':s.add_argument('--before-sha256',required=True)
        if verb=='command':s.add_argument('--command-id',required=True)
        if verb=='freeze':
            for option in ('source-file','test-file','build-file','test-operation-id','build-operation-id'):
                s.add_argument('--'+option,action='append',default=[])
    _experience_options(subs.add_parser('prepare-context'),required=True)
    return p


def request_for(args,binding):
    if args.operation_id:identifier(args.operation_id)
    if args.verb=='status':
        return {'schema':'M2_CONSTRUCTION_STATUS_REQUEST_1',**({'operation_id':args.operation_id} if args.operation_id else {})}
    require(binding['phase'] not in ('PLAN_READ_ONLY','RESTORE_READ_ONLY'),'BRIDGE_PHASE_READ_ONLY')
    if binding['phase']=='CHECKPOINT_ONLY':
        require(args.verb in ('create','patch') and args.path=='CHECKPOINT.md','BRIDGE_CHECKPOINT_ONLY')
    value={'schema':'M2_CONSTRUCTION_'+args.verb.upper()+'_REQUEST_'+('2' if args.verb in ('create','patch') else '1'),
           'grant_id':binding['grant_id'],'task_id':binding['task_id'],'task_revision':binding['task_revision'],'operation_id':args.operation_id}
    if args.verb in ('create','patch'):
        if args.content_text is not None:raw=args.content_text.encode('utf-8')
        elif args.content_b64 is not None:raw=base64.b64decode(args.content_b64,validate=True)
        else:raw=sys.stdin.buffer.read(binding['max_request_bytes']+1)
        require(len(raw)<=binding['max_request_bytes'],'BRIDGE_PAYLOAD_TOO_LARGE')
        value.update(path=args.path,content_b64=base64.b64encode(raw).decode('ascii'))
        if args.verb=='patch':
            require(fixed_hash(args.before_sha256),'BRIDGE_BEFORE_HASH');value['before_sha256']=args.before_sha256
    elif args.verb=='command':value['command_id']=identifier(args.command_id)
    else:
        for field,attribute in [('source_files','source_file'),('test_files','test_file'),('build_files','build_file'),('test_operation_ids','test_operation_id'),('build_operation_ids','build_operation_id')]:
            value[field]=getattr(args,attribute)
    require(len(canonical(value)+b'\n')<=binding['max_request_bytes'],'BRIDGE_REQUEST_TOO_LARGE')
    return value


def append_file(path,raw):
    with path.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def save(path,value):append_file(path,canonical(value)+b'\n')


def _call_experience_adapter(args,kernel,method,**kwargs):
    require(_experience_requested(args),'BRIDGE_EXPERIENCE_OPTIONS_REQUIRED')
    adapter=canonical_path(str(Path(__file__).resolve().parents[1]/'src'/'m2_construction'/'failure_experience.py'))
    raw=read_fixed(adapter,args.experience_adapter_sha256,'BRIDGE_EXPERIENCE_ADAPTER_CHANGED')
    name='m2_construction._failure_experience_'+uuid.uuid4().hex
    spec=importlib.util.spec_from_file_location(name,str(adapter))
    require(spec is not None and spec.loader is not None,'BRIDGE_EXPERIENCE_ADAPTER_LOADER')
    module=importlib.util.module_from_spec(spec)
    previous_path=sys.path[:];previous_bytecode=sys.dont_write_bytecode
    try:
        sys.path.insert(0,str(kernel/'src'));sys.dont_write_bytecode=True
        sys.modules[name]=module
        # Execute the exact checked bytes, rather than rereading through the loader.
        exec(compile(raw,str(adapter),'exec'),module.__dict__)
        function=getattr(module,method)
        require(callable(function),'BRIDGE_EXPERIENCE_ADAPTER_INTERFACE')
        result=function(descriptor_path=args.experience_descriptor,
                        descriptor_sha256=args.experience_descriptor_sha256,**kwargs)
        require(type(result) is dict,'BRIDGE_EXPERIENCE_ADAPTER_RESULT')
        canonical(result)
        return result
    finally:
        sys.path[:]=previous_path;sys.dont_write_bytecode=previous_bytecode
        sys.modules.pop(name,None)


def _archive_experience(args,kernel,receipt,binding,config):
    fields=('experience_descriptor','experience_descriptor_sha256','experience_adapter_sha256')
    if not any(getattr(args,field,None) is not None for field in fields):return
    path=receipt.parent/'failure-experience.json'
    try:
        result=_call_experience_adapter(args,kernel,'archive_receipt',receipt_path=receipt,
                                       bridge_binding=strict(canonical(binding)),config=strict(canonical(config)))
        save(path,result)
    except BaseException as exc:
        try:
            save(path,{'schema':'CK_NATIVE_B_FAILURE_EXPERIENCE_1','status':'ARCHIVE_FAILED',
                       'error_type':type(exc).__name__,'dispatch_allowed':False})
        except BaseException:
            pass


def run_prepare_context(args):
    try:
        binding,config,control,kernel,python=load_binding(args.binding,args.binding_sha256)
        output=dict(_call_experience_adapter(args,kernel,'prepare_context',
                                            bridge_binding=strict(canonical(binding)),config=strict(canonical(config))))
        output['dispatch_allowed']=False
        return output,0 if output.get('status')=='PREPARED' else 3
    except BaseException as exc:
        return {'schema':'CK_NATIVE_B_PREPARE_CONTEXT_RESULT_1','status':'PREPARE_CONTEXT_FAILED',
                'error_type':type(exc).__name__,'dispatch_allowed':False},3


def launch(args):
    global DISPATCH_ATTEMPTED
    binding,config,control,kernel,python=load_binding(args.binding,args.binding_sha256)
    request=request_for(args,binding)
    invocation=uuid.uuid4().hex
    control.mkdir(parents=True,exist_ok=True)
    parent=control/('queries' if args.verb=='status' else 'operations');parent.mkdir(exist_ok=True)
    folder=parent/(invocation if args.verb=='status' else args.operation_id)
    try:folder.mkdir()
    except FileExistsError:raise Refused('BRIDGE_OPERATION_ALREADY_RESERVED_USE_STATUS') from None
    canonical_path(str(folder))
    requestpath=folder/'request.json';save(requestpath,request)
    command=[str(python),'-B','-m','m2_construction.cli','--config',binding['cli_config_path'],'--config-sha256',binding['cli_config_sha256'],args.verb,'--request',str(requestpath)]
    env={key:value for key,value in os.environ.items() if key.upper() in ('SYSTEMROOT','WINDIR','SYSTEMDRIVE','TEMP','TMP','PATH')}
    env.update(PYTHONPATH=str(kernel/'src'),PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    record={'schema':'CK_NATIVE_B_BRIDGE_RECEIPT_1','bridge_invocation_id':invocation,'run_id':binding['run_id'],
            'task_id':binding['task_id'],'task_revision':binding['task_revision'],'grant_id':binding['grant_id'],
            'operation_id':args.operation_id,'verb':args.verb,'phase':binding['phase'],'bridge_pid':os.getpid(),'bridge_parent_pid':os.getppid(),
            'bridge_sha256':digest(Path(__file__).read_bytes()),'binding_path':str(args.binding),'binding_sha256':args.binding_sha256,
            'cli_config_sha256':binding['cli_config_sha256'],'kernel_capture_sha256':binding['kernel_capture_sha256'],
            'request_path':str(requestpath),'request_sha256':digest(requestpath.read_bytes()),'native_argv':command,
            'native_cwd':str(kernel),'native_environment_sha256':digest(canonical(env)),
            'identity_verification':'EXTERNAL_NATIVE_TOOL_TRANSCRIPT_REQUIRED','actor_claim_accepted_as_identity':False,
            'control_plane_request_is_product_effect':False,'OS_bypass_isolated':False,
            'started_utc':datetime.now(timezone.utc).isoformat(),'automatic_retry':False}
    save(folder/'prepared.json',record)
    began=time.perf_counter_ns();stdout=b'';stderr=b'';code=None;native_pid=None;transport='CLI_NOT_STARTED'
    try:
        DISPATCH_ATTEMPTED=True
        child=subprocess.Popen(command,cwd=kernel,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        native_pid=child.pid;save(folder/'launch.json',{'native_pid':native_pid,'started_utc':datetime.now(timezone.utc).isoformat()})
        try:
            stdout,stderr=child.communicate(timeout=binding['cli_timeout_seconds']);code=child.returncode;transport='CLI_RETURNED'
        except subprocess.TimeoutExpired:
            child.kill();stdout,stderr=child.communicate();code=child.returncode;transport='CLI_TIMEOUT_EFFECT_STATE_UNRESOLVED'
    except OSError as exc:
        stderr=(type(exc).__name__+': CLI process could not be launched.').encode();transport='CLI_LAUNCH_FAILED'
    append_file(folder/'native.stdout',stdout);append_file(folder/'native.stderr',stderr)
    native=None
    try:native=strict(stdout);require(type(native) is dict,'BRIDGE_NATIVE_OUTPUT_TYPE')
    except (ValueError,UnicodeDecodeError):native=None
    stable=True
    try:load_binding(args.binding,args.binding_sha256)
    except (ValueError,OSError,KeyError,TypeError):stable=False
    record.update(native_pid=native_pid,native_exit_code=code,native_stdout_path=str(folder/'native.stdout'),native_stdout_sha256=digest(stdout),
                  native_stderr_path=str(folder/'native.stderr'),native_stderr_sha256=digest(stderr),native_result=native,
                  transport_status=transport,post_call_inputs_unchanged=stable,elapsed_ns=time.perf_counter_ns()-began,
                  finished_utc=datetime.now(timezone.utc).isoformat())
    if native:
        evidence=[]
        for field in ('receipt_path','manifest_path'):
            if field in native:
                path=Path(native[field]);expected=native.get('receipt_sha256' if field=='receipt_path' else 'manifest_sha256')
                readable=path.is_absolute() and path.resolve().is_relative_to(Path(config['state_root'])) and path.is_file()
                actual=digest(path.read_bytes()) if readable else None
                evidence.append({'field':field,'path':str(path),'expected_sha256':expected,'actual_sha256':actual,
                                 'matches':actual is not None and expected==actual})
        record['native_artifact_observations']=evidence
    artifacts_match=all(item['matches'] for item in record.get('native_artifact_observations',[]))
    record['returned_native_artifacts_match']=artifacts_match
    receipt=folder/'receipt.json';save(receipt,record)
    _archive_experience(args,kernel,receipt,binding,config)
    output={'schema':'CK_NATIVE_B_BRIDGE_RESULT_1','bridge_invocation_id':invocation,'run_id':binding['run_id'],'task_id':binding['task_id'],
            'operation_id':args.operation_id,'native_result':native,'native_exit_code':code,'transport_status':transport,
            'post_call_inputs_unchanged':stable,'bridge_receipt_path':str(receipt),'bridge_receipt_sha256':digest(receipt.read_bytes()),
            'returned_native_artifacts_match':artifacts_match,
            'identity_verification':'EXTERNAL_NATIVE_TOOL_TRANSCRIPT_REQUIRED'}
    exit_code=code if transport=='CLI_RETURNED' and stable and artifacts_match and native is not None and code in (0,2,3) else 3
    return output,exit_code


def main(argv=None):
    try:
        args=parser().parse_args(argv)
        if args.verb=='prepare-context':output,code=run_prepare_context(args)
        else:
            _experience_requested(args)
            output,code=launch(args)
    except Refused as exc:
        output={'status':'BRIDGE_INDETERMINATE' if DISPATCH_ATTEMPTED else 'BRIDGE_REFUSED','reason':str(exc),
                'dispatch_attempted':DISPATCH_ATTEMPTED,'automatic_retry':False};code=3 if DISPATCH_ATTEMPTED else 2
    except (OSError,ValueError,TypeError,KeyError,UnicodeError) as exc:
        output={'status':'BRIDGE_INDETERMINATE' if DISPATCH_ATTEMPTED else 'BRIDGE_REFUSED','reason':'BRIDGE_INVALID_INPUT_OR_IO',
                'error_type':type(exc).__name__,'dispatch_attempted':DISPATCH_ATTEMPTED,'automatic_retry':False};code=3 if DISPATCH_ATTEMPTED else 2
    print(canonical(output).decode('utf-8'));return code


if __name__=='__main__':raise SystemExit(main())
