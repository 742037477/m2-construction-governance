"""Portable package byte checks; inventory is not a signature or execution authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile

ZIP='dist/m2-construction-portable-20261004.zip'


def need(ok, why):
    if not ok: raise ValueError(why)


def members(root):
    doc=json.loads((root/'DELIVERY_MEMBERS.json').read_bytes())
    need(doc['schema']=='CK_DELIVERY_MEMBERS_1','MEMBER_SCHEMA')
    names=[]
    for x in doc['files']:
        n=x['destination']; p=PurePosixPath(n)
        need(not p.is_absolute() and '..' not in p.parts and '\\' not in n and ':' not in n,'MEMBER_PATH')
        path=root/n; need(not path.is_symlink() and root in path.resolve().parents,'MEMBER_LOCATION')
        raw=path.read_bytes()
        need(len(raw)==x['bytes'] and hashlib.sha256(raw).hexdigest()==x['sha256'],'MEMBER_BYTES')
        names.append(n)
    need(len(names)==len(set(names)),'MEMBER_DUPLICATE')
    return doc,sorted(names+['DELIVERY_MEMBERS.json'])


def check(root, scratch, run_local):
    doc,names=members(root)
    need(doc['core_directory']=='core','CORE_LAYOUT')
    env={k:v for k,v in os.environ.items() if k.upper() in {'PATH','SYSTEMROOT','SYSTEMDRIVE','WINDIR','TEMP','TMP'}}
    env.update(PYTHONPATH=os.pathsep.join([str(root/'src'),str(root/doc['core_directory']/'src')]),PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    commands=[[sys.executable,'-B','-m','m2_construction.cli','--help'],
              [sys.executable,'-B',str(root/'tools/native_b_runtime.py'),'--help']]
    targets=doc['test_targets']
    need(len(targets)==1 and all('::' in x and x.split('::')[0] in names and x.startswith('tests/') for x in targets),'ONE_LOCAL_TEST_NODE')
    if run_local:
        need(targets==['tests/test_failure_experience.py::test_flow01_real_failure_cross_process_new_binding'],
             'ORIGINAL_FLOW01_ONLY')
        commands.append([sys.executable,'-B',str(root/'tools/run_failure_sample.py'),
                         '--output',str(scratch/'failure-sample')])
    for argv in commands:
        p=subprocess.run(argv,cwd=root,env=env,capture_output=True,timeout=240,check=False)
        print(json.dumps({'argv':argv,'exit_code':p.returncode,'stdout':p.stdout.decode('utf-8','replace'),
                          'stderr':p.stderr.decode('utf-8','replace')},ensure_ascii=False))
        need(p.returncode==0,'ACTUAL_ENTRY_OR_LOCAL_TEST_FAILED')
    members(root)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=['child-check','build','package-check'])
    p.add_argument('--scratch');a=p.parse_args();root=Path.cwd().resolve();doc,names=members(root)
    if a.mode=='build':
        need(not (root/ZIP).exists(),'ZIP_ALREADY_EXISTS')
        with zipfile.ZipFile(root/ZIP,'x',compression=zipfile.ZIP_DEFLATED) as z:
            for n in names:z.write(root/n,n)
        print(json.dumps({'built':ZIP,'sha256':hashlib.sha256((root/ZIP).read_bytes()).hexdigest(),'members':len(names)}))
        return
    need(a.scratch is not None,'SCRATCH_REQUIRED');scratch=Path(a.scratch)
    need(scratch.is_absolute() and not scratch.exists() and root not in scratch.parents and scratch not in root.parents,'FRESH_EXTERNAL_SCRATCH')
    scratch.mkdir(parents=True,exist_ok=False)
    if a.mode=='child-check':
        check(root,scratch,True)
    else:
        with zipfile.ZipFile(root/ZIP) as z:
            need(z.namelist()==names,'EXACT_ZIP_MEMBERS')
            for n in names:need(z.read(n)==(root/n).read_bytes(),'ZIP_SOURCE_BYTES')
            dest=scratch/'unpacked';dest.mkdir();z.extractall(dest)
        check(dest,scratch,False)
        members(root)
    print('Actual bounded package/entry/local checks completed; no authority or human PASS.')


if __name__=='__main__':
    main()
