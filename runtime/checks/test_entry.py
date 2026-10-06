"""Portable wrapper integration checks; no product or human acceptance claims."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ['M2_PORTABLE_TEST_ROOT']).resolve()
SCRATCH.mkdir(parents=True, exist_ok=True)

class EntryTests(unittest.TestCase):
    def setUp(self):
        self.work=Path(tempfile.mkdtemp(prefix='entry-',dir=SCRATCH))

    def call(self,*args,package=ROOT):
        return subprocess.run([sys.executable,'-I','-B',str(package/'m2.py'),*map(str,args)],
            cwd=self.work,capture_output=True,timeout=180)

    def data(self,*args,code=0,**kw):
        r=self.call(*args,**kw)
        self.assertEqual(r.returncode,code,r.stderr.decode('utf-8','replace')+r.stdout.decode('utf-8','replace'))
        return json.loads(r.stdout)

    def test_no_argument_and_workflow_do_not_claim_execution(self):
        result=self.call()
        self.assertEqual(result.returncode,0,result.stderr)
        for name in ('doctor','project-init','context','kernel','tool'):
            self.assertIn(name.encode(),result.stdout)
        plan=self.data('workflow')
        self.assertFalse(plan['execution_authority'])
        self.assertIn('INDEPENDENT_AUDIT',[x['id'] for x in plan['stages']])
        self.assertIn('HUMAN_ACCEPTANCE',[x['id'] for x in plan['stages']])

    def test_doctor_and_start_from_unrelated_unicode_directory(self):
        dest=self.work/'新 包 with spaces'
        shutil.copytree(ROOT,dest)
        result=self.data('doctor',package=dest)
        self.assertEqual(result['status'],'STARTUP_READY')
        self.assertEqual(result['baseline_members_verified'],53)
        self.assertEqual(result['governance_status'],'NOT_STARTED')
        result=self.data('start',package=dest)
        self.assertEqual(result['status'],'NEEDS_PROJECT_CONFIGURATION')
        self.assertEqual(result['human_acceptance'],'NOT_CLAIMED')

    def test_changed_kernel_denied_before_import(self):
        dest=self.work/'bad-package'
        shutil.copytree(ROOT,dest)
        (dest/'baseline/M2-Construction-Portable-20261004/core/src/m2_construction/cli.py').write_text('raise RuntimeError("EXECUTED_TAMPERED")',encoding='utf-8')
        result=self.data('kernel','--help',package=dest,code=2)
        self.assertEqual(result['reason'],'BASELINE_FILE_CHANGED')
        self.assertNotIn('EXECUTED_TAMPERED',json.dumps(result))

    def test_kernel_and_bridge_help_keep_all_original_verbs(self):
        r=self.call('kernel','--help')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn(b'post-verify',r.stdout)
        self.assertIn(b'ceo-accept',r.stdout)
        r=self.call('tool','--help')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn(b'prepare-context',r.stdout)
        self.assertNotIn(b'ceo-accept',r.stdout)

    def bootstrap(self,version):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        workspace=self.work/'project'
        workspace.mkdir()
        cfg={'schema':f'M2_CONSTRUCTION_CLI_CONFIG_{version}',
             'workspace_root':str(workspace),'state_root':str(self.work/'state')}
        for field,kind in [('pin_path','M2_CONSTRUCTION_PIN_1')]+([('reviewer_pin_path','M2_CONSTRUCTION_REVIEWER_PIN_1')] if version>=2 else [])+([('child_reviewer_pin_path','M2_CONSTRUCTION_REVIEWER_PIN_1'),('ceo_pin_path','M2_CONSTRUCTION_CEO_PIN_1')] if version>=3 else []):
            key=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
            path=self.work/(field+'.json')
            path.write_text(json.dumps({'schema':kind,'trust_domain':'TEST_ONLY','public_key_b64':base64.b64encode(key).decode(),'fingerprint':hashlib.sha256(key).hexdigest()},sort_keys=True,separators=(',',':'),ensure_ascii=False),encoding='utf-8')
            cfg[field]=str(path)
            cfg['expected_'+field.removesuffix('_path')+'_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        path=self.work/'bootstrap.json'
        path.write_text(json.dumps(cfg),encoding='utf-8')
        return path,hashlib.sha256(path.read_bytes()).hexdigest()

    def test_config_one_cannot_claim_independent_review(self):
        cfg,h=self.bootstrap(1)
        result=self.data('readiness','--config',cfg,'--config-sha256',h,code=3)
        self.assertEqual(result['status'],'EXECUTION_ONLY_CONFIGURATION')
        self.assertIn('INDEPENDENT_AUDIT',result['missing_capabilities'])
        self.assertFalse((self.work/'state').exists())

    def test_config_three_is_not_a_pass_or_a_signed_authorization(self):
        cfg,h=self.bootstrap(3)
        result=self.data('readiness','--config',cfg,'--config-sha256',h)
        self.assertEqual(result['status'],'FULL_CHAIN_CONFIGURATION_PRESENT')
        self.assertFalse(result['execution_authority'])
        self.assertEqual(result['governance_status'],'NOT_STARTED')
        self.assertFalse((self.work/'state').exists())
        bad=self.data('readiness','--config',cfg,'--config-sha256','0'*64,code=2)
        self.assertEqual(bad['reason'],'CLI_CONFIG_CHANGED')

    def test_project_cli_restores_references_and_excludes_changed_bytes(self):
        project=self.work/'项目'
        project.mkdir()
        roles=('requirements','design','code','tests','decisions','known_issues','memory','evidence')
        args=[]
        for role in roles:
            (project/(role+'.txt')).write_text('已提供的项目资料 '+role,encoding='utf-8')
            args+=['--source',role+'='+role+'.txt']
        cfg=self.work/'project.json'
        result=self.data('project-init','--root',project,'--config',cfg,'--goal','核对项目实际资料',*args)
        self.assertEqual(result['status'],'CONTEXT_READY_FOR_REVIEW')
        started=self.data('start','--project',cfg)
        self.assertEqual(started['status'],'PROJECT_CONTEXT_READY')
        self.assertFalse(started['execution_authority'])
        (project/'memory.txt').write_text('Changed content must not be adopted',encoding='utf-8')
        restored=self.data('start','--project',cfg,code=3)
        self.assertEqual(restored['status'],'PROJECT_CONTEXT_INCOMPLETE')
        item=next(x for x in restored['project_context']['sources'] if x['kind']=='memory')
        self.assertEqual(item['hash_status'],'MISMATCH')
        self.assertNotIn('content',item)

    def test_missing_project_config_is_structured_denial_without_traceback(self):
        result=self.data('context','--config',self.work/'absent.json',code=2)
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['reason'],'CONFIG_MISSING')

    def test_real_failure_sample_remains_failure_and_unknowns_not_promoted(self):
        out=self.work/'sample evidence'
        data=self.data('sample','--output',out)
        self.assertEqual(data['status'],'DEMO_COMPLETED')
        self.assertEqual(data['independent_acceptance'],'NOT_CLAIMED')
        result=json.loads((out/'flow01/flow-result.json').read_text(encoding='utf-8'))
        text=json.dumps(result)
        self.assertIn('FAILED',text)
        self.assertFalse(data['execution_authority'])
        denied=self.data('sample','--output',out,code=2)
        self.assertEqual(denied['reason'],'NEW_OUTPUT_REQUIRED')

if __name__=='__main__':unittest.main()
