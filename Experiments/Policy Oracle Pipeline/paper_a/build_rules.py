"""Source-linked candidate rules; checklist coverage is deliberately qualified."""
import csv
import json
import re
import tarfile
import os
import threading
import time
import pyarrow.parquet as pq
from pathlib import Path
from oracles import MINED

ROOT=Path(__file__).resolve().parent
from paths import OUT
PAPER='https://arxiv.org/html/2605.02091v1#S3.T1'
SECURE='https://docs.github.com/en/actions/reference/security/secure-use'
SYNTAX='https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax'
R_GROUPS={
 'R1_permissions_declared':'privilege','R2_no_write_all':'privilege',
 'R3_no_pr_target':'privilege','R4_no_workflow_run':'privilege',
 'R5_no_untrusted_in_run':'execution_integrity',
 'R6_third_party_sha_pinned':'supply_chain','R7_all_actions_sha_pinned':'supply_chain',
 'R8_checkout_no_persist_creds':'credentials',
 'R9_job_timeouts':'workflow_hygiene','R10_concurrency':'workflow_hygiene',
 'R11_no_continue_on_error':'ci_integrity'}

CHECKLIST=[
 ('W1','Failure reporting','dropped','Runtime notifications cannot be established from YAML'),
 ('W2','Runner support','tool-covered','actionlint runner-label check; partial, not appropriateness'),
 ('W3','General security','dropped','Umbrella criterion; evaluate specific security rules instead'),
 ('J1','Job naming','dropped','Clarity requires an independently defined rubric'),
 ('J2','Job structure','tool-covered','actionlint syntax/schema'),
 ('J3','Job debugging','dropped','Debug logging is contextual, not a universal safe default'),
 ('J4','Runner suitability','dropped','Requires task and execution context'),
 ('J5','Job modularity','dropped','Subjective scope needs a rubric'),
 ('J6','Job isolation','dropped','Requires execution/data-flow evidence'),
 ('J7','Cache effectiveness','dropped','Requires runtime and workload evidence'),
 ('J8','Cache portability','dropped','Requires environments and execution evidence'),
 ('J9','Parallelism tuning','dropped','Requires measured resources and workload'),
 ('J10','Build caching','dropped','Caching presence does not establish reduced build time'),
 ('J11','Runner authorization','dropped','Needs runner authorization inventory'),
 ('S1','Command decomposition','dropped','Needs a complexity/clarity rubric'),
 ('S2','Step organization','dropped','Compound semantic requirement'),
 ('S3','Input sanitization','tool-covered','zizmor template-injection is partial coverage only'),
 ('S4','Platform input checks','dropped','Requires task-specific validators'),
 ('S5','JDK input checks','dropped','Requires Java/platform context'),
 ('S6','Preserve validation','custom','D_test_or_lint_step_removed and D_continue_on_error_added are review proxies; justification is unobserved'),
 ('S7','Step debugging','dropped','Context-specific requirement'),
 ('S8','Command failures','dropped','Syntactic lint does not establish command failure propagation'),
 ('S9','Configurable conditions','dropped','Requires repository/task semantics'),
 ('S10','Change-detection strength','dropped','Needs a validated context-sensitive rubric'),
 ('S11','Native conditional structure','dropped','Valid alternatives prevent a universal syntactic requirement'),
 ('S12','Condition documentation','dropped','Requires a documentation/maintainability rubric'),
 ('S13','Immutable action references','tool-covered','Z_unpinned_uses plus R6/R7; domains differ'),
 ('S14','Action currency','dropped','Historical release information unobserved in offline runs'),
 ('S15','Security analysis steps','dropped','Named scanner step alone does not establish effective scanning'),
 ('P1','Secret storage','tool-covered','zizmor secret-related audits cover only specific encodings; not full secrets-management assessment'),
]

def write(name,rows):
 target=OUT/name
 temporary=target.with_name(target.name+f'.{os.getpid()}.{threading.get_ident()}.tmp')
 with temporary.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
 for attempt in range(50):
  try: temporary.replace(target); break
  except PermissionError:
   if attempt==49: raise
   time.sleep(.02)

def group(identifier):
 if any(x in identifier for x in ['permission','trigger','github_app','self_hosted']): return 'privilege'
 if any(x in identifier for x in ['secret','credential','artipacked']): return 'credentials'
 if any(x in identifier for x in ['injection','github_env','insecure_command','unsound']): return 'execution_integrity'
 if any(x in identifier for x in ['pinned','uses','action_ref','impostor','publishing','cache','package','url']): return 'supply_chain'
 return 'workflow_hygiene'

def main():
 OUT.mkdir(exist_ok=True)
 classifications=[dict(checklist_id=i,criterion_summary=s,classification=c,source=PAPER,coverage_limit=l) for i,s,c,l in CHECKLIST]
 assert len(classifications)==30 and len({r['checklist_id'] for r in classifications})==30
 write('checklist_classification.csv',classifications)
 rules=[]
 with tarfile.open(ROOT/'sources/zizmor-1.30.1.tar.gz') as archive:
  for member in archive.getmembers():
   if '/src/audit/' not in member.name or not member.name.endswith('.rs'): continue
   text=archive.extractfile(member).read().decode()
   meta=re.search(r'audit_meta!\(\s*\w+,\s*"([^"]+)",\s*"([^"]+)"',text)
   if not meta: continue
   audit,statement=meta.groups()
   if audit in ['self-repository','archived-uses']: continue
   identifier='Z_'+audit.replace('-','_')
   rules.append(dict(rule_id=identifier,statement='Avoid the scanner condition: '+statement,
    source='https://github.com/zizmorcore/zizmor/blob/v1.30.1/'+member.name.split('/',1)[1],
    source_reference='https://docs.zizmor.sh/audits/#'+audit,evidence_type='artifact',rule_group=group(identifier),
    check_type='zizmor',check='oracles.check_zizmor',audit_id=audit,
    qualification='Pinned offline diagnostic; persona/config/context can limit coverage. Not an adopted repository policy by default.'))
 mapping=dict(zip(MINED.RULES,[
  'Explicit permission declaration','No literal write-all permissions','No pull_request_target trigger','No workflow_run trigger',
  'No listed untrusted expressions interpolated into run','Third-party action references use full SHAs','Action references use full SHAs',
  'Checkout explicitly disables credential persistence','Jobs declare timeout limits','Declare workflow or job concurrency','No literal continue-on-error true']))
 for rule,statement in mapping.items():
  rules.append(dict(rule_id=rule,statement=statement,source=SECURE if int(rule.split('_')[0][1:])<=8 else SYNTAX,
    source_reference=str((MINED.ROOT/'README.md').relative_to(ROOT.parents[2])),evidence_type='artifact',rule_group=R_GROUPS[rule],
    check_type='custom_literal',check='oracles.check_custom',audit_id='',
    qualification='Original R1–R11 candidate baseline, not a universal vendor requirement; literal applicability/limits retained from mining task'))
 for identifier,statement in [('D_permissions_broadened','Effective permission level increased where both sides are known'),('D_test_or_lint_step_removed','Lexically identified test/lint step removed without an identical implementation elsewhere'),('D_continue_on_error_added','New literal continue-on-error true')]:
  rules.append(dict(rule_id=identifier,statement=statement,source=SYNTAX,source_reference=PAPER+' (S6 motivates preserving validation)',
    evidence_type='change',rule_group='privilege' if identifier=='D_permissions_broadened' else 'ci_integrity',check_type='custom_change',check='oracles.change_flags',audit_id='',
    qualification='Review flag, not an automatic policy violation; unknown permission defaults and alternative test coverage remain explicit'))
 # Rebuilding source classifications must not discard actionlint kinds
 # discovered by completed runs.
 actionlint_ids=set()
 for path in OUT.glob('*/findings.parquet'):
  actionlint_ids.update(r for r in pq.read_table(path,columns=['rule_id'])['rule_id'].to_pylist() if r.startswith('A_'))
 for identifier in sorted(actionlint_ids):
  rules.append(dict(rule_id=identifier,statement='Resolve actionlint '+identifier[2:]+' diagnostic',
    source='https://github.com/rhysd/actionlint/blob/v1.7.12/docs/checks.md',source_reference='Pinned actionlint 1.7.12',
    evidence_type='artifact',rule_group='workflow_correctness',check_type='actionlint',check='oracles.check_actionlint',audit_id='',
    qualification='Isolated YAML, no shellcheck/pyflakes or repository action configuration; task success is separate'))
 write('rule_catalog.csv',rules)
 write('zizmor_audit_mapping.csv',[dict(audit_id=r['audit_id'],rule_id=r['rule_id'],source=r['source']) for r in rules if r['audit_id']])
 print(json.dumps(dict(checklist_items=len(classifications),rules=len(rules),classifications={k:sum(r['classification']==k for r in classifications) for k in ['tool-covered','custom','dropped']}),indent=2))

if __name__=='__main__': main()
