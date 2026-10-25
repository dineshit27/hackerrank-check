import csv
import json
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/sample_output.csv', 'r', encoding='utf-8') as f:
    samples = list(csv.DictReader(f))

for s in samples:
    cid = s['case_id']
    status = s['deletion_status']
    steps = json.loads(s['steps_json'])
    
    findings = [st for st in steps if st['phase'] == 'FINDING']
    remediations = [st for st in steps if st['phase'] == 'REMEDIATION']
    verifications = [st for st in steps if st['phase'] == 'VERIFICATION']
    
    print(f"\n{cid} ({status}): {len(findings)} findings, {len(remediations)} rems, {len(verifications)} verifs")
    if findings:
        for f_st in findings:
            print(f"  FINDING: {f_st['system_id']} | {f_st['resource_id']} | {f_st['operation']} | ev={f_st['evidence_id']}")
        for r_st in remediations:
            print(f"  REMEDIATION: {r_st['system_id']} | {r_st['resource_id']} | {r_st['operation']}")
        for v_st in verifications:
            print(f"  VERIF: {v_st['system_id']} | {v_st['resource_id']} | {v_st['operation']} | ev={v_st['evidence_id']}")
    else:
        for v_st in verifications:
            print(f"  VERIF: {v_st['system_id']} | {v_st['resource_id']} | {v_st['operation']} | ev={v_st['evidence_id']}")
