with open('dataset/evidence/records/security_audit_ledger_20261001.json', 'r', encoding='utf-8') as f:
    text = f.read()
    if '6645' in text or '5569' in text:
        print("Found in security_audit_ledger_20261001.json!")
    else:
        print("Not in security_audit_ledger_20261001.json. Content sample:")
        print(text[:300])
