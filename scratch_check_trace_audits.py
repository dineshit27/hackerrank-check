with open('dataset/evidence/logs/resource_lookup_trace_20260926_103856.log', 'r', encoding='utf-8') as f:
    for line in f:
        if 'audit_record' in line or 'security_service' in line:
            print(line.strip())
