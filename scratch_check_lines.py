with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    for line in f:
        if '6645' in line:
            print("Activity with 6645:", line.strip())

with open('dataset/evidence/logs/resource_lookup_trace_20260926_103856.log', 'r', encoding='utf-8') as f:
    for line in f:
        if '5569' in line:
            print("Log with 5569:", line.strip())
