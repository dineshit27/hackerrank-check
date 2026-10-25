with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    for line in f:
        if 'audit_record' in line:
            parts = line.strip().split(',')
            if '6645' in parts[5] or '5569' in parts[5]:
                print(line.strip())
