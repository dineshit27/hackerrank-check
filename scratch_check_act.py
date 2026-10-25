import csv

with open('dataset/system_activity.csv', 'r', encoding='utf-8') as f:
    activities = list(csv.DictReader(f))

print(f"Total activities: {len(activities)}")
res_to_act = {}
for act in activities:
    res = act['resource_id']
    if res not in res_to_act:
        res_to_act[res] = []
    res_to_act[res].append(act)

sample_res = ['account_001', 'account_7566', 'audit_record_2016', 'analytics_9406', 'search_001', 'search_898', 'account_410']
for r in sample_res:
    acts = res_to_act.get(r, [])
    print(f"\nResource {r}: {len(acts)} activities")
    for a in acts:
        print(f"  {a['activity_id']} | {a['event_time']} | {a['event_type']} | {a['source_system']} -> {a['target_system']} | res={a['reported_result']} | {a['details']}")
