import re

line1 = '2026-04-19T06:51:21Z {"severity":"INFO","trace_id":"tr-7722221","resource_id":"search_9365"}'
line2 = '2026-02-03T05:51:23Z | DEBUG | security_service | tr-4612767 | audit_record_query_started | subject_ref="user_517"'
line3 = '2026-02-03T05:51:30Z | DEBUG | security_service | tr-4612767 | audit_record_read_completed | resource_id="audit_record_4027"'

def get_trace(l):
    m = re.search(r'(?:trace_id|requestId|trace)[=:"]+([a-zA-Z0-9_\-]+)', l)
    if m: return m.group(1)
    m2 = re.search(r'\|\s*(tr-[a-zA-Z0-9_\-]+)\s*\|', l)
    if m2: return m2.group(1)
    return None

def get_resources(l):
    return re.findall(r'resource_id[=:"]+([a-zA-Z0-9_]+)', l)

print('Line 1 trace:', get_trace(line1), 'res:', get_resources(line1))
print('Line 2 trace:', get_trace(line2), 'res:', get_resources(line2))
print('Line 3 trace:', get_trace(line3), 'res:', get_resources(line3))
