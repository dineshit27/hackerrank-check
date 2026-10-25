import re

# Read evidence_94 log and check the trace for l.fontaine46@yahoo.com
path = 'dataset/evidence/logs/resource_lookup_trace_20260926_103856.log'
with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

# Find traces that involve l.fontaine46@yahoo.com
fontaine_traces = set()
for line in lines:
    if 'fontaine' in line.lower() or 'l.fontaine46' in line.lower():
        m = re.search(r'trace_id=([\w\-]+)', line)
        if m:
            fontaine_traces.add(m.group(1))
        print('FONTAINE LINE: %s' % line.strip())

print('\nFontaine traces:', fontaine_traces)
print()

# Now collect all lines for those traces
for tr in fontaine_traces:
    print('=== TRACE %s ===' % tr)
    for line in lines:
        if tr in line:
            print('  %s' % line.strip())
    print()

# Also check what account_7566 lines look like (need to find the email association)
print('=== account_7566 lines ===')
for line in lines:
    if 'account_7566' in line:
        print('  %s' % line.strip())
