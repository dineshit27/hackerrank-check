import csv
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/deletion_requests.csv', 'r', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

# Let's inspect cases that might have non-deletion language
non_deletion_flags = []
for r in requests:
    t = r['request_text'].lower()
    # Check for negations or non-deletion intent
    if any(p in t for p in [
        'not asking for deletion', 'do not close', "don't close", 'do not delete', "don't delete",
        'leave the account', 'keep the account', 'as it is', 'in place', 'continue using',
        'without removing', 'information request', 'portable format', 'copy of last year',
        'misspelled', 'out of date', 'promotional emails', 'marketing lists only', 'resetting the login'
    ]):
        non_deletion_flags.append(r['case_id'])

print("Cases with non-deletion flags:", non_deletion_flags)
