import sys, os, re
sys.path.insert(0, os.path.abspath('code'))
import main

for fn in ['account_history_report_20260718.pdf', 'legal_retention_register_20260529.pdf', 'security_retention_extract.pdf']:
    path = os.path.join('dataset/evidence/documents', fn)
    txt = main.extract_pdf_streams(path)
    print(f'=== {fn} ===')
    emails = re.findall(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', txt)
    res = re.findall(r'([a-zA-Z_]+_\d+)', txt)
    print('  emails:', set(emails))
    print('  res sample:', list(set(res))[:10])
