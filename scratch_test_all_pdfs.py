import csv
import json
import os
import glob
import re
import sqlite3
import base64
import zlib
import sys
sys.stdout.reconfigure(encoding='utf-8')

with open('dataset/evidence_files.csv', 'r', encoding='utf-8') as f:
    ev_files = {r['file_id']: r for r in csv.DictReader(f)}

print(f"Total evidence files: {len(ev_files)}")

# Let's inspect the 4 PDFs to extract text from all 4
def extract_pdf_text(path):
    with open(path, 'rb') as f:
        data = f.read()
    texts = []
    pos = 0
    while True:
        idx = data.find(b'stream', pos)
        if idx == -1:
            break
        end_idx = data.find(b'endstream', idx)
        if end_idx == -1:
            break
        s_data = data[idx+6:end_idx].strip()
        try:
            try:
                a85 = base64.a85decode(s_data, adobe=True)
                decomp = zlib.decompress(a85)
            except Exception:
                decomp = zlib.decompress(s_data)
            txt = decomp.decode('latin1', errors='ignore')
            matches = re.findall(r'\((.*?)\)', txt)
            if matches:
                texts.append(" ".join(matches))
        except Exception:
            pass
        pos = end_idx + 9
    return "\n".join(texts)

pdf_files = [ef for ef in ev_files.values() if ef['file_path'].endswith('.pdf')]
for pf in pdf_files:
    p = os.path.join('dataset', pf['file_path'])
    txt = extract_pdf_text(p)
    print(f"\nPDF {pf['file_id']} ({pf['file_path']}): length={len(txt)}")
    print("Sample text:", txt[:300].replace('\n', ' '))
