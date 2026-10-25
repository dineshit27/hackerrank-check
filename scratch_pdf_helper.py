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

# Helper to decode PDF
def extract_pdf_strings(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        pos = 0
        texts = []
        while True:
            idx = data.find(b'stream', pos)
            if idx == -1: break
            e_idx = data.find(b'endstream', idx)
            if e_idx == -1: break
            raw = data[idx+6:e_idx].strip()
            try:
                try:
                    a85 = base64.a85decode(raw, adobe=True)
                    decomp = zlib.decompress(a85)
                except Exception:
                    decomp = zlib.decompress(raw)
                txt = decomp.decode('latin1', errors='ignore')
                texts.append(txt)
            except Exception:
                pass
            pos = e_idx + 9
        return "\n".join(texts)
    except Exception:
        return ""

print("PDF extractor ready.")
