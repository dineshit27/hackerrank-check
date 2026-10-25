import base64
import zlib
import re

with open('dataset/evidence/documents/security_retention_extract.pdf', 'rb') as f:
    data = f.read()

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
        # Check if ascii85
        try:
            a85 = base64.a85decode(s_data, adobe=True)
            decomp = zlib.decompress(a85)
        except Exception:
            decomp = zlib.decompress(s_data)
        txt = decomp.decode('latin1', errors='ignore')
        matches = re.findall(r'\(.*?\)', txt)
        print("Found text in stream at", idx)
        for m in matches:
            if 'audit' in m or 'user_' in m or '6645' in m or '5569' in m:
                print(" ", m)
    except Exception:
        pass
    pos = end_idx + 9
