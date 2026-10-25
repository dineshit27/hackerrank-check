import zlib
import re

with open('dataset/evidence/documents/delivery_correction_attachment.pdf', 'rb') as f:
    data = f.read()

pos = 0
while True:
    idx = data.find(b'stream', pos)
    if idx == -1:
        break
    end_idx = data.find(b'endstream', idx)
    if end_idx == -1:
        break
    stream_content = data[idx+6:end_idx].strip()
    try:
        decomp = zlib.decompress(stream_content)
        print(f"Decompressed stream at {idx}:")
        text_matches = re.findall(r'\((.*?)\)', decomp.decode('latin1', errors='ignore'))
        print("Text:", " ".join(text_matches[:30]))
    except Exception as e:
        # maybe not flate
        pass
    pos = end_idx + 9
