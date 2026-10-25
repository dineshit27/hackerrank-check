import re

with open('dataset/evidence/documents/delivery_correction_attachment.pdf', 'rb') as f:
    data = f.read()

# Look for text inside PDF streams
import zlib

print("PDF size:", len(data))
# Find FlateDecode streams
streams = re.findall(b'stream\r?\n(.*?)\r?\nendstream', data, re.DOTALL)
print("Number of streams:", len(streams))

extracted_texts = []
for s in streams:
    try:
        decomp = zlib.decompress(s)
        extracted_texts.append(decomp.decode('latin1', errors='ignore'))
    except Exception:
        extracted_texts.append(s.decode('latin1', errors='ignore'))

combined = "\n".join(extracted_texts)
# Find BT ... ET blocks or string literals ( ... )
strings = re.findall(r'\((.*?)\)', combined)
print(f"Extracted {len(strings)} strings from PDF. First 20:")
for s in strings[:20]:
    if len(s.strip()) > 2:
        print(" ", s)
