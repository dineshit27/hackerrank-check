import base64
import zlib

with open('dataset/evidence/documents/delivery_correction_attachment.pdf', 'rb') as f:
    data = f.read()

idx16 = data.find(b'16 0 obj')
s_idx = data.find(b'stream', idx16)
e_idx = data.find(b'endstream', s_idx)
s_data = data[s_idx+6:e_idx].strip()

# ASCII85 decode with adobe=True
a85 = base64.a85decode(s_data, adobe=True)
# Flate decode
decomp = zlib.decompress(a85)
print("Decompressed length:", len(decomp))
print(decomp.decode('latin1', errors='ignore'))
