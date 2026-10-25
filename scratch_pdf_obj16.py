import zlib

with open('dataset/evidence/documents/delivery_correction_attachment.pdf', 'rb') as f:
    data = f.read()

idx16 = data.find(b'16 0 obj')
print("idx16:", idx16)
print(data[idx16:idx16+300])

s_idx = data.find(b'stream', idx16)
e_idx = data.find(b'endstream', s_idx)
s_data = data[s_idx+6:e_idx].strip()
try:
    decomp = zlib.decompress(s_data)
    print("Decompressed length:", len(decomp))
    print(decomp.decode('latin1', errors='ignore'))
except Exception as e:
    print("Error:", e)
