import os
import glob
import struct

pngs = glob.glob('dataset/evidence/images/*.png')
print(f"Total PNGs: {len(pngs)}")

for p in pngs:
    print(f"\nChecking {p}:")
    with open(p, 'rb') as f:
        data = f.read()
    # Check PNG chunks
    pos = 8
    chunks = []
    while pos < len(data):
        length = struct.unpack('>I', data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8].decode('latin1', errors='ignore')
        cdata = data[pos+8:pos+8+length]
        crc = data[pos+8+length:pos+12+length]
        chunks.append(ctype)
        if ctype in ['tEXt', 'zTXt', 'iTXt']:
            print(f"  {ctype} chunk: {cdata[:100]}")
        pos += 12 + length
    print(f"  Chunks found: {set(chunks)}")
