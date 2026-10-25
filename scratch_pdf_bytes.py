with open('dataset/evidence/documents/delivery_correction_attachment.pdf', 'rb') as f:
    data = f.read(500)

print(data[:300])
