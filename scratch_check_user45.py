with open('dataset/evidence/databases/customer_data_inventory_20260310.sql', 'r', encoding='utf-8') as f:
    for line in f:
        if 'user_45' in line:
            print(line.strip())
