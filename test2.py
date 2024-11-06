import re
import json

# Dữ liệu JSON giả định
json_data = '''{
    "query1": "SELECT * FROM users;",
    "query2": "SELECT * FROM products WHERE name = 'item'; DROP TABLE users;",
    "query3": "INSERT INTO orders (id, name) VALUES (1, 'test');"
}'''

data = json.loads(json_data)

# Quy tắc regex để phát hiện chuỗi có dấu `;`
rule = r";.*;"

# Hàm kiểm tra chuỗi có khớp với quy tắc hay không
def detect_sqli(data, rule):
    detected_queries = []
    for key, value in data.items():
        if re.search(rule, value):  # Sử dụng regex để kiểm tra khớp
            detected_queries.append((key, value))
    return detected_queries

# Kiểm tra dữ liệu với quy tắc
matches = detect_sqli(data, rule)

# In kết quả
if matches:
    print("Các truy vấn có khả năng chứa SQL Injection:")
    for match in matches:
        print(f"{match[0]}: {match[1]}")
else:
    print("Không có truy vấn nào chứa SQL Injection.")
