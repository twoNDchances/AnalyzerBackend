def traverse_json(data, indent=0):
    # Kiểm tra nếu là dictionary
    if isinstance(data, dict):
        for key, value in data.items():
            print(" " * indent + f"Key: {key}")
            traverse_json(value, indent + 2)  # Gọi lại hàm để lặp qua phần tử con

    # Kiểm tra nếu là list
    elif isinstance(data, list):
        for index, item in enumerate(data):
            print(" " * indent + f"Index: {index}")
            traverse_json(item, indent + 2)  # Gọi lại hàm để lặp qua từng phần tử trong list

    # Nếu là giá trị đơn (string, int, float, ...)
    else:
        print(" " * indent + f"Value: {data}")

# Ví dụ JSON phức tạp
json_data = {
    "name": "Alice",
    "age": 30,
    "address": {
        "city": "Wonderland",
        "postal_code": "12345"
    },
    "hobbies": [
        {"name": "Reading", "type": "Indoor"},
        {"name": "Hiking", "type": "Outdoor"}
    ]
}

# Gọi hàm để duyệt qua toàn bộ JSON
traverse_json(json_data)
