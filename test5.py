import re

def replace_variables(user_input, variables):
    """
    Thay thế các biến có dạng $variable trong chuỗi bằng giá trị tương ứng từ từ điển variables.
    
    Parameters:
    user_input (str): Chuỗi đầu vào chứa các biến.
    variables (dict): Từ điển chứa tên biến và giá trị tương ứng.
    
    Returns:
    str: Chuỗi với các biến đã được thay thế.
    """
    # Hàm thay thế sử dụng trong re.sub
    def replacer(match):
        var_name = match.group(1)  # Lấy tên biến sau $
        return str(variables.get(var_name, f"${{{var_name}}}"))  # Trả về giá trị của biến, hoặc giữ nguyên nếu không tìm thấy
    
    # Thay thế tất cả các $variable bằng giá trị từ từ điển variables
    result = re.sub(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", replacer, user_input)
    return result

# Ví dụ sử dụng
name = "Alice"
age = 30
var_name_example = "example_value"

# Đưa các biến vào từ điển
variables = {
    "name": name,
    "age": age,
    "var_name_example": var_name_example
}

user_input = "Hello $name, you are $age years old. Here is$var_name_example."
output = replace_variables(user_input, variables)
print(output)  # Kết quả: "Hello Alice, you are 30 years old. Here is example_value."
