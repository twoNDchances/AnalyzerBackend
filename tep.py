import re
patterns = [
  re.compile(r"(?i)<.*?script.*?>.*?(<\/script>)?")
 #   re.compile(r'(?i)(<script>)')
]
input_string = "<scrIpt>"
for pattern in patterns:
    if pattern.search(input_string):
        print("c")
        break
