import re
from psycopg2 import connect
from gather import PSQL_HOST, PSQL_PORT, PSQL_USER, PSQL_PASS

psql_conn = connect(
    host=PSQL_HOST,
    port=PSQL_PORT,
    user=PSQL_USER,
    password=PSQL_PASS,
    database='analyzers'
    )

psql_curs = psql_conn.cursor()

# Define regex patterns for different SQL injection tactics
# sql_patterns = [
#     re.compile(r"(?i)\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW)\b"),  # Common SQL keywords
#     re.compile(r"(?i)\b(OR|AND)\s+\d+=\d+"),  # Boolean logic (e.g., OR 1=1)
#     re.compile(r"(?i)--|;|#"),  # Comment indicators and semicolon
#     re.compile(r"(?i)'|\""),  # Unescaped quotes
#     re.compile(r"(?i)\b(UNION SELECT|INFORMATION_SCHEMA|TABLE_NAME|COLUMN_NAME|LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\b")  # Advanced SQLi techniques
# ]

psql_curs.execute('SELECT * FROM rule WHERE id = 2;')

rows = psql_curs.fetchone()

sql_patterns = [
    re.compile(rf'{rows[2]}')
]

print(sql_patterns)
# for row in rows:
#     if row[2].__len__() != 0:
#         sql_patterns.append(re.compile(rf'{row[2]}'))

# Function to check for SQL injection patterns
def detect_sql_injection(input_string):
    for pattern in sql_patterns:
        if pattern.search(input_string):
            return "Potential SQL Injection detected"
    return "Input is clean"

# Test with various SQL injection inputs
test_inputs = [
    "SELECT * FROM users WHERE username = 'admin' OR 1=1",
    "drop table students; --",
    "UNION SELECT username, password FROM users",
    "Normal text input",
    "0x554E494F4E2053454C4543542056455253494F4E28293B202D2D20",
    "'; SELECT;"
]

# Check each test input
for input_string in test_inputs:
    print(f"Input: {input_string} -> {detect_sql_injection(input_string)}")
