import psycopg2
from gather import PSQL_HOST, PSQL_PORT, PSQL_USER, PSQL_PASS

connection_params = {
    'host': PSQL_HOST,
    'port': PSQL_PORT,
    'database': 'postgres',
    'user': PSQL_USER,
    'password': PSQL_PASS
}

try:
    connection = psycopg2.connect(**connection_params)
    connection.autocommit = True
except (Exception, psycopg2.DatabaseError) as error:
    print("Error occurred:", error)

cursor = connection.cursor()

cursor.execute("DROP DATABASE IF EXISTS analyzers;")

cursor.execute("CREATE DATABASE analyzers;")

cursor.close()
connection.close()

connection_params['database'] = 'analyzers'
connection = psycopg2.connect(**connection_params)
connection.autocommit = True
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE rule (
    id SERIAL PRIMARY KEY,
    rule_type VARCHAR(128) NOT NULL,
    rule_execution TEXT NOT NULL,
    rule_description VARCHAR(256) NULL
);
""")

cursor.execute("""
CREATE TABLE action (
    id SERIAL PRIMARY KEY,
    action_name VARCHAR(128) NOT NULL,
    action_type VARCHAR(64),
    action_configuration TEXT
);
""")

cursor.execute("""
CREATE TABLE sqli (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(64) NOT NULL,
    is_enabled BOOLEAN NOT NULL,
    target_field TEXT,
    ip_root_cause_field TEXT,
    regex_matcher TEXT,
    rule_library VARCHAR(64) DEFAULT 'SQLI',
    action_id INT,
    type_attack VARCHAR(16) DEFAULT 'sqli'
);
""")

cursor.execute("""
CREATE TABLE xss (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(64) NOT NULL,
    is_enabled BOOLEAN NOT NULL,
    target_field TEXT,
    ip_root_cause_field TEXT,
    regex_matcher TEXT,
    rule_library VARCHAR(64) DEFAULT 'XSS',
    action_id INT,
    type_attack VARCHAR(16) DEFAULT 'xss'
);
""")

cursor.execute("""
CREATE TABLE result (
    id SERIAL PRIMARY KEY,
    analyzer VARCHAR(32) NOT NULL,
    reference VARCHAR(64) NOT NULL,
    count INT DEFAULT 0,
    log TEXT
);
""")

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW)\\b',
    'Common SQL keywords'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
    'Boolean logic statements'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|SLEEP|BENCHMARK|WAITFOR|EXECUTE)\\b)',
    'Common statement for MySQL'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|SLEEP|BENCHMARK|WAITFOR)\\b)',
    'Common statement for PostgreSQL'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|SLEEP|DBMS_LOCK.SLEEP)\\b)',
    'Common statement for Oracle'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)(\\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|UNION|GRANT|REVOKE|SHOW|FROM|WHERE|ORDER BY|GROUP BY|HAVING|LIMIT|OFFSET|LIKE|IN|WAITFOR)\\b)',
    'Common statement for SQL Server'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\\b(UNION SELECT|INFORMATION_SCHEMA|TABLE_NAME|COLUMN_NAME|LOAD_FILE|INTO OUTFILE|INTO DUMPFILE)\\b',
    'Advanced SQLi techniques'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\'\\s*=\\s*\'|"\\s*=\\s*"',
    'Direct comparison of strings (Example: \'admin\' = \'admin\')'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '([\'"]?;\\s*--\\s*)',
    'Common payload'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\\b(ADD COLUMN|ALTER COLUMN|DROP COLUMN|RENAME COLUMN|RENAME TABLE|REPLACE INTO|INTO OUTFILE|INTO DUMPFILE|CASE WHEN)\\b',
    'Database and table manipulation commands'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\\b(VERSION|DATABASE|USER|SYSTEM_USER|SESSION_USER|CURRENT_USER|BENCHMARK|SLEEP|RAND|MD5|SHA1|SHA2)\\b',
    'Suspicious function calls (Example: version, database)'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '0x[0-9A-Fa-f]+',
    'Hexadecimal values (often used in injections)'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '\\|\\|',
    'Concatenation with || operator (specific to certain SQL dialects)'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'SQLI',
    '(?i)\\b\\d+\\s*=\\s*\\d+\\b',
    'Detect conditions with tautologies (Example: \'1\'=\'1\')'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?(=|:|>)(.*?[\"\']|>|.*?)>',
    'Detect html injection'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?script.*?>.*?(</script>)?',
    "Detect <script> tags"
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?img.*?\b[^>]*?(onerror.*?=|>)',
    'Detect img onerror event'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?iframe.*?>(.*?)?(</.*?iframe.*?>)?',
    'Detect iframe tags'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?body.*?\b[^>]*?(onload.*?=|>)',
    'Detect body onload event'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?svg.*?(=|>)(</svg>)?',
    'Detect svg with events'
))
#Từ khúc này trở đi, nên sửa lại XSS để đúng hơn
cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?div.*?style=.*?expression\\(.*?\\).*?>',
    'Detect CSS expression in style'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?input.*?type=.*?hidden.*?value=.*?javascript:.*?>',
    'Detect hidden input with javascript'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)(\\"|\'|)\\s*alert\\(.*?\\);?(\\\\"|\'|)',
    'Detect alert() usage'
))

cursor.execute("""
    INSERT INTO rule (rule_type, rule_execution, rule_description) 
    VALUES (%s, %s, %s);
""", (
    'XSS',
    '(?i)<.*?form.*?action=.*?javascript:.*?>',
    'Detect form with javascript action'
))


cursor.execute('''
    INSERT INTO action (action_name, action_type, action_configuration)
    VALUES (%s, %s, %s);
''', (
    'test-webhook',
    'webhook',
    '{"type": "default", "message": "Test"}'
))

cursor.execute('''
    INSERT INTO sqli (rule_name, is_enabled, target_field, ip_root_cause_field, regex_matcher, action_id)
    VALUES (%s, %s, %s, %s, %s, %s);
''', (
    'my-rule-1',
    True,
    'request.body',
    'client.ip',
    '',
    1
))

cursor.execute('''
    INSERT INTO sqli (rule_name, is_enabled, target_field, ip_root_cause_field, regex_matcher, rule_library, action_id)
    VALUES (%s, %s, %s, %s, %s, %s, %s);
''', (
    'my-rule-2',
    True,
    'request.body',
    'client.ip',
    '(?i)\\b(OR|AND)\\s+\\d+=\\d+',
    None,
    1
))

if connection:
    cursor.close()
    connection.close()