from psycopg2 import connect, DatabaseError
from gather import PSQL_HOST, PSQL_PORT, PSQL_USER, PSQL_PASS

connection_params = {
    'host': PSQL_HOST,
    'port': PSQL_PORT,
    'database': 'analyzers',
    'user': PSQL_USER,
    'password': PSQL_PASS
}

try:
    connection = connect(**connection_params)
    connection.autocommit = True
    psql_cursor = connection.cursor()
except (Exception, DatabaseError) as error:
    print("Error occurred:", error)
