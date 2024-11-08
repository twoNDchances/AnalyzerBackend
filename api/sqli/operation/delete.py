from flask_restful import Resource
from ...sql import psql_cursor


class SQLInjectionRuleDelete(Resource):
    def delete(self, id):
        if id is None:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'ID required'
            }, 400
        psql_cursor.execute(f'SELECT id FROM sqli WHERE id = {id};')
        result = psql_cursor.fetchone()
        if result is None:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'SQL Injection Rule not found'
            }, 404
        psql_cursor.execute(f'DELETE FROM sqli WHERE id = {id};')
        return {
            'type': 'sqli',
            'data': {
                'id': id
            },
            'reason': 'Success'
        }
