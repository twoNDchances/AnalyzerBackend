from flask_restful import Resource
from ...sql import psql_cursor


class CrossSiteScriptingRuleDelete(Resource):
    def delete(self, id):
        if id is None:
            return {
                'type': 'xss',
                'data': None,
                'reason': 'ID required'
            }, 400
        psql_cursor.execute(f'SELECT id FROM xss WHERE id = {id};')
        result = psql_cursor.fetchone()
        if result is None:
            return {
                'type': 'xss',
                'data': None,
                'reason': 'SQL Injection Rule not found'
            }, 404
        psql_cursor.execute(f'DELETE FROM xss WHERE id = {id};')
        return {
            'type': 'xss',
            'data': {
                'id': id
            },
            'reason': 'Success'
        }
