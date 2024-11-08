from flask_restful import Resource
from ...sql import psql_cursor


class SQLInjectionRuleDetails(Resource):
    def get(self, id):
        if not id:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'BadRequest'
            }, 400
        psql_cursor.execute(f'SELECT * FROM sqli WHERE id = {id};')
        result = psql_cursor.fetchone()
        if result is None:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'NotFound'
            }, 404
        psql_cursor.execute('SELECT DISTINCT rule_type FROM rule;')
        rows = psql_cursor.fetchall()
        choice_rules = {
            'choice': 'not_used' if result[6] is None else result[6],
            'rules': [
                row[0] for row in rows
            ]
        }
        psql_cursor.execute('SELECT action_name FROM action;')
        rows = psql_cursor.fetchall()
        choice_actions = {
            'choice': 'not_used' if result[7] is None else self.get_action_name_by_id(id=result[7])[0],
            'actions': [
                row[0] for row in rows
            ]
        }
        return {
            'type': 'sqli',
            'data': {
                'id': result[0],
                'rule_name': result[1],
                'is_enabled': result[2],
                'target_field': result[3],
                'ip_root_cause_field': result[4],
                'regex_matcher': result[5],
                'rule_library': choice_rules,
                'action_id': choice_actions,
                'type_attack': result[8]
            },
            'reason': 'Success'
        }
    
    def get_action_name_by_id(self, id):
        psql_cursor.execute(f"SELECT action_name FROM action WHERE id = {id};")
        result = psql_cursor.fetchone()
        return result

