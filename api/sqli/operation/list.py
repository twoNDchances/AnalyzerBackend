from flask import jsonify
from flask_restful import Resource
from ...sql import psql_cursor


class SQLInjectionRuleList(Resource):
    def get(self):
        psql_cursor.execute("SELECT * FROM sqli;")
        sqli_rows = psql_cursor.fetchall()
        if sqli_rows.__len__() == 0:
            return {
                'type': 'sqli',
                'data': [], 
                'reason': 'NotFound'
            }, 404
        sqlis = []
        for row in sqli_rows:
            sqli = {
                'id': row[0],
                'rule_name': row[1],
                'is_enabled': row[2],
                'target_field': row[3],
                'ip_root_cause_field': row[4],
                'regex_matcher': 'Defined' if row[5].__len__() > 0 else 'Undefined',
                'rule_library': row[6] if row[6] is not None else 'Not Used',
                'action_id': self.get_action_type_by_id(id=row[7])[0] if row[7] is not None else 'Inaction'
            }
            sqlis.append(sqli)
        return jsonify({
            'type': 'sqli',
            'data': sqlis,
            'reason': 'Success'
        })

    def get_action_type_by_id(self, id: int):
        psql_cursor.execute(f"SELECT action_type FROM action WHERE id = {id};")
        result = psql_cursor.fetchone()
        return result
