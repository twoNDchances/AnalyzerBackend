from flask import jsonify
from flask_restful import Resource
from ...sql import psql_cursor


class CrossSiteScriptingRuleList(Resource):
    def get(self):
        psql_cursor.execute("SELECT * FROM xss;")
        xss_rows = psql_cursor.fetchall()
        if len(xss_rows) == 0:
            return {
                'type': 'xss',
                'data': [],
                'reason': 'NotFound'
            }, 404
        xsss = []
        for row in xss_rows:
            xss = {
                'id': row[0],
                'rule_name': row[1],
                'is_enabled': row[2],
                'target_field': row[3],
                'ip_root_cause_field': row[4],
                'regex_matcher': 'Defined' if len(row[5]) > 0 else 'Undefined',
                'rule_library': row[6] if row[6] is not None else 'Not Used',
                'action_id': self.get_action_type_by_id(id=row[7])[0] if row[7] is not None else 'Inaction'
            }
            xsss.append(xss)
        return jsonify({
            'type': 'xss',
            'data': xsss,
            'reason': 'Success'
        })

    def get_action_type_by_id(self, id: int):
        psql_cursor.execute("SELECT action_type FROM action WHERE id = %s;", (id,))
        result = psql_cursor.fetchone()
        return result
