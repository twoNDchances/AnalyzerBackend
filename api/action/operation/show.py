from flask_restful import Resource
from ...sql import psql_cursor


class ActionShow(Resource):
    def get(self, id):
        if id is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'ID is required'
            }, 400
        psql_cursor.execute(f'SELECT * FROM action WHERE id = {id};')
        row = psql_cursor.fetchone()
        if row is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'NotFound'
            }, 404
        sqli_related_actions = []
        psql_cursor.execute(f'SELECT rule_name FROM sqli WHERE action_id = {id};')
        sqlis = psql_cursor.fetchall()
        if sqlis.__len__() > 0:
            for sqli in sqlis:
                sqli_related_actions.append(sqli[0])

        xss_related_actions = []
        psql_cursor.execute(f'SELECT rule_name FROM xss WHERE action_id = {id};')
        xsss = psql_cursor.fetchall()
        if xsss.__len__() > 0:
            for xss in xsss:
                xss_related_actions.append(xss[0])
        action = {
            'id': row[0],
            'action_name': row[1],
            'action_type': row[2],
            'action_configuration': row[3],
            'rule_related': {
                'sqli': sqli_related_actions,
                'xss': xss_related_actions
            }
        }
        return {
            'type': 'action',
            'data': action,
            'reason': 'Success'
        }