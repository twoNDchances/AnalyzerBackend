from flask_restful import Resource
from ...sql import psql_cursor


class ActionDelete(Resource):
    def get(self, id):
        if id is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'ID is required'
            }, 400
        psql_cursor.execute(f'SELECT * FROM action WHERE id = {id};')
        action = psql_cursor.fetchone()
        if action is None:
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
        
        return {
            'type': 'action',
            'data': {
                'sqli': sqli_related_actions,
                'xss': xss_related_actions
            },
            'reason': 'Success'
        }


    def delete(self, id):
        if id is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'ID is required'
            }, 400
        psql_cursor.execute(f'SELECT * FROM action WHERE id = {id};')
        action = psql_cursor.fetchone()
        if action is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'NotFound'
            }, 404
        psql_cursor.execute(f'SELECT id FROM sqli WHERE action_id = {id};')
        sqlis = psql_cursor.fetchall()
        if sqlis.__len__() > 0:
            for sqli in sqlis:
                psql_cursor.execute('UPDATE sqli SET action_id = %s WHERE id = %s', (None, sqli[0]))

        psql_cursor.execute(f'SELECT id FROM xss WHERE action_id = {id};')
        xsss = psql_cursor.fetchall()
        if xsss.__len__() > 0:
            for xss in xsss:
                psql_cursor.execute('UPDATE xss SET action_id = %s WHERE id = %s', (None, xss[0]))
        
        psql_cursor.execute(f'DELETE FROM action WHERE id = {id};')
        return {
            'type': 'action',
            'data': {
                'action_type': action[2],
                'id': action[0]
            },
            'reason': 'Success'
        }