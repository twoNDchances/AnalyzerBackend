from flask import request, jsonify
from flask_restful import Resource
from ...sql import psql_cursor


class ActionList(Resource):
    def get(self):
        psql_cursor.execute('SELECT * FROM action;')
        rows = psql_cursor.fetchall()
        if rows.__len__() == 0:
            return {
                'type': 'action',
                'data': [],
                'reason': 'NotFound'
            }, 404
        if request.args.get('actionName') is not None:
            return {
                'type': 'action',
                'data': [row[1] for row in rows],
                'reason': 'Success'
            }
        return jsonify({
            'type': 'action',
            'data': [{
                'id': row[0],
                'action_name': row[1],
                'action_type': row[2],
                'action_configuration': row[3]
            } for row in rows],
            'reason': 'Success'
        })
