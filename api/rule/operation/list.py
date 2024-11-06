from flask import jsonify, request
from flask_restful import Resource
from ...sql import psql_cursor


class RuleLibrary(Resource):
    def get(self):
        psql_cursor.execute('SELECT * FROM rule;')
        rows = psql_cursor.fetchall()
        if rows.__len__() == 0:
            return {
                'type': 'rule',
                'data': [],
                'reason': 'NotFound'
            }, 404
        if request.args.get('ruleType') is not None:
            psql_cursor.execute('SELECT DISTINCT rule_type FROM rule;')
            rows = psql_cursor.fetchall()
            return jsonify({
                'type': 'rule',
                'data': [row[0] for row in rows],
                'reason': 'Success'
            })
        return jsonify({
            'type': 'rule',
            'data': [{
                'id': row[0],
                'rule_type': row[1],
                'rule_execution': row[2],
                'rule_description': row[3]
            } for row in rows],
            'reason': 'Success'
        })