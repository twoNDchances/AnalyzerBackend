from flask import request
from flask_restful import Resource
from json import loads
from ...sql import psql_cursor


class RuleInheritance(Resource):
    def get(self):
        psql_cursor.execute('SELECT * FROM rule;')
        rows = psql_cursor.fetchall()
        if rows.__len__() == 0:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'NotFound'
            }, 404
        psql_cursor.execute('SELECT DISTINCT rule_type FROM rule;')
        rows = psql_cursor.fetchall()
        return {
            'type': 'rule',
            'data': [row[0] for row in rows],
            'reason': 'Success'
        }
    
    def post(self):
        try:
            loads(request.data)
        except:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        rule_type = request_body.get('ruleType')
        rule_library = request_body.get('ruleLibrary')
        rule_execution = request_body.get('ruleExecution')
        rule_description = request_body.get('ruleDescription')
        if not rule_type:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'Rule Type is required'
            }, 400
        if not rule_execution:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'Rule Execution is required'
            }, 400
        if not rule_description:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'Rule Description is required'
            }, 400
        psql_cursor.execute(f"SELECT DISTINCT rule_type FROM rule WHERE rule_type = '{rule_type}';")
        rule = psql_cursor.fetchone()
        if rule is not None:
            return {
                'type': 'rule',
                'data': None,
                'reason': 'Rule Type is exist'
            }, 406
        rule_holder = []
        if rule_library:
            if isinstance(rule_library, str):
                psql_cursor.execute(f"SELECT rule_execution, rule_description FROM rule WHERE rule_type = '{rule_library}';")
                rule_holder = psql_cursor.fetchall()
            if isinstance(rule_library, list):
                for each_rule in rule_library:
                    psql_cursor.execute(f"SELECT rule_execution, rule_description FROM rule WHERE rule_type = '{each_rule}';")
                    rule_holder = rule_holder + psql_cursor.fetchall()
        if isinstance(rule_execution, str) and isinstance(rule_description, str):
            if rule_execution.__len__() == 0 or rule_description.__len__() == 0:
                return {
                    'type': 'rule',
                    'data': None,
                    'reason': 'Both Rule Execution and Rule Description is required'
                }, 406
            psql_cursor.execute('''
                INSERT INTO rule (rule_type, rule_execution, rule_description)
                VALUES (%s, %s, %s)
            ''', (rule_type, rule_execution, rule_description))
        else:
            if isinstance(rule_execution, list) and isinstance(rule_description, list):
                for rule_exec, rule_descr in zip(rule_execution, rule_description):
                    if rule_exec.__len__() == 0 or rule_descr.__len__() == 0:
                        return {
                            'type': 'rule',
                            'data': None,
                            'reason': 'Both Rule Execution and Rule Description is required'
                        }, 406
                    psql_cursor.execute('''
                        INSERT INTO rule (rule_type, rule_execution, rule_description)
                        VALUES (%s, %s, %s)
                    ''', (rule_type, rule_exec, rule_descr))
            else:
                return {
                    'type': 'rule',
                    'data': None,
                    'reason': 'Both Rule Execution and Rule Description is required'
                }, 406
        for rule_hold in rule_holder:
            psql_cursor.execute('''
                INSERT INTO rule (rule_type, rule_execution, rule_description)
                VALUES (%s, %s, %s)
            ''', (rule_type, rule_hold[0], rule_hold[1]))
        return {
            'type': 'rule',
            'data': None,
            'reason': 'Success'
        }