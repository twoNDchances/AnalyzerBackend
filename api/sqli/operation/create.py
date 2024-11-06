from flask import request
from flask_restful import Resource
from json import loads
from ...sql import psql_cursor


class SQLInjectionRuleCreation(Resource):
    def post(self):
        try:
            loads(request.data)
        except:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        if (request_body.get('ruleName') and request_body.get('isEnabled') and request_body.get('targetField') and request_body.get('ipRootCauseField') and request_body.get('regexMatcher') and request_body.get('ruleLibrary') and request_body.get('action')) is None:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Lack of requirement fields'
            }, 400
        if request_body['ruleName'].__len__() == 0 or request_body['ipRootCauseField'].__len__() == 0:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Fill all of requirement fields'
            }, 406
        if request_body['isEnabled'] not in ['true', 'false']:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Only \'true\' or \'false\' for Is Enabled'
            }, 406
        psql_cursor.execute('SELECT DISTINCT rule_type FROM rule;')
        rows = psql_cursor.fetchall()
        rule_types = ['not_used']
        for row in rows:
            rule_types.append(row[0])
        if request_body['ruleLibrary'] not in rule_types:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Rule Library not found'
            }, 406
        psql_cursor.execute('SELECT action_name FROM action;')
        rows = psql_cursor.fetchall()
        action_names = ['not_used']
        for row in rows:
            action_names.append(row[0])
        if request_body['action'] not in action_names:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Action not found'
            }, 406
        if request_body['regexMatcher'].__len__() == 0 and request_body['ruleLibrary'] == 'not_used':
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Regex Matcher cannot be left blank if Rule Library is not used and vice versa'
            }, 406
        psql_cursor.execute("SELECT rule_name FROM sqli WHERE rule_name = '{rule_name}';".format(rule_name=request_body['ruleName']))
        rows = psql_cursor.fetchall()
        if rows.__len__() > 0:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'Rule Name is already exist'
            }, 406
        psql_cursor.execute("SELECT id FROM action WHERE action_name = '{action_name}';".format(action_name=request_body['action']))
        action_id = psql_cursor.fetchone()
        psql_cursor.execute('''
            INSERT INTO sqli (rule_name, is_enabled, target_field, ip_root_cause_field, regex_matcher, rule_library, action_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        ''', (
            request_body['ruleName'],
            request_body['isEnabled'],
            request_body['targetField'],
            request_body['ipRootCauseField'],
            request_body['regexMatcher'],
            request_body['ruleLibrary'],
            action_id
        ))
        psql_cursor.execute('''
            INSERT INTO result (analyzer, reference, log)
            VALUES (%s, %s, %s);
        ''', (
            'SQLI',
            request_body['ruleName'],
            '{}'
        ))
        return {
            'type': 'sqli',
            'data': None,
            'reason': 'Success'
        }
