from flask import request
from flask_restful import Resource
from json import loads
from ...sql import psql_cursor


class CrossSiteScriptingRuleCreation(Resource):
    def post(self):
        try:
            loads(request.data)
        except:
            return {
                'type': 'xss',
                'data': None,
                'reason': 'Body must be JSON'
            }, 400
        request_body = dict(request.get_json())
        if (request_body.get('ruleName') and request_body.get('isEnabled') and request_body.get('targetField') and request_body.get('ipRootCauseField') and request_body.get('regexMatcher') and request_body.get('ruleLibrary') and request_body.get('action')) is None:
            return {
                'type': 'xss',
                'data': None,
                'reason': 'Lack of required fields'
            }, 400
        if not request_body['ruleName'] or not request_body['ipRootCauseField']:
            return {
                'type': 'xss',
                'data': None,
                'reason': 'Fill all required fields'
            }, 406
        if request_body['isEnabled'] not in ['true', 'false']:
            return {
                'type': 'xss',
                'data': None,
                'reason': 'Only "true" or "false" is allowed for isEnabled'
            }, 406
        psql_cursor.execute('SELECT DISTINCT rule_type FROM rule;')
        rows = psql_cursor.fetchall()
        rule_types = ['not_used']
        for row in rows:
            rule_types.append(row[0])
        if request_body['ruleLibrary'] not in rule_types:
            return {
                'type': 'xss',
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
                'type': 'xss',
                'data': None,
                'reason': 'Action not found'
            }, 406
        if not request_body['regexMatcher'] and request_body['ruleLibrary'] == 'not_used':
            return {
                'type': 'xss',
                'data': None,
                'reason': 'Regex Matcher cannot be blank if Rule Library is not used and vice versa'
            }, 406
        psql_cursor.execute("SELECT rule_name FROM xss WHERE rule_name = %s;", (request_body['ruleName'],))
        if psql_cursor.fetchone():
            return {
                'type': 'xss',
                'data': None,
                'reason': 'Rule Name already exists'
            }, 406
        psql_cursor.execute("SELECT id FROM action WHERE action_name = '{action_name}';".format(action_name=request_body['action']))
        action_id = psql_cursor.fetchone()
        psql_cursor.execute('''
            INSERT INTO xss (rule_name, is_enabled, target_field, ip_root_cause_field, regex_matcher, rule_library, action_id)
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
            'XSS',
            request_body['ruleName'],
            '{}'
        ))
        return {
            'type': 'xss',
            'data': None,
            'reason': 'Success'
        }
