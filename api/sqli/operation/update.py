from flask import request
from flask_restful import Resource
from json import loads
from ...sql import psql_cursor


class SQLInjectionRuleUpdate(Resource):
    def put(self, id):
        if id is None:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'ID required'
            }, 400
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
        psql_cursor.execute(f"SELECT * FROM sqli WHERE id = '{id}';")
        result = psql_cursor.fetchone()
        if result is None:
            return {
                'type': 'sqli',
                'data': None,
                'reason': 'SQL Injection Rule is not found for update'
            }, 404
        old_rule_name = result[1]
        old_is_enabled = result[2]
        old_target_field = result[3]
        old_ip_root_cause_field = result[4]
        old_regex_matcher = result[5]
        old_rule_library = result[6]
        old_action_id = result[7] if result[7] != 'not_used' else None
        if old_rule_name != request_body.get('ruleName'):
            psql_cursor.execute("SELECT rule_name FROM sqli WHERE rule_name = '{rule_name}';".format(rule_name=request_body['ruleName']))
            rows = psql_cursor.fetchall()
            if rows.__len__() > 0:
                return {
                    'type': 'sqli',
                    'data': None,
                    'reason': 'Rule Name is already exist'
                }, 406
            old_rule_name = request_body.get('ruleName')

        if old_is_enabled != request_body.get('isEnabled'):
            old_is_enabled = request_body.get('isEnabled')

        if old_target_field != request_body.get('targetField'):
            old_target_field = request_body.get('targetField')

        if old_ip_root_cause_field != request_body.get('ipRootCauseField'):
            old_ip_root_cause_field = request_body.get('ipRootCauseField')

        if old_regex_matcher != request_body.get('regexMatcher'):
            old_regex_matcher = request_body.get('regexMatcher')

        if old_rule_library != request_body.get('ruleLibrary'):
            old_rule_library = request_body.get('ruleLibrary')

        action_id = None

        if request_body.get('action') != 'not_used':
            action_id = self.get_id_by_action_name(action_name=request_body.get('action'))[0]

        if old_action_id != action_id:
            old_action_id = action_id

        psql_cursor.execute('''
            UPDATE sqli SET 
            rule_name = %s, 
            is_enabled = %s, 
            target_field = %s, 
            ip_root_cause_field = %s, 
            regex_matcher = %s, 
            rule_library = %s, 
            action_id = %s
            WHERE id = %s
        ''', (old_rule_name, old_is_enabled, old_target_field, old_ip_root_cause_field, old_regex_matcher, old_rule_library, old_action_id, id))
        print(request.get_json())
        return {
            'type': 'sqli',
            'data': {
                'id': id,
                'rule_name': old_rule_name,
                'is_enabled': old_is_enabled,
                'target_field': old_target_field,
                'ip_root_cause_field': old_ip_root_cause_field,
                'regex_matcher': 'Defined' if old_regex_matcher.__len__() != 0 else 'Undefined',
                'rule_library': old_rule_library if old_rule_library != 'not_used' else 'Not Used',
                'action': self.get_action_type_by_id(id=old_action_id)[0] if old_action_id is not None else 'Inaction'
            },
            'reason': 'Success'
        }
    
    def get_id_by_action_name(self, action_name: int):
        psql_cursor.execute(f"SELECT id FROM action WHERE action_name = '{action_name}';")
        result = psql_cursor.fetchone()
        return result
    
    def get_action_type_by_id(self, id: int):
        psql_cursor.execute(f"SELECT action_type FROM action WHERE id = {id};")
        result = psql_cursor.fetchone()
        return result