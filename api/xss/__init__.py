from flask import Blueprint, request
from json import loads
from .operation import xss_operation_blueprint
from ..sql import psql_cursor
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, traverse_json


xss_main_blueprint = Blueprint(name='xss_main_blueprint', import_name=__name__)

xss_main_blueprint.register_blueprint(blueprint=xss_operation_blueprint, url_prefix='/xss')

xss_analyzer_blueprint = Blueprint(name='xss_analyzer_blueprint', import_name=__name__)

@xss_analyzer_blueprint.route('/xss/<string:rule_name>', methods=['POST'])
def xss_analyzer_endpoint(rule_name: str):
    psql_cursor.execute("SELECT * FROM xss WHERE rule_name = %s", (rule_name,))
    row = psql_cursor.fetchone()
    if row is None:
        return {
            'type': 'xss_analyzer',
            'data': None,
            'reason': 'Rule Not Found'
        }, 404
    try:
        json_data = loads(request.data)
    except ValueError:
        return {
            'type': 'xss_analyzer',
            'data': None,
            'reason': 'Request body must be JSON'
        }, 400
    if not row[2]:
        return {
            'type': 'xss_analyzer',
            'data': None,
            'reason': 'This analyzer is disabled'
        }
    target_field = row[3]
    ip_root_cause_field = row[4]
    regex_matcher = row[5]
    rule_library = row[6]
    action_id = row[7]
    error_logs = []
    result = None
    json = request.get_json()
    rules = []
    ip_root_cause_field_value = '<>'
    ip_root_cause_field_validation = parse_path(path=ip_root_cause_field)
    if isinstance(ip_root_cause_field_validation, str):
        ip_root_cause_field_value = get_value_from_json(data=json_data, path=ip_root_cause_field)
        if not isinstance(ip_root_cause_field_value, str):
            error_logs.append({
                'message': 'IP Root Cause Field is invalid or missing',
                'pattern': ip_root_cause_field
            })
    else:
        error_logs.append({
            'message': 'IP Root Cause Field has an invalid format',
            'pattern': ip_root_cause_field
        })
    if regex_matcher:
        if is_valid_regex(regex_matcher):
            rules.append(re.compile(regex_matcher))
        else:
            error_logs.append({
                'message': 'Invalid Regex Matcher',
                'pattern': regex_matcher
            })
    if rule_library != 'not_used':
        psql_cursor.execute("SELECT rule_execution FROM rule WHERE rule_type = %s", (rule_library,))
        rule_executions = psql_cursor.fetchall()
        for rule_execution in rule_executions:
            if is_valid_regex(rule_execution[0]):
                rules.append(re.compile(rule_execution[0]))
            else:
                error_logs.append({
                    'message': 'Invalid rule in rule library',
                    'pattern': rule_execution[0]
                })
    if not target_field:
        all_fields = traverse_json(json_data)
        if all_fields.__len__() > 0:
            flag = False
            for field in all_fields:
                for key, value in field.items():
                    for rule in rules:
                        if rule.search(str(value)):
                            result = {
                                'message': f'XSS detected by {rule_name} analyzer',
                                'field_name': key,
                                'field_value': value,
                                'by_rule': str(rule),
                                'ip_root_cause': ip_root_cause_field_value
                            }
                            flag = True
                            break
                    if flag:
                        break
                if flag:
                    break
            return {
                'type': 'xss_analyzer',
                    'data': result,
                    'reason': 'Potential XSS detected'
                }if result is not None else {
                'type': 'xss_analyzer',
                'data': None,
                'reason': 'Log clean'
            }
        else:
            return {
                'type': 'xss_analyzer',
                'data': None,
                'reason': 'No log'
            }
    else:
        target_field_path = parse_path(target_field)
        if isinstance(target_field_path, str):
            json_value = get_value_from_json(json_data, target_field)
            if json_value is not None:
                json_value_str = str(json_value)
                for rule in rules:
                    if rule.search(json_value_str):
                        result = {
                            'message': f'XSS detected by {rule_name} analyzer',
                            'field_name': target_field,       
                            'field_value': json_value,
                            'by_rule': str(rule),
                            'ip_root_cause': ip_root_cause_field_value
                        }
                        break
                return {
                    'type': 'xss_analyzer',
                    'data': result,
                    'reason': 'Potential XSS detected'
                }if result is not None else {
                        'type': 'sqli_analyzer',
                        'data': None,
                        'reason': 'Clean log'
                    }
            else:
                error_logs.append({
                    'message': 'Target Field is missing or invalid',
                    'pattern': target_field
                })
        elif str(type(target_field_path)) == "<class 'list'>":
            for path in target_field_path:
                json_value = get_value_from_json(data=json, path=path)
                if json_value is not None:
                    json_value_str = str(json_value)
                    for rule in rules:
                        if rule.search(json_value_str):
                            result = {
                                'message': f'Detected from {rule_name} analyzer',
                                'field_name': path,
                                'field_value': json_value_str,
                                'by_rule': str(rule),
                                'ip_root_cause': ip_root_cause_field_value
                            }
                            break
                    return {
                        'type': 'xss_analyzer',
                        'data': result,
                        'reason': 'Potential XSS detected'
                    } if result is not None else {
                        'type': 'xss_analyzer',
                        'data': None,
                        'reason': 'Clean log'
                    }
                else:
                    error_logs.append({
                        'message': 'Target Field is not exist',
                        'pattern': f'{path}'
                    })
        else:
            error_logs.append({
                'message': 'Target Field is invalid format',
                'pattern': f'{target_field}'
            })
    return {
        'type': 'xss_analyzer',
        'data': None,
        'reason': 'Success'
    }
