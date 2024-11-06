from flask import Blueprint, request
from json import loads
from .operation import sqli_operation_blueprint
from ..sql import psql_cursor
from ..functions import get_value_from_json, parse_path, is_valid_regex, re, traverse_json


sqli_main_blueprint = Blueprint(name='sqli_main_blueprint', import_name=__name__)

sqli_main_blueprint.register_blueprint(blueprint=sqli_operation_blueprint, url_prefix='/sqli')

sqli_analyzer_blueprint = Blueprint(name='sqli_analyzer_blueprint', import_name=__name__)

@sqli_analyzer_blueprint.route('/sqli/<string:rule_name>', methods=['POST'])
def sqli_analyzer_endpoint(rule_name: str):
    psql_cursor.execute(f"SELECT * FROM sqli WHERE rule_name = '{rule_name}'")
    row = psql_cursor.fetchone()
    if row is None:
        return {
            'type': 'sqli_analyzer',
            'data': None,
            'reason': 'NotFound'
        }, 404
    try:
        loads(request.data)
    except:
        return {
            'type': 'sqli_analyzer',
            'data': None,
            'reason': 'Body must be JSON'
        }, 400
    if row[2] is False:
        return {
            'type': 'sqli_analyzer',
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
    all_fields = traverse_json(data=json)
    if ip_root_cause_field_validation is None or str(type(ip_root_cause_field_validation)) != "<class 'str'>":
        error_logs.append({
            'message': 'IP Root Cause Field is invalid format',
            'pattern': ip_root_cause_field
        })
    else:
        ip_root_cause_field_value = get_value_from_json(data=json, path=ip_root_cause_field)
        if ip_root_cause_field_value is None or str(type(ip_root_cause_field_value)) != "<class 'str'>":
            error_logs.append({
                'message': 'IP Root Cause Field is not exist or invalid data type',
                'pattern': ip_root_cause_field
            })
    if regex_matcher.__len__() > 0:
        if is_valid_regex(pattern=regex_matcher) is False:
            error_logs.append({
                'message': 'Regex Matcher is invalid',
                'pattern': regex_matcher
            })
        else:
            rules.append(re.compile(rf'{regex_matcher}'))
    if rule_library != 'not_used':
        psql_cursor.execute("SELECT id, rule_type, rule_execution FROM rule WHERE rule_type = '{rule_library}';".format(rule_library=rule_library))
        rule_executions = psql_cursor.fetchall()
        for rule_execution in rule_executions:
            if is_valid_regex(pattern=rule_execution[2]) is False:
                error_logs.append({
                    'message': f'Rule id {rule_execution[0]} is invalid from {rule_execution[1]}',
                    'pattern': rule_execution[2]
                })
            else:
                rules.append(re.compile(rf'{rule_execution[2]}'))
    if target_field.__len__() == 0:
        if all_fields.__len__() > 0:
            flag = False
            for field in all_fields:
                for key, value in field.items():
                    for rule in rules:
                        if rule.search(str(value)):
                            result = {
                                'message': f'Detected from {rule_name} analyzer',
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
                'type': 'sqli_analyzer',
                'data': result,
                'reason': 'Potential SQL Injection detected'
            } if result is not None else {
                'type': 'sqli_analyzer',
                'data': None,
                'reason': 'Clean log'
            }
        else:
            return {
                'type': 'sqli_analyzer',
                'data': None,
                'reason': 'No log'
            }
    else:
        target_field_path = parse_path(path=target_field)
        if str(type(target_field_path)) == "<class 'str'>":
            json_value = get_value_from_json(data=json, path=target_field)
            if json_value is not None:
                json_value_str = str(json_value)
                for rule in rules:
                    if rule.search(json_value_str):
                        result = {
                            'message': f'Detected from {rule_name} analyzer',
                            'field_name': target_field,
                            'field_value': json_value_str,
                            'by_rule': str(rule),
                            'ip_root_cause': ip_root_cause_field_value
                        }
                        break
                return {
                    'type': 'sqli_analyzer',
                    'data': result,
                    'reason': 'Potential SQL Injection detected'
                } if result is not None else {
                    'type': 'sqli_analyzer',
                    'data': None,
                    'reason': 'Clean log'
                }
            else:
                error_logs.append({
                    'message': 'Target Field is not exist',
                    'pattern': f'{target_field}'
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
                        'type': 'sqli_analyzer',
                        'data': result,
                        'reason': 'Potential SQL Injection detected'
                    } if result is not None else {
                        'type': 'sqli_analyzer',
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
        'type': 'sqli_analyzer',
        'data': None,
        'reason': 'Success'
    }
    # if target_field.__len__() == 0:
    #     if regex_matcher.__len__() > 0:
    #         if is_valid_regex(pattern=regex_matcher) is False:
    #             error_logs.append({
    #                 'message': 'Regex Matcher is invalid',
    #                 'pattern': regex_matcher
    #             })
    #         else:
    #             rules.append(re.compile(rf'{regex_matcher}'))
    #     if rule_library != 'not_used':
    #         psql_cursor.execute("SELECT id, rule_type, rule_execution FROM rule WHERE rule_type = '{rule_library}';".format(rule_library=rule_library))
    #         rule_executions = psql_cursor.fetchall()
    #         for rule_execution in rule_executions:
    #             if is_valid_regex(pattern=rule_execution[2]) is False:
    #                 error_logs.append({
    #                     'message': f'Rule id {rule_execution[0]} is invalid from {rule_execution[1]}',
    #                     'pattern': rule_execution[2]
    #                 })
    #             else:
    #                 rules.append(re.compile(rf'{rule_execution[2]}'))
    #     fields = traverse_json(data=json)
    #     if fields.__len__() > 0:
    #         flag = False
    #         for field in fields:
    #             for key, value in field.items():
    #                 for rule in rules:
    #                     if rule.search(str(value)):
    #                         result = {
    #                             'message': f'Detected from {rule_name} analyzer',
    #                             'field_name': key,
    #                             'field_value': value,
    #                             'by_rule': str(rule),
    #                             'ip_root_cause': ip_root_cause_field_value
    #                         }
    #                         flag = True
    #                         break
    #                 if flag:
    #                     break
    #             if flag:
    #                 break
    #     return {
    #         'type': 'sqli_analyzer',
    #         'data': result,
    #         'reason': 'Potential SQL Injection detected'
    #     } if result is not None else {
    #         'type': 'sqli_analyzer',
    #         'data': None,
    #         'reason': 'Clean log'
    #     }
    # else:
    #     target_field_path = parse_path(path=target_field)
    #     if str(type(target_field_path)) == "<class 'str'>":
    #         json_value = get_value_from_json(data=json, path=target_field)
    #         if json_value is not None:
    #             json_value_str = str(json_value)
    #             if regex_matcher.__len__() > 0:
    #                 if is_valid_regex(pattern=regex_matcher) is False:
    #                     error_logs.append({
    #                         'message': 'Regex Matcher is invalid',
    #                         'pattern': regex_matcher
    #                     })
    #                 else:
    #                     rules.append(re.compile(rf'{regex_matcher}'))
    #             if rule_library != 'not_used':
    #                 psql_cursor.execute("SELECT id, rule_type, rule_execution FROM rule WHERE rule_type = '{rule_library}';".format(rule_library=rule_library))
    #                 rule_executions = psql_cursor.fetchall()
    #                 for rule_execution in rule_executions:
    #                     if is_valid_regex(pattern=rule_execution[2]) is False:
    #                         error_logs.append({
    #                             'message': f'Rule id {rule_execution[0]} is invalid from {rule_execution[1]}',
    #                             'pattern': rule_execution[2]
    #                         })
    #                     else:
    #                         rules.append(re.compile(rf'{rule_execution[2]}'))
    #             for rule in rules:
    #                 if rule.search(json_value_str):
    #                     result = {
    #                         'message': f'Detected from {rule_name} analyzer',
    #                         'field_name': target_field,
    #                         'field_value': json_value_str,
    #                         'by_rule': str(rule),
    #                         'ip_root_cause': ip_root_cause_field_value
    #                     }
    #                     break
    #             return {
    #                 'type': 'sqli_analyzer',
    #                 'data': result,
    #                 'reason': 'Potential SQL Injection detected'
    #             } if result is not None else {
    #                 'type': 'sqli_analyzer',
    #                 'data': None,
    #                 'reason': 'Clean log'
    #             }
    #         else:
    #             error_logs.append({
    #                 'message': 'Target Field is not exist',
    #                 'pattern': f'{target_field}'
    #             })
    #     elif str(type(target_field_path)) == "<class 'list'>":
    #         for path in target_field_path:
    #             json_value = get_value_from_json(data=json, path=path)
    #             if json_value is not None:
    #                 json_value_str = str(json_value)
    #                 if regex_matcher.__len__() > 0:
    #                     if is_valid_regex(pattern=regex_matcher) is False:
    #                         error_logs.append({
    #                             'message': 'Regex Matcher is invalid',
    #                             'pattern': regex_matcher
    #                         })
    #                     else:
    #                         rules.append(re.compile(rf'{regex_matcher}'))
    #                 if rule_library != 'not_used':
    #                     psql_cursor.execute("SELECT id, rule_type, rule_execution FROM rule WHERE rule_type = '{rule_library}';".format(rule_library=rule_library))
    #                     rule_executions = psql_cursor.fetchall()
    #                     for rule_execution in rule_executions:
    #                         if is_valid_regex(pattern=rule_execution[2]) is False:
    #                             error_logs.append({
    #                                 'message': f'Rule id {rule_execution[0]} is invalid from {rule_execution[1]}',
    #                                 'pattern': rule_execution[2]
    #                             })
    #                         else:
    #                             rules.append(re.compile(rf'{rule_execution[2]}'))
    #                 for rule in rules:
    #                     if rule.search(json_value_str):
    #                         result = {
    #                             'message': f'Detected from {rule_name} analyzer',
    #                             'field_name': target_field,
    #                             'field_value': json_value_str,
    #                             'by_rule': str(rule),
    #                             'ip_root_cause': ip_root_cause_field_value
    #                         }
    #                         break
    #                 return {
    #                     'type': 'sqli_analyzer',
    #                     'data': result,
    #                     'reason': 'Potential SQL Injection detected'
    #                 } if result is not None else {
    #                     'type': 'sqli_analyzer',
    #                     'data': None,
    #                     'reason': 'Clean log'
    #                 }
    #             else:
    #                 error_logs.append({
    #                     'message': 'Target Field is not exist',
    #                     'pattern': f'{target_field}'
    #                 })
    #     else:
    #         error_logs.append({
    #             'message': 'Target Field is invalid format',
    #             'pattern': f'{target_field}'
    #         })
    # return {
    #     'type': 'sqli_analyzer',
    #     'data': None,
    #     'reason': 'Success'
    # }