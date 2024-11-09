from flask import request
from flask_restful import Resource
from json import dumps, loads
from requests import get
from ...sql import psql_cursor


class ActionUpdate(Resource):
    def put(self, id):
        if id is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'ID is required'
            }, 400
        psql_cursor.execute(f"SELECT * FROM action WHERE id = {id};")
        action = psql_cursor.fetchone()
        if action is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'NotFound'
            }, 404
        try:
            loads(request.data)
        except:
            return {
                'type': 'action',
                'data': None,
                'reason': 'Body must be JSON'
            }, 400
        request_body = dict(request.get_json())

        action_name = request_body.get("actionName")
        action_configuration = loads(request_body.get("actionConfiguration"))

        if not all([action_name, action_configuration]):
            return {
                'type': 'action',
                'data': None,
                'reason': 'Missing required fields'
            }, 400
        if not isinstance(action_configuration, dict):
            return {
                'type': 'action',
                'data': None,
                'reason': 'Invalid configuration format'
            }, 400
        if action[2] == 'webhook':
            url = action_configuration.get("url")
            type = action_configuration.get("type")
            method = action_configuration.get('method')
            if not url:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': '"url" field is required'
                }, 400
            if not type:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': '"type" field is required'
                }, 400
            if type not in ['default', 'custom']:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': '"type" field must be in [default, custom]'
                }, 406
            if type == 'custom':
                body = action_configuration.get('body')
                if not body:
                    return {
                        'type': 'action',
                        'data': None,
                        'reason': '"body" field is required for custom type'
                    }, 400
                if not isinstance(body, dict):
                    return {
                        'type': 'action',
                        'data': None,
                        'reason': '"body" field must be JSON for custom type'
                    }, 400
            if not method:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': '"method" is required'
                }, 400
            if method.lower() not in ['post', 'get', 'put', 'patch', 'delete']:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': '"method" must be in [POST, GET, PUT, PATCH, DELETE]'
                }, 400
            try:
                headers = {"Content-Type": "application/json"}
                response = get(url, headers=headers, json={})
                if response.status_code != 200:
                    return {
                        'type': 'action',
                        'data': None,
                        'reason': "Webhook test failed with status code: " + str(response.status_code)
                    }, 400
            except:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': "GET request to webhook for testing fail"
                }, 500
        if action[2] == 'email':
            return {
                'type': 'action',
                'data': None,
                'reason': 'Success'
            }
        old_action_name = action[1]
        old_action_configuration = action[3]
        action_name_flag = False
        action_configuration_flag = False
        if old_action_name != action_name:
            psql_cursor.execute(f"SELECT action_name FROM action WHERE action_name = '{action_name}';")
            result = psql_cursor.fetchone()
            if result is not None:
                return {
                    'type': 'action',
                    'data': None,
                    'reason': 'Action Name is exist'
                }, 406
            old_action_name = action_name
            action_name_flag = True
        if old_action_configuration != action_configuration:
            old_action_configuration = action_configuration
            action_configuration_flag = True
        if action_name_flag is True or action_configuration_flag is True:
            psql_cursor.execute(f'''
                UPDATE action SET action_name = %s, action_configuration = %s WHERE id = {id};
            ''', (old_action_name, dumps(old_action_configuration)))
        return {
            'type': 'action',
            'data': {
                'id': action[0],
                'action_name': old_action_name,
                'action_type': action[2],
                'action_configuration': old_action_configuration
            },
            'reason': 'Success'
        }
