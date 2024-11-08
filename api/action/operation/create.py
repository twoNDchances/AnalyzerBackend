from flask import request
from flask_restful import Resource
from json import loads, dumps
from requests import get
from ...sql import psql_cursor


class ActionCreate(Resource):
    def post(self, kind):
        if kind is None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'Action Kind required'
            }, 400
        action_list = [
            'webhook',
            'email'
        ]
        if kind not in action_list:
            return {
                'type': 'action',
                'data': None,
                'reason': 'Action Kind not found'
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
        action_configuration = request_body.get("actionConfiguration")

        if not all([action_name, action_configuration]):
            return {
                'type': 'action',
                'data': None,
                'reason': 'Missing required fields'
            }, 400
        psql_cursor.execute(f"SELECT action_name FROM action WHERE action_name = '{action_name}';")
        action = psql_cursor.fetchone()
        if action is not None:
            return {
                'type': 'action',
                'data': None,
                'reason': 'Action Name is exist'
            }, 406
        if not isinstance(action_configuration, dict):
            return {
                'type': 'action',
                'data': None,
                'reason': 'Invalid configuration format'
            }, 400
        if kind == 'webhook':
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
                response = get(url, headers=headers)
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
            psql_cursor.execute(
                """
                INSERT INTO action (action_name, action_type, action_configuration)
                VALUES (%s, 'webhook', %s);
                """,
                (action_name, dumps(action_configuration))
            )
            return {
                'type': 'action',
                'data': None,
                'reason': 'Success'
            }
        if kind == 'email':
            return {
                'type': 'action',
                'data': None,
                'reason': 'Success'
            }
        return {
            'type': 'action',
            'data': None,
            'reason': "Action Kind not found"
        }, 404


