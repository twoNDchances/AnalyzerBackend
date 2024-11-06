from flask import Blueprint
from flask_restful import Api
from .list import ActionList


action_operation_blueprint = Blueprint(name='action_operation_blueprint', import_name=__name__)

action_operation_api = Api(app=action_operation_blueprint)

action_operation_api.add_resource(ActionList, '/list')
