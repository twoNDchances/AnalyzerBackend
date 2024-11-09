from flask import Blueprint
from flask_restful import Api
from .list import ActionList
from .create import ActionCreate
from .show import ActionShow
from .update import ActionUpdate
from .delete import ActionDelete


action_operation_blueprint = Blueprint(name='action_operation_blueprint', import_name=__name__)

action_operation_api = Api(app=action_operation_blueprint)

action_operation_api.add_resource(ActionList, '/list')
action_operation_api.add_resource(ActionCreate, '/create/<string:kind>')
action_operation_api.add_resource(ActionShow, '/show/<string:id>')
action_operation_api.add_resource(ActionUpdate, '/update/<string:id>')
action_operation_api.add_resource(ActionDelete, '/delete/<string:id>')
