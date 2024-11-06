from flask import Blueprint
from flask_restful import Api
from .list import SQLInjectionRuleList
from .create import SQLInjectionRuleCreation


sqli_operation_blueprint = Blueprint(name='sqli_operation_blueprint', import_name=__name__)
sqli_operation_api = Api(app=sqli_operation_blueprint)

sqli_operation_api.add_resource(SQLInjectionRuleList, '/list')
sqli_operation_api.add_resource(SQLInjectionRuleCreation, '/create')
