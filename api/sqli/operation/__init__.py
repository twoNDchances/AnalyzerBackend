from flask import Blueprint
from flask_restful import Api
from .list import SQLInjectionRuleList
from .create import SQLInjectionRuleCreation
from .show import SQLInjectionRuleDetails
from .update import SQLInjectionRuleUpdate
from .delete import SQLInjectionRuleDelete


sqli_operation_blueprint = Blueprint(name='sqli_operation_blueprint', import_name=__name__)
sqli_operation_api = Api(app=sqli_operation_blueprint)

sqli_operation_api.add_resource(SQLInjectionRuleList, '/list')
sqli_operation_api.add_resource(SQLInjectionRuleCreation, '/create')
sqli_operation_api.add_resource(SQLInjectionRuleDetails, '/show/<string:id>')
sqli_operation_api.add_resource(SQLInjectionRuleUpdate, '/update/<string:id>')
sqli_operation_api.add_resource(SQLInjectionRuleDelete, '/delete/<string:id>')
