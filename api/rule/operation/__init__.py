from flask import Blueprint
from flask_restful import Api
from .list import RuleLibrary


rule_operation_blueprint = Blueprint(name='rule_operation_blueprint', import_name=__name__)
rule_operation_api = Api(app=rule_operation_blueprint)

rule_operation_api.add_resource(RuleLibrary, '/rule-library')
