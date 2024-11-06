from flask import Blueprint
from flask_restful import Api
from .list import CrossSiteScriptingRuleList
from .create import CrossSiteScriptingRuleCreation


xss_operation_blueprint = Blueprint(name='xss_operation_blueprint', import_name=__name__)
xss_operation_api = Api(app=xss_operation_blueprint)

xss_operation_api.add_resource(CrossSiteScriptingRuleList, '/list')
xss_operation_api.add_resource(CrossSiteScriptingRuleCreation, '/create')

