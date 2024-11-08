from flask import Blueprint
from flask_restful import Api
from .list import CrossSiteScriptingRuleList
from .create import CrossSiteScriptingRuleCreation
from .show import CrossSiteScriptingRuleDetails
from .update import CrossSiteScriptingRuleUpdate
from .delete import CrossSiteScriptingRuleDelete


xss_operation_blueprint = Blueprint(name='xss_operation_blueprint', import_name=__name__)
xss_operation_api = Api(app=xss_operation_blueprint)

xss_operation_api.add_resource(CrossSiteScriptingRuleList, '/list')
xss_operation_api.add_resource(CrossSiteScriptingRuleCreation, '/create')
xss_operation_api.add_resource(CrossSiteScriptingRuleDetails, '/show/<string:id>')
xss_operation_api.add_resource(CrossSiteScriptingRuleUpdate, '/update/<string:id>')
xss_operation_api.add_resource(CrossSiteScriptingRuleDelete, '/delete/<string:id>')
