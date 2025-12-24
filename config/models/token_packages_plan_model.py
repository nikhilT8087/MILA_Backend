from typing import Any
from bson import ObjectId
from services.translation import translate_message
from core.utils.response_mixin import CustomResponseMixin
from config.db_config import token_packages_plan_collection
response = CustomResponseMixin()

async def get_token_packages_plans():
    return await token_packages_plan_collection.find({'status':'active'}).to_list()

async def get_token_packages_plan(plan_id, lang:str) -> Any:
    """
        get token package plan by id
        """
    packages_plan_data = await token_packages_plan_collection.find_one({"_id": ObjectId(plan_id), "status": "active"})
    if not packages_plan_data:
        return response.error_message(
            translate_message("TOKEN_PACKAGE_PLAN_NOT_FOUND", lang=lang),
            data=[],
            status_code=404,
        )
    return packages_plan_data