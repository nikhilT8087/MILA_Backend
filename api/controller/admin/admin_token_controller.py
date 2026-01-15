from bson import ObjectId

from config.db_config import token_packages_plan_collection
from config.models.token_packages_plan_model import store_token_packages_plan
from core.utils.exceptions import CustomValidationError
from core.utils.helper import convert_objectid_to_str, serialize_datetime_fields, calculate_usdt_amount
from schemas.token_package_schema import TokenPackageCreateRequestModel, TokenPackagePlanCreateModel, \
    TokenPackagePlanResponseModel
from core.utils.response_mixin import CustomResponseMixin
from services.translation import translate_message

response = CustomResponseMixin()


async def create_token_package_plan(request:TokenPackageCreateRequestModel, user_id:str, lang:str):

    try:
        existing_plan = await token_packages_plan_collection.find_one({
            "title": request.title.title()
        })
        if existing_plan:
            raise response.raise_exception(
                translate_message("TOKEN_PACKAGE_PLAN_TITLE_ALREADY_EXISTS", lang=lang),
                status_code=409
            )
        amount = calculate_usdt_amount(int(request.tokens))
        doc = await store_token_packages_plan(
            TokenPackagePlanCreateModel(
                title=request.title.title(),
                amount=float(amount),
                tokens=int(request.tokens)
            ),
            admin_user=user_id
        )
        doc = serialize_datetime_fields(doc)
        doc = convert_objectid_to_str(doc)
        data = TokenPackagePlanResponseModel(
            **doc
        ).model_dump()

        return response.success_message(
            translate_message("TOKEN_PACKAGE_PLAN_CREATED", lang=lang),
            data=[data],
            status_code=201
        )
    except CustomValidationError as error:
        return response.error_message(
            message=error.message,
            data=error.data,
            status_code=error.status_code
        )
    except Exception as e:
        return response.raise_exception(
            translate_message("TOKEN_PACKAGE_PLAN_CREATION_FAILED", lang=lang),
            data=str(e),
            status_code=500
        )

