from bson import ObjectId

from config.db_config import token_packages_plan_collection
from config.models.token_packages_plan_model import store_token_packages_plan, update_token_package_plan, \
    soft_delete_token_package_plan, get_token_packages_plans
from core.utils.core_enums import TokenPlanStatus
from core.utils.exceptions import CustomValidationError
from core.utils.helper import convert_objectid_to_str, serialize_datetime_fields, calculate_usdt_amount
from schemas.token_package_schema import TokenPackageCreateRequestModel, TokenPackagePlanCreateModel, \
    TokenPackagePlanResponseModel, TokenPackagePlanUpdateRequestModel
from core.utils.response_mixin import CustomResponseMixin
from services.translation import translate_message

response = CustomResponseMixin()


async def create_token_package_plan(request:TokenPackageCreateRequestModel, user_id:str, lang:str):

    try:
        existing_plan = await token_packages_plan_collection.find_one({
            "title": request.title.strip().title()
        })
        if existing_plan:
            raise response.raise_exception(
                translate_message("TOKEN_PACKAGE_PLAN_TITLE_ALREADY_EXISTS", lang=lang),
                status_code=409
            )
        amount = calculate_usdt_amount(int(request.tokens))
        doc = await store_token_packages_plan(
            TokenPackagePlanCreateModel(
                title=request.title.strip().title(),
                amount=str(amount),
                tokens=str(request.tokens)
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

async def update_token_package_plan_controller(
    plan_id: str,
    payload: TokenPackagePlanUpdateRequestModel,
    current_user: dict,
    lang: str
):
    try:
        updated_plan = await update_token_package_plan(
            plan_id=plan_id,
            payload=payload,
            admin_user_id=str(current_user["_id"]),
            lang=lang
        )

        updated_plan = serialize_datetime_fields(updated_plan)
        updated_plan = convert_objectid_to_str(updated_plan)
        data = TokenPackagePlanResponseModel(
            **updated_plan
        ).model_dump()
        return response.success_message(
            translate_message("TOKEN_PLAN_UPDATED_SUCCESSFULLY", lang=lang),
            data=[data]
        )
    except CustomValidationError as error:
        return response.error_message(
            message=error.message,
            data=error.data,
            status_code=error.status_code
        )
    except Exception as e:
        return response.raise_exception(
            translate_message("TOKEN_PACKAGE_PLAN_UPDATE_FAILED", lang=lang),
            data=str(e),
            status_code=500
        )

async def soft_delete_token_package_plan_controller(
    plan_id: str,
    current_user: dict,
    lang: str
):
    try:
        deleted_plan = await soft_delete_token_package_plan(
            plan_id=plan_id,
            admin_user_id=str(current_user["_id"]),
            lang=lang
        )

        return response.success_message(
            translate_message(
                message="TOKEN_PACKAGE_PLAN_DELETED_SUCCESSFULLY",
                lang=lang
            ),
            data=[deleted_plan]
        )
    except CustomValidationError as error:
        return response.error_message(
            message=error.message,
            data=error.data,
            status_code=error.status_code
        )
    except Exception as e:
        return response.raise_exception(
            translate_message(message="TOKEN_PACKAGE_PLAN_DELETE_FAILED", lang=lang),
            data=str(e),
            status_code=500
        )

async def fetch_active_token_package_plans(
    lang: str
):
    """
    Controller to fetch token package plans.
    """

    try:
        token_plans = await get_token_packages_plans(
            condition={
                "status": {
                    "$in": [
                        TokenPlanStatus.active.value,
                        TokenPlanStatus.inactive.value
                    ]
                },
                "$or": [
                    {"deleted": {"$exists": False}},
                    {"deleted": None},
                    {"deleted": False}
                ]
            }
        )
        token_plans = convert_objectid_to_str(token_plans)
        token_plans = serialize_datetime_fields(token_plans)
        return response.success_message(
            translate_message(
                message="TOKEN_PACKAGE_PLANS_FETCHED_SUCCESSFULLY",
                lang=lang
            ),
            data=token_plans
        )

    except Exception as e:
        raise response.raise_exception(
            translate_message(
                message="ERROR_WHILE_FETCHING_TOKEN_PACKAGE_PLANS",
                lang=lang
            ),
            data=str(e),
            status_code=500
        )




