from fastapi import APIRouter, Depends, Query

from api.controller.admin.admin_token_controller import create_token_package_plan
from core.utils.permissions import AdminPermission
from schemas.token_package_schema import TokenPackagePlanResponseModel, TokenPackageCreateRequestModel

admin_router = APIRouter(prefix="/api/admin/token-plans", tags=["Admin • Token Plans"])
supported_langs = ["en", "fr"]
@admin_router.post("", response_model=TokenPackagePlanResponseModel)
async def create_token_plan(
    request: TokenPackageCreateRequestModel,
    current_user: dict = Depends(AdminPermission(allowed_roles=["admin"])),
    lang: str = Query(None)
):
    """
    Create a new token package plan (Admin only).
    """

    lang = lang if lang in supported_langs else "en"
    user_id = str(current_user["_id"])
    return await create_token_package_plan(request=request, user_id=user_id, lang=lang)
