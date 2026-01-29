from fastapi import APIRouter, Query, Depends
from typing import Optional
from api.controller.user_management_controller import * 
from schemas.user_management_schema import *
from core.utils.permissions import AdminPermission
from api.controller.admin.dashboard_controller import get_dashboard_controller
from core.utils.core_enums import DashboardFilter

adminrouter = APIRouter(prefix="/dashboard")


@adminrouter.get("/details")
async def get_dashboard(
    filter_type: DashboardFilter = DashboardFilter.MONTHLY,
    lang: str = "en",
    admin: dict = Depends(AdminPermission(allowed_roles=["admin"]))
):
    return await get_dashboard_controller(
        filter_type=filter_type,
        lang=lang
    )
