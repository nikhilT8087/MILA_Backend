from fastapi import APIRouter, Depends, Query, Path
from api.controller.contest_controller import *
from core.utils.permissions import UserPermission
from core.utils.pagination import pagination_params, StandardResultsSetPagination

router = APIRouter(prefix="", tags=["contest"])

@router.get("/active-past-contests")
async def get_contests(
    contest_type: str = Query(..., enum=["active", "past"]),
    pagination: StandardResultsSetPagination = Depends(pagination_params),
    current_user: dict = Depends(UserPermission(["user"])),
    lang: str = Query("en")
):
    """
    Fetch contests for logged-in user

    Query params:
    - contest_type=active
    - contest_type=past
    - page, page_size
    """
    return await get_contests_controller(
        current_user=current_user,
        contest_type=contest_type,
        pagination=pagination,
        lang=lang
    )


@router.get("/contest_details/{contest_id}")
async def get_contest_details(
    contest_id: str = Path(..., description="Contest ID"),
    current_user: dict = Depends(UserPermission(["user"])),
    lang: str = Query("en")
):
    """
    Fetch contest details for logged-in user

    Path params:
    - contest_id

    Response includes:
    - contest status & visibility
    - banner, description, prize pool
    - important dates
    - participants preview
    - current standings (if voting started)
    - CTA state (participate / vote)
    """
    return await get_contest_details_controller(
        contest_id=contest_id,
        current_user=current_user,
        lang=lang
    )