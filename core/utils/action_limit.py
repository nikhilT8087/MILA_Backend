from datetime import datetime, timedelta
from bson import ObjectId
from config.db_config import (
    user_collection ,
    user_like_history ,
    user_passed_hostory ,
    favorite_collection
)
from core.utils.core_enums import MembershipType
from bson import ObjectId
from datetime import datetime
from core.utils.response_mixin import CustomResponseMixin
from services.translation import translate_message
from config.basic_config import settings

response = CustomResponseMixin()

DAILY_FREE_LIMIT = settings.DAILY_FREE_LIMIT

async def check_daily_action_limit(user_id: str, lang: str = "en"):

    user = await user_collection.find_one(
        {"_id": ObjectId(user_id)},
        {"membership_type": 1}
    )

    if not user:
        return response.error_message(
            translate_message("USER_NOT_FOUND", lang),
            data=[],
            status_code=404
        )

    if user.get("membership_type") == MembershipType.PREMIUM.value:
        return None

    start_of_day = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = start_of_day + timedelta(days=1)

    # likes done by this user
    liked_count = await user_like_history.count_documents({
        "liked_by_user_ids": user_id,
        "updated_at": {"$gte": start_of_day, "$lt": end_of_day}
    })

    # passes done by this user
    passed_doc = await user_passed_hostory.find_one({
        "user_id": user_id,
        "updated_at": {"$gte": start_of_day, "$lt": end_of_day}
    })
    passed_count = len(passed_doc.get("passed_user_ids", [])) if passed_doc else 0

    # favorites done by this user
    fav_doc = await favorite_collection.find_one({
        "user_id": user_id,
        "updated_at": {"$gte": start_of_day, "$lt": end_of_day}
    })
    fav_count = len(fav_doc.get("favorite_user_ids", [])) if fav_doc else 0

    total_actions = liked_count + passed_count + fav_count

    if total_actions >= 10:
        return response.error_message(
            translate_message("DAILY_LIMIT_REACHED", lang),
            data=[],
            status_code=400
        )

    return None