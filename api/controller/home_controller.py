
from config.db_config import (
    onboarding_collection,
    user_passed_hostory,
    user_match_history
)

from api.controller.onboardingController import fetch_user_by_id
from bson import ObjectId

async def _get_excluded_user_ids(user_id: str) -> set:
    excluded = {user_id}

    passed = await user_passed_hostory.find_one(
        {"user_id": user_id},
        {"passed_user_ids": 1}
    )
    if passed:
        excluded.update(passed.get("passed_user_ids", []))

    matches = user_match_history.find({"user_ids": user_id})
    async for m in matches:
        excluded.update(m["user_ids"])

    return excluded

async def get_home_suggestions(user_id: str, lang: str = "en"):
    # 1️ Fetch logged-in user onboarding
    user = await onboarding_collection.find_one(
        {"user_id": user_id}
    )

    if not user or not user.get("onboarding_completed"):
        return {
            "count": 0,
            "results": [],
            "message": "Onboarding not completed"
        }

    # 2️ Build exclusion list
    excluded_ids = await _get_excluded_user_ids(user_id)

    # 3️ Strict rule-based match query
    query = {
        "onboarding_completed": True,
        "user_id": {"$nin": list(excluded_ids)},

        # Mutual interest
        "preferred_city":{"$in":user.get("preferred_city" , [])},
        "gender": {"$in": user.get("interested_in", [])},
        "interested_in": {"$in": [user.get("gender")]}
    }

    cursor = onboarding_collection.find(query)

    # 4️ Fetch full details
    results = []
    async for candidate in cursor:
        details = await fetch_user_by_id(candidate["user_id"] , lang="en")
        if details:
            results.append(details)

    return {
        "count": len(results),
        "results": results
    }
