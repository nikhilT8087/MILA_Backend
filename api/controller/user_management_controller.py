from bson import ObjectId
from typing import Optional
from datetime import datetime , timedelta
from config.db_config import (user_collection ,
                            onboarding_collection , 
                            file_collection ,
                            countries_collection , 
                            verification_collection , 
                            user_match_history ,
                            user_suspension_collection ,
                            admin_blocked_users_collection,
                            deleted_account_collection)

from api.controller.files_controller import generate_file_url
from core.utils.helper import serialize_datetime_fields
from api.controller.files_controller import generate_file_url
from core.utils.response_mixin import CustomResponseMixin
from core.utils.pagination import StandardResultsSetPagination
from services.translation import translate_message
from core.utils.core_enums import VerificationStatusEnum

response = CustomResponseMixin()

# Get all users table
async def get_admin_users(
    status: Optional[str],
    lang: str = "en",
    search: Optional[str] = None,
    gender: Optional[str] = None,
    country: Optional[str] = None,
    verification: Optional[str] = None,
    membership: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    pagination: StandardResultsSetPagination = None
):
    try:
        pipeline = []

        user_match = {
            "is_deleted": {"$ne": True}
        }

        if status:
            user_match["login_status"] = status

        if membership:
            user_match["membership_type"] = membership

        if date_from or date_to:
            user_match["created_at"] = {}
            if date_from:
                user_match["created_at"]["$gte"] = date_from
            if date_to:
                user_match["created_at"]["$lte"] = date_to

        pipeline.append({"$match": user_match})

        pipeline.append({
            "$addFields": {
                "userIdStr": {"$toString": "$_id"}
            }
        })

        pipeline.extend([
            {
                "$lookup": {
                    "from": "user_onboarding",
                    "localField": "userIdStr",
                    "foreignField": "user_id",
                    "as": "onboarding"
                }
            },
            {"$unwind": "$onboarding"}
        ])

        if search:
            pipeline.append({
                "$match": {
                    "username": {"$regex": search, "$options": "i"}
                }
            })

        if gender:
            pipeline.append({"$match": {"onboarding.gender": gender}})

        if country:
            pipeline.append({"$match": {"onboarding.country": country}})

        pipeline.append({
            "$lookup": {
                "from": "verification_history",
                "let": {"uid": "$userIdStr"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$eq": ["$user_id", "$$uid"]}
                        }
                    },
                    {"$sort": {"verified_at": -1}},
                    {"$limit": 1}
                ],
                "as": "verification"
            }
        })

        pipeline.append({
            "$addFields": {
                "verification_status": {
                    "$cond": {
                        "if": {"$gt": [{"$size": "$verification"}, 0]},
                        "then": {"$arrayElemAt": ["$verification.status", 0]},
                        "else": VerificationStatusEnum.PENDING
                    }
                }
            }
        })

        if verification:
            pipeline.append({
                "$match": {"verification_status": verification}
            })

        pipeline.append({
            "$lookup": {
                "from": "users_matched_history",
                "let": {"uid": "$userIdStr"},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {"$in": ["$$uid", "$user_ids"]}
                        }
                    }
                ],
                "as": "matches"
            }
        })

        pipeline.append({
            "$addFields": {
                "match_count": {"$size": "$matches"}
            }
        })

        pipeline.append({
            "$addFields": {
                "countryObjId": {
                    "$toObjectId": "$onboarding.country"
                }
            }
        })

        pipeline.append({
            "$lookup": {
                "from": "countries",
                "localField": "countryObjId",
                "foreignField": "_id",
                "as": "country"
            }
        })

        pipeline.append({
            "$unwind": {
                "path": "$country",
                "preserveNullAndEmptyArrays": True
            }
        })

        pipeline.extend([
            {"$sort": {"created_at": -1}},
            {"$skip": pagination.skip},
            {"$limit": pagination.limit}
        ])

        pipeline.append({
            "$project": {
                "_id": 0,
                "user_id": {"$toString": "$_id"},

                "username": 1,
                "email": 1,
                "membership_type": 1,
                "login_status": 1,

                "verification_status": 1,
                "match_count": 1,

                "gender": "$onboarding.gender",
                "sexual_orientation": "$onboarding.sexual_orientation",
                "relationship _status": "$onboarding.marital_status",

                "country": {
                    "id": {"$toString": "$country._id"},
                    "name": "$country.name"
                },

                "registration_date": "$created_at"
            }
        })

        results = await user_collection.aggregate(pipeline).to_list(None)

        for user in results:
            if user.get("registration_date"):
                user["registration_date"] = user["registration_date"].isoformat()

        return response.success_message(
            translate_message("USERS_FETCHED_SUCCESSFULLY", lang),
            data=results,
            status_code=200
        )

    except Exception as e:
        return response.error_message(
            translate_message("FAILED_TO_FETCH_USERS", lang),
            data=str(e),
            status_code=500
        )

# Get complete user details (View)
async def get_admin_user_details(user_id: str, lang: str = "en"):
    try:
        # Fetch user
        user = await user_collection.find_one(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}},
            {"password": 0}
        )

        if not user:
            return response.error_message(
                translate_message("USER_NOT_FOUND", lang),
                data=[],
                status_code=404
            )

        # Fetch onboarding
        onboarding = await onboarding_collection.find_one(
            {"user_id": user_id},
            {"_id": 0}
        )


        # Fetch country
        country_data = None
        if onboarding and onboarding.get("country"):
            country = await countries_collection.find_one(
                {"_id": ObjectId(onboarding["country"])},
                {"name": 1}
            )
            if country:
                country_data = {
                    "id": str(country["_id"]),
                    "name": country["name"]
                }


        # Fetch verification (latest)
        verification = await verification_collection.find(
            {"user_id": user_id}
        ).sort("verified_at", -1).limit(1).to_list(1)

        verification_status = (
            verification[0]["status"]
            if verification else VerificationStatusEnum.PENDING
        )


        # Fetch matches + usernames
        matches_cursor = user_match_history.find(
            {"user_ids": user_id}
        )

        matched_user_ids = set()
        async for match in matches_cursor:
            for uid in match.get("user_ids", []):
                if uid != user_id:
                    matched_user_ids.add(uid)

        match_count = len(matched_user_ids)

        matched_users = []
        if matched_user_ids:
            users_cursor = user_collection.find(
                {
                    "_id": {"$in": [ObjectId(uid) for uid in matched_user_ids]},
                    "is_deleted": {"$ne": True}
                },
                {"username": 1}
            )

            async for u in users_cursor:
                matched_users.append({
                    "user_id": str(u["_id"]),
                    "username": u.get("username")
                })


        # Fetch photos
        photos = []
        if onboarding and onboarding.get("images"):
            files = await file_collection.find(
                {"_id": {"$in": [ObjectId(i) for i in onboarding["images"]]}}
            ).to_list(None)

            for f in files:
                url = await generate_file_url(
                    f["storage_key"], f.get("storage_backend")
                )
                photos.append({
                    "id": str(f["_id"]),
                    "url": url
                })


        # Profile photo (first image)
        profile_photo = photos[0] if photos else None


        # Standardized response
        result = {
            "user_id": user_id,

            "username": user.get("username"),
            "email": user.get("email"),
            "profile_photo": profile_photo,

            "verification_status": verification_status,
            "login_status": user.get("login_status"),
            "membership_type": user.get("membership_type"),

            "gender": onboarding.get("gender") if onboarding else None,
            "country": country_data,
            "relationship_status": onboarding.get("marital_status") if onboarding else None,
            "sexual_orientation": onboarding.get("sexual_orientation") if onboarding else None,
            "registration_date": user.get("created_at"),

            "bio": onboarding.get("bio") if onboarding else None,
            "passions": onboarding.get("passions") if onboarding else None,
            "photos": photos,

            "match_count": match_count,
            "matched_users": matched_users
        }

        return response.success_message(
            translate_message("USER_DETAILS_FETCHED_SUCCESSFULLY", lang),
            data=[serialize_datetime_fields(result)],
            status_code=200
        )

    except Exception as e:
        return response.error_message(
            translate_message("FAILED_TO_FETCH_USER_DETAILS", lang),
            data=str(e),
            status_code=500
        )

#Suspend user
async def admin_suspend_user(
    user_id: str,
    days: int,
    admin_id: str,
    lang: str = "en"
):
    try:
        user = await user_collection.find_one(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}}
        )

        if not user:
            return response.error_message(
                translate_message("USER_NOT_FOUND", lang),
                data=[],
                status_code=404
            )
        
        check_already = await user_suspension_collection.find_one(
            {
                "user_id": user_id,
                "suspended_until": {"$gt": datetime.utcnow()}
            }
        )

        if check_already:
            return response.error_message(
                translate_message("USER_ALREADY_SUSPENDED",lang),
                data=[],
                status_code=400
            )

        suspended_from = datetime.utcnow()
        suspended_until = suspended_from + timedelta(days=days)

        # Store suspension history
        await user_suspension_collection.insert_one({
            "user_id": user_id,
            "suspended_by": admin_id,
            "suspended_from": suspended_from,
            "suspended_until": suspended_until,
            "created_at": suspended_from,
            "updated_at": suspended_from
        })

        return response.success_message(
            translate_message("USER_SUSPENDED_SUCCESSFULLY", lang),
            data=[{
                "user_id": user_id,
                "suspended_until": suspended_until.isoformat()
            }],
            status_code=200
        )

    except Exception as e:
        return response.error_message(
            translate_message("FAILED_TO_SUSPEND_USER", lang),
            data=str(e),
            status_code=500
        )

#Block user
async def admin_block_user(
    user_id: str,
    admin_id: str,
    lang: str = "en"
):
    try:
        
        # Check user exists
        
        user = await user_collection.find_one(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}}
        )

        if not user:
            return response.error_message(
                translate_message("USER_NOT_FOUND", lang),
                data=[],
                status_code=404
            )

        
        # Check already blocked
        
        already_blocked = await admin_blocked_users_collection.find_one({
            "user_id": user_id,
        })

        if already_blocked:
            return response.error_message(
                translate_message("USER_ALREADY_BLOCKED", lang),
                data=[],
                status_code=400
            )

        now = datetime.utcnow()

        
        # Block user (PERMANENT)
        
        await admin_blocked_users_collection.insert_one({
            "user_id": user_id,
            "blocked_by": admin_id,
            "created_at": now,
            "updated_at": now
        })

        return response.success_message(
            translate_message("USER_BLOCKED_SUCCESSFULLY", lang),
            data=[{
                "user_id": user_id,
                "blocked_by": admin_id
            }],
            status_code=200
        )

    except Exception as e:
        return response.error_message(
            translate_message("FAILED_TO_BLOCK_USER", lang),
            data=str(e),
            status_code=500
        )

# Delete user account
async def admin_delete_user(
    user_id: str,
    admin_id: str,
    lang: str = "en"
):
    try:
        user = await user_collection.find_one(
            {"_id": ObjectId(user_id), "is_deleted": {"$ne": True}}
        )

        if not user:
            return response.error_message(
                translate_message("USER_NOT_FOUND", lang),
                data=[],
                status_code=404
            )

        email = user.get("email")

        already_delted = await deleted_account_collection.find_one(
            {"user_id": user_id,}
        )
        if already_delted:
            return response.error_message(
                translate_message("ACCOUNT_ALREADY_DELETED",lang),
                data=[],
                status_code=400
            )
        # Store deletion audit record
        
        await deleted_account_collection.insert_one({
            "user_id": user_id,
            "email": email,
            "deleted_by": admin_id,
            "created_at": datetime.now(),
            "updated_at":datetime.now()
        })


        return response.success_message(
            translate_message("ACCOUNT_DELETED_SUCCESSFULLY", lang),
            data=[{
                "user_id": user_id,
                "deleted_by": admin_id
            }],
            status_code=200
        )

    except Exception as e:
        return response.error_message(
            translate_message("FAILED_TO_DELETE_ACCOUNT", lang),
            data=str(e),
            status_code=500
        )
