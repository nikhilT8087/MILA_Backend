#profile_controller.py:

from bson import ObjectId
from config.db_config import user_collection, onboarding_collection
from core.utils.response_mixin import CustomResponseMixin
from core.utils.age_calculation import calculate_age
from api.controller.files_controller import save_file, generate_file_url
from datetime import date, datetime

response = CustomResponseMixin()


async def get_user_profile_controller(current_user: dict, lang: str = "en"):
    """
    Fetch profile using User + Onboarding data
    """
    user = await user_collection.find_one(
        {"_id": ObjectId(current_user["_id"])}
    )
    if not user:
        return response.error_message("User not found", status_code=404)

    onboarding = await onboarding_collection.find_one(
        {"user_id": str(user["_id"])}
    )
    print("onboarded user: ", onboarding)
    age = None
    if onboarding and onboarding.get("birthdate"):
        age = calculate_age(onboarding["birthdate"])

    verification_status = user.get("is_verified")
    membership_type = user.get("membership_type", "free")

    if verification_status == True:
        screen_state = "verified_user"
    elif verification_status == False:
        screen_state = "unverified_rejected"
    else:
        screen_state = "unverified_pending"

    public_gallery = onboarding.get("public_gallery", []) if onboarding else []
    private_gallery = onboarding.get("private_gallery", []) if onboarding else []

    private_gallery_locked = membership_type == "free"

    tokens = onboarding.get("tokens", 0) if onboarding else 0

    return response.success_message(
        "Profile fetched successfully",
        data=[{
            "name": user.get("username"),
            "age": age,
            "email": user.get("email"),
            "profile_photo": onboarding.get("selfie_image") if onboarding else None,
            "screen_state": screen_state,
            "verification": {
                "status": verification_status,
                "show_badge": verification_status == "verified",
                "show_retry": verification_status == "rejected",
            },
            "tokens": tokens,
            "membership": {
                "type": membership_type,
                "show_upgrade": membership_type == "free"
            },
            "public_gallery": {
                "items": public_gallery,
                "count": len(public_gallery)
            },
            "private_gallery": {
                "items": [] if private_gallery_locked else private_gallery,
                "count": len(private_gallery),
                "locked": private_gallery_locked
            },
            "menu": {
                "basic_details": True,
                "favourites": True,
                "subscription_billing": True,
                "notifications": True,
                "change_language": True,
                "logout": True
            }
        }],
        status_code=200
    )

async def upload_public_gallery_controller(images, current_user):
    """
    Public Gallery Rules:
    - Multiple images allowed
    - No price
    - Max 5 images (BRD)
    """

    if not images:
        return response.error_message("No images provided", 400)

    if len(images) > 5:
        return response.error_message(
            "Maximum 5 public gallery images allowed",
            400
        )

    public_items = []

    for image in images:
        public_url, storage_key, backend = await save_file(
            file_obj=image,
            file_name=image.filename,
            user_id=str(current_user["_id"]),
            file_type="public_gallery"
        )

        public_items.append({
            "image_url": public_url,
            "storage_key": storage_key,
            "backend": backend,
            "uploaded_at": datetime.utcnow()
        })
        
    await onboarding_collection.update_one(
        {"user_id": str(current_user["_id"])},
        {
            "$push": {
                "public_gallery": {
                    "$each": public_items
                }
            },
            "$set": {"updated_at": datetime.utcnow()}
        }
    )
    return response.success_message(
        "Public gallery images uploaded successfully",
        data={"count": len(public_items)},
        status_code=200
    )

async def upload_private_gallery_controller(image, price, current_user):
    """
    Private Gallery Rules (UPDATED):
    - Single image per upload
    - Price required
    - Free users: max 3 images
    - Premium users: max 20 images
    """

    if price <= 0:
        return response.error_message(
            "Price must be greater than zero",
            400
        )

    onboarding = await onboarding_collection.find_one(
        {"user_id": str(current_user["_id"])},
        {"private_gallery": 1}
    )

    existing_count = len(onboarding.get("private_gallery", [])) if onboarding else 0
    membership = current_user.get("membership_type")

    max_limit = 3 if membership == "free" else 20

    if existing_count >= max_limit:
        return response.error_message(
            f"Private gallery limit reached. Upgrade to premium to add more photos.",
            403 if membership == "free" else 400
        )

    public_url, storage_key, backend = await save_file(
        file_obj=image,
        file_name=image.filename,
        user_id=str(current_user["_id"]),
        file_type="private_gallery"
    )

    private_item = {
        "image_url": public_url,
        "price": price,
        "storage_key": storage_key,
        "backend": backend,
        "uploaded_at": datetime.utcnow().isoformat()
    }

    await onboarding_collection.update_one(
        {"user_id": str(current_user["_id"])},
        {
            "$push": {"private_gallery": private_item},
            "$set": {"updated_at": datetime.utcnow()}
        }
    )

    return response.success_message(
        "Private gallery image uploaded successfully",
        data={
            **private_item,
            "remaining_slots": max_limit - (existing_count + 1)
        },
        status_code=200
    )

async def get_public_gallery_controller(current_user):
    onboarding = await onboarding_collection.find_one(
        {"user_id": str(current_user["_id"])},
        {"public_gallery": 1}
    )

    gallery = onboarding.get("public_gallery", []) if onboarding else []

    result = []

    for item in gallery:
        image_url = (
            # item.get("image_url")
            await generate_file_url(item["storage_key"], item["backend"])
        )

        result.append({
            "image_url": image_url,
        })

    return response.success_message(
        "Public gallery fetched successfully",
        data={
            "count": len(result),
            "items": result
        },
        status_code=200
    )

async def get_private_gallery_controller(current_user):
    onboarding = await onboarding_collection.find_one(
        {"user_id": str(current_user["_id"])},
        {"private_gallery": 1}
    )

    gallery = onboarding.get("private_gallery", []) if onboarding else []

    membership = current_user.get("membership_type", "free")
    max_limit = 3 if membership == "free" else 20

    result = []

    for item in gallery:
        image_url = (
            item.get("image_url")
            or await generate_file_url(item["storage_key"], item["backend"])
        )

        result.append({
            "image_url": image_url,
            "price": item.get("price"),
        })

    return response.success_message(
        "Private gallery fetched successfully",
        data={
            "count": len(result),
            "limit": max_limit,
            "membership": membership,
            "remaining_slots": max_limit - len(result),
            "items": result
        },
        status_code=200
    )

