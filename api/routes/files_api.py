
from fastapi import Query, Request
from api.controller.files_controller import *
from schemas.response_schema import Response
from fastapi import UploadFile
from fastapi import APIRouter, UploadFile, File as UploadFileField, Depends
from typing import Optional
from fastapi import Form
from fastapi import Body


ALLOWED_FILE_TYPES = ["profile_photo", "document", "pdf", "csv", "docx", "image"]
router = APIRouter()
supported_langs = ["en", "fr"]

#api to upload-profile-photo for a user
@router.post("/upload-profile-photo")
async def upload_profile_photo(
    file: UploadFile = UploadFileField(...),
    overwrite: bool = Query(False),
    lang: str = Query(None),
    current_user: dict = Depends(UserPermission(allowed_roles=["user", "admin"]))
):
    lang = lang if lang in supported_langs else "en"
    return await upload_profile_photo_controller(current_user, file, file.filename, overwrite, lang)


#api to get-profile-photo for a user
@router.get("/profile-photo")
async def get_profile_photo(
    lang: str = Query(None),
    current_user: dict = Depends(UserPermission(allowed_roles=["user", "admin"]))
):
    lang = lang if lang in supported_langs else "en"
    return await get_profile_photo_controller(current_user, lang)


#api to upload-files for a user
@router.post("/upload-file", response_model=Response)
async def upload_file(
    request: Request,
    # file: Optional[UploadFile] = File(None),   # file for multipart
    file: Optional[UploadFile] = UploadFileField(None),
    file_type: Optional[str] = Form(None),
    file_name: Optional[str] = Form(None),
    file_content: Optional[str] = Body(None),
    current_user: dict = Depends(UserPermission(allowed_roles=["user", "admin"])),
    lang: str = Query(None)
):
    """
    Supports both:
    1. multipart/form-data (file upload)
    2. JSON body (base64 encoded content)
    """
    lang = lang if lang in supported_langs else "en"

    # Handle multipart upload
    if file:
        file_name = file.filename
        file_type = file_type or "document"
        file_obj = file

    # Handle JSON base64 upload
    elif file_content and file_name and file_type:
        if file_type not in ALLOWED_FILE_TYPES:
            return response.error_message(f"Invalid file_type '{file_type}'", data={}, status_code=400)
        file_bytes = b64decode(file_content)
        file_obj = StarletteUploadFile(BytesIO(file_bytes), filename=file_name, content_type="application/octet-stream")
    
    else:
        return response.error_message(
            "No valid file provided. Use multipart/form-data or JSON body with base64 content.",
            data={}, status_code=400
        )

    # Validate file_type
    if file_type not in ALLOWED_FILE_TYPES:
        return response.error_message(f"Invalid file_type '{file_type}'", data={}, status_code=400)

    return await upload_file_controller(
        current_user=current_user,
        file_obj=file_obj,
        file_name=file_name,
        file_type=file_type,
        lang=lang
    )


#api to get files or specific file for a user
@router.get("/user-files", response_model=Response)
async def get_user_files(
    file_type: Optional[str] = None, 
    current_user: dict = Depends(UserPermission(allowed_roles=["user","admin"])),
    lang: str = Query(None)
):
    lang = lang if lang in supported_langs else "en"
    """
    Route to fetch user files.
    Calls controller with optional file_type filter.
    """
    
    return await get_user_files_controller(current_user, file_type,lang)


#api to delete-file for a user
@router.delete("/delete-user-file/{file_id}")
async def delete_user_file(
    file_id: str,
    current_user: dict = Depends(UserPermission(allowed_roles=["user","admin"])),
    lang: str = Query(None)
):
    lang = lang if lang in supported_langs else "en"
    """
    Delete a specific uploaded file (not profile photo) for the current user.
    """
    return await delete_user_file_controller(file_id, current_user["_id"],lang)