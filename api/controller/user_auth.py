import asyncio
from datetime import datetime, timedelta, date
from io import BytesIO
import json
import re
from typing import List, Optional
import uuid
import bcrypt
import boto3
from api.controller.files_controller import *
from botocore.exceptions import ClientError
from fastapi.responses import StreamingResponse
from bson import ObjectId
from core.utils.auth_utils import *
from fastapi import Request, Header
from jose import jwt,JWTError
from config.models.user_models import PyObjectId, UserCreate, UserRole,  store_token
from core.utils.helper import validate_pwd,validate_new_pwd,validate_confirm_new_password,serialize_datetime_fields,convert_objectid_to_str
from core.utils.rate_limiter import rate_limit_check
from schemas.user_schemas import *
from config.db_config import *
from tasks import send_password_reset_email_task, send_contact_us_email_task
from core.utils.redis_helper import redis_client 
from core.utils.pagination import StandardResultsSetPagination   
from services.translation import translate_message
from core.templates.email_templates import *

AWS_S3_REGION = os.getenv("AWS_S3_REGION")
AWS_S3_BUCKET_NAME = os.getenv("AWS_S3_BUCKET_NAME")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_MINUTES =int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

response = CustomResponseMixin()

#controller for login the user 
async def login(request: Request, lang: str = "en"):
    """
    Authenticate a user using email and password, and return access & refresh tokens.
    Profile photo URL is generated dynamically from Files model.
    """
    try:
        role = request.role
        email = request.email

        # Step 1: Fetch user by email
        user = await user_collection.find_one({"email": email})
        if not user:
            return response.error_message(
                translate_message("INVALID_CREDENTIALS", lang=lang),
                data={}, status_code=400
            )

        # Step 2: Check if account is deleted or deactivated
        if user.get("is_deleted", False):
            return response.error_message(
                translate_message("ACCOUNT_DELETED", lang=lang),
                data={}, status_code=403
            )
        if user.get("is_deactivated", False):
            return response.error_message(
                translate_message("ACCOUNT_DEACTIVATED", lang=lang),
                data={}, status_code=403
            )

        # Step 3: Validate password
        is_password_valid = verify_password(request.password, user["password"])
        if not is_password_valid:
            return response.error_message(
                translate_message("login.invalid_credentials", lang=lang),
                data={}, status_code=400
            )

        # Step 4: Validate role
        user_role = user.get("role", "user")
        if role != user_role:
            return response.error_message(
                translate_message("login.role_mismatch", lang=lang, role=user_role),
                data={}, status_code=403
            )

        # Step 5: Generate tokens
        token_payload = {
            "sub": user["email"],
            "user_id": str(user["_id"]),
            "role": user_role
        }
        access_token = create_access_token(token_payload)
        refresh_token = create_refresh_token(token_payload)

        access_token_expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

        # Step 6: Store tokens
        token_collection.insert_one({
            "user_id": str(user["_id"]),
            "email": user["email"],
            "access_token": access_token,
            "refresh_token": refresh_token,
            "access_token_expire": access_token_expire,
            "refresh_token_expire": refresh_token_expire,
            "is_blacklisted": False,
            "created_at": datetime.utcnow()
        })

        # Step 7: Prepare user data
        user_data = user.copy()
        user_data.pop("password", None)
        user_data["user_id"] = str(user_data.pop("_id"))
        user_data["role"] = user_role

        # Convert any ObjectId in user_data (like profile_photo_id)
        user_data = convert_objectid_to_str(user_data)

        # # Step 8: Get profile photo URL
        profile_url = await get_profile_photo_url(current_user=user)
        user_data["profile_url"] = profile_url if profile_url else None


        # Step 9: Return response
        response_data = {
            "token_type": "bearer",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_data": user_data,
            "role": user_role
        }

        response_data = serialize_datetime_fields(response_data)

        return response.success_message(
            translate_message("LOGIN_SUCCESS", lang=lang),
            data=response_data
        )

    except Exception as e:
        return response.raise_exception(
            translate_message("FAILED_LOGIN", lang=lang),
            data=str(e),
            status_code=500
        )


#controller for login the admin_login 
async def admin_login(request: UserLogin, lang: str = "en"):
    """
    Authenticate an admin user using email and password, generate tokens, 
    and return user data including profile photo URL.
    """
    try:
        # Step 1: Find user by email
        user = await user_collection.find_one({"email": request.email})
        if not user:
            return response.error_message(
                translate_message("INVALID_CREDENTIALS", lang=lang),
                data={}, status_code=400
            )
        
        # Step 2: Check role
        if user.get("role") != "admin":
            return response.error_message(
                translate_message("INVALID_ADMIN_CREDENTIALS", lang=lang),
                data={}, status_code=400
            )
        
        # Step 3: Validate password
        if not verify_password(request.password, user["password"]):
            return response.error_message(
                translate_message("INVALID_CREDENTIALS", lang=lang),
                data={}, status_code=400
            )

        # Step 4: Generate access & refresh tokens
        token_payload = {
            "sub": user["email"],
            "user_id": str(user["_id"])
        }
        access_token = create_access_token(token_payload)
        refresh_token = create_refresh_token(token_payload)

        access_token_expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

        # Step 5: Store tokens in DB
        store_token(
            user_id=str(user["_id"]),
            email=user["email"],
            access_token=access_token,
            refresh_token=refresh_token,
            access_token_expire=access_token_expire,
            refresh_token_expire=refresh_token_expire
        )

        # Step 6: Prepare user data for response
        user_data = user.copy()
        user_data.pop("password", None)
        user_data["user_id"] = str(user_data.pop("_id"))

        # Convert ObjectId fields in user_data to string
        user_data = convert_objectid_to_str(user_data)

        # Step 7: Get profile photo URL
        profile_url = await get_profile_photo_url(current_user=user)
        user_data["profile_url"] = profile_url if profile_url else None


        # Step 8: Prepare response
        response_data = {
            "token_type": "bearer",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_data": user_data,
        }

        # Serialize datetime fields in response
        response_data = serialize_datetime_fields(response_data)

        return response.success_message(
            translate_message("LOGIN_SUCCESS", lang=lang),
            data=response_data
        )

    except Exception as e:
        return response.raise_exception(
            translate_message("FAILED_LOGIN", lang=lang),
            data=str(e),
            status_code=500
        )


#controller for creating_user
async def create_user(user: UserCreate, lang: str = "en", request: Request = None):
    """
    Register a new user in the system.
    """
    # Check for duplicate email first
    existing_user = await user_collection.find_one({"email": user.email})
    if existing_user:
        return response.error_message(
            translate_message("Email '{email}' is already registered. Please use a different email address.",lang,email=user.email),
            data={}, 
            status_code=400
        )
    
    # Validate role
    valid_roles = ["admin", "user"]
    if user.role not in valid_roles:
        return response.error_message(translate_message("Invalid role. Must be one of: {roles}",lang, roles=", ".join(valid_roles)), data={}, status_code=400)

    user_dict = user.model_dump(exclude={"id"})
    hased_pwd = get_hashed_password(user.password)
    user_dict["password"] = hased_pwd
    user_dict["membership_type"] = "basic"
    
    try:
        result = await user_collection.insert_one(user_dict)
        user.id = PyObjectId(result.inserted_id)  # Convert inserted_id to PyObjectId

        return response.success_message(translate_message("User Created Successfully", lang), data={"user": {"id": str(user.id), "email": user.email, "role": user.role}})
    except Exception as e: 
        return response.error_message(translate_message("Error while creating user", lang), data=str(e), status_code=400)


#controller for refresh_token
async def refresh_token(request: RefreshTokenRequest, lang: str = "en"):
    """
    Refresh the access token using a valid refresh token.
    """
    # Check if the token exists in the collection
    result  = await token_collection.find_one({"refresh_token": request.refresh_token})
    existing_token = await result if isinstance(result, asyncio.Future) else result
    if not existing_token:
        raise response.raise_exception(message=translate_message("Refresh token not found.", lang), data={}, status_code=400)

    # Check if the token is blacklisted
    if existing_token.get("is_blacklisted", True):
        raise response.raise_exception(
            message=translate_message("The refresh token is blacklisted.", lang), data={}, status_code=401
        )

    # Verify token and generate new access token
    token_data = verify_refresh_token(request.refresh_token)

    await token_collection.update_one(
        {"refresh_token": request.refresh_token},
        {"$set": {"is_blacklisted": True}}
    )
    user = await user_collection.find_one({"email": token_data["sub"]})
    if not user:
        return response.raise_exception(
            message="User not found.",
            data={},
            status_code=404
        )

    new_access_token, new_refresh_token = generate_login_tokens(user)

    return response.success_message(
        "Token refreshed successfully",
        data={
            "access_token": new_access_token,
            "refresh_token": new_refresh_token
        }
    )


#controller for logout
async def logout(request: LogoutRequest, lang: str = "en"):
    """
    Logout a user by blacklisting their refresh token.
    """

    print("lang",lang)
    try:
        # Verify the token
        token_data = verify_token(request.refresh_token)
    except Exception as e:
        raise response.raise_exception(message=translate_message("Invalid refresh token.", lang), data={}, status_code=400)

    # Find the token in the database
    existing_token = await token_collection.find_one({"refresh_token": request.refresh_token})

    if not existing_token:
        raise response.raise_exception(message=translate_message("Refresh token not found.", lang), data={}, status_code=400)

    # Step 3: Check if the token is already blacklisted
    if existing_token.get("is_blacklisted", True):
        raise response.raise_exception(message=translate_message("This token is already blacklisted.", lang), data={}, status_code=400)

    login_user = existing_token.get("user_id", "")
    if not login_user:
        raise response.raise_exception(message=translate_message("User ID not found.", lang),  data={}, status_code=400)

    # Blacklist the token
    await token_collection.update_one(
        {"refresh_token": request.refresh_token},
        {"$set": {"is_blacklisted": True}}
    )

    return response.success_message(translate_message("Logout successful.", lang), data={})


# helper function -Dependency to extract user email from token
def get_current_user_email(request: Request):
    """
    Dependency to extract the email of the current user from the Authorization header in /change-password api.
    """
    # Extract token from Authorization header
    authorization = request.headers.get("Authorization")
    if not authorization or not authorization.startswith("Bearer "):
        raise response.raise_exception( message="Invalid or missing token",status_code=401)
    token = authorization.split(" ")[1]
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_ACCESS_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise response.raise_exception(message="Invalid token: email not found",data={},status_code=401)
        return email
    except JWTError:
        raise response.raise_exception( message="Invalid or expired token",status_code=401)


#controller for update_password_controller
async def update_password_controller(
        request: ResetPasswordRequest, 
        email: str,
        lang: str = "en"
    ):
    """
    Update a user's password after verifying the current password.
    """
    print("lang",lang)
    # Step 1: Find the user by email
    user = await user_collection.find_one({"email": email})

    if not user:
        raise response.raise_exception(status_code=404, message=translate_message("User not found", lang))

    # Step 2: Verify current password
    if not pwd_context.verify(request.current_password, user["password"]):
        raise response.raise_exception(message=translate_message("Current password is incorrect", lang),status_code=400)

    # Step 3: Validate password strength
    validate_pwd(request.new_password)

    # Step 4: Validate new password
    if request.new_password != request.confirm_new_password:
        raise response.raise_exception(message=translate_message("New password and confirm password do not match", lang),status_code=400)

    # Step 5: Check if the new password is the same as the current password
    if request.new_password == request.current_password:
        raise response.raise_exception(message=translate_message("New password cannot be the same as the current password", lang), status_code=400)

    # Step 6: Hash and update the new password
    hashed_password = pwd_context.hash(request.new_password)

    await user_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed_password, "updated_at": datetime.utcnow()}}
    )

    return response.success_message(translate_message("Password reset successful", lang), data={})


#controller for request_password_reset
async def request_password_reset(request: RequestResetPassword, lang: str = "en"):
        """
        Request Password Reset (Forgot Password Flow):-
        Sends a password reset request for the user based on the provided email.
        If the user exists, an OTP or reset link will be sent to their registered email.
        """

        # ✅ Validate email is not empty
        if not request.email or not request.email.strip():
            return response.error_message(
                translate_message("Email is required", lang),
                data={}, 
                status_code=400
            )
        
        email = request.email.strip()

        # Step 1: Check if the user exists
        user = await user_collection.find_one({"email": email})

        if not user:
            return response.error_message(
                translate_message("User not found", lang),
                data={}, 
                status_code=404
            )

        # Step 2: Generate the reset code
        reset_code = generate_verification_code()

        # Step 3: Store the reset code in Redis with an expiration time of 15 minutes
        try:
            await store_in_redis(f"password_reset:{email}", reset_code, ttl=15 * 60)  # 15 minutes TTL
        except Exception as e:
            print(f"Error storing reset code in Redis: {e}")
            return response.error_message(
                translate_message("Failed to process password reset request. Please try again.", lang),
                data={}, 
                status_code=500
            )

        # Step 4: Send the reset code to the user's email
        try:
            email_subject = translate_message("Password Reset Request", lang)
            email_body = translate_message(
                "Your password reset code is: {reset_code}. It will expire in 15 minutes.",
                lang=lang,
                reset_code=reset_code
            )

            # Send email asynchronously and handle failures gracefully
            send_password_reset_email_task.delay(user['email'], email_subject, email_body)
            
            # Step 5: Return success message
            return response.success_message(
                translate_message("Password reset code sent to email", lang), 
                data={"email": email},
                status_code=200
            )
            
        except Exception as e:
            print(f"Error sending password reset email: {e}")
            # Even if email fails, we still return success to prevent user enumeration
            # The reset code is still stored in Redis
            return response.success_message(
                translate_message("Password reset code sent to email", lang), 
                data={"email": email},
                status_code=200
            )


#controller for verify_forgot_pwd_otp
async def verify_forgot_pwd_otp(otp: ForgotPasswordOtpVerify,lang: str = "en"):
        """
        Verify Forgot Password OTP (Forgot Password Flow):-
        Verifies the OTP sent to the user during the forgot password process.
        """
       
        # Step 1: Validate input
        if not(otp.reset_otp and otp.email):
            response.raise_exception(message=translate_message("Email or OTP cannot be empty", lang),)

        # Retrieve the stored reset code from Redis
        stored_code = await get_from_redis(f"password_reset:{otp.email}")

        # Step 2: Validate the reset code
        if not stored_code:
            raise response.raise_exception(message=translate_message("Invalid or expired reset code", lang),status_code=400 )

        if stored_code != otp.reset_otp:
            raise response.raise_exception(message=translate_message("Invalid verification code", lang), status_code=400)

        # Step 3: Generate a temporary token or flag
        temp_token = str(uuid.uuid4())  # Unique identifier for session tracking
        
        # Strategic logging to validate Redis key creation
        redis_key = f"reset_token:{otp.email}"
        print(f"[DEBUG] Storing token in Redis key: {redis_key}")
        print(f"[DEBUG] Token value: {temp_token}")
        
        await store_in_redis(redis_key, temp_token, ttl=500)  # Set token with 5-minute expiration

        # Step 4: Return success response with the token
        return response.success_message(translate_message("OTP verified successfully", lang),data={"reset_token": temp_token})


#controller for change_password
async def change_password(request: ForgotPasswordRequest, email: str, lang: str = "en"):
        """
        Change Password (Forgot Password Flow):-
        Allows the user to set a new password after successful OTP verification.
        """

        # Check if user exists
        print("lang",lang)
        user = await user_collection.find_one({"email": email})
        if not user:
            raise response.raise_exception(message=translate_message("User not found", lang), status_code=404)
        reset_token = request.reset_token

        # Strategic logging to validate Redis key issue
        redis_key = f"reset_token:{email}"
        
        # Step 1: Validate the temporary token
        stored_token = await get_from_redis(redis_key)

        if not stored_token or stored_token != reset_token:
            print(f"[DEBUG] Token validation failed - stored: {stored_token}, provided: {reset_token}")
            raise response.raise_exception(message=translate_message("Invalid or expired reset token", lang), status_code=400)
   
        # Step 2: Validate password strength
        validate_new_pwd(request.new_password)

        validate_confirm_new_password(request.confirm_new_password)
        
        # Step 3: Validate the new password and confirm password
        if request.new_password != request.confirm_new_password:
            raise response.raise_exception(message=translate_message("New password and confirm password do not match", lang),status_code=400)

        # Step 4: Hash the new password
        hashed_password = pwd_context.hash(request.new_password)

        # Step 5: Update the user's password in the database
        await user_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"password": hashed_password, "updated_at": datetime.utcnow()}}
        )

        # Step 6: Delete the reset tokens from Redis after password change
        await delete_from_redis(f"password_reset:{email}")
        await delete_from_redis(f"reset_token:{email}")

        # Step 7: Return success response
        return response.success_message(translate_message("Password reset successful", lang), data={})


#controller for process_and_hash_password 
async def process_and_hash_password(accounts: List[AdminAccountCreateRequest], lang: str = "en"):
    """
    Create Admins Files with Hashed Passwords:-
    Receives a list of admin accounts, hashes their passwords, and returns the data as a downloadable JSON file.
    """

    updated_accounts = []
    
    for account in accounts:
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(account.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create the response with hashed password
        updated_account = AdminAccountResponse(
            first_name=account.first_name,
            last_name=account.last_name,
            email=account.email,
            role=account.role,
            password=hashed_password,
            is_verified=True
        )
        
        # Add the modified account to the list
        updated_accounts.append(updated_account)
    
    # Convert the updated accounts to a JSON string
    updated_json = json.dumps([{
        **account.dict(),
        'is_verified': True  # Ensure is_verified is True in JSON output
    } for account in updated_accounts], indent=4)
    
    # Create a BytesIO buffer to send the JSON content as a file
    buffer = BytesIO()
    buffer.write(updated_json.encode('utf-8'))
    buffer.seek(0)  # Rewind the buffer to the beginning
    
    # Return the JSON content as a downloadable file
    return StreamingResponse(buffer, media_type="application/json", headers={"Content-Disposition": "attachment; filename=admin_accounts.json"})


#controller for get_user_profile_details 
async def get_user_profile_details(request: Request, current_user: dict, lang: str = "en"):
    """
    Get complete user profile info including profile photo URL (S3 presigned URL or LOCAL path).
    Uses Files model and helper to generate fetchable URL.
    """
    try:
        user_id = str(current_user["_id"])

        # Fetch all user fields
        user_data = await user_collection.find_one({"_id": ObjectId(user_id)})

        if not user_data:
            return response.success_message(
                translate_message("USER_NOT_FOUND", lang=lang),
                data=None
            )

        # Convert ObjectId to str for all relevant fields
        user_data = convert_objectid_to_str(user_data)

        # Remove sensitive info
        user_data.pop("password", None)

        # Get profile photo URL
        profile_url = await get_profile_photo_url(current_user=user_data)
        user_data["profile_photo_url"] = profile_url if profile_url else None


        user_data = serialize_datetime_fields(user_data)

        return response.success_message(
            translate_message("USER_PROFILE_FETCHED", lang=lang),
            data=user_data
        )

    except Exception as e:
        return response.raise_exception(
            translate_message("ERROR_FETCHING_PROFILE", lang=lang),
            data=str(e),
            status_code=500
        )


#controller for update_profile_controller
async def update_profile_controller(request: Request, current_user, user_data, lang: str = "en"):
    """
    Update User Profile:
    Updates the current user's profile with provided data.
    Returns updated fields including profile photo URL (if exists).
    """
    try:
        user_id = current_user["_id"]
        if not isinstance(user_id, ObjectId):
            user_id = ObjectId(user_id)

        # Initialize update data with timestamp
        updated_data = {"updated_at": datetime.utcnow()}

        # Validate username if provided
        if user_data.username:
            if not re.match(r"^[a-zA-Z0-9_.-]{3,20}$", user_data.username):
                return response.error_message(
                    translate_message(
                        "Username must be 3-20 characters long and can only contain letters, numbers, underscores, periods, and dashes.",
                        lang
                    ),
                    data={"username": user_data.username},
                    status_code=400
                )
            # Check if username already exists  
            existing_username = await user_collection.find_one({"username": user_data.username})
            if existing_username and str(existing_username["_id"]) != str(user_id):
                return response.error_message(
                    translate_message("Username already exists. Please choose a different one.", lang),
                    data={"username": user_data.username},
                    status_code=400
                )
            updated_data["username"] = user_data.username

        # Update first_name and last_name if provided
        if user_data.first_name:
            updated_data["first_name"] = user_data.first_name
        if user_data.last_name:
            updated_data["last_name"] = user_data.last_name

        # Only update if there are actual changes besides updated_at
        if len(updated_data) > 1:
            result = await user_collection.update_one(
                {"_id": user_id},
                {"$set": updated_data}
            )
            if result.modified_count == 0:
                return response.error_message(
                    translate_message("No changes were made to the profile.", lang),
                    status_code=400
                )

        # Prepare response data
        user_doc = await user_collection.find_one({"_id": user_id})
        response_data = {
            "user_id": str(user_doc["_id"]),
            "username": user_doc.get("username"),
            "first_name": user_doc.get("first_name"),
            "last_name": user_doc.get("last_name"),
            "profile_url": None
        }

        # Get profile photo URL dynamically (if exists)
        profile_url = await get_profile_photo_url(current_user=user_doc)
        if profile_url:
            response_data["profile_url"] = profile_url

        return response.success_message(
            translate_message("User Profile Updated successfully.", lang),
            data=response_data,
            status_code=200
        )

    except Exception as e:
        return response.error_message(
            translate_message("Error updating user profile", lang) + f": {str(e)}",
            status_code=500
        )


#######################
#controller for delete_user_profile_file
async def delete_user_profile_file(user_id: str, lang: str = "en"):
    """
    Delete user's profile photo (S3 or LOCAL) based on STORAGE_BACKEND env variable,
    and remove reference from user collection.
    """
    try:
        # 1. Fetch user and profile photo reference
        user_doc = await user_collection.find_one({"_id": ObjectId(user_id)})
        profile_file_id = user_doc.get("profile_photo_id")
        if not profile_file_id:
            return response.success_message(translate_message("NO_PROFILE_PHOTO_FOUND", lang), data={})

        # 2. Fetch file document
        file_doc = await file_collection.find_one({"_id": ObjectId(profile_file_id)})
        if not file_doc:
            return response.success_message(translate_message("FILE_RECORD_NOT_FOUND", lang), data={})

        storage_backend = os.getenv("STORAGE_BACKEND", "LOCAL")  # Fetch from environment
        storage_key = str(file_doc.get("storage_key")).replace("\\", "/")

        # 3. Delete file depending on storage backend
        if storage_backend.upper() == "S3":
            s3_client = boto3.client(
                "s3",
                region_name=AWS_S3_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY
            )
            try:
                s3_client.delete_object(Bucket=AWS_S3_BUCKET_NAME, Key=storage_key)
            except ClientError as e:
                return response.raise_exception(translate_message("S3_DELETION_ERROR", lang) + f": {str(e)}", status_code=500)
                
        elif storage_backend.upper() == "LOCAL":
            try:
                # Convert storage_key to real file path
                local_path = os.path.join(UPLOAD_DIR, *storage_key.split("/"))
                if os.path.exists(local_path):
                    os.remove(local_path)
            except Exception as e:
                return response.raise_exception(translate_message("LOCAL_FILE_DELETION_ERROR", lang) + f": {str(e)}", status_code=500)

        # 4. Mark file as deleted in DB
        await file_collection.update_one(
            {"_id": ObjectId(profile_file_id)},
            {"$set": {"is_deleted": True, "deleted_at": datetime.utcnow()}}
        )

        # 5. Remove reference from user
        await user_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$unset": {"profile_photo_id": ""}}
        )
        return response.success_message(translate_message("PROFILE_PHOTO_DELETED_SUCCESS", lang), data={})

    except Exception as e:
        return response.raise_exception(translate_message("UNEXPECTED_ERROR", lang) + f": {str(e)}", status_code=500)

#controller for deactivate_user_controller
async def deactivate_user_controller(user_id: str, current_user: dict, lang: str = "en"):
    """
    Deactivate a user account by setting is_deactivated to True.
    Only admins can deactivate user accounts.
    """
    try:
        # ✅ Validate user_id format
        if not ObjectId.is_valid(user_id):
            return response.error_message(translate_message("Invalid user ID format", lang),  status_code=400)
        
        # ✅ Check if user exists
        user = await user_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return response.error_message(translate_message("User not found", lang),  status_code=404)
        
        # ✅ Prevent admin from deactivating themselves
        if str(user["_id"]) == str(current_user["_id"]):
            return response.error_message(translate_message("You cannot deactivate your own account", lang),  status_code=400)

        # ✅ Check if already deactivated
        if user.get("is_deactivated", False):
            return response.error_message(translate_message("User account is already deactivated", lang),  status_code=400)
        
        # ✅ Perform deactivation
        result = await user_collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "is_deactivated": True,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 1:
            return response.success_message(
                translate_message("User account deactivated successfully", lang),
                data={
                    "user_id": user_id,
                    "email": user.get("email"),
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "deactivated_at": datetime.utcnow().isoformat()
                },
                status_code=200
            )
        else:
            return response.error_message(translate_message("Failed to deactivate user account", lang), status_code=500)
            
    except Exception as e:
        return response.error_message(
            translate_message("Error deactivating user", lang) + f": {str(e)}",
            status_code=500
        )


#controller for delete_user_account_controller
async def delete_user_account_controller(user_id: str, current_user: dict, lang: str = "en"):
    """
    Soft delete a user account by setting is_deleted to True.
    Only admins can delete user accounts.
    """
    try:
        # ✅ Validate user_id format
        if not ObjectId.is_valid(user_id):
            return response.error_message(translate_message("Invalid user ID format", lang), status_code=400)
        
        # ✅ Check if user exists
        user = await user_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return response.error_message(translate_message("User not found", lang), status_code=404)
        
        # ✅ Prevent admin from deleting themselves
        if str(user["_id"]) == str(current_user["_id"]):
            return response.error_message(translate_message("You cannot delete your own account", lang), status_code=400)

        # ✅ Prevent deletion of admin accounts
        if user.get("role") == "admin":
            return response.error_message(translate_message("Admin accounts cannot be deleted", lang), status_code=403)

        # ✅ Check if already deleted
        if user.get("is_deleted", False):
            return response.error_message(translate_message("User account is already deleted", lang), status_code=400)
        
        # ✅ Perform soft delete
        result = await user_collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": datetime.utcnow(),
                    "deleted_by": str(current_user["_id"]),
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count == 1:
            return response.success_message(
                translate_message("User account deleted successfully", lang),
                data={
                    "user_id": user_id,
                    "email": user.get("email"),
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "deleted_at": datetime.utcnow().isoformat(),
                    "deleted_by": str(current_user["_id"])
                },
                status_code=200
            )
        else:
            return response.error_message(translate_message("Failed to delete user account", lang), status_code=500)
            
    except Exception as e:
        return response.error_message(
            translate_message("Error deleting user", lang) + f": {str(e)}",
            status_code=500
        )

async def signup_controller(payload: Signup):
    # Step 1: Check if email already exists in DB
    existing = await user_collection.find_one({"email": payload.email})
    if existing:
        return response.error_message("Email already registered. Please log in instead.")

    # Step 2: Generate OTP
    otp = generate_verification_code()
    print("OTP: ", otp)
    # Step 3: Save signup data temporarily in Redis
    signup_data = {
        "username": payload.username,
        "email": payload.email,
        "password": get_hashed_password(payload.password)
    }

    await redis_client.setex(
        f"signup:{payload.email}:data",
        600,
        json.dumps(signup_data)
    )

    # Store OTP for 5 minutes
    await redis_client.setex(
        f"signup:{payload.email}:otp",
        300,
        otp
    )

    # Step 4: Send verification email
    subject, body = signup_verification_template(payload.username, otp)
    is_html = True
    await send_email(payload.email, subject, body, is_html)

    return response.success_message("OTP sent successfully. Please verify to continue.", 
                                    data={"otp": otp})

async def verify_signup_otp_controller(payload):
    email = payload.email
    otp = payload.otp

    # Step 1: Get stored OTP
    stored_otp = await redis_client.get(f"signup:{email}:otp")
    if not stored_otp:
        return response.error_message("OTP expired or not found. Please request a new OTP.", 400)

    stored_otp = stored_otp.encode() if isinstance(stored_otp, bytes) else stored_otp

    # Step 2: Compare OTP
    if otp != stored_otp:
        return response.error_message("Invalid OTP. Please try again.", 400)

    # Step 3: Get stored signup data
    temp_data = await redis_client.get(f"signup:{email}:data")
    if not temp_data:
        return response.error_message("Signup session expired. Please sign up again.", 400)

    temp_data = json.loads(temp_data.encode())

    # Step 4: Save verified user into MongoDB
    try:
        result = await user_collection.insert_one({
            "username": temp_data["username"],
            "email": temp_data["email"],
            "password": temp_data["password"],
            "membership_type": "basic",
            "is_verified": True,
            "created_at": datetime.utcnow(),
            "updated_at": None,
            "role": UserRole.USER,
            "two_factor_enabled": False
        })

        user_id = str(result.inserted_id)

    except Exception as e:
        return response.error_message(f"Failed to create user: {str(e)}", 500)

    # Step 5: Cleanup Redis keys
    await redis_client.delete(f"signup:{email}:otp")
    await redis_client.delete(f"signup:{email}:data")

    # Success Response
    return response.success_message(
        "Email verified successfully!",
        data={"user_id": user_id}
    )

async def resend_otp_controller(payload):
    email = payload.email

    # Step 1: Check if signup session still exists
    temp_data = await redis_client.get(f"signup:{email}:data")
    if not temp_data:
        return response.error_message("Signup session expired. Please start again.", 400)

    # Step 2: Generate new OTP
    otp = generate_verification_code()

    await redis_client.setex(
        f"signup:{email}:otp",
        300,  # 5 minutes
        otp
    )

    # Step 3: Send email again
    subject, body = signup_verification_template(
        json.loads(temp_data.decode())["username"],
        otp
    )

    await send_email(email, subject, body, is_html=True)

    return response.success_message("A new OTP has been sent to your email.")

async def login_controller(payload: LoginRequest):
    email = payload.email
    password = payload.password
    remember = payload.remember_me

    # Step 1: Check user exists
    user = await user_collection.find_one({"email": email})
    if not user:
        return response.error_message("Invalid email or password.", 400)

    # Step 2: Validate password
    if not verify_password(password, user["password"]):
        return response.error_message("Invalid email or password.", 400)

    # Step 3: If 2FA disabled → return tokens immediately
    if not user.get("two_factor_enabled", True):
        access_token, refresh_token = generate_login_tokens(user)
        return response.success_message("Login successful", data={
            "access_token": access_token,
            "refresh_token": refresh_token
        })

    # Step 4: If 2FA enabled → generate OTP
    otp = generate_verification_code()

    await redis_client.setex(f"login:{email}:otp", 300, otp)

    subject, body = login_verification_template(user["username"], otp)
    await send_email(email, subject, body, is_html=True)

    return response.success_message(
        "OTP sent to your email. Please verify to continue.",
        data={
            "otp_required": True,
            "otp": otp}
    )

async def verify_login_otp_controller(payload):
    email = payload.email
    otp = payload.otp

    stored_otp = await redis_client.get(f"login:{email}:otp")
    if not stored_otp:
        return response.error_message("OTP expired or invalid. Please request a new one.", 400)

    stored_otp = stored_otp.decode() if isinstance(stored_otp, bytes) else stored_otp

    if otp != stored_otp:
        return response.error_message("Incorrect OTP.", 400)

    user = await user_collection.find_one({"email": email})

    access_token, refresh_token = generate_login_tokens(user)

    # Remove otp after success
    await redis_client.delete(f"login:{email}:otp")

    return response.success_message("Login successful", data={
        "access_token": access_token,
        "refresh_token": refresh_token
    })

async def resend_login_otp_controller(payload):
    email = payload.email

    # Check user exists
    user = await user_collection.find_one({"email": email})
    if not user:
        return response.error_message("User not found.", 404)

    # Generate new OTP
    otp = generate_verification_code()

    await redis_client.setex(f"login:{email}:otp", 300, otp)

    subject, body = login_verification_template(user["username"], otp)
    await send_email(email, subject, body, is_html=True)

    return response.success_message("A new OTP has been sent to your email.")

async def send_reset_password_otp_controller(payload: ForgotPasswordRequest):
    email = payload.email

    # Step 1: Check user exists
    user = await user_collection.find_one({"email": email})
    if not user:
        return response.error_message("No account found with this email.", 404)

    # Step 2: Generate OTP
    otp = generate_verification_code()

    # Save OTP for 5 minutes
    await redis_client.setex(f"reset:{email}:otp", 300, otp)

    # Email Template
    subject, body = reset_password_otp_template(user["username"], otp)

    await send_email(email, subject, body, is_html=True)

    return response.success_message("OTP sent to your email.")

async def verify_reset_password_otp_controller(payload):
    email = payload.email
    otp = payload.otp

    stored_otp = await redis_client.get(f"reset:{email}:otp")

    if not stored_otp:
        return response.error_message("OTP expired or invalid.", 400)

    stored_otp = stored_otp.decode() if isinstance(stored_otp, bytes) else stored_otp

    if otp != stored_otp:
        return response.error_message("Incorrect OTP.", 400)

    # Mark OTP as verified (valid for 10 minutes)
    await redis_client.setex(f"reset:{email}:verified", 600, "true")

    return response.success_message("OTP verified successfully.")

async def reset_password_controller(payload):
    email = payload.email
    new_password = payload.new_password

    # Ensure user completed OTP verification
    is_verified = await redis_client.get(f"reset:{email}:verified")
    if not is_verified:
        return response.error_message("OTP verification required.", 400)

    # Hash new password
    hashed_password = get_hashed_password(new_password)

    # Update DB
    await user_collection.update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )

    # Remove reset session data
    await redis_client.delete(f"reset:{email}:otp")
    await redis_client.delete(f"reset:{email}:verified")

    return response.success_message("Password reset successfully. Please log in.")
