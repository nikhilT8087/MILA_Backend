from fastapi import APIRouter,Depends,Request,Query
from config.models.user_models import PyObjectId, UserCreate
from core.utils.response_mixin import CustomResponseMixin
from core.utils.auth_utils import *
from typing import List, Optional
from schemas.user_schemas import *
from api.controller.user_auth import *
from schemas.response_schema import Response
from core.utils.permissions import UserPermission, AdminPermission
from core.utils.pagination import StandardResultsSetPagination
import time
from fastapi import Body


supported_langs = ["en", "fr"]


# Initializing the router instance
router = APIRouter()

class AuthViews:
    """
    Authentication-related endpoints for user login, registration,
    token management, and password operations.
    """

    #api to login a user
    @router.post("/login", response_model=dict)
    async def verify_login(request: UserLogin, lang: str = Query(None)):
        """
        User login endpoint. JWT token
        """
        lang = lang if lang in supported_langs else "en"
        return await login(request, lang=lang)


    #api to login admin
    @router.post("/admin/login", response_model=dict)
    async def admin_login(request: AdminLogin, lang: str = Query(None)):
        """
        Admin login endpoint. JWT token
        """
        lang = lang if lang in supported_langs else "en"
        return await admin_login(request, lang)


    #api to register an admin and user
    @router.post("/register", response_model=Response)
    async def create_user(user: UserCreate, lang: str = Query(None)):
        """
        User registration endpoint.
        """
        lang = lang if lang in supported_langs else "en"
        return await create_user(user=user, lang=lang, request=Request)


    #api for refresh-token an admin and user
    @router.post("/refresh-token", response_model=Response)
    async def refresh_token_endpoint(request_body: RefreshTokenRequest, request: Request, lang: str = Query(None)):
        """
        Refresh JWT token endpoint.
        """
        lang = lang if lang in supported_langs else "en"
        return await refresh_token(request_body, lang)

    #api for logout
    @router.post("/logout", response_model=Response)
    async def logout(request: LogoutRequest, lang: str = Query(None)):
        """
        Logout endpoint to invalidate user session.
        """
        lang = lang if lang in supported_langs else "en"
        return await logout(request, lang)


    # api for Reset password API
    @router.post("/change-password", response_model=dict)
    async def reset_password(request: ResetPasswordRequest, email: str = Depends(get_current_user_email), lang: str = Query(None)):
        """
        change password for a logged-in user (reset password):-.
        """
        lang = lang if lang in supported_langs else "en"
        return await update_password_controller(request, email=email, lang=lang)


    # api for request-password-reset
    @router.post("/request-password-reset")
    async def request_password_reset(request: RequestResetPassword, lang: str = Query(None)):
        """
        Request Password Reset (Forgot Password Flow):-
        Sends a password reset request for the user based on the provided email.
        If the user exists, an OTP or reset link will be sent to their registered email.
        """
        lang = lang if lang in supported_langs else "en"
        return await request_password_reset(request, lang)


    # api for forgot_pwd_otp_ver
    @router.post("/forgot_pwd_otp_ver")
    async def verify_forgot_pwd_otp(otp :ForgotPasswordOtpVerify, lang: str = Query(None)):
        """
        Verify Forgot Password OTP (Forgot Password Flow):-
        Verifies the OTP sent to the user during the forgot password process.
        """
        lang = lang if lang in supported_langs else "en"
        return await verify_forgot_pwd_otp(otp, lang)


    # api for forgot-password
    @router.post("/forgot-password")
    async def change_password(request: ForgotPasswordRequest, email: str, lang: str = Query(None)):
        """
        Change Password (Forgot Password Flow):-
        Allows the user to set a new password after successful OTP verification.
        """
        lang = lang if lang in supported_langs else "en"
        return await change_password(request, email, lang)
    

# api for create-admins-file with Hashed Passwords
@router.post("/create-admins-file")
async def hash_password(accounts: List[AdminAccountCreateRequest], 
                        current_user: dict = Depends(UserPermission(allowed_roles=["admin"]))):
    """
    Create Admins File with Hashed Passwords:-
    Receives a list of admin accounts, hashes their passwords, and returns the data as a downloadable JSON file.
    """
    return await process_and_hash_password(accounts)


# api for getting user-profile-details
@router.get("/user-profile-details", response_model=Response)
async def user_profile_route(request: Request, current_user: dict = Depends(UserPermission(allowed_roles=["user","admin"])), lang: str = Query(None)):
    """
    Get User Profile Details:-
    Retrieves the profile details of the current user.
    """

    lang = lang if lang in supported_langs else "en"
    return await get_user_profile_details(request,current_user,lang)


# api for update-profile
@router.put("/update-profile")
async def update_profile(
    request: Request,
    user_data: UsernameUpdateRequest,
    current_user=Depends(UserPermission(allowed_roles=["user","admin"])),lang: str = Query(None)
):
    """
    Update User Profile:-
    Updates the current user's profile with provided data.
    """
    lang = lang if lang in supported_langs else "en"
    return await update_profile_controller(request, current_user=current_user, user_data=user_data, lang=lang)


# api for delete-user-profile
@router.delete("/delete-user-profile")
async def delete_user_profile(request: Request,
                            current_user: dict = Depends(UserPermission(allowed_roles=["user","admin"])),
                            lang: str = Query(None)
                            ):
    """
    Delete current user's profile image (S3 or LOCAL)
    """
    lang = lang if lang in supported_langs else "en"
    return await delete_user_profile_file(user_id=current_user["_id"],lang=lang)


# api for deactivate-user by id 
@router.put("/deactivate-user/{user_id}", response_model=Response)
async def deactivate_user_route(
    user_id: str,
    current_user: dict = Depends(AdminPermission(allowed_roles=["admin"])),
    lang: str = Query(None)
):
    """
    Deactivate a User:-
    Deactivates a user account by the admin.
    """
    lang = lang if lang in supported_langs else "en"
    return await deactivate_user_controller(user_id, current_user, lang)


# api for delete-user by id 
@router.delete("/delete-user/{user_id}", response_model=Response)
async def delete_user_route(
    user_id: str,
    current_user: dict = Depends(AdminPermission(allowed_roles=["admin"])), lang: str = Query("en")
): 
    """
    Delete a User Account:-
    Soft delete a user account by ID. Only admins can access this API.
    """
    lang = lang if lang in supported_langs else "en"
    return await delete_user_account_controller(user_id, current_user, lang)