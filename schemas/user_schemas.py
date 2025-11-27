from pydantic import BaseModel,Field, EmailStr,field_validator,validator,ValidationInfo
from tasks import send_email_task
from typing import Optional
import re
from datetime import datetime
from enum import Enum

#UserLogin Schema 
class UserLogin(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    role: str = Field(..., description="User role for validation")
    is_test: Optional[bool] = False  # Defaults to False if not provided
    
    @field_validator("email")
    def validate_email(cls, v):
        """Ensure email is not empty and properly formatted."""
        if not v or not v.strip():
            raise ValueError("Email is required")
        return v.strip()
    
    @field_validator("password")
    def validate_password(cls, v):
        """Ensure password is not empty."""
        if not v or not v.strip():
            raise ValueError("Password is required")
        return v.strip()
    
    @field_validator("role")
    def validate_role(cls, v):
        """Ensure role is valid and not empty."""
        if not v or not v.strip():
            raise ValueError("Role is required")
        valid_roles = ["admin", "user"]
        if v.strip().lower() not in valid_roles:
            raise ValueError(f"Invalid role. Must be one of: {', '.join(valid_roles)}")
        return v.strip().lower()


#AdminLogin Schema 
class AdminLogin(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    is_test: Optional[bool] = False  # Defaults to False if not provided
    
    @field_validator("email")
    def validate_email(cls, v):
        """Ensure email is not empty and properly formatted."""
        if not v or not v.strip():
            raise ValueError("Email is required")
        return v.strip()
    
    @field_validator("password")
    def validate_password(cls, v):
        """Ensure password is not empty."""
        if not v or not v.strip():
            raise ValueError("Password is required")
        return v.strip()


#RefreshTokenRequest Schema 
class RefreshTokenRequest(BaseModel):
    refresh_token: str


#send_email Schema 
async def send_email(to_email: str, subject:str, body:str):  
    # Trigger the Celery task
    send_email_task.delay(to_email, subject, body)


#LogoutRequest Schema 
class LogoutRequest(BaseModel):
    refresh_token: str


#ResetPasswordRequest Schema 
class ResetPasswordRequest(BaseModel):
    # email: str  # Add user_id here
    current_password: str
    new_password: str
    confirm_new_password: str


# Request Reset Password Schema
class RequestResetPassword(BaseModel):
    email: str

    @field_validator("email")
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError("Email is required")
        return v.strip()


# Password Reset Request Schema
class ForgotPasswordOtpVerify(BaseModel):
    reset_otp: str
    email: str

    @field_validator("reset_otp")
    def validate_reset_otp(cls, v):
        if not v or not v.strip():
            raise ValueError("Reset OTP cannot be empty.")
        if not v.isdigit():
            raise ValueError("Reset OTP must contain only digits.")
        if len(v) != 6:
            raise ValueError("Reset OTP must be exactly 6 digits.")
        return v

    @field_validator("email")
    def validate_email(cls, v):
        if not v or not v.strip():
            raise ValueError("Email is required")
        return v.strip()
    

#ForgotPasswordRequest Schema 
class ForgotPasswordRequest(BaseModel):
    reset_token: str
    new_password: str
    confirm_new_password: str

    @field_validator("reset_token")
    def validate_reset_token(cls, v):
        if not v or not v.strip():
            raise ValueError("Reset token cannot be empty.")
        return v.strip()

    @field_validator("new_password")
    def validate_new_password(cls, v):
        if not v or not v.strip():
            raise ValueError("New password cannot be empty.")
        return v

    @field_validator("confirm_new_password")
    def validate_confirm_new_password(cls, v, info):
        if not v or not v.strip():
            raise ValueError("Confirm password cannot be empty.")
        # Defer matching check to a root validator instead
        return v


#AdminAccountCreateRequest Schema 
class AdminAccountCreateRequest(BaseModel):
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    email: EmailStr
    password: str
    role: str = "admin"  # Default role is admin
    is_verified: bool = True


# Schema for the response with hashed password
class AdminAccountResponse(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    role: str
    password: str
    is_verified: bool = True

    class Config:
        from_attributes  = True


#VerificationRequest Schema   
class UsernameUpdateRequest(BaseModel):
    username: Optional[str] = None
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    # s3_key: Optional[str] = None

    @field_validator("first_name")
    def validate_first_name(cls, v):
        """Ensure first name is not empty, contains no numbers, and is properly trimmed."""
        if not v or not v.strip():
            raise ValueError("First name cannot be empty or contain only spaces.")
        if any(char.isdigit() for char in v):
            raise ValueError("First name cannot contain numbers.")
        if len(v.strip()) < 2:
            raise ValueError("First name must be at least 2 characters long.")
        # Regex pattern: only letters, hyphens, apostrophes, and spaces allowed
        if not re.match(r"^[a-zA-Z\s\-']+$", v):
            raise ValueError("First name must contain only letters")
        return v.strip()
    
    @field_validator("last_name")
    def validate_last_name(cls, v):
        """Ensure last name is not empty, contains no numbers, and is properly trimmed."""
        if not v or not v.strip():
            raise ValueError("Last name cannot be empty or contain only spaces.")
        if any(char.isdigit() for char in v):
            raise ValueError("Last name cannot contain numbers.")
        if len(v.strip()) < 2:
            raise ValueError("Last name must be at least 2 characters long.")
        # Regex pattern: only letters, hyphens, apostrophes, and spaces allowed
        if not re.match(r"^[a-zA-Z\s\-']+$", v):
            raise ValueError("Last name must contain only letters")
        return v.strip()

    # @field_validator("s3_key")
    # def validate_s3_key(cls, v):
    #     """Ensure s3_key is not just spaces (if provided)."""
    #     if v is not None and not v.strip():
    #         raise ValueError("s3_key cannot be empty or contain only spaces.")
    #     return v
