from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import date, datetime
from config.models.user_models import PyObjectId
from enum import Enum

class GenderEnum(str, Enum):
    Male = "male"
    Female = "female"
    Transgender = "transgender"


class SexualOrientationEnum(str, Enum):
    Straight = "straight"
    Gay = "gay"
    Bisexual = "bisexual"


class MaritalStatusEnum(str, Enum):
    Single = "single"
    Married = "married"
    Divorced = "divorced"
    In_a_relationship="in_a_relationship"
    Open = "open"


class InterestedInEnum(str, Enum):
    Male = "male"
    Female = "female"
    Gay = "gay"


class OnboardingModel(BaseModel):
    id: Optional[PyObjectId] = Field(default=None)
    user_id: str

    # Step 1 fields
    birthdate: Optional[datetime] = None
    gender: Optional[str] = None
    sexual_orientation: Optional[str] = None
    marital_status: Optional[str] = None
    city: Optional[str] = None

    # Step 2 fields
    bio: Optional[str] = None
    passions: List[str] = []

    # Step 3 fields
    interested_in: Optional[List[InterestedInEnum]] = None
    sexual_preferences: List[str] = []
    preferred_city: Optional[List[str]] = None

    # Step 4 fields
    images: List[str] = []
    selfie_image: Optional[str] = None

    # Bonus fields
    tokens: Optional[int] = None
    public_gallery: Optional[List[str]] = None
    private_gallery: Optional[List[str]] = None

    onboarding_completed: bool = False

    created_at: datetime = datetime.utcnow()
    updated_at: datetime = datetime.utcnow()

    class Config:
        use_enum_values = True
        arbitrary_types_allowed = True


class OnboardingStepUpdate(BaseModel):

    # Step 1 fields
    birthdate: Optional[datetime] = None
    gender: Optional[GenderEnum] = None
    sexual_orientation: Optional[SexualOrientationEnum] = None
    marital_status: Optional[MaritalStatusEnum] = None
    city: Optional[str] = None

    # Step 2 fields
    bio: Optional[str] = None
    passions: Optional[List[str]] = None

    # Step 3 fields
    interested_in: Optional[List[InterestedInEnum]] = None
    sexual_preferences: Optional[List[str]] = None
    preferred_city: Optional[List[str]] = None

    # Step 4 fields
    images: Optional[List[str]] = None
    selfie_image: Optional[str] = None

    # Optional fields
    tokens: Optional[int] = None
    public_gallery: Optional[List[str]] = None
    private_gallery: Optional[List[str]] = None

    onboarding_completed: Optional[bool] = None

    @field_validator("birthdate", mode="before")
    @classmethod
    def validate_birthdate(cls, value):
        if value is None:
            return None

        if isinstance(value, datetime):
            parsed = value
        
        elif isinstance(value, str):
            for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
            
            else:
                raise ValueError("birthdate can not be null or birthdate must be in DD-MM-YYYY or DD/MM/YYYY or YYYY-MM-DD format")
        
        elif isinstance(value, date):
            parsed = datetime.combine(value, datetime.min.time())

        else:
            raise ValueError("Invalid birthdate format")

        # Check if date is today
        if parsed.date() == datetime.utcnow().date():
            raise ValueError("birthdate cannot be today's date")

        return parsed


    @field_validator(
        "city",
        "bio",
        "selfie_image",
        mode="before"
    )
    @classmethod
    def validate_non_empty(cls, value, info):
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            raise ValueError(f"{info.field_name} cannot be empty")
        return value.strip() if isinstance(value, str) else value


    @field_validator(
        "passions",
        "sexual_preferences",
        "images",
        "public_gallery",
        "private_gallery",
        "preferred_city",
        mode="before"
    )
    @classmethod
    def validate_list_fields(cls, value, info):
        if value is None:
            return None

        if not isinstance(value, list):
            raise ValueError(f"{info.field_name} must be a list")

        if len(value) == 0:
            raise ValueError(f"{info.field_name} cannot be an empty list")

        for v in value:
            if not isinstance(v, str) or not v.strip():
                raise ValueError(f"{info.field_name} contains empty or invalid values")

        return value


    @field_validator("onboarding_completed", mode="before")
    @classmethod
    def validate_onboarding_completed(cls, value):
        if value is None:
            return None
        if not isinstance(value, bool):
            raise ValueError("onboarding_completed must be boolean")
        return value


    class Config:
        use_enum_values = True
