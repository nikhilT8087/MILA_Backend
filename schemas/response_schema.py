from pydantic import BaseModel, model_validator
from typing import Optional, Dict

# Schema for Response
class Response(BaseModel):
    message: Optional[str] = None
    data: Optional[Dict] = None
    success: bool
    status_code: int

    @model_validator(mode="before")
    def validate_message_fields(cls, values):
        if not values.get("message") and not values.get("data"):
            raise ValueError("Either 'message' or 'data' must be provided.")
        return values