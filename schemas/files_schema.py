

from pydantic import BaseModel, Field
from typing import Optional

# Schema for UploadProfilePhotoRequest
class UploadProfilePhotoRequest(BaseModel):
    file_name: str = Field(..., description="Name of the file to upload")
    overwrite: Optional[bool] = Field(False, description="Overwrite existing profile photo if True")
