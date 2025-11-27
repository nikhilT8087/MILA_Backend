from pydantic import BaseModel

# Schema for Token
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# Schema for TokenData
class TokenData(BaseModel):
    username: str
    user_id: str