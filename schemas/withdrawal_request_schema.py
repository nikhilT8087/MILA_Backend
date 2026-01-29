from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
from datetime import datetime
from core.utils.core_enums import WithdrawalStatus
from decimal import Decimal


class AdminWithdrawalUpdateModel(BaseModel):
    status: WithdrawalStatus
    paid_amount: float = Field(..., ge=0)
    platform_fee: float = Field(default=0, ge=0)
    tron_fee: float = Field(default=0, ge=0)
    payment_details: List[dict] = Field(default_factory=list)

class AdminWithdrawalResponseModel(BaseModel):
    id: str = Field(alias="_id")
    user_id: str
    request_amount: float
    paid_amount: float
    remaining_amount: float
    status: str
    wallet_address: str
    platform_fee: float
    tron_fee: float
    tokens: int
    created_at: str
    updated_at: str

    model_config = {"populate_by_name": True}

class AdminWithdrawalCompleteRequestModel(BaseModel):
    tron_txn_id: str = Field(
        ...,
        description="TRON blockchain transaction ID used to send funds"
    )
    paid_amount:Decimal = Field(
        ...,
        gt=0,
        description="Amount actually sent to user's wallet"
    )
    tron_fee:Decimal = Field(
        ...,
        ge=0,
        description="TRON transaction fee"
    )

    @field_validator("paid_amount", "tron_fee")
    def validate_amount(cls, value: float):
        if value <= 0:
            raise ValueError("Amount must be greater than 0")
        return value

    @field_validator("tron_txn_id")
    def validate_tron_txn_id(cls, value: str):
        if not value or not value.strip():
            raise ValueError("tron_txn_id cannot be empty")
        return value.strip()
