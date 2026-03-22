# backend/app/schemas.py
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# --- Auth ---
class UserCreate(BaseModel):
    email: str
    password: str
    role: Optional[str] = "analyst"

class UserOut(BaseModel):
    id: int
    email: str
    role: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str


# --- Transaction ---
class TransactionCreate(BaseModel):
    user_id: str
    amount: float
    device_id: Optional[str] = None
    location: Optional[str] = None
    transaction_type: Optional[str] = "transfer"
    receiver_id: Optional[str] = None

class TransactionStatusUpdate(BaseModel):
    status: str  # safe or suspicious

class TransactionOut(BaseModel):
    id: int
    user_id: str
    amount: float
    device_id: Optional[str]
    location: Optional[str]
    transaction_type: Optional[str]
    status: str
    risk_score: float
    risk_level: str
    ml_score: float
    rule_flags: Optional[list]
    timestamp: datetime
    class Config:
        from_attributes = True


# --- Alert ---
class AlertOut(BaseModel):
    id: int
    transaction_id: int
    risk_level: str
    recommended_action: str
    explanation: str
    reviewed: str
    reviewed_by: Optional[str]
    created_at: datetime
    class Config:
        from_attributes = True

class AlertReview(BaseModel):
    reviewed_by: str