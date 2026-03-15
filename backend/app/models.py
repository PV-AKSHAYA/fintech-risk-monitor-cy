# backend/app/models.py
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")  # analyst or admin
    created_at = Column(DateTime, server_default=func.now())


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, nullable=False)
    receiver_id = Column(String, nullable=True)
    amount = Column(Float, nullable=False)
    device_id = Column(String)
    location = Column(String)
    transaction_type = Column(String)
    timestamp = Column(DateTime, server_default=func.now())
    status = Column(String, default="pending")   # pending / safe / suspicious
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="Low")   # Low / Medium / High
    ml_score = Column(Float, default=0.0)
    rule_flags = Column(JSON, default=list)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, nullable=False)
    risk_level = Column(String)
    recommended_action = Column(String)
    explanation = Column(String)
    reviewed = Column(String, default="no")      # no / yes
    reviewed_by = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    reviewed_at = Column(DateTime, nullable=True)