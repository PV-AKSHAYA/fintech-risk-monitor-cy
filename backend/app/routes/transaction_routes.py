# backend/app/routes/transaction_routes.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from app.database import get_db
from app import models, schemas
from app.routes.auth_routes import get_current_user
from services.risk_engine import evaluate_transaction

router = APIRouter()


@router.post("/", response_model=schemas.TransactionOut)
def add_transaction(
    txn: schemas.TransactionCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    txn_data = txn.dict()

    # Add timestamp if not provided
    if "timestamp" not in txn_data or not txn_data["timestamp"]:
        txn_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Run risk engine
    risk = evaluate_transaction(txn_data)

    # Save transaction to DB
    new_txn = models.Transaction(
        user_id          = txn_data["user_id"],
        receiver_id      = txn_data.get("receiver_id", "unknown"),
        amount           = txn_data["amount"],
        device_id        = txn_data.get("device_id"),
        location         = txn_data.get("location"),
        transaction_type = txn_data.get("transaction_type"),
        status           = "pending",
        risk_score       = risk["risk_score"],
        risk_level       = risk["risk_level"],
        ml_score         = risk["ml_score"],
        rule_flags       = risk["rule_flags"]
    )
    db.add(new_txn)
    db.commit()
    db.refresh(new_txn)

    # Auto create alert if MEDIUM or HIGH
    if risk["risk_level"] in ["MEDIUM", "HIGH"]:
        alert = models.Alert(
            transaction_id     = new_txn.id,
            risk_level         = risk["risk_level"],
            recommended_action = risk["recommended_action"],
            explanation        = risk["explanation"]
        )
        db.add(alert)
        db.commit()

    return new_txn


@router.get("/", response_model=list[schemas.TransactionOut])
def get_transactions(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    return db.query(models.Transaction).all()


@router.get("/{txn_id}", response_model=schemas.TransactionOut)
def get_transaction(
    txn_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    txn = db.query(models.Transaction).filter(models.Transaction.id == txn_id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return txn


@router.patch("/{txn_id}/status", response_model=schemas.TransactionOut)
def update_status(
    txn_id: int,
    body: schemas.TransactionStatusUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    txn = db.query(models.Transaction).filter(models.Transaction.id == txn_id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if body.status not in ["safe", "suspicious"]:
        raise HTTPException(status_code=400, detail="Status must be 'safe' or 'suspicious'")
    txn.status = body.status
    db.commit()
    db.refresh(txn)
    return txn