# backend/app/routes/alert_routes.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from app.database import get_db
from app import models, schemas
from app.routes.auth_routes import get_current_user

router = APIRouter()


@router.get("/", response_model=list[schemas.AlertOut])
def get_alerts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    return db.query(models.Alert).all()


@router.get("/{alert_id}", response_model=schemas.AlertOut)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/review", response_model=schemas.AlertOut)
def review_alert(
    alert_id: int,
    body: schemas.AlertReview,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.reviewed    = "yes"
    alert.reviewed_by = body.reviewed_by
    alert.reviewed_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert