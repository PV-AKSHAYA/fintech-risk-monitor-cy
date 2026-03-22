# backend/app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine
from app import models
from app.routes import auth_routes, transaction_routes, alert_routes
# from services.ml_inference import load_model

# Create all DB tables
models.Base.metadata.create_all(bind=engine)

# # Load ML model once at startup
# load_model()

app = FastAPI(title="Transaction Risk Monitor API", version="1.0")

# CORS — allows React frontend on port 3000 to talk to this server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router, prefix="/auth", tags=["Auth"])
app.include_router(transaction_routes.router, prefix="/transactions", tags=["Transactions"])
app.include_router(alert_routes.router,       prefix="/alerts",       tags=["Alerts"])

@app.get("/")
def root():
    return {"message": "Transaction Risk Monitor API is running"}