import joblib
import pandas as pd
import numpy as np

# 1. Load the model and the explainer we saved earlier
MODEL_PATH = "ml/models/fraud_model.pkl"
EXPLAINER_PATH = "ml/models/shap_explainer.pkl"

model = joblib.load(MODEL_PATH)
explainer = joblib.load(EXPLAINER_PATH)

def predict_fraud_risk(transaction_data: dict):
    """
    Takes a dictionary (from the API) and returns a risk score + explanation.
    """
    # Convert incoming JSON/Dict to a DataFrame
    df_input = pd.DataFrame([transaction_data])
    
    # Calculate probability
    # [0][1] gives the probability of class 1 (Fraud)
    prob = model.predict_proba(df_input)[0][1]
    risk_score = round(prob * 100, 2)
    
    # Generate SHAP explanation for this specific transaction
    shap_vals = explainer.shap_values(df_input)
    
    # Find the top reason for the score (the feature with highest SHAP value)
    feature_names = df_input.columns
    top_feature_index = np.argmax(shap_vals[0])
    reason = f"High influence from: {feature_names[top_feature_index]}"
    
    return {
        "risk_score": risk_score,
        "is_flagged": risk_score > 50, # Threshold for flagging
        "explanation": reason
    }