import joblib
import pandas as pd

# Load the model
model = joblib.load('ml/models/fraud_model.pkl')

def run_test():
    print("--- Starting ML Logic Tests ---")
    
    # Define a high-risk scenario
    high_risk_tx = {
        'amount': 99999,
        'hour': 3,
        'amount_diff_from_avg': 95000,
        'location_enc': 1,
        'device_enc': 5
    }
    
    # Define a low-risk scenario
    low_risk_tx = {
        'amount': 20,
        'hour': 14,
        'amount_diff_from_avg': 2,
        'location_enc': 1,
        'device_enc': 5
    }

    # Run predictions
    for name, tx in [("High Risk", high_risk_tx), ("Low Risk", low_risk_tx)]:
        df = pd.DataFrame([tx])
        prob = model.predict_proba(df)[0][1]
        print(f"Test [{name}]: Risk Score = {prob*100:.2f}%")
        
        # Simple Assertion: High risk should be > Low risk
        if name == "High Risk" and prob < 0.5:
            print("❌ FAILED: High risk transaction was ignored.")
        elif name == "Low Risk" and prob > 0.5:
            print("❌ FAILED: Normal transaction was flagged.")
        else:
            print(f"✅ PASSED")

if __name__ == "__main__":
    run_test()