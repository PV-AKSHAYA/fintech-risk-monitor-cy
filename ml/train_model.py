import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler # Added StandardScaler
from sklearn.linear_model import LogisticRegression
from imblearn.over_sampling import SMOTE
import shap
import warnings

# Ignore the feature names warning for a cleaner terminal output
warnings.filterwarnings("ignore", category=UserWarning)

def train():
    print("--- Starting Final Model Training ---")
    
    # 1. Load Data
    try:
        df = pd.read_csv('ml/dataset/transactions.csv')
    except FileNotFoundError:
        df = pd.read_csv('dataset/transactions.csv')
    
    # 2. Feature Engineering
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    user_avg = df.groupby('user_id')['amount'].transform('mean')
    df['amount_diff_from_avg'] = df['amount'] - user_avg
    
    le_loc = LabelEncoder()
    df['location_enc'] = le_loc.fit_transform(df['location'])
    le_dev = LabelEncoder()
    df['device_enc'] = le_dev.fit_transform(df['device_id'])
    
    features = ['amount', 'hour', 'amount_diff_from_avg', 'location_enc', 'device_enc']
    X = df[features]
    y = df['is_fraud']
    
    # 3. Scaling & Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Initialize and fit the scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # 4. Handle Imbalance with SMOTE
    smote = SMOTE(random_state=42)
    X_res, y_res = smote.fit_resample(X_train_scaled, y_train)
    
    # 5. Add 10% Realism Noise
    n_noise = int(0.10 * len(y_res))
    noise_idx = np.random.choice(len(y_res), n_noise, replace=False)
    y_res.iloc[noise_idx] = 1 - y_res.iloc[noise_idx]
    
    # 6. Train Model
    model = LogisticRegression(max_iter=1000, C=0.01, random_state=42)
    model.fit(X_res, y_res)
    
    # 7. Save ALL Artifacts
    joblib.dump(model, 'ml/models/fraud_model.pkl')
    joblib.dump(scaler, 'ml/models/scaler.pkl') # CRITICAL: Save the scaler!
    
    # Save SHAP Explainer
    explainer = shap.LinearExplainer(model, X_res)
    joblib.dump(explainer, 'ml/models/shap_explainer.pkl')
    
    print("✅ SUCCESS: Model, Scaler, and Explainer saved to ml/models/")

if __name__ == "__main__":
    train()