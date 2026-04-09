import sys
import os
import joblib
import pandas as pd
import json

# Add backend to sys.path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

MODEL_PATH = os.path.join('backend', 'models', 'phishing_rf_production.pkl')
META_PATH = os.path.join('backend', 'models', 'model_metadata.json')

print("Loading model...")
try:
    model = joblib.load(MODEL_PATH)
    with open(META_PATH, 'r') as f:
        metadata = json.load(f)
    print("Model and metadata loaded.")
    
    cols = metadata["feature_cols"]
    # Dummy features
    features = {col: 0.0 for col in cols}
    X = pd.DataFrame([[features.get(col, 0) for col in cols]], columns=cols)
    
    print("Predicting...")
    prob = model.predict_proba(X)[0][1]
    print(f"Prediction successful: {prob}")
except Exception as e:
    print(f"Error during ML prediction: {e}")
    import traceback
    traceback.print_exc()
