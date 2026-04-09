import joblib
import json
import pandas as pd

def load_production_model(model_path, meta_path):
    model = joblib.load(model_path)
    with open(meta_path, "r") as f:
        metadata = json.load(f)
    return model, metadata


def predict_url_risk(features, model, metadata):
    """
    Predict risk based on extracted features using the production ML model.
    """
    cols = metadata.get("feature_cols", [])
    threshold = metadata.get("decision_threshold", 0.5)

    if not cols:
        raise ValueError("No feature columns found in metadata")

    # Build dataframe in correct order, defaulting missing features to 0.0
    # Also ensures data types are correct for the model
    try:
        data = [[float(features.get(col, 0.0)) for col in cols]]
        X = pd.DataFrame(data, columns=cols)
        
        # Get probability of class 1 (phishing)
        probabilities = model.predict_proba(X)
        prob = float(probabilities[0][1])
        
        return {
            "ml_probability": round(prob, 4),
            "ml_score": int(round(prob * 100)),
            "is_phishing": prob >= threshold,
            "feature_count": len(cols)
        }
    except Exception as e:
        # Re-raise with context to be caught by the app logger
        raise RuntimeError(f"ML prediction execution failed: {str(e)}")
