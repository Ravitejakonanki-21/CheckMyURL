import joblib
import json
import pandas as pd

def load_production_model(model_path, meta_path):
    model = joblib.load(model_path)
    with open(meta_path, "r") as f:
        metadata = json.load(f)
    return model, metadata


def predict_url_risk(features, model, metadata):
    cols = metadata["feature_cols"]
    threshold = metadata.get("decision_threshold", 0.5)

    # Build dataframe in correct order
    X = pd.DataFrame([[features.get(col, 0) for col in cols]], columns=cols)

    prob = model.predict_proba(X)[0][1]

    return {
        "ml_probability": round(prob, 4),
        "ml_score": int(prob * 100),
        "is_phishing": prob >= threshold
    }
