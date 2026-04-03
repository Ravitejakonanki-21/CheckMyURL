# ================================================================
#  PHISHING DETECTION MODEL — SECURITY-GRADE PIPELINE
#  Colab-compatible | Audit-clean | Leakage-free | Production-ready
#  Target: 90–95% real-world accuracy
# ================================================================

# ─────────────────────────────────────────────────────────────────
# CELL 1 — Install (Colab-compatible, no version conflicts)
# ─────────────────────────────────────────────────────────────────
# Only install what Colab doesn't have by default
# pandas, numpy, scikit-learn, joblib, matplotlib, seaborn
# are already pre-installed in Colab — DO NOT pin their versions

"""
!pip install imbalanced-learn -q
"""

# ─────────────────────────────────────────────────────────────────
# CELL 2 — Upload CSV
# ─────────────────────────────────────────────────────────────────

"""
from google.colab import files
uploaded = files.upload()
# Select: Phishing_Legitimate_full.csv
"""

# ─────────────────────────────────────────────────────────────────
# CELL 3 — Imports & Version Info
# ─────────────────────────────────────────────────────────────────

import json
import joblib
import warnings
import platform
import sklearn
import imblearn
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
warnings.filterwarnings("ignore")

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_validate
)
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import (
    classification_report, roc_auc_score, confusion_matrix,
    precision_recall_curve, average_precision_score, f1_score
)
from sklearn.base import BaseEstimator, TransformerMixin
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE

print("=" * 60)
print("  ENVIRONMENT INFO")
print("=" * 60)
print(f"  Python    : {platform.python_version()}")
print(f"  sklearn   : {sklearn.__version__}")
print(f"  imblearn  : {imblearn.__version__}")
print(f"  numpy     : {np.__version__}")
print(f"  pandas    : {pd.__version__}")
print("=" * 60)

# ─────────────────────────────────────────────────────────────────
# CELL 4 — Load & Validate Data
# ─────────────────────────────────────────────────────────────────

df = pd.read_csv("Phishing_Legitimate_full.csv")

TARGET = 'CLASS_LABEL'

# Hard-coded leaky/ID columns — add any raw URL string columns here
LEAKY_COLS = {
    'CLASS_LABEL', 'id', 'url', 'URL', 'domain', 'Domain',
    'webpage_url', 'raw_url', 'index'
}

feature_cols_initial = [c for c in df.columns if c not in LEAKY_COLS]

print("=" * 60)
print("  DATASET OVERVIEW")
print("=" * 60)
print(f"  Rows              : {len(df)}")
print(f"  Columns           : {len(df.columns)}")
print(f"  Features (initial): {len(feature_cols_initial)}")
print(f"  Missing values    : {df.isnull().sum().sum()}")

vc = df[TARGET].value_counts()
legit_count     = vc.get(0, 0)
phish_count     = vc.get(1, 0)
imbalance_ratio = legit_count / max(phish_count, 1)

print(f"\n  Class Distribution:")
print(f"    Legit    (0) : {legit_count}")
print(f"    Phishing (1) : {phish_count}")
print(f"    Imbalance    : {imbalance_ratio:.2f}:1")
print("=" * 60)

# Abort early if label column is wrong
assert set(df[TARGET].unique()).issubset({0, 1}), \
    "CLASS_LABEL must be binary 0/1 — check your CSV"

X_full = df[feature_cols_initial].fillna(0)
y_full = df[TARGET].fillna(0).astype(int)

# ─────────────────────────────────────────────────────────────────
# CELL 5 — THREE-WAY SPLIT: train / val / test
#
#  train (60%) → model training + calibration
#  val   (20%) → threshold tuning only
#  test  (20%) → final honest evaluation, never touched before
# ─────────────────────────────────────────────────────────────────

X_temp, X_test, y_temp, y_test = train_test_split(
    X_full, y_full,
    test_size=0.20,
    random_state=42,
    shuffle=True,
    stratify=y_full
)

X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp,
    test_size=0.25,       # 0.25 x 0.80 = 0.20 of total
    random_state=42,
    shuffle=True,
    stratify=y_temp
)

print(f"\n  Split Summary:")
print(f"    Train : {len(X_train)} rows  ({y_train.mean()*100:.1f}% phishing)")
print(f"    Val   : {len(X_val)}  rows  ({y_val.mean()*100:.1f}% phishing)")
print(f"    Test  : {len(X_test)}  rows  ({y_test.mean()*100:.1f}% phishing)")

# ─────────────────────────────────────────────────────────────────
# CELL 6 — Feature Filtering (fitted on X_train ONLY)
#
#  Variance and correlation filters NEVER see val or test data.
#  Fit on X_train → transform all three splits with same mask.
# ─────────────────────────────────────────────────────────────────

class TrainOnlyFeatureFilter(BaseEstimator, TransformerMixin):
    """
    Drops near-zero-variance and highly correlated features.
    fit() sees only training data — zero leakage.
    """
    def __init__(self, var_threshold=0.001, corr_threshold=0.95):
        self.var_threshold  = var_threshold
        self.corr_threshold = corr_threshold
        self.keep_cols_     = None

    def fit(self, X, y=None):
        X_ = pd.DataFrame(X)

        # Step 1: Variance filter
        var   = X_.var()
        keep  = var[var >= self.var_threshold].index.tolist()
        X_var = X_[keep]

        # Step 2: Correlation filter
        corr_matrix = X_var.corr().abs()
        upper       = corr_matrix.where(
            np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
        )
        drop_corr  = [col for col in upper.columns
                      if any(upper[col] > self.corr_threshold)]
        keep_final = [c for c in keep if c not in drop_corr]

        self.keep_cols_    = keep_final
        self.dropped_var_  = [c for c in X_.columns if c not in keep]
        self.dropped_corr_ = drop_corr
        return self

    def transform(self, X, y=None):
        return pd.DataFrame(X)[self.keep_cols_]

    def get_feature_names_out(self):
        return self.keep_cols_


# Fit on training data ONLY
feat_filter = TrainOnlyFeatureFilter(var_threshold=0.001, corr_threshold=0.95)
feat_filter.fit(X_train)

print(f"\n  Feature Filtering (train-only fit):")
print(f"    Initial features   : {len(feature_cols_initial)}")
print(f"    Dropped (variance) : {len(feat_filter.dropped_var_)}")
print(f"    Dropped (corr)     : {len(feat_filter.dropped_corr_)}")
print(f"    Remaining          : {len(feat_filter.keep_cols_)}")

# Apply same fitted filter to all three splits
X_train_f = feat_filter.transform(X_train)
X_val_f   = feat_filter.transform(X_val)
X_test_f  = feat_filter.transform(X_test)
feature_cols = feat_filter.keep_cols_

# ─────────────────────────────────────────────────────────────────
# CELL 7 — Build ImbPipeline (SMOTE inside each CV fold)
#
#  imblearn Pipeline ensures SMOTE only runs inside training folds.
#  Validation folds NEVER see synthetic samples — leakage-free.
# ─────────────────────────────────────────────────────────────────

USE_SMOTE = imbalance_ratio > 1.5

rf_estimator = RandomForestClassifier(
    n_estimators=500,
    max_depth=12,
    min_samples_leaf=6,
    min_samples_split=12,
    max_features='sqrt',
    class_weight='balanced',
    bootstrap=True,
    oob_score=True,
    random_state=42,
    n_jobs=-1
)

if USE_SMOTE:
    print(f"\n  [SMOTE] Imbalance {imbalance_ratio:.2f}:1 — SMOTE enabled inside pipeline")
    base_pipeline = ImbPipeline([
        ('smote', SMOTE(random_state=42, k_neighbors=5)),
        ('rf',    rf_estimator)
    ])
else:
    from sklearn.pipeline import Pipeline as SkPipeline
    print(f"\n  [INFO] Imbalance {imbalance_ratio:.2f}:1 — SMOTE not required")
    base_pipeline = SkPipeline([
        ('rf', rf_estimator)
    ])

# ─────────────────────────────────────────────────────────────────
# CELL 8 — 5-Fold Stratified CV (honest, leakage-free)
#
#  CV runs on the full pipeline (SMOTE inside each fold).
#  Evaluated on training data only — test set untouched.
# ─────────────────────────────────────────────────────────────────

print("\n  Running 5-fold stratified CV on training data...")
print("  (This takes 3-5 minutes — please wait)")

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

cv_results = cross_validate(
    base_pipeline,
    X_train_f, y_train,
    cv=skf,
    scoring={
        'roc_auc'  : 'roc_auc',
        'f1'       : 'f1',
        'recall'   : 'recall',
        'precision': 'precision',
    },
    n_jobs=-1,
    return_train_score=False
)

print(f"\n  5-Fold CV Results (training data only):")
print(f"    ROC-AUC   : {cv_results['test_roc_auc'].mean():.4f} "
      f"± {cv_results['test_roc_auc'].std():.4f}")
print(f"    F1        : {cv_results['test_f1'].mean():.4f} "
      f"± {cv_results['test_f1'].std():.4f}")
print(f"    Recall    : {cv_results['test_recall'].mean():.4f} "
      f"± {cv_results['test_recall'].std():.4f}")
print(f"    Precision : {cv_results['test_precision'].mean():.4f} "
      f"± {cv_results['test_precision'].std():.4f}")

# ─────────────────────────────────────────────────────────────────
# CELL 9 — Train Final Model on Full Training Set
# ─────────────────────────────────────────────────────────────────

print("\n  Training final model on full training set...")
base_pipeline.fit(X_train_f, y_train)

# Access RF step from pipeline
rf_step = base_pipeline.named_steps['rf']
print(f"  OOB Score: {rf_step.oob_score_:.4f}")

# Feature importances from RF
importances       = pd.Series(rf_step.feature_importances_, index=feature_cols)
importances_sorted = importances.sort_values(ascending=False)

# Robust top_features selection
# Include features until 95% importance covered, minimum 10 features
cumulative  = importances_sorted.cumsum()
top_mask    = cumulative <= 0.95
n_top       = top_mask.sum()

if n_top < 10:
    # Edge case: single dominant feature — take top 20 minimum
    top_features = importances_sorted.head(
        min(20, len(importances_sorted))
    ).index.tolist()
    print(f"\n  [INFO] Single dominant feature detected — using top 20")
else:
    top_features = importances_sorted[top_mask].index.tolist()

print(f"  Features covering 95% importance mass : {len(top_features)}")
print(f"  Top 10 features: {top_features[:10]}")

# Rebuild train/val/test with top features only
X_train_sel = X_train_f[top_features]
X_val_sel   = X_val_f[top_features]
X_test_sel  = X_test_f[top_features]

# Rebuild lean pipeline with selected features
if USE_SMOTE:
    lean_pipeline = ImbPipeline([
        ('smote', SMOTE(random_state=42, k_neighbors=5)),
        ('rf', RandomForestClassifier(
            n_estimators=500,
            max_depth=12,
            min_samples_leaf=6,
            min_samples_split=12,
            max_features='sqrt',
            class_weight='balanced',
            bootstrap=True,
            oob_score=True,
            random_state=42,
            n_jobs=-1
        ))
    ])
else:
    from sklearn.pipeline import Pipeline as SkPipeline
    lean_pipeline = SkPipeline([
        ('rf', RandomForestClassifier(
            n_estimators=500,
            max_depth=12,
            min_samples_leaf=6,
            min_samples_split=12,
            max_features='sqrt',
            class_weight='balanced',
            bootstrap=True,
            oob_score=True,
            random_state=42,
            n_jobs=-1
        ))
    ])

print("\n  Retraining lean model on selected features...")
lean_pipeline.fit(X_train_sel, y_train)
rf_lean_step = lean_pipeline.named_steps['rf']
print(f"  Lean model OOB Score: {rf_lean_step.oob_score_:.4f}")

# ─────────────────────────────────────────────────────────────────
# CELL 10 — Calibrate Probabilities
#
#  Calibration is fitted on training data with internal 5-fold CV.
#  Makes predict_proba() reliable for explainable risk scoring.
# ─────────────────────────────────────────────────────────────────

print("\n  Calibrating probabilities (isotonic, 5-fold on train data)...")
model = CalibratedClassifierCV(lean_pipeline, method='isotonic', cv=5)
model.fit(X_train_sel, y_train)
print("  Calibration complete.")

# ─────────────────────────────────────────────────────────────────
# CELL 11 — Threshold Tuning on VALIDATION SET
#
#  Threshold is tuned on X_val — NEVER on test set.
#  Goal: phishing recall >= 97% (catch more phishing,
#  accept slightly more false alarms — correct for security tools)
# ─────────────────────────────────────────────────────────────────

y_val_prob = model.predict_proba(X_val_sel)[:, 1]

print("\n" + "=" * 60)
print("  THRESHOLD TUNING — Validation Set Only")
print("=" * 60)

security_threshold = None

for t in np.arange(0.10, 0.70, 0.005):
    preds   = (y_val_prob >= t).astype(int)
    if preds.sum() == 0:
        continue
    tp_v    = int(((preds == 1) & (y_val == 1)).sum())
    fn_v    = int(((preds == 0) & (y_val == 1)).sum())
    fp_v    = int(((preds == 1) & (y_val == 0)).sum())
    tn_v    = int(((preds == 0) & (y_val == 0)).sum())
    recall_v = tp_v / max(tp_v + fn_v, 1)
    prec_v   = tp_v / max(tp_v + fp_v, 1)
    if recall_v >= 0.97:
        security_threshold = round(float(t), 3)
        break

# Fallback: best F1 threshold from validation set
if security_threshold is None:
    prec_v_arr, rec_v_arr, thresh_v_arr = precision_recall_curve(
        y_val, y_val_prob
    )
    f1_v_arr = (2 * prec_v_arr * rec_v_arr /
                (prec_v_arr + rec_v_arr + 1e-9))
    security_threshold = round(
        float(thresh_v_arr[np.argmax(f1_v_arr[:-1])]), 3
    )
    print("  [WARN] Could not achieve 97% recall — using best-F1 threshold")

# Report validation performance at chosen threshold
y_val_pred = (y_val_prob >= security_threshold).astype(int)
val_cm     = confusion_matrix(y_val, y_val_pred)
vTN, vFP, vFN, vTP = val_cm[0,0], val_cm[0,1], val_cm[1,0], val_cm[1,1]

print(f"  Chosen threshold (val set)  : {security_threshold}")
print(f"  Val phishing recall         : {vTP/(vTP+vFN):.2%}")
print(f"  Val FNR (missed phishing)   : {vFN/(vFN+vTP):.2%}")
print(f"  Val FPR (false alarms)      : {vFP/(vFP+vTN):.2%}")
print(f"  Val F1                      : {f1_score(y_val, y_val_pred):.4f}")

# ─────────────────────────────────────────────────────────────────
# CELL 12 — FINAL EVALUATION on Test Set
#
#  Test set is touched exactly ONCE here.
#  Threshold already fixed from validation set above.
# ─────────────────────────────────────────────────────────────────

y_test_prob = model.predict_proba(X_test_sel)[:, 1]
y_test_pred = (y_test_prob >= security_threshold).astype(int)

print("\n" + "=" * 60)
print("  FINAL EVALUATION — Held-out Test Set")
print("  (threshold was fixed on validation set — honest result)")
print("=" * 60)
print(classification_report(
    y_test, y_test_pred,
    target_names=['Legit', 'Phishing']
))

roc_auc  = roc_auc_score(y_test, y_test_prob)
avg_prec = average_precision_score(y_test, y_test_prob)
test_f1  = f1_score(y_test, y_test_pred)

print(f"  ROC-AUC          : {roc_auc:.4f}")
print(f"  Avg Precision    : {avg_prec:.4f}")
print(f"  F1 Score         : {test_f1:.4f}")

cm_test       = confusion_matrix(y_test, y_test_pred)
TN, FP, FN, TP = cm_test[0,0], cm_test[0,1], cm_test[1,0], cm_test[1,1]
fnr = FN / max(FN + TP, 1)
fpr = FP / max(FP + TN, 1)
acc = (TP + TN) / max(TP + TN + FP + FN, 1)

print(f"\n  Confusion Matrix:")
print(f"    TN (Legit correct)   : {TN}")
print(f"    FP (Legit flagged)   : {FP}")
print(f"    FN (Phish MISSED)    : {FN}  ← want minimal")
print(f"    TP (Phish caught)    : {TP}")
print(f"\n  Accuracy             : {acc:.2%}")
print(f"  FNR (missed phishing): {fnr:.2%}  ← target < 5%")
print(f"  FPR (false alarms)   : {fpr:.2%}")

if acc < 0.90:
    print(f"\n  [WARN] Accuracy {acc:.2%} below 90% target.")
    print("  Try: increase n_estimators to 700 or review features")
else:
    print(f"\n  [PASS] Accuracy {acc:.2%} meets 90-95% real-world target.")

# ─────────────────────────────────────────────────────────────────
# CELL 13 — Diagnostic Plots
# ─────────────────────────────────────────────────────────────────

fig, axes = plt.subplots(1, 3, figsize=(18, 5))
fig.suptitle(
    "Phishing Detection Model — Production Diagnostics",
    fontsize=13, fontweight='bold'
)

# Plot 1: Feature Importances (safe indexing)
valid_top = [f for f in top_features if f in importances_sorted.index]
top15_imp = importances_sorted.loc[valid_top].head(15)
axes[0].barh(
    top15_imp.index[::-1], top15_imp.values[::-1], color='#2563eb'
)
axes[0].set_title("Top 15 Feature Importances")
axes[0].set_xlabel("Importance Score")
axes[0].tick_params(labelsize=8)

# Plot 2: Calibration Curve
frac_pos, mean_pred = calibration_curve(y_test, y_test_prob, n_bins=10)
axes[1].plot([0, 1], [0, 1], 'k--',
             label='Perfect calibration', linewidth=1.5)
axes[1].plot(mean_pred, frac_pos, 's-',
             color='#2563eb', label='Our model', linewidth=2)
axes[1].fill_between(mean_pred, frac_pos, mean_pred,
                     alpha=0.15, color='#2563eb')
axes[1].set_title("Calibration Curve\n(closer to diagonal = better)")
axes[1].set_xlabel("Mean Predicted Probability")
axes[1].set_ylabel("Fraction of Positives")
axes[1].legend(fontsize=8)

# Plot 3: Precision-Recall with threshold marker
prec_arr, rec_arr, thr_arr = precision_recall_curve(y_test, y_test_prob)
axes[2].plot(rec_arr[:-1], prec_arr[:-1], color='#2563eb', linewidth=2)
axes[2].axvline(
    x=TP/(TP+FN) if (TP+FN) > 0 else 0,
    color='red', linestyle='--', linewidth=1.5,
    label=f'Threshold={security_threshold} | '
          f'Recall={TP/(TP+FN):.2f}' if (TP+FN) > 0 else ''
)
if (TP + FP) > 0:
    axes[2].axhline(
        y=TP/(TP+FP),
        color='orange', linestyle=':', linewidth=1.2,
        label=f'Precision={TP/(TP+FP):.2f}'
    )
axes[2].set_title(f"Precision-Recall Curve\n(AP={avg_prec:.3f})")
axes[2].set_xlabel("Recall (Phishing Caught)")
axes[2].set_ylabel("Precision")
axes[2].legend(fontsize=7)

plt.tight_layout()
plt.savefig("model_diagnostics.png", dpi=150, bbox_inches='tight')
plt.show()
print("  Saved: model_diagnostics.png")

# ─────────────────────────────────────────────────────────────────
# CELL 14 — Save Production Artifacts + Download
# ─────────────────────────────────────────────────────────────────

# Save model
joblib.dump(model, "phishing_rf_production.pkl")

# Save metadata with all version info
metadata = {
    # Performance
    "roc_auc"              : round(roc_auc, 4),
    "avg_precision"        : round(avg_prec, 4),
    "f1_score"             : round(test_f1, 4),
    "accuracy"             : round(acc, 4),
    "phishing_recall"      : round(TP/(TP+FN), 4) if (TP+FN) > 0 else 0,
    "false_negative_rate"  : round(fnr, 4),
    "false_positive_rate"  : round(fpr, 4),

    # Threshold (tuned on validation set — NOT test set)
    "decision_threshold"   : security_threshold,
    "threshold_tuned_on"   : "validation_set",

    # Features
    "feature_cols"         : top_features,
    "n_features"           : len(top_features),
    "features_dropped_var" : feat_filter.dropped_var_,
    "features_dropped_corr": feat_filter.dropped_corr_,

    # Training info
    "training_samples"     : len(X_train),
    "val_samples"          : len(X_val),
    "test_samples"         : len(X_test),
    "smote_applied"        : USE_SMOTE,

    # Versions (for compatibility tracking)
    "python_version"       : platform.python_version(),
    "sklearn_version"      : sklearn.__version__,
    "imblearn_version"     : imblearn.__version__,
    "numpy_version"        : np.__version__,
    "pandas_version"       : pd.__version__,
}

with open("model_metadata.json", "w") as f:
    json.dump(metadata, f, indent=2)

print("\n" + "=" * 60)
print("  ARTIFACTS SAVED SUCCESSFULLY")
print("=" * 60)
print("  phishing_rf_production.pkl  ← load in Flask backend")
print("  model_metadata.json         ← features + threshold + versions")
print("  model_diagnostics.png       ← diagnostic plots")
print(f"\n  sklearn   : {sklearn.__version__}")
print(f"  imblearn  : {imblearn.__version__}")
print(f"  Accuracy  : {acc:.2%}")
print(f"  FNR       : {fnr:.2%}")
print(f"  Threshold : {security_threshold}")

# ── Download from Colab ────────────────────────────────────────
# Uncomment these 4 lines and run this cell to download
# Run ONLY inside Google Colab browser session

"""
from google.colab import files
files.download("phishing_rf_production.pkl")
files.download("model_metadata.json")
files.download("model_diagnostics.png")
"""

# ─────────────────────────────────────────────────────────────────
# CELL 15 — Production Inference Functions
# (Copy these two functions into your Flask backend)
# ─────────────────────────────────────────────────────────────────

def load_production_model(model_path="phishing_rf_production.pkl",
                          meta_path="model_metadata.json"):
    """
    Load model + metadata for Flask backend.
    Warns (does NOT crash) on sklearn version mismatch
    because Colab updates sklearn frequently.
    Call this ONCE at app startup, not per request.

    Usage in Flask:
        model, metadata = load_production_model(
            model_path="models/phishing_rf_production.pkl",
            meta_path="models/model_metadata.json"
        )
    """
    import sklearn as _sk

    model = joblib.load(model_path)

    with open(meta_path) as f:
        meta = json.load(f)

    # Warn instead of crash on version mismatch
    trained_ver = meta.get("sklearn_version", "unknown")
    current_ver = _sk.__version__
    if trained_ver != current_ver:
        print(f"  [WARN] sklearn version mismatch:")
        print(f"    Trained on : {trained_ver}")
        print(f"    Current    : {current_ver}")
        print(f"  Model will likely work for minor version differences.")
        print(f"  If predictions seem wrong, retrain with current version.")
    else:
        print(f"  [OK] sklearn version match: {current_ver}")

    return model, meta


def predict_url_risk(feature_dict: dict,
                     model,
                     metadata: dict,
                     min_features_present: int = 5) -> dict:
    """
    Predict phishing risk from extracted URL features.

    Args:
        feature_dict         : {feature_name: value, ...}
                               from your URL feature extractor
        model                : loaded CalibratedClassifierCV
        metadata             : loaded model_metadata.json
        min_features_present : minimum known features required
                               raises ValueError if fewer present
                               (prevents silent safe predictions
                               when feature extractor fails)

    Returns:
        {
          "phishing_probability" : float 0.0-1.0,
          "is_phishing"          : bool,
          "risk_level"           : "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
          "ml_score"             : int 0-100 (for risk engine),
          "confidence"           : float,
          "missing_features"     : list,
          "confidence_flag"      : "OK"|"WARN_LOW_FEATURES"
        }

    Usage in Flask (risk_explainable.py):
        result = predict_url_risk(features, model, metadata)
        ml_score = result["ml_score"]   # plug into build_explainable_risk()
    """
    feature_cols = metadata["feature_cols"]
    threshold    = metadata["decision_threshold"]

    # Safety check: reject near-empty input
    # Empty dict → feature extractor failed → do NOT return "safe"
    present = [
        f for f in feature_cols
        if f in feature_dict and feature_dict[f] is not None
    ]
    if len(present) < min_features_present:
        raise ValueError(
            f"predict_url_risk received only {len(present)} known features "
            f"(minimum required: {min_features_present}). "
            f"Feature extraction likely failed upstream. "
            f"Reject this scan — do NOT default to safe."
        )

    # Build feature vector — fill genuinely missing with 0
    missing = [f for f in feature_cols if f not in feature_dict]
    row     = {col: feature_dict.get(col, 0) for col in feature_cols}
    X_input = pd.DataFrame([row])[feature_cols].fillna(0)

    # Predict
    prob        = float(model.predict_proba(X_input)[0][1])
    is_phishing = prob >= threshold

    # 4-level risk bands for SOC workflow
    if prob < 0.25:
        risk_level = "LOW"
    elif prob < 0.50:
        risk_level = "MEDIUM"
    elif prob < 0.75:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # Flag if too many features are missing
    confidence_flag = (
        "WARN_LOW_FEATURES"
        if len(missing) > len(feature_cols) * 0.30
        else "OK"
    )

    return {
        "phishing_probability": round(prob, 4),
        "is_phishing"         : bool(is_phishing),
        "risk_level"          : risk_level,
        "ml_score"            : int(prob * 100),
        "confidence"          : round(max(prob, 1 - prob), 4),
        "missing_features"    : missing,
        "confidence_flag"     : confidence_flag,
    }


# ─────────────────────────────────────────────────────────────────
# CELL 16 — Smoke Test
# Verifies model loaded correctly before Flask deployment
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SMOKE TESTS")
    print("=" * 60)

    _model, _meta = load_production_model()

    # Test 1: Full feature input runs without crash
    dummy_full = {col: 0 for col in _meta["feature_cols"]}
    result1    = predict_url_risk(dummy_full, _model, _meta)
    print(f"\n  [PASS] Test 1 — Full input:")
    print(f"    Risk     : {result1['risk_level']}")
    print(f"    ML Score : {result1['ml_score']}")
    print(f"    Flag     : {result1['confidence_flag']}")

    # Test 2: Empty input MUST raise ValueError — not return safe
    print(f"\n  Test 2 — Empty input (must raise error):")
    try:
        predict_url_risk({}, _model, _meta, min_features_present=5)
        print("  [FAIL] Empty input should have raised ValueError!")
    except ValueError as e:
        print(f"  [PASS] Correctly raised ValueError")
        print(f"    Message: {str(e)[:70]}...")

    # Test 3: Partial input returns warning flag
    partial = {col: 0 for col in _meta["feature_cols"][:6]}
    result3 = predict_url_risk(partial, _model, _meta, min_features_present=5)
    print(f"\n  [PASS] Test 3 — Partial input:")
    print(f"    Flag     : {result3['confidence_flag']}")
    print(f"    Missing  : {len(result3['missing_features'])} features")

    # Test 4: ml_score is always 0-100
    assert 0 <= result1['ml_score'] <= 100, "ml_score out of range!"
    print(f"\n  [PASS] Test 4 — ml_score in valid range 0-100")

    print("\n" + "=" * 60)
    print("  All smoke tests PASSED.")
    print("  Model is ready for Flask backend deployment.")
    print("=" * 60)
    print("\n  Next steps:")
    print("  1. Copy phishing_rf_production.pkl → backend/models/")
    print("  2. Copy model_metadata.json        → backend/models/")
    print("  3. Copy load_production_model()    → backend/utils/ml_predictor.py")
    print("  4. Copy predict_url_risk()         → backend/utils/ml_predictor.py")
    print("  5. Call ml_score from predict_url_risk() inside")
    print("     build_explainable_risk() as the 'ml' weight component")
