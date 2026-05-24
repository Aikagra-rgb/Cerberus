import argparse
import json
import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.config import DATA_DIR, MODEL_CONFIGS, MODELS_DIR, UNIFIED_FEATURES


# ---------------------------------------------------------
# CORE TRAINING FUNCTION
# Uses a Random Forest Classifier with a StandardScaler pipeline.
# Labels: 0 = BENIGN, 1 = ATTACK (anything not BENIGN).
# ---------------------------------------------------------
def train_model(model_type, max_rows=None):
    if model_type not in MODEL_CONFIGS:
        print(f"[!] Unknown model type: '{model_type}'")
        print(f"    Available: {list(MODEL_CONFIGS.keys())}")
        return

    config = MODEL_CONFIGS[model_type]
    dataset_path = os.path.join(DATA_DIR, config["filename"])
    save_path = os.path.join(MODELS_DIR, f"{model_type}_classifier.pkl")
    metrics_path = os.path.join(MODELS_DIR, f"{model_type}_metrics.json")

    # 1. Check the dataset file exists
    if not os.path.exists(dataset_path):
        print(f"[!] Dataset not found: {dataset_path}")
        print(f"    Place '{config['filename']}' in the data/ folder.")
        return

    print(f"\n{'='*60}")
    print(f"  Training: {model_type.upper()} Brain (Random Forest Classifier)")
    print(f"  Dataset:  {config['filename']}")
    print(f"  Info:     {config['description']}")
    print(f"{'='*60}")

    # 2. Load Data
    try:
        df = pd.read_csv(dataset_path, nrows=max_rows)
    except Exception as e:
        print(f"[!] CSV Load Error: {e}")
        return

    # 3. Clean column names (CIC CSVs often have leading spaces)
    df.columns = df.columns.str.strip()
    original_count = len(df)

    # Replace Inf and drop NaN for our feature columns
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=UNIFIED_FEATURES, inplace=True)

    # 4. Binary Label: 0 = BENIGN, 1 = ATTACK (anything that is NOT BENIGN)
    df['is_attack'] = (df['Label'].str.strip() != 'BENIGN').astype(int)

    benign_count = int((df['is_attack'] == 0).sum())
    attack_count = int((df['is_attack'] == 1).sum())

    # Show what attack types were found
    attack_labels = df[df['is_attack'] == 1]['Label'].unique().tolist()
    attack_labels_safe = [str(l).encode('ascii', 'replace').decode() for l in attack_labels]

    print(f"  [+] Records after cleaning: {len(df):,} / {original_count:,}")
    print(f"  [+] Benign: {benign_count:,}  |  Attack: {attack_count:,}")
    print(f"  [+] Attack types found: {attack_labels_safe if attack_labels_safe else 'None'}")
    print(f"  [+] Features: {len(UNIFIED_FEATURES)} columns")

    if attack_count < 20:
        print(f"  [!] WARNING: Only {attack_count} attack samples — too few for reliable training.")
        print(f"      Try running without --max-rows to load the full CSV.")
        print(f"      Skipping this model.\n")
        return

    # 5. Balance the dataset (undersample majority class)
    #    Prevents the model from being biased toward always predicting BENIGN.
    if benign_count > attack_count * 3:
        benign_sample = df[df['is_attack'] == 0].sample(
            n=min(attack_count * 3, benign_count), random_state=42
        )
        attack_sample = df[df['is_attack'] == 1]
        df_balanced = pd.concat([benign_sample, attack_sample])
        print(f"  [+] Balanced: {len(benign_sample):,} Benign + {len(attack_sample):,} Attack")
    else:
        df_balanced = df

    X = df_balanced[UNIFIED_FEATURES].values
    y = df_balanced['is_attack'].values

    # 6. Train/Test Split (80/20, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  [+] Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # 7. Build Pipeline: StandardScaler + RandomForestClassifier
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        ))
    ])
    pipeline.fit(X_train, y_train)

    # 8. Evaluate on held-out test set
    y_pred = pipeline.predict(X_test)
    print(f"\n  {'~'*50}")
    print(f"  VALIDATION REPORT: {model_type.upper()}")
    print(f"  {'~'*50}")
    
    report_labels = sorted(set(y_test) | set(y_pred))
    report_names = []
    for l in report_labels:
        report_names.append("BENIGN" if l == 0 else "ATTACK")
    print(classification_report(
        y_test, y_pred,
        labels=report_labels,
        target_names=report_names,
        zero_division=0
    ))

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    print(f"  Confusion Matrix:")
    print(f"    True Negatives  (Benign correctly identified): {tn:,}")
    print(f"    False Positives (Benign misclassified):        {fp:,}")
    print(f"    False Negatives (Attack MISSED):               {fn:,}")
    print(f"    True Positives  (Attack correctly caught):     {tp:,}")

    total_attacks = fn + tp
    if total_attacks > 0:
        detection_rate = (tp / total_attacks) * 100
        print(f"\n  >>> DETECTION RATE: {detection_rate:.1f}% of attacks caught <<<")

    # 9. Extract Performance and Statistical Metrics
    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    # Extract Feature Importances from the Random Forest Classifier
    rf_model = pipeline.named_steps['classifier']
    importances = rf_model.feature_importances_
    feature_importance_dict = {
        feature: float(importance)
        for feature, importance in zip(UNIFIED_FEATURES, importances)
    }

    metrics_payload = {
        "model_type": model_type,
        "dataset": config["filename"],
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        },
        "feature_importances": feature_importance_dict
    }

    # 10. Save Model and Metrics atomically
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    # Save Model
    tmp_model_path = save_path + ".tmp"
    joblib.dump(pipeline, tmp_model_path)
    os.replace(tmp_model_path, save_path)
    
    # Save Metrics JSON
    tmp_metrics_path = metrics_path + ".tmp"
    with open(tmp_metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=4)
    os.replace(tmp_metrics_path, metrics_path)
    
    print(f"  [+] Saved Model Pipeline to: {save_path}")
    print(f"  [+] Saved Statistical Metrics to: {metrics_path}")
    print(f"{'='*60}\n")


# ---------------------------------------------------------
# TRAIN ALL MODELS
# ---------------------------------------------------------
def train_all(max_rows=None):
    print("\n" + "=" * 60)
    print("  TRAINING ALL MODELS (Random Forest Classifier)")
    print("=" * 60)
    for model_type in MODEL_CONFIGS:
        train_model(model_type, max_rows=max_rows)
    print("\n[*] All models trained successfully.")


# ---------------------------------------------------------
# CLI ENTRY POINT
# ---------------------------------------------------------
if __name__ == "__main__":
    all_types = list(MODEL_CONFIGS.keys())

    parser = argparse.ArgumentParser(
        description="Train LogSentry HIDS AI Models (Random Forest Classifier)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Available model types:\n  " + "\n  ".join(
            [f"{k:15s} - {v['description']}" for k, v in MODEL_CONFIGS.items()]
        )
    )
    parser.add_argument(
        "--type", type=str,
        choices=all_types + ["all"],
        required=True,
        help="Which model to train. Use 'all' to train every model."
    )
    parser.add_argument(
        "--max-rows", type=int,
        help="Limit dataset rows for quick testing (e.g., 50000)"
    )

    args = parser.parse_args()

    if args.type == "all":
        train_all(max_rows=args.max_rows)
    else:
        train_model(args.type, args.max_rows)