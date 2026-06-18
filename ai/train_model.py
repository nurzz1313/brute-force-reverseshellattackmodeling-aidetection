from pathlib import Path
import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

DATASET_PATH = Path("train_dataset.csv")
MODEL_PATH = Path("attack_detector.joblib")
REPORT_PATH = Path("model_report.txt")
CM_PATH = Path("confusion_matrix.csv")

TARGET = "label"

DROP_COLUMNS = [
    "event_id",
    "timestamp",
    "source_ip",
    "username",
    "session_id",
    "filename",
    "sha256",
]


def load_dataset() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    if TARGET not in df.columns:
        raise ValueError(f"Missing target column: {TARGET}")
    return df


def build_pipeline(X: pd.DataFrame) -> Pipeline:
    categorical_features = [c for c in X.columns if X[c].dtype == "object"]
    numeric_features = [c for c in X.columns if c not in categorical_features]

    numeric_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value=0)),
        ]
    )

    categorical_transformer = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="constant", fill_value="missing")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_features),
            ("cat", categorical_transformer, categorical_features),
        ]
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )

    return Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )


def main():
    df = load_dataset()

    existing_drop = [c for c in DROP_COLUMNS if c in df.columns]
    X = df.drop(columns=existing_drop + [TARGET])
    y = df[TARGET]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y,
    )

    pipeline = build_pipeline(X)
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=sorted(y.unique()))
    cm_df = pd.DataFrame(cm, index=sorted(y.unique()), columns=sorted(y.unique()))

    joblib.dump(pipeline, MODEL_PATH)
    cm_df.to_csv(CM_PATH, encoding="utf-8")

    report_text = []
    report_text.append("Attack Detector Model Report")
    report_text.append("=" * 50)
    report_text.append(f"Accuracy: {acc:.4f}")
    report_text.append("")
    report_text.append(report)

    REPORT_PATH.write_text("\n".join(report_text), encoding="utf-8")

    print("[OK] Model saved:", MODEL_PATH)
    print("[OK] Report saved:", REPORT_PATH)
    print("[OK] Confusion matrix saved:", CM_PATH)
    print(f"[OK] Accuracy: {acc:.4f}")


if __name__ == "__main__":
    main()