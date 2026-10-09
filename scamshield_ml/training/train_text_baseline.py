from pathlib import Path
import json
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"
OUT = ROOT / "training" / "outputs"

OUT.mkdir(parents=True, exist_ok=True)


RANDOM_STATE = 42
TEST_SIZE = 0.20


# ============================================================
# DATA LOADERS
# ============================================================

def load_uci():
    path = DATA / "text_binary_uci.csv"

    df = pd.read_csv(path)

    df = df[
        ["text", "label"]
    ].dropna()

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    return df


def load_hinglish():
    path = DATA / "text_binary_hinglish.csv"

    df = pd.read_csv(path)

    df = df[
        ["text", "label"]
    ].dropna()

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    return df


def load_job_scam():
    path = DATA / "job_scam.csv"

    df = pd.read_csv(path)

    df = df[
        ["text", "scam_label"]
    ].dropna()

    df = df.rename(
        columns={"scam_label": "label"}
    )

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)

    return df


# ============================================================
# MODEL
# ============================================================

def build_model():

    return Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",

                # word + character features help with:
                # URLs, obfuscation, spelling variations,
                # SMS language and scam keywords.
                analyzer="word",
                ngram_range=(1, 2),

                min_df=2,
                max_df=0.98,

                sublinear_tf=True,

                max_features=150000
            )
        ),

        (
            "classifier",
            LinearSVC(
                C=1.0,
                class_weight="balanced"
            )
        )
    ])


# ============================================================
# TRAIN / VALIDATION / TEST
# ============================================================

def train_dataset(name, df):

    print("\n" + "=" * 70)
    print(f"DATASET: {name}")
    print("=" * 70)

    print(f"Rows: {len(df):,}")
    print(
        "Labels:",
        df["label"].value_counts().sort_index().to_dict()
    )

    # --------------------------------------------------------
    # First split:
    # 80% development
    # 20% final test
    # --------------------------------------------------------

    train_val, test = train_test_split(
        df,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=df["label"]
    )

    # --------------------------------------------------------
    # Second split:
    # 80% train
    # 20% validation
    #
    # Overall:
    # TRAIN = 64%
    # VAL   = 16%
    # TEST  = 20%
    # --------------------------------------------------------

    train, val = train_test_split(
        train_val,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=train_val["label"]
    )

    print("\nSPLIT:")
    print(f"Train:      {len(train):,}")
    print(f"Validation: {len(val):,}")
    print(f"Test:       {len(test):,}")

    print("\nTrain labels:")
    print(
        train["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    print("\nValidation labels:")
    print(
        val["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    print("\nTest labels:")
    print(
        test["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    model = build_model()

    print("\nTraining TF-IDF + LinearSVC...")

    model.fit(
        train["text"],
        train["label"]
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    val_pred = model.predict(
        val["text"]
    )

    val_precision = precision_score(
        val["label"],
        val_pred,
        zero_division=0
    )

    val_recall = recall_score(
        val["label"],
        val_pred,
        zero_division=0
    )

    val_f1 = f1_score(
        val["label"],
        val_pred,
        zero_division=0
    )

    print("\nVALIDATION")
    print("-" * 50)
    print(f"Precision: {val_precision:.4f}")
    print(f"Recall:    {val_recall:.4f}")
    print(f"F1:        {val_f1:.4f}")

    print("\nValidation classification report:")
    print(
        classification_report(
            val["label"],
            val_pred,
            target_names=[
                "BENIGN",
                "SCAM"
            ],
            zero_division=0
        )
    )

    print("Validation confusion matrix:")
    print(
        confusion_matrix(
            val["label"],
            val_pred
        )
    )

    # --------------------------------------------------------
    # Final TEST
    # --------------------------------------------------------

    test_pred = model.predict(
        test["text"]
    )

    test_precision = precision_score(
        test["label"],
        test_pred,
        zero_division=0
    )

    test_recall = recall_score(
        test["label"],
        test_pred,
        zero_division=0
    )

    test_f1 = f1_score(
        test["label"],
        test_pred,
        zero_division=0
    )

    print("\nTEST")
    print("-" * 50)
    print(f"Precision: {test_precision:.4f}")
    print(f"Recall:    {test_recall:.4f}")
    print(f"F1:        {test_f1:.4f}")

    print("\nTest classification report:")
    print(
        classification_report(
            test["label"],
            test_pred,
            target_names=[
                "BENIGN",
                "SCAM"
            ],
            zero_division=0
        )
    )

    test_cm = confusion_matrix(
        test["label"],
        test_pred
    )

    print("Test confusion matrix:")
    print(test_cm)

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    model_path = (
        OUT / f"{name}_tfidf_svm.joblib"
    )

    joblib.dump(
        model,
        model_path
    )

    print(
        f"\n[SAVED MODEL] {model_path}"
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    metrics = {
        "dataset": name,
        "random_state": RANDOM_STATE,

        "total_rows": int(len(df)),

        "split": {
            "train": int(len(train)),
            "validation": int(len(val)),
            "test": int(len(test))
        },

        "validation": {
            "precision": float(val_precision),
            "recall": float(val_recall),
            "f1": float(val_f1),
            "confusion_matrix": val_pred.tolist()
            if False else
            confusion_matrix(
                val["label"],
                val_pred
            ).tolist()
        },

        "test": {
            "precision": float(test_precision),
            "recall": float(test_recall),
            "f1": float(test_f1),
            "confusion_matrix": test_cm.tolist()
        }
    }

    metrics_path = (
        OUT / f"{name}_metrics.json"
    )

    metrics_path.write_text(
        json.dumps(
            metrics,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"[SAVED METRICS] {metrics_path}"
    )

    return {
        "dataset": name,
        "test_precision": test_precision,
        "test_recall": test_recall,
        "test_f1": test_f1,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("SCAMSHIELD — TEXT BASELINE TRAINING")
    print("TF-IDF + Linear SVM")
    print("=" * 70)

    datasets = {
        "uci": load_uci(),
        "hinglish": load_hinglish(),
        "job_scam": load_job_scam(),
    }

    results = []

    for name, df in datasets.items():

        result = train_dataset(
            name,
            df
        )

        results.append(result)

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = pd.DataFrame(results)

    print("\n" + "=" * 70)
    print("FINAL TEST SUMMARY")
    print("=" * 70)

    print(
        summary.to_string(
            index=False
        )
    )

    summary.to_csv(
        OUT / "baseline_summary.csv",
        index=False
    )

    print(
        f"\n[SAVED] {OUT / 'baseline_summary.csv'}"
    )

    print("\nTraining complete.")


if __name__ == "__main__":
    main()