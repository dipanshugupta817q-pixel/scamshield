from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"
MODELS = ROOT / "training" / "outputs"


def load_dataset(name):

    if name == "uci":
        df = pd.read_csv(DATA / "text_binary_uci.csv")
        return df[["text", "label"]].dropna()

    if name == "hinglish":
        df = pd.read_csv(DATA / "text_binary_hinglish.csv")
        return df[["text", "label"]].dropna()

    if name == "job_scam":
        df = pd.read_csv(DATA / "job_scam.csv")
        df = df[["text", "scam_label"]].dropna()
        df = df.rename(columns={"scam_label": "label"})
        return df

    raise ValueError(name)


def evaluate(model_name, test_name):

    model_path = MODELS / f"{model_name}_tfidf_svm.joblib"

    model = joblib.load(model_path)

    df = load_dataset(test_name)

    X = df["text"].astype(str)
    y = df["label"].astype(int)

    pred = model.predict(X)

    precision = precision_score(
        y,
        pred,
        zero_division=0
    )

    recall = recall_score(
        y,
        pred,
        zero_division=0
    )

    f1 = f1_score(
        y,
        pred,
        zero_division=0
    )

    print("\n" + "=" * 70)
    print(
        f"MODEL: {model_name.upper()}  →  TEST: {test_name.upper()}"
    )
    print("=" * 70)

    print(f"Rows:      {len(df):,}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")

    print("\nClassification report:")
    print(
        classification_report(
            y,
            pred,
            target_names=["BENIGN", "SCAM"],
            zero_division=0
        )
    )

    print("Confusion matrix:")
    print(
        confusion_matrix(y, pred)
    )


def main():

    print("=" * 70)
    print("SCAMSHIELD — CROSS-SOURCE GENERALIZATION TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # Each model was trained only on its own dataset.
    # We now test it on completely different data.
    # --------------------------------------------------------

    tests = [
        ("uci", "hinglish"),
        ("uci", "job_scam"),

        ("hinglish", "uci"),
        ("hinglish", "job_scam"),

        ("job_scam", "uci"),
        ("job_scam", "hinglish"),
    ]

    for model_name, test_name in tests:
        evaluate(
            model_name,
            test_name
        )


if __name__ == "__main__":
    main()
