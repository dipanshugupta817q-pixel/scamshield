from pathlib import Path
import json

import pandas as pd
import joblib

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


# ============================================================
# PATHS
# ============================================================

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"
OUT = ROOT / "training" / "outputs"

OUT.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42


# ============================================================
# LOAD DATASETS
# ============================================================

def load_uci():
    df = pd.read_csv(DATA / "text_binary_uci.csv")

    df = df[["text", "label"]].dropna()

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    df["source"] = "uci"

    return df


def load_hinglish():
    df = pd.read_csv(DATA / "text_binary_hinglish.csv")

    df = df[["text", "label"]].dropna()

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    df["source"] = "hinglish"

    return df


def load_job_scam():
    df = pd.read_csv(DATA / "job_scam.csv")

    df = df[["text", "scam_label"]].dropna()

    df = df.rename(
        columns={"scam_label": "label"}
    )

    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(int)
    df["source"] = "job_scam"

    return df


# ============================================================
# COMBINE DATASETS
# ============================================================

def load_all():

    uci = load_uci()
    hinglish = load_hinglish()
    job = load_job_scam()

    # Deduplicate WITHIN each source only.
    # Do NOT deduplicate across sources because Hinglish
    # contains UCI-derived examples.

    uci = uci.drop_duplicates(
        subset=["text"]
    )

    hinglish = hinglish.drop_duplicates(
        subset=["text"]
    )

    job = job.drop_duplicates(
        subset=["text"]
    )

    combined = pd.concat(
        [
            uci,
            hinglish,
            job
        ],
        ignore_index=True
    )

    combined = combined[
        ["text", "label", "source"]
    ].reset_index(drop=True)

    return combined


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
                analyzer="word",
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.98,
                sublinear_tf=True,
                max_features=200000
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
# EVALUATION
# ============================================================

def evaluate_model(model, test_df, title):

    X_test = test_df["text"]
    y_test = test_df["label"]

    predictions = model.predict(X_test)

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    cm = confusion_matrix(
        y_test,
        predictions
    )

    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    print(f"Rows:      {len(test_df):,}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1:        {f1:.4f}")

    print("\nClassification report:")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=["BENIGN", "SCAM"],
            zero_division=0
        )
    )

    print("Confusion matrix:")
    print(cm)

    return {
        "title": title,
        "rows": int(len(test_df)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "confusion_matrix": cm.tolist()
    }


# ============================================================
# EXPERIMENT A
# RANDOM MIXED TRAIN / VALIDATION / TEST
# ============================================================

def mixed_training_test(combined):

    print("\n")
    print("#" * 70)
    print("EXPERIMENT A — RANDOM MIXED TRAIN/VALIDATION/TEST")
    print("#" * 70)

    train_val, test = train_test_split(
        combined,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=combined["label"]
    )

    train, validation = train_test_split(
        train_val,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=train_val["label"]
    )

    print("\nSPLIT")
    print("-" * 50)
    print(f"Train:      {len(train):,}")
    print(f"Validation: {len(validation):,}")
    print(f"Test:       {len(test):,}")

    print("\nTrain source distribution:")
    print(
        train["source"].value_counts().to_dict()
    )

    print("\nTest source distribution:")
    print(
        test["source"].value_counts().to_dict()
    )

    print("\nTraining combined model...")

    model = build_model()

    model.fit(
        train["text"],
        train["label"]
    )

    validation_result = evaluate_model(
        model,
        validation,
        "COMBINED MODEL → VALIDATION"
    )

    test_result = evaluate_model(
        model,
        test,
        "COMBINED MODEL → RANDOM TEST"
    )

    source_results = []

    for source in [
        "uci",
        "hinglish",
        "job_scam"
    ]:

        source_test = test[
            test["source"] == source
        ]

        if len(source_test) == 0:
            continue

        result = evaluate_model(
            model,
            source_test,
            f"COMBINED MODEL → RANDOM TEST → {source.upper()}"
        )

        result["source"] = source

        source_results.append(result)

    model_path = (
        OUT / "combined_tfidf_svm.joblib"
    )

    joblib.dump(
        model,
        model_path
    )

    print(
        f"\n[SAVED MODEL] {model_path}"
    )

    return {
        "validation": validation_result,
        "test": test_result,
        "per_source": source_results
    }


# ============================================================
# EXPERIMENT B
# LEAVE-ONE-SOURCE-OUT
# ============================================================

def leave_one_source_out(combined):

    print("\n")
    print("#" * 70)
    print("EXPERIMENT B — LEAVE-ONE-SOURCE-OUT")
    print("#" * 70)

    results = []

    sources = [
        "uci",
        "hinglish",
        "job_scam"
    ]

    for held_out in sources:

        print("\n")
        print("-" * 70)
        print(
            f"HOLDING OUT: {held_out.upper()}"
        )
        print("-" * 70)

        train_df = combined[
            combined["source"] != held_out
        ].copy()

        test_df = combined[
            combined["source"] == held_out
        ].copy()

        print(
            f"Training rows: {len(train_df):,}"
        )

        print(
            f"Test rows:     {len(test_df):,}"
        )

        print("\nTraining source distribution:")

        print(
            train_df["source"]
            .value_counts()
            .to_dict()
        )

        print("\nTraining model...")

        model = build_model()

        model.fit(
            train_df["text"],
            train_df["label"]
        )

        result = evaluate_model(
            model,
            test_df,
            f"LEAVE-ONE-OUT → TEST = {held_out.upper()}"
        )

        result["held_out_source"] = held_out

        results.append(result)

    return results


# ============================================================
# DATASET STATISTICS
# ============================================================

def print_dataset_statistics(combined):

    print("\n")
    print("#" * 70)
    print("COMBINED DATASET STATISTICS")
    print("#" * 70)

    print(
        f"\nTotal rows: {len(combined):,}"
    )

    print("\nRows by source:")

    print(
        combined["source"]
        .value_counts()
        .to_string()
    )

    print("\nLabels by source:")

    print(
        pd.crosstab(
            combined["source"],
            combined["label"]
        ).to_string()
    )

    print("\nOverall labels:")

    print(
        combined["label"]
        .value_counts()
        .sort_index()
        .to_dict()
    )


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(
    mixed_results,
    loo_results
):

    output = {
        "random_state": RANDOM_STATE,
        "random_mixed": mixed_results,
        "leave_one_source_out": loo_results
    }

    path = (
        OUT / "combined_text_experiments.json"
    )

    path.write_text(
        json.dumps(
            output,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"\n[SAVED RESULTS] {path}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("SCAMSHIELD — COMBINED TEXT EXPERIMENTS")
    print("TF-IDF + LinearSVC")
    print("=" * 70)

    combined = load_all()

    print_dataset_statistics(
        combined
    )

    mixed_results = mixed_training_test(
        combined
    )

    loo_results = leave_one_source_out(
        combined
    )

    save_results(
        mixed_results,
        loo_results
    )

    print("\n")
    print("=" * 70)
    print("ALL EXPERIMENTS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()