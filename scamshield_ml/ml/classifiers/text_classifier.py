from pathlib import Path
import joblib
import math

ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = ROOT / "training" / "outputs" / "combined_tfidf_svm.joblib"

MODEL = None


def _load_model():
    global MODEL

    if MODEL is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Text model not found: {MODEL_PATH}"
            )

        MODEL = joblib.load(MODEL_PATH)

    return MODEL


def predict(text: str):
    model = _load_model()

    prediction = int(model.predict([text])[0])
    decision = float(model.decision_function([text])[0])

    # LinearSVC decision_function is NOT a probability.
    # Convert its magnitude to a bounded model-strength score.
    confidence = 1.0 - math.exp(-abs(decision))

    # Current model is binary:
    # 0 = non-scam
    # 1 = scam
    label = "SCAM" if prediction == 1 else "NON_SCAM"

    return label, float(confidence)
