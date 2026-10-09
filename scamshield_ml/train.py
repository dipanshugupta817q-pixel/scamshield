from pathlib import Path
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "training.csv"
MODELS = ROOT / "models"
MODELS.mkdir(exist_ok=True)

df = pd.read_csv(DATA).dropna(subset=["text", "category"])
X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["category"], test_size=0.2, random_state=42, stratify=df["category"]
)

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=1,
        max_df=0.98,
        sublinear_tf=True,
        max_features=20000,
        strip_accents="unicode",
    )),
    ("clf", LogisticRegression(max_iter=1500, class_weight="balanced")),
])

pipe.fit(X_train, y_train)
pred = pipe.predict(X_test)

print("=== Classification Report ===")
print(classification_report(y_test, pred, zero_division=0))
print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, pred, labels=pipe.classes_))

joblib.dump(pipe, MODELS / "text_model.joblib")
print(f"Saved: {MODELS / 'text_model.joblib'}")
