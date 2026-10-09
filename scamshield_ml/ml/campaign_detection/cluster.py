from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "models" / "campaign_store.joblib"

def _load():
    if STORE.exists():
        return joblib.load(STORE)
    return {"texts": [], "ids": [], "vectorizer": None, "matrix": None}

def campaign_id(text):
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:8].upper()
    return f"CMP-{int(digest, 16) % 9000 + 1000}"

def assign_campaign(text, threshold=0.55):
    text = text or ""
    store = _load()

    if not store["texts"]:
        cid = campaign_id(text)
        store["texts"] = [text]
        store["ids"] = [cid]
        store["vectorizer"] = TfidfVectorizer(ngram_range=(1,2), min_df=1)
        store["matrix"] = store["vectorizer"].fit_transform(store["texts"])
        joblib.dump(store, STORE)
        return {"campaign_id": cid, "similarity": 1.0, "number_of_samples": 1}

    vec = store["vectorizer"]
    new = vec.transform([text])
    sims = cosine_similarity(new, store["matrix"])[0]
    best_idx = int(np.argmax(sims))
    best = float(sims[best_idx])

    if best >= threshold:
        cid = store["ids"][best_idx]
        count = sum(x == cid for x in store["ids"]) + 1
    else:
        cid = campaign_id(text)
        count = 1

    store["texts"].append(text)
    store["ids"].append(cid)
    # Refit vectorizer so future samples can use new vocabulary.
    store["vectorizer"] = TfidfVectorizer(ngram_range=(1,2), min_df=1)
    store["matrix"] = store["vectorizer"].fit_transform(store["texts"])
    joblib.dump(store, STORE)

    return {
        "campaign_id": cid,
        "similarity": round(best, 2),
        "number_of_samples": count,
    }
