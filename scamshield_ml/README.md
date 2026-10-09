# ScamShield ML

Standalone ML service for scam detection. Backend should call only:

    from ml.inference import analyze
    result = analyze(text=..., urls=[...], ocr_text=...)

The module returns the fixed JSON contract:
risk_score, risk_level, category, confidence, signals, recommendations, campaign_id

## Quick start

```bash
pip install -r requirements.txt
python train.py
python demo.py
```

Training creates `models/text_model.joblib` and `models/vectorizer.joblib`.

## Architecture

input -> preprocessing -> TF-IDF text classifier -> URL feature/risk analysis
      -> rule/signal engine -> weighted risk score -> recommendations
      -> campaign similarity/clustering -> fixed JSON

The model is intentionally lightweight for a hackathon baseline. Replace
`data/training.csv` with a larger labeled dataset when available without
changing the inference contract.
