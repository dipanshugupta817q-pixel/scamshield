import re

def normalize_text(text: str) -> str:
    text = text or ""
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def combine_inputs(text: str = "", ocr_text: str = "") -> str:
    parts = [text or "", ocr_text or ""]
    return normalize_text(" ".join(p for p in parts if p))
