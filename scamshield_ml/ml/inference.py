import re

from ml.preprocessing.text import combine_inputs
from ml.features.url_features import analyze_urls
from ml.classifiers.text_classifier import predict
from ml.risk_engine.engine import (
    build_signals,
    calculate_risk,
    risk_level,
    recommendations,
)
from ml.campaign_detection.cluster import assign_campaign


CATEGORY_PATTERNS = {
    "KYC_PHISHING": [
        r"\bkyc\b",
        r"\bpan\b",
        r"\baadhaar\b",
        r"\bverify (your )?(account|identity|kyc)\b",
        r"\bkyc (has )?(expired|pending|blocked)\b",
    ],
    "UPI_PAYMENT_SCAM": [
        r"\bupi\b",
        r"\bpayment\b",
        r"\btransfer\b",
        r"\bsend money\b",
        r"\bcollect request\b",
        r"\bpay now\b",
    ],
    "INVESTMENT_SCAM": [
        r"\binvestment\b",
        r"\binvest\b",
        r"\bguaranteed (returns?|profit)\b",
        r"\b\d+% (returns?|profit)\b",
        r"\breturns?\b.*\b(invest|money|profit)\b",
        r"\bprofit\b.*\b(invest|money)\b",
        r"\bdouble your money\b",
        r"\btrading\b.*\b(profit|returns?|money)\b",
        r"\bcrypto\b.*\b(profit|returns?|invest)\b",
    ],
    "JOB_SCAM": [
        r"\bjob\b",
        r"\bvacancy\b",
        r"\bhiring\b",
        r"\brecruitment\b",
        r"\bwork from home\b",
        r"\bregistration fee\b",
        r"\bprocessing fee\b",
        r"\bjob\b.*\bfee\b",
        r"\bfee\b.*\bjob\b",
    ],
    "DELIVERY_REFUND_SCAM": [
        r"\bdelivery\b",
        r"\bcourier\b",
        r"\bparcel\b",
        r"\brefund\b",
        r"\bshipment\b",
        r"\border\b",
        r"\bdelivery\b.*\b(pay|fee|refund)\b",
        r"\brefund\b.*\b(pay|fee)\b",
    ],
    "IMPERSONATION": [
        r"\bcustomer care\b",
        r"\bsupport team\b",
        r"\bverify (your )?account\b",
        r"\bofficial\b",
        r"\bpolice\b",
        r"\bincome tax\b",
        r"\bwe are (from|calling from)\b",
    ],
    "ACCOUNT_TAKEOVER": [
        r"\blogin\b",
        r"\bsign.?in\b",
        r"\bpassword\b",
        r"\baccount (has been )?(blocked|suspended)\b",
        r"\breset (your )?password\b",
        r"\bverify\b.*\bpassword\b",
        r"\bpassword\b.*\botp\b",
    ],
    "LOTTERY_PRIZE_SCAM": [
        r"\blottery\b",
        r"\bprize\b",
        r"\breward\b",
        r"\bwinner\b",
        r"\bwon\b",
        r"\bclaim (your )?(prize|reward)\b",
        r"\bwon\b.*\b(lakh|crore|prize|reward)\b",
    ],
    "PHISHING": [
        r"\bclick (the )?link\b",
        r"\bverify (now|immediately)\b",
        r"\bsecure.?login\b",
        r"\baccount verification\b",
        r"\bverify\b.*\blink\b",
    ],
}


CATEGORY_PRIORITY = [
    "KYC_PHISHING",
    "ACCOUNT_TAKEOVER",
    "UPI_PAYMENT_SCAM",
    "INVESTMENT_SCAM",
    "LOTTERY_PRIZE_SCAM",
    "JOB_SCAM",
    "DELIVERY_REFUND_SCAM",
    "IMPERSONATION",
    "PHISHING",
]


def detect_category(text: str, scam_label: str = "SCAM") -> str:
    text_lower = (text or "").lower()
    scores = {}

    for category, patterns in CATEGORY_PATTERNS.items():
        matched = sum(
            1
            for pattern in patterns
            if re.search(pattern, text_lower)
        )
        if matched:
            scores[category] = matched

    if not scores:
        return "OTHER"

    # Prefer delivery/refund when the message explicitly describes a
    # parcel, shipment, or delivery problem together with a payment demand.
    delivery_context = any(
        re.search(pattern, text_lower)
        for pattern in (
            r"\bdelivery\b",
            r"\bparcel\b",
            r"\bcourier\b",
            r"\bshipment\b",
        )
    )
    payment_demand = any(
        re.search(pattern, text_lower)
        for pattern in (
            r"\bpay\b",
            r"\bpayment\b",
            r"\bfee\b",
            r"\bcard details\b",
            r"\bcard number\b",
            r"\bcvv\b",
        )
    )

    if (
        delivery_context
        and payment_demand
        and "DELIVERY_REFUND_SCAM" in scores
    ):
        return "DELIVERY_REFUND_SCAM"

    # Otherwise select the category with the strongest pattern match.
    # Use CATEGORY_PRIORITY only to break ties.
    max_score = max(scores.values())
    tied = {category for category, score in scores.items() if score == max_score}

    for category in CATEGORY_PRIORITY:
        if category in tied:
            return category

    return max_score and max(scores, key=scores.get) or "OTHER"

def analyze(text="", urls=None, ocr_text=""):
    combined = combine_inputs(text, ocr_text)
    url_info = analyze_urls(urls or [])

    scam_label, confidence = predict(combined)
    category = detect_category(combined, scam_label)

    signals = build_signals(
        combined,
        url_info["risk_score"],
        category,
        confidence,
    )

    score = calculate_risk(
        confidence,
        url_info["risk_score"],
        signals,
        category,
    )

    # Align final prediction with high/critical risk.
    if score >= 60:
        scam_label = "SCAM"

    campaign = assign_campaign(combined)

    return {
        "prediction": str(scam_label).upper(),
        "risk_score": score,
        "risk_level": risk_level(score),
        "category": category,
        "confidence": round(confidence, 2),
        "signals": signals,
        "recommendations": recommendations(category, score),
        "campaign_id": campaign["campaign_id"],
    }
