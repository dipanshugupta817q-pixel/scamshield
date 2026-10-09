import re
import math

SIGNAL_NAMES = [
    "Urgency",
    "Impersonation",
    "Suspicious URL",
    "Financial Request",
    "Credential Request",
    "Threat-language pattern",
]

PATTERNS = {
    "Urgency": r"\b(urgent|immediately|right now|within \d+ (?:minutes?|hours?)|last chance|expire|expires|act now)\b",
    "Impersonation": r"\b(sbi|hdfc|icici|axis|paytm|phonepe|amazon|flipkart|uidai|income tax|police|bank|customer care|support team)\b",
    "Financial Request": r"\b(pay|payment|transfer|send|fee|processing fee|deposit|upi|refund fee|charge|money|invest|investment|returns?|profit|rs\.?|₹|prize|reward|lottery|winner|won|claim|share|whatsapp|euro)\b",
    "Credential Request": r"\b(otp|pin|password|cvv|card number|account number|kyc|pan|aadhaar|login|verify your account)\b",
    "Threat-language pattern": r"\b(blocked|suspended|legal action|police|penalty|fine|arrest|deactivate|closed)\b",
}


def _pattern_score(text, pattern):
    return min(1.0, len(re.findall(pattern, text or "", flags=re.I)) / 2.0)


def build_signals(text, url_risk, category, model_confidence):
    out = []

    for name in SIGNAL_NAMES:
        if name == "Suspicious URL":
            score = url_risk / 100.0
        else:
            score = _pattern_score(
                text,
                PATTERNS.get(name, r"(?!x)x")
            )

        out.append({
            "name": name,
            "score": round(score, 2)
        })

    if category != "OTHER" and model_confidence >= 0.50:
        for signal in out:
            if (
                signal["name"] == "Impersonation"
                and category in {
                    "IMPERSONATION",
                    "KYC_PHISHING",
                    "ACCOUNT_TAKEOVER",
                }
            ):
                signal["score"] = max(
                    signal["score"],
                    round(model_confidence, 2)
                )

    return out


def _bounded_number(value, low, high, default=0.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default

    if not math.isfinite(number):
        return default

    return max(low, min(high, number))


def calculate_risk(model_confidence, url_risk, signals, category):
    # Validate all externally supplied numeric values.
    ml_strength = _bounded_number(model_confidence, 0.0, 1.0)
    url_score = _bounded_number(url_risk, 0.0, 100.0)

    vals = {}
    for signal in signals or []:
        if not isinstance(signal, dict):
            continue

        name = signal.get("name")
        if not name:
            continue

        vals[name] = _bounded_number(signal.get("score"), 0.0, 1.0)

    urgency = vals.get("Urgency", 0.0)
    impersonation = vals.get("Impersonation", 0.0)
    financial = vals.get("Financial Request", 0.0)
    credentials = vals.get("Credential Request", 0.0)
    threat = vals.get("Threat-language pattern", 0.0)
    suspicious_url = vals.get("Suspicious URL", 0.0)

    # Preserve the existing score formula.
    # LinearSVC strength is NOT a calibrated probability.
    score = (
        25 * ml_strength
        + 20 * (url_score / 100.0)
        + 12 * urgency
        + 12 * impersonation
        + 15 * financial
        + 18 * credentials
        + 10 * threat
    )

    category_floor = {
        "KYC_PHISHING": 60,
        "UPI_PAYMENT_SCAM": 50,
        "INVESTMENT_SCAM": 50,
        "JOB_SCAM": 45,
        "DELIVERY_REFUND_SCAM": 45,
        "ACCOUNT_TAKEOVER": 60,
        "LOTTERY_PRIZE_SCAM": 50,
        "PHISHING": 50,
        "IMPERSONATION": 45,
    }

    if category != "OTHER":
        score += 8

    if category in category_floor:
        score = max(score, category_floor[category])

    strong_signals = sum(
        1
        for value in vals.values()
        if value >= 0.50
    )

    if strong_signals >= 4:
        score += 8

    if strong_signals >= 5:
        score += 5

    if (
        category == "KYC_PHISHING"
        and credentials >= 0.50
        and urgency >= 0.50
        and threat >= 0.50
    ):
        score += 10

    if (
        category in {
            "KYC_PHISHING",
            "PHISHING",
            "ACCOUNT_TAKEOVER",
        }
        and suspicious_url >= 0.50
        and credentials >= 0.50
    ):
        score += 8

    return int(round(_bounded_number(score, 0.0, 100.0)))


def risk_level(score):
    score = _bounded_number(score, 0.0, 100.0)

    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def recommendations(category, score):
    rec = []

    if score >= 30:
        rec.append("Do not click the link")

    if (
        category in {
            "KYC_PHISHING",
            "ACCOUNT_TAKEOVER",
            "PHISHING",
        }
        or score >= 60
    ):
        rec.append("Do not share OTP/PIN/password")

    if (
        category in {
            "UPI_PAYMENT_SCAM",
            "INVESTMENT_SCAM",
            "DELIVERY_REFUND_SCAM",
            "LOTTERY_PRIZE_SCAM",
        }
        or score >= 60
    ):
        rec.append("Do not transfer money")

    if score >= 30:
        rec.append("Verify through official website/app")
        rec.append("Contact the organisation through official channel")

    return rec


