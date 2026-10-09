from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "work", "live", "buzz", "shop",
    "online", "site", "icu", "tk", "ml", "ga", "cf", "gq"
}
SUSPICIOUS_WORDS = {
    "verify", "verification", "kyc", "update", "secure", "login", "signin",
    "account", "refund", "reward", "prize", "claim", "wallet", "payment",
    "otp", "password", "urgent", "suspend", "blocked"
}
BRANDS = {
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "googlepay",
    "amazon", "flipkart", "swiggy", "zomato", "irctc", "uidai", "income",
    "police", "bank"
}

def analyze_url(url: str) -> dict:
    raw = (url or "").strip()
    p = urlparse(raw if "://" in raw else "http://" + raw)
    host = (p.hostname or "").lower()
    path_query = (p.path + "?" + p.query).lower()
    full = raw.lower()

    try:
        ip_based = bool(ipaddress.ip_address(host))
    except ValueError:
        ip_based = False

    labels = [x for x in host.split(".") if x]
    tld = labels[-1] if len(labels) >= 2 else ""
    special = len(re.findall(r"[^a-zA-Z0-9]", full))
    suspicious_words = sum(1 for w in SUSPICIOUS_WORDS if w in full)
    brand_hits = [b for b in BRANDS if b in host or b in path_query]
    subdomains = max(0, len(labels) - 2)

    score = 0
    if len(raw) > 100: score += 15
    elif len(raw) > 70: score += 8
    if special >= 12: score += 10
    elif special >= 7: score += 5
    if subdomains >= 3: score += 10
    elif subdomains == 2: score += 5
    if tld in SUSPICIOUS_TLDS: score += 18
    if ip_based: score += 25
    if suspicious_words >= 3: score += 20
    elif suspicious_words >= 1: score += 10
    if "@" in full: score += 20
    if "-" in host: score += 5
    if brand_hits and (subdomains >= 2 or "-" in host or tld in SUSPICIOUS_TLDS):
        score += 15
    if p.scheme != "https": score += 8

    return {
        "url": raw,
        "length": len(raw),
        "special_chars": special,
        "subdomains": subdomains,
        "tld": tld,
        "https": p.scheme == "https",
        "ip_based": ip_based,
        "brand_hits": brand_hits,
        "suspicious_keywords": suspicious_words,
        "risk_score": min(100, score),
    }

def analyze_urls(urls):
    results = [analyze_url(u) for u in (urls or []) if u]
    if not results:
        return {"risk_score": 0, "details": []}
    return {
        "risk_score": round(sum(x["risk_score"] for x in results) / len(results)),
        "details": results,
    }
