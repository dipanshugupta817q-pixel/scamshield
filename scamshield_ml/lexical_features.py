
import ipaddress
import re
from urllib.parse import urlparse, urlsplit, urlunsplit, unquote

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction import DictVectorizer
from sklearn.preprocessing import StandardScaler


SUSPICIOUS_WORDS = [
    "login", "verify", "verification", "secure", "account",
    "update", "password", "signin", "confirm", "wallet",
    "banking", "payment", "recover", "credential",
    "authenticate", "support", "webscr"
]


def normalize_url(value):
    value = str(value).strip()

    if not value or value.lower() in ("nan", "none", "null"):
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value

    return value[:5000]


def extract_features(url):
    url = normalize_url(url)

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = unquote(parsed.path or "")
        query = unquote(parsed.query or "")
        fragment = parsed.fragment or ""
        netloc = parsed.netloc or ""
    except (ValueError, TypeError):
        hostname, path, query, fragment, netloc = "", "", "", "", ""

    lower_url = url.lower()

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "digit_count": sum(c.isdigit() for c in url),
        "letter_count": sum(c.isalpha() for c in url),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "has_https": int(url.startswith("https://")),
        "has_ip_host": has_ip,
        "has_punycode": int("xn--" in hostname),
        "has_at_symbol": int("@" in netloc),
        "has_encoded_chars": int("%" in url),
        "has_fragment": int(bool(fragment)),
        "suspicious_word_count": sum(
            lower_url.count(word) for word in SUSPICIOUS_WORDS
        ),
    }


class LexicalFeatures(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        self.vectorizer = DictVectorizer()
        self.scaler = StandardScaler(with_mean=False)

        matrix = self.vectorizer.fit_transform(
            [extract_features(url) for url in X]
        )
        self.scaler.fit(matrix)
        return self

    def transform(self, X):
        matrix = self.vectorizer.transform(
            [extract_features(url) for url in X]
        )
        return self.scaler.transform(matrix)

def normalize_model_url(value):
    """Canonicalize URLs consistently for model training and inference."""
    url = normalize_url(value)

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if not hostname:
            return url

        hostname = hostname.lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]

        userinfo = (
            parsed.netloc.rsplit("@", 1)[0] + "@"
            if "@" in parsed.netloc else ""
        )

        port = parsed.port
        if ":" in hostname and not hostname.startswith("["):
            hostname = "[" + hostname + "]"

        netloc = userinfo + hostname
        if port is not None:
            netloc += ":" + str(port)

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path,
            parsed.query,
            parsed.fragment,
        ))
    except (ValueError, TypeError):
        return url
