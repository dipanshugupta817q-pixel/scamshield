from pathlib import Path
import os
import csv
import io
import json
import hashlib
import zipfile
import urllib.request
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"

DIRS = {
    "sms": RAW / "sms",
    "malware_urls": RAW / "malware_urls",
    "benign_candidate_domains": RAW / "benign_candidate_domains",
    "job_scams": RAW / "job_scams",
    "auxiliary_curated": RAW / "auxiliary_curated",
}

for d in DIRS.values():
    d.mkdir(parents=True, exist_ok=True)

MANIFEST = RAW / "download_manifest.json"

SOURCES = []


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, target, headers=None):
    target = Path(target)

    if target.exists() and target.stat().st_size > 0:
        print(f"[SKIP] Already exists: {target}")
        return False

    print(f"[DOWNLOAD] {url}")
    req = urllib.request.Request(
        url,
        headers=headers or {
            "User-Agent": "ScamShield-Research/1.0"
        },
    )

    with urllib.request.urlopen(req, timeout=180) as response:
        data = response.read()

    target.write_bytes(data)
    print(f"[OK] {target} ({target.stat().st_size / 1024 / 1024:.2f} MB)")
    return True


def record(source, path, purpose, provenance, license_info=None, notes=None):
    p = Path(path)

    item = {
        "source": source,
        "file": str(p.relative_to(ROOT)),
        "purpose": purpose,
        "provenance": provenance,
        "license": license_info,
        "sha256": sha256(p),
        "bytes": p.stat().st_size,
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "notes": notes,
    }

    SOURCES.append(item)


# ============================================================
# 1. UCI SMS SPAM COLLECTION
# ============================================================

uci_zip = DIRS["sms"] / "sms_spam_collection.zip"

download(
    "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
    uci_zip,
)

uci_file = DIRS["sms"] / "SMSSpamCollection"

if not uci_file.exists():
    with zipfile.ZipFile(uci_zip) as z:
        z.extractall(DIRS["sms"])

record(
    "UCI SMS Spam Collection",
    uci_file,
    "Real public SMS ham/spam baseline",
    "UCI SMS Spam Collection; original corpus contains collected SMS spam and legitimate SMS.",
    "CC BY 4.0",
    "Do not treat spam as equivalent to all ScamShield categories.",
)


# ============================================================
# 2. URLHAUS
# ============================================================

urlhaus_key = os.getenv("URLHAUS_AUTH_KEY")

if not urlhaus_key:
    print("[WARNING] URLHAUS_AUTH_KEY is not set.")
    print("         Existing URLhaus data will be preserved.")
else:
    urlhaus_file = DIRS["malware_urls"] / "urlhaus_recent.csv"

    urlhaus_url = (
        "https://urlhaus-api.abuse.ch/v2/files/exports/"
        f"{urlhaus_key}/recent.csv"
    )

    try:
        download(urlhaus_url, urlhaus_file)

        record(
            "URLhaus",
            urlhaus_file,
            "Malicious URL intelligence",
            "abuse.ch URLhaus malware URL database",
            None,
            "Classify as MALWARE_URL, not PHISHING. Do not use as benign data.",
        )

    except Exception as e:
        print(f"[WARNING] URLhaus download failed: {e}")
        print("         Existing URLhaus data will not be overwritten.")


# ============================================================
# 3. TRANCO TOP DOMAINS
# ============================================================

tranco_file = DIRS["benign_candidate_domains"] / "tranco_top_1m.csv"

try:
    download(
        "https://tranco-list.eu/top-1m.csv.zip",
        DIRS["benign_candidate_domains"] / "tranco_top_1m.csv.zip",
    )

    tranco_zip = DIRS["benign_candidate_domains"] / "tranco_top_1m.csv.zip"

    if not tranco_file.exists():
        with zipfile.ZipFile(tranco_zip) as z:
            members = z.namelist()
            csv_member = next(
                (m for m in members if m.endswith(".csv")),
                None
            )

            if csv_member:
                with z.open(csv_member) as src:
                    tranco_file.write_bytes(src.read())

    record(
        "Tranco",
        tranco_file,
        "Candidate legitimate/popular-domain pool",
        "Tranco research-oriented top-domain ranking",
        None,
        "NOT ground-truth benign. Domains can be compromised or abused.",
    )

except Exception as e:
    print(f"[WARNING] Tranco download failed: {e}")


# ============================================================
# 4. HINGLISH / ENGLISH SCAM AUXILIARY DATASET
# ============================================================

hinglish_file = DIRS["auxiliary_curated"] / "hinglish_scam_text.json"

try:
    download(
        "https://huggingface.co/datasets/"
        "bolewara/hinglish-scam-text-dataset/"
        "resolve/main/data.json",
        hinglish_file,
    )

    record(
        "Hinglish & English Financial Scam/Fraud Dataset",
        hinglish_file,
        "Indian-language scam robustness / auxiliary training",
        "Hugging Face dataset by Anuj Bolewar",
        "CC BY 4.0",
        "Contains UCI-derived English samples and hand-written Hinglish examples. "
        "Do not represent all samples as real incident messages.",
    )

except Exception as e:
    print(f"[WARNING] Hinglish dataset download failed: {e}")


# ============================================================
# 5. INTERNSHIP / JOB SCAM DATASET
# ============================================================

job_file = DIRS["job_scams"] / "internship_job_scam_dataset.csv"

try:
    download(
        "https://huggingface.co/datasets/"
        "agnialf/Internship-Job-Scam-Dataset/"
        "resolve/main/internship_job_scam_dataset.csv",
        job_file,
    )

    record(
        "Internship Job Scam Dataset",
        job_file,
        "Job-scam auxiliary dataset",
        "Based on Employment Scam Aegean Dataset (EMSCAD), with custom processing.",
        None,
        "Contains legitimate/fraudulent source-derived examples plus "
        "rule-augmented suspicious variants. Preserve source_type during preprocessing.",
    )

except Exception as e:
    print(f"[WARNING] Job scam dataset download failed: {e}")


# ============================================================
# MANIFEST
# ============================================================

manifest = {
    "project": "ScamShield",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "sources": SOURCES,
    "existing_files": [],
}

for p in RAW.rglob("*"):
    if p.is_file() and p.name != "download_manifest.json":
        manifest["existing_files"].append({
            "file": str(p.relative_to(ROOT)),
            "bytes": p.stat().st_size,
            "sha256": sha256(p),
        })

MANIFEST.write_text(
    json.dumps(manifest, indent=2),
    encoding="utf-8",
)

print()
print("=" * 65)
print("SCAMSHIELD REAL-DATA INGESTION COMPLETE")
print("=" * 65)
print(f"Manifest: {MANIFEST}")
print()

for item in manifest["existing_files"]:
    print(
        f"{item['file']} | "
        f"{item['bytes'] / 1024 / 1024:.2f} MB | "
        f"{item['sha256'][:16]}..."
    )

print()
print("IMPORTANT:")
print("- Tranco = candidate legitimate domains, NOT ground truth.")
print("- URLhaus = malware URLs, NOT phishing labels.")
print("- Curated datasets remain separately identified.")
print("- No synthetic samples are added by this script.")
