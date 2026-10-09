from pathlib import Path
import json
import hashlib
import pandas as pd


ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed"

OUT.mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save_csv(df: pd.DataFrame, path: Path):
    df.to_csv(path, index=False)
    print(f"[SAVED] {path}")
    print(f"        rows={len(df):,}")
    print(f"        columns={df.columns.tolist()}")


# ============================================================
# 1. UCI SMS SPAM COLLECTION
# ============================================================

def prepare_uci_sms():
    src = RAW / "sms" / "SMSSpamCollection"

    if not src.exists():
        raise FileNotFoundError(src)

    df = pd.read_csv(
        src,
        sep="\t",
        header=None,
        names=["label", "text"],
        encoding="utf-8"
    )

    df["label"] = df["label"].map({
        "ham": 0,
        "spam": 1
    })

    df["source"] = "UCI_SMS_Spam_Collection"
    df["source_type"] = "public_real_dataset"

    df["text"] = (
        df["text"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df = df[
        (df["text"].str.len() > 0) &
        (df["label"].isin([0, 1]))
    ].copy()

    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    df = df[
        [
            "text",
            "label",
            "source",
            "source_type"
        ]
    ]

    save_csv(
        df,
        OUT / "text_binary_uci.csv"
    )

    print("\nUCI LABELS:")
    print(df["label"].value_counts().to_dict())

    return df


# ============================================================
# 2. JOB / INTERNSHIP SCAM DATASET
# ============================================================

def prepare_job_scam():
    src = RAW / "job_scams" / "internship_job_scam_dataset.csv"

    if not src.exists():
        raise FileNotFoundError(src)

    df = pd.read_csv(src, low_memory=False)

    required = [
        "title",
        "location",
        "text",
        "label",
        "risk_level",
        "red_flags",
        "source_dataset",
        "source_type",
        "original_fraudulent",
        "internship_related"
    ]

    missing = [c for c in required if c not in df.columns]

    if missing:
        raise ValueError(
            f"Job dataset missing columns: {missing}"
        )

    # Preserve the original label.
    df["original_label"] = (
        df["label"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    # We only create a binary scam signal here.
    # We DO NOT invent the other ScamShield categories.
    df["scam_label"] = df["original_label"].isin(
        ["fraudulent", "suspicious"]
    ).astype(int)

    df["text"] = (
        df["title"].fillna("").astype(str)
        + "\n"
        + df["location"].fillna("").astype(str)
        + "\n"
        + df["text"].fillna("").astype(str)
    ).str.strip()

    df["source"] = "Internship_Job_Scam_Dataset"

    df = df[
        df["text"].str.len() > 0
    ].copy()

    df = df.drop_duplicates(
        subset=["text"]
    ).reset_index(drop=True)

    output = df[
        [
            "text",
            "scam_label",
            "original_label",
            "risk_level",
            "red_flags",
            "original_fraudulent",
            "internship_related",
            "source_dataset",
            "source_type",
            "source"
        ]
    ]

    save_csv(
        output,
        OUT / "job_scam.csv"
    )

    print("\nJOB LABELS:")
    print(
        output["original_label"]
        .value_counts()
        .to_dict()
    )

    print("\nJOB SCAM BINARY:")
    print(
        output["scam_label"]
        .value_counts()
        .to_dict()
    )

    return output


# ============================================================
# 3. HINGLISH AUXILIARY DATASET
# ============================================================

def prepare_hinglish():
    src = RAW / "auxiliary_curated" / "hinglish_scam_text.json"

    if not src.exists():
        raise FileNotFoundError(src)

    data = json.loads(
        src.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError(
            "Unexpected Hinglish dataset structure"
        )

    rows = data.get("rows", [])

    if not isinstance(rows, list):
        raise ValueError(
            "Expected 'rows' to be a list"
        )

    records = []

    for item in rows:
        if not isinstance(item, dict):
            continue

        text = str(
            item.get("text", "")
        ).strip()

        label = item.get("label")

        if not text:
            continue

        if label not in [0, 1]:
            continue

        records.append({
            "text": text,
            "label": int(label),
            "source": "Hinglish_Scam_Text_Dataset",
            "source_type": "auxiliary_curated"
        })

    df = pd.DataFrame(records)

    if df.empty:
        raise ValueError(
            "No valid Hinglish records found"
        )

    df = df.drop_duplicates(
        subset=["text"]
    ).reset_index(drop=True)

    save_csv(
        df,
        OUT / "text_binary_hinglish.csv"
    )

    print("\nHINGLISH LABELS:")
    print(
        df["label"]
        .value_counts()
        .to_dict()
    )

    return df


# ============================================================
# 4. URLHAUS MALICIOUS URL DATA
# ============================================================

def prepare_urlhaus():
    src = RAW / "malware_urls" / "urlhaus_recent.csv"

    if not src.exists():
        raise FileNotFoundError(src)

    df = pd.read_csv(
        src,
        low_memory=False
    )

    required = [
        "id",
        "date_added",
        "url",
        "url_status",
        "threat",
        "tags"
    ]

    missing = [
        c for c in required
        if c not in df.columns
    ]

    if missing:
        raise ValueError(
            f"URLhaus missing columns: {missing}"
        )

    df["url"] = (
        df["url"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

    df = df[
        df["url"].str.len() > 0
    ].copy()

    df = df.drop_duplicates(
        subset=["url"]
    ).reset_index(drop=True)

    # IMPORTANT:
    # URLhaus is malware URL intelligence.
    # We explicitly preserve this label as malware,
    # NOT phishing.
    df["malicious"] = 1
    df["label_type"] = "MALWARE_URL"
    df["source"] = "URLhaus"

    output = df[
        [
            "url",
            "malicious",
            "label_type",
            "url_status",
            "threat",
            "tags",
            "date_added",
            "source"
        ]
    ]

    save_csv(
        output,
        OUT / "malicious_urls_urlhaus.csv"
    )

    print("\nURLHAUS THREATS:")
    print(
        output["threat"]
        .value_counts()
        .head(20)
        .to_dict()
    )

    print("\nURLHAUS STATUS:")
    print(
        output["url_status"]
        .value_counts()
        .to_dict()
    )

    return output


# ============================================================
# 5. TRANCO CANDIDATE LEGITIMATE DOMAINS
# ============================================================

def prepare_tranco_candidates():
    src = (
        RAW
        / "benign_candidate_domains"
        / "tranco_top_1m.csv"
    )

    if not src.exists():
        raise FileNotFoundError(src)

    df = pd.read_csv(
        src,
        header=None,
        names=["rank", "domain"]
    )

    df["domain"] = (
        df["domain"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    df["rank"] = pd.to_numeric(
        df["rank"],
        errors="coerce"
    )

    df = df[
        (df["rank"].notna()) &
        (df["domain"].str.len() > 0)
    ].copy()

    df = df.drop_duplicates(
        subset=["domain"]
    ).reset_index(drop=True)

    # IMPORTANT:
    # Tranco is NOT ground-truth benign data.
    # Therefore this dataset is only marked as a
    # candidate negative pool.
    df["candidate_benign"] = 1
    df["label_type"] = "CANDIDATE_BENIGN"
    df["source"] = "Tranco"

    output = df[
        [
            "rank",
            "domain",
            "candidate_benign",
            "label_type",
            "source"
        ]
    ]

    save_csv(
        output,
        OUT / "candidate_benign_domains_tranco.csv"
    )

    return output


# ============================================================
# 6. DATASET MANIFEST
# ============================================================

def create_processed_manifest():
    manifest = {
        "project": "ScamShield",
        "stage": "processed_dataset_preparation",
        "synthetic_data_used": False,
        "datasets": []
    }

    for path in sorted(OUT.glob("*.csv")):
        manifest["datasets"].append({
            "file": str(path.relative_to(ROOT)),
            "rows": int(
                pd.read_csv(
                    path,
                    nrows=0
                ).shape[0]
            ),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size
        })

    manifest_path = (
        OUT / "processed_manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2
        ),
        encoding="utf-8"
    )

    print(
        f"\n[SAVED] {manifest_path}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("SCAMSHIELD — REAL DATA PREPARATION")
    print("=" * 70)

    print("\n[1/5] Preparing UCI SMS...")
    prepare_uci_sms()

    print("\n[2/5] Preparing Job Scam...")
    prepare_job_scam()

    print("\n[3/5] Preparing Hinglish auxiliary data...")
    prepare_hinglish()

    print("\n[4/5] Preparing URLhaus...")
    prepare_urlhaus()

    print("\n[5/5] Preparing Tranco candidate pool...")
    prepare_tranco_candidates()

    create_processed_manifest()

    print("\n" + "=" * 70)
    print("DATA PREPARATION COMPLETE")
    print("=" * 70)

    print("""
IMPORTANT DATA POLICY

UCI:
    Binary spam/ham only.

Job Scam:
    Fraudulent/suspicious/legitimate preserved.
    Used for JOB_SCAM learning.

Hinglish:
    Auxiliary curated dataset.
    Not treated as independent real-world incident data.

URLhaus:
    Malware URL intelligence.
    NOT labelled as phishing.

Tranco:
    Candidate legitimate-domain pool.
    NOT ground-truth benign labels.

No synthetic training examples were created.
""")


if __name__ == "__main__":
    main()