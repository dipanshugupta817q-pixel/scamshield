import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from database.models import Scan


def save_scan(
    db: Session,
    text: str,
    urls: list[str],
    ocr_text: str,
    result: dict,
) -> dict:
    campaign = result.get("campaign") or {}
    campaign_id = (
        result.get("campaign_id")
        or campaign.get("campaign_id")
        or ""
    )

    analysis_id = f"SCN-{uuid4().hex[:12].upper()}"

    scan = Scan(
        analysis_id=analysis_id,
        created_at=datetime.now(timezone.utc),
        input_text=text,
        input_urls_json=json.dumps(urls, ensure_ascii=False),
        ocr_text=ocr_text,
        category=str(result.get("category") or "OTHER"),
        risk_score=int(result.get("risk_score") or 0),
        risk_level=str(result.get("risk_level") or "LOW"),
        prediction=str(
            result.get("binary_prediction")
            or result.get("prediction")
            or "UNKNOWN"
        ),
        campaign_id=str(campaign_id),
        result_json=json.dumps(result, ensure_ascii=False, default=str),
    )

    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except Exception:
        db.rollback()
        raise

    return scan_to_dict(scan)


def scan_to_dict(scan: Scan, include_result: bool = False) -> dict:
    urls = json.loads(scan.input_urls_json or "[]")
    preview_source = (
        scan.input_text
        or scan.ocr_text
        or (urls[0] if urls else "")
    )

    item = {
        "analysis_id": scan.analysis_id,
        "timestamp": scan.created_at.isoformat() if scan.created_at else None,
        "category": scan.category,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "prediction": scan.prediction,
        "campaign_id": scan.campaign_id or None,
        "input_preview": preview_source[:180],
        "urls": urls,
    }

    if include_result:
        item["result"] = json.loads(scan.result_json)

    return item


def get_scan(db: Session, analysis_id: str):
    return db.scalar(
        select(Scan).where(Scan.analysis_id == analysis_id)
    )


def list_scans(db: Session, limit: int = 50, offset: int = 0):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    total = db.scalar(
        select(func.count()).select_from(Scan)
    ) or 0

    rows = db.scalars(
        select(Scan)
        .order_by(desc(Scan.created_at), desc(Scan.id))
        .offset(offset)
        .limit(limit)
    ).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [scan_to_dict(row) for row in rows],
    }


def get_stats(db: Session):
    total = db.scalar(
        select(func.count()).select_from(Scan)
    ) or 0

    high_risk = db.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.risk_level.in_(["HIGH", "CRITICAL"]))
    ) or 0

    categories = db.execute(
        select(Scan.category, func.count())
        .group_by(Scan.category)
        .order_by(desc(func.count()))
    ).all()

    risk_levels = db.execute(
        select(Scan.risk_level, func.count())
        .group_by(Scan.risk_level)
    ).all()

    return {
        "total_scans": total,
        "high_or_critical_scans": high_risk,
        "category_distribution": {
            category: count for category, count in categories
        },
        "risk_distribution": {
            level: count for level, count in risk_levels
        },
    }
