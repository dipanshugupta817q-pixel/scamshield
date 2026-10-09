import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from database.database import Base, engine, get_db
from database import models
from database.crud import save_scan, get_scan, list_scans, get_stats
from ml.inference import analyze


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="ScamShield API",
    description="Scam detection, scan history, threat statistics and user reports.",
    version="1.1.0",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class AnalyzeRequest(BaseModel):
    text: str = Field(default="", max_length=20000)
    urls: List[str] = Field(default_factory=list, max_length=20)
    ocr_text: str = Field(default="", max_length=20000)


class MissedScamReportRequest(BaseModel):
    report_type: str = Field(
        default="MISSED_DETECTION",
        max_length=40,
    )
    description: str = Field(
        default="",
        max_length=3000,
    )
    suspicious_content: str = Field(
        default="",
        max_length=10000,
    )


# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "scamshield-ml",
    }


@app.get("/api/v1/health")
def api_health():
    return {
        "status": "ok",
        "service": "scamshield-api",
        "version": "1.1.0",
    }


# --------------------------------------------------
# SCAM ANALYSIS
# --------------------------------------------------

@app.post("/analyze")
@app.post("/api/v1/analyze")
def analyze_message(
    request: AnalyzeRequest,
    db: Session = Depends(get_db),
):
    if (
        not request.text.strip()
        and not request.ocr_text.strip()
        and not request.urls
    ):
        raise HTTPException(
            status_code=400,
            detail="Provide message text, OCR text, or at least one URL.",
        )

    try:
        result = analyze(
            text=request.text,
            urls=request.urls,
            ocr_text=request.ocr_text,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Check the ML service logs.",
        )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=500,
            detail="The ML engine returned an invalid response.",
        )

    try:
        saved = save_scan(
            db=db,
            text=request.text,
            urls=request.urls,
            ocr_text=request.ocr_text,
            result=result,
        )
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Analysis completed but saving the scan failed.",
        )

    return {
        **result,
        "analysis_id": saved["analysis_id"],
        "timestamp": saved["timestamp"],
    }


# --------------------------------------------------
# SCAN HISTORY
# --------------------------------------------------

@app.get("/history")
@app.get("/api/v1/history")
def scan_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    return list_scans(
        db,
        limit=limit,
        offset=offset,
    )


@app.get("/history/{analysis_id}")
@app.get("/api/v1/history/{analysis_id}")
def scan_details(
    analysis_id: str,
    db: Session = Depends(get_db),
):
    scan = get_scan(db, analysis_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    return {
        "analysis_id": scan.analysis_id,
        "timestamp": (
            scan.created_at.isoformat()
            if scan.created_at
            else None
        ),
        "category": scan.category,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "prediction": scan.prediction,
        "campaign_id": scan.campaign_id or None,
        "input_text": scan.input_text,
        "urls": json.loads(scan.input_urls_json or "[]"),
        "ocr_text": scan.ocr_text,
        "result": json.loads(scan.result_json),
    }


# --------------------------------------------------
# STATISTICS
# --------------------------------------------------

@app.get("/stats")
@app.get("/api/v1/stats")
def scan_stats(
    db: Session = Depends(get_db),
):
    return get_stats(db)


# --------------------------------------------------
# MISSED-SCAM REPORTS
# --------------------------------------------------

ALLOWED_REPORT_TYPES = {
    "MISSED_DETECTION",
    "SUSPICIOUS_URL",
    "SUSPICIOUS_MESSAGE",
    "MALWARE_CONCERN",
    "OTHER",
}


@app.post("/api/v1/reports", status_code=201)
def create_missed_scam_report(
    request: MissedScamReportRequest,
    db: Session = Depends(get_db),
):
    description = request.description.strip()
    suspicious_content = request.suspicious_content.strip()
    report_type = request.report_type.strip().upper()

    if not description and not suspicious_content:
        raise HTTPException(
            status_code=400,
            detail="Provide a description or suspicious content.",
        )

    if report_type not in ALLOWED_REPORT_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported report type.",
        )

    report_id = f"RPT-{uuid4().hex[:12].upper()}"

    report = models.MissedScamReport(
        report_id=report_id,
        created_at=datetime.now(timezone.utc),
        report_type=report_type,
        description=description,
        suspicious_content=suspicious_content,
        status="RECEIVED",
    )

    try:
        db.add(report)
        db.commit()
        db.refresh(report)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save the report. Please retry.",
        )

    return {
        "report_id": report.report_id,
        "status": report.status,
        "created_at": (
            report.created_at.isoformat()
            if report.created_at
            else None
        ),
        "message": (
            "Report saved to ScamShield. "
            "This does not mean an official cybercrime complaint "
            "was submitted."
        ),
    }


@app.get("/api/v1/reports/{report_id}")
def get_missed_scam_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    report = db.scalar(
        select(models.MissedScamReport).where(
            models.MissedScamReport.report_id == report_id
        )
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not found.",
        )

    return {
        "report_id": report.report_id,
        "status": report.status,
        "report_type": report.report_type,
        "created_at": (
            report.created_at.isoformat()
            if report.created_at
            else None
        ),
    }
