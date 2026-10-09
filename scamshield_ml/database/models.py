
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    analysis_id: Mapped[str] = mapped_column(
        String(40),
        unique=True,
        index=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    input_text: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    input_urls_json: Mapped[str] = mapped_column(
        Text,
        default="[]",
        nullable=False,
    )

    ocr_text: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(80),
        default="OTHER",
        index=True,
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        index=True,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(20),
        default="LOW",
        index=True,
        nullable=False,
    )

    prediction: Mapped[str] = mapped_column(
        String(40),
        default="UNKNOWN",
        nullable=False,
    )

    campaign_id: Mapped[str] = mapped_column(
        String(80),
        default="",
        index=True,
        nullable=False,
    )

    result_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )


class MissedScamReport(Base):
    __tablename__ = "missed_scam_reports"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    report_id: Mapped[str] = mapped_column(
        String(40),
        unique=True,
        index=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
        nullable=False,
    )

    report_type: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    suspicious_content: Mapped[str] = mapped_column(
        Text,
        default="",
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="RECEIVED",
        nullable=False,
    )
