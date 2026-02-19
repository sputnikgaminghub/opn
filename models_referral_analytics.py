from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Index

from extensions import db


class ReferralTrafficEvent(db.Model):
    """Lightweight referral traffic analytics.

    Stores anonymous clickstream events from the referral onboarding page.
    No wallet linkage is required (pre-connect).
    """

    __tablename__ = "referral_traffic_events"

    id = Column(Integer, primary_key=True)
    referral_code = Column(String(32), nullable=False, index=True)
    event = Column(String(40), nullable=False, index=True)  # landing_view, click_presale, click_airdrop, click_staking, click_telegram
    ua = Column(String(300), nullable=True)
    ip_hash = Column(String(80), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("idx_ref_traffic_code_event_time", "referral_code", "event", "created_at"),
    )
