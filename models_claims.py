from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Index, Integer, String

from extensions import db


class ClaimWindowState(db.Model):
    """Per-wallet state for the 6-hour claim window feature."""

    __tablename__ = "claim_window_state"

    wallet = Column(String(42), primary_key=True)
    last_claim_at = Column(DateTime, nullable=True)
    # YYYY-MM-DD (UTC) of last claim used for streak tracking
    last_claim_day = Column(String(10), nullable=True)
    streak_days = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("idx_claim_state_last_claim_at", "last_claim_at"),
    )


class ClaimWindowClaim(db.Model):
    """History of individual claim window claims (credits)."""

    __tablename__ = "claim_window_claims"

    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    amount = Column(Float, nullable=False, default=0.0)
    points = Column(Integer, nullable=False, default=0)
    claimed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_claim_wallet_claimed_at", "wallet", "claimed_at"),
    )
