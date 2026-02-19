from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String

from extensions import db


class UserActivityEvent(db.Model):
    """Append-only engagement ledger used for leaderboards.

    This table is intentionally separate from token rewards. The `points` column
    is an internal engagement score used for streak/rank/leaderboards.
    """

    __tablename__ = "user_activity_events"

    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), ForeignKey("users.wallet"), nullable=False, index=True)
    action = Column(String(40), nullable=False)
    points = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_activity_created_at", "created_at"),
        Index("idx_activity_wallet_created", "wallet", "created_at"),
    )
