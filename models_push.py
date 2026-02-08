from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Index

from extensions import db

class PushSubscription(db.Model):
    __tablename__ = "push_subscriptions"

    id = Column(Integer, primary_key=True)
    endpoint = Column(String(1024), unique=True, nullable=False)
    p256dh = Column(String(255), nullable=False)
    auth = Column(String(255), nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_sent_at = Column(DateTime, nullable=True)
    last_message_id = Column(Integer, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_push_subscriptions_active", "is_active"),
    )
