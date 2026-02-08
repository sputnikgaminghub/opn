from datetime import datetime

from extensions import db


class Announcement(db.Model):
    __tablename__ = "announcements"

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(255), nullable=False)
    body_md = db.Column(db.Text, nullable=False)

    # "normal" | "critical"
    type = db.Column(db.String(16), default="normal", nullable=False)

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_pinned = db.Column(db.Boolean, default=False, nullable=False)

    # Optional scheduling window
    starts_at = db.Column(db.DateTime, nullable=True)
    ends_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class AnnouncementView(db.Model):
    __tablename__ = "announcement_views"

    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(
        db.Integer, db.ForeignKey("announcements.id"), nullable=False, index=True
    )

    # If a wallet is known, we treat it as the unique identity.
    wallet = db.Column(db.String(128), nullable=True, index=True)
    # Otherwise we use a stable, anonymous key stored client-side.
    viewer_key = db.Column(db.String(128), nullable=True, index=True)

    viewed_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "announcement_id", "wallet", name="uniq_announcement_wallet"
        ),
        db.UniqueConstraint(
            "announcement_id", "viewer_key", name="uniq_announcement_viewer"
        ),
    )
