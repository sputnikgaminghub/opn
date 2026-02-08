#!/usr/bin/env python3
"""Send daily push notification to all active subscriptions (max 1/day, UTC).

Intended to be run from a scheduler (e.g., Render Cron) at 12:00 UTC.
"""

from datetime import datetime, timezone

from app import app  # noqa: F401
from extensions import db
from models_push import PushSubscription
from push_api import _pick_message, _send_web_push, _utc_today_date

def main():
    today = _utc_today_date()
    sent = skipped = failed = deactivated = 0

    with app.app_context():
        subs = PushSubscription.query.filter_by(is_active=True).all()
        for sub in subs:
            try:
                if sub.last_sent_at and sub.last_sent_at.replace(tzinfo=timezone.utc).date() == today:
                    skipped += 1
                    continue

                msg_id, msg = _pick_message(sub.last_message_id)
                payload = {
                    "title": msg["title"],
                    "body": msg["body"],
                    "url": "/",
                }
                _send_web_push(sub, payload)

                sub.last_sent_at = datetime.utcnow()
                sub.last_message_id = msg_id
                sent += 1
            except Exception:
                failed += 1

        db.session.commit()

    print({
        "ok": True,
        "sent": sent,
        "skipped": skipped,
        "failed": failed,
        "deactivated": deactivated,
        "total_active": len(subs) if 'subs' in locals() else 0,
    })

if __name__ == "__main__":
    main()
