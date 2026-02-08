import os
import json
import base64
import secrets
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import text

from extensions import db
from models_push import PushSubscription

try:
    from pywebpush import webpush, WebPushException
except Exception:  # pragma: no cover
    webpush = None
    WebPushException = Exception

push_api = Blueprint("push_api", __name__)

# -------------------------------
# Helpers
# -------------------------------

def _admin_ok(req) -> bool:
    # Prefer header auth; do NOT accept query params.
    key = req.headers.get("X-Admin-Key", "")
    expected = os.getenv("ADMIN_API_KEY", "")
    return bool(expected) and secrets.compare_digest(key, expected)

def _get_vapid_public_key() -> str:
    return os.getenv("VAPID_PUBLIC_KEY", "").strip()

def _get_vapid_private_key() -> str:
    return os.getenv("VAPID_PRIVATE_KEY", "").strip()

def _get_vapid_subject() -> str:
    # e.g. "mailto:you@example.com" or "https://yoursite.com"
    return os.getenv("VAPID_SUBJECT", "mailto:admin@example.com").strip()

def _utc_today_date():
    return datetime.now(timezone.utc).date()

def _pick_message(last_message_id: int | None):
    # 3–10 utility messages; keep short.
    messages = [
        {"title": "Update reminder", "body": "Check today’s presale status and latest updates."},
        {"title": "Airdrop updates", "body": "Your airdrop page may have new info—take a look."},
        {"title": "Site update", "body": "Review tokenomics and roadmap for the latest changes."},
        {"title": "Quick check", "body": "Don’t miss updates—open the site to stay informed."},
        {"title": "Announcement check", "body": "Visit the dashboard for the latest announcements."},
        {"title": "Presale progress", "body": "Presale progress can change fast—review the latest."},
        {"title": "Reminder", "body": "Verify your details and stay up to date."},
        {"title": "New info", "body": "New updates may be available—open the site."},
    ]
    if last_message_id is None or last_message_id < 0 or last_message_id >= len(messages):
        msg_id = secrets.randbelow(len(messages))
        return msg_id, messages[msg_id]
    # avoid immediate repeats
    choices = [i for i in range(len(messages)) if i != last_message_id]
    msg_id = choices[secrets.randbelow(len(choices))]
    return msg_id, messages[msg_id]

def _send_web_push(sub: PushSubscription, payload: dict):
    if not webpush:
        raise RuntimeError("pywebpush not installed")
    vapid_private = _get_vapid_private_key()
    vapid_public = _get_vapid_public_key()
    if not vapid_private or not vapid_public:
        raise RuntimeError("VAPID keys not configured")
    webpush(
        subscription_info={
            "endpoint": sub.endpoint,
            "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
        },
        data=json.dumps(payload),
        vapid_private_key=vapid_private,
        vapid_claims={"sub": _get_vapid_subject()},
        timeout=12,
    )

# -------------------------------
# Public endpoints (user opt-in)
# -------------------------------

@push_api.get("/api/push/public-key")
def push_public_key():
    pub = _get_vapid_public_key()
    if not pub:
        return jsonify({"ok": False, "error": "VAPID_PUBLIC_KEY not configured"}), 500
    return jsonify({"ok": True, "publicKey": pub})

@push_api.post("/api/push/subscribe")
def push_subscribe():
    data = request.get_json(silent=True) or {}
    endpoint = (data.get("endpoint") or "").strip()
    keys = data.get("keys") or {}
    p256dh = (keys.get("p256dh") or "").strip()
    auth = (keys.get("auth") or "").strip()

    if not endpoint or not p256dh or not auth:
        return jsonify({"ok": False, "error": "Invalid subscription payload"}), 400

    sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if sub:
        sub.p256dh = p256dh
        sub.auth = auth
        sub.is_active = True
    else:
        sub = PushSubscription(endpoint=endpoint, p256dh=p256dh, auth=auth, is_active=True)
        db.session.add(sub)

    db.session.commit()
    return jsonify({"ok": True})

@push_api.post("/api/push/unsubscribe")
def push_unsubscribe():
    data = request.get_json(silent=True) or {}
    endpoint = (data.get("endpoint") or "").strip()
    if not endpoint:
        return jsonify({"ok": False, "error": "Missing endpoint"}), 400
    sub = PushSubscription.query.filter_by(endpoint=endpoint).first()
    if sub:
        sub.is_active = False
        db.session.commit()
    return jsonify({"ok": True})

# -------------------------------
# Admin endpoints (cron triggers)
# -------------------------------

@push_api.post("/api/admin/push/send-daily")
def admin_send_daily_push():
    if not _admin_ok(request):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    # Enforce 1/day per subscription (UTC day).
    today = _utc_today_date()
    subs = PushSubscription.query.filter_by(is_active=True).all()

    sent = 0
    skipped = 0
    failed = 0
    deactivated = 0

    for sub in subs:
        try:
            if sub.last_sent_at and sub.last_sent_at.replace(tzinfo=timezone.utc).date() == today:
                skipped += 1
                continue

            msg_id, msg = _pick_message(sub.last_message_id)
            payload = {
                "title": msg["title"],
                "body": msg["body"],
                "url": "/",  # open homepage; can be changed to a deep link later
            }
            _send_web_push(sub, payload)

            sub.last_sent_at = datetime.utcnow()
            sub.last_message_id = msg_id
            sent += 1
        except WebPushException as e:
            failed += 1
            # If subscription is gone/expired, deactivate it.
            try:
                status = getattr(getattr(e, "response", None), "status_code", None)
                if status in (404, 410):
                    sub.is_active = False
                    deactivated += 1
            except Exception:
                pass
        except Exception:
            failed += 1

    db.session.commit()
    return jsonify({
        "ok": True,
        "sent": sent,
        "skipped": skipped,
        "failed": failed,
        "deactivated": deactivated,
        "total_active": len(subs),
    })
