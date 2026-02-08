from __future__ import annotations

import os
from datetime import datetime

from flask import Blueprint, abort, jsonify, render_template, request, session

from extensions import db
from models_announcements import Announcement


admin_announcements = Blueprint("admin_announcements", __name__)

ADMIN_KEY = os.getenv("ADMIN_API_KEY")


def require_admin():
    if session.get("is_admin") is True:
        return
    if ADMIN_KEY and request.args.get("key") == ADMIN_KEY:
        session["is_admin"] = True
        return
    abort(403)


def parse_dt(v: str | None):
    if not v:
        return None
    v = v.strip()
    if not v:
        return None
    # Accept either ISO datetime or YYYY-MM-DD
    try:
        return datetime.fromisoformat(v)
    except Exception:
        return None


@admin_announcements.get("/admin/announcements")
def admin_page():
    require_admin()
    return render_template("admin_announcements.html")


@admin_announcements.get("/api/admin/announcements")
def list_announcements():
    require_admin()
    anns = Announcement.query.order_by(Announcement.created_at.desc()).all()
    return jsonify(
        {
            "announcements": [
                {
                    "id": a.id,
                    "title": a.title,
                    "type": a.type,
                    "is_active": bool(a.is_active),
                    "is_pinned": bool(a.is_pinned),
                    "starts_at": a.starts_at.isoformat() if a.starts_at else None,
                    "ends_at": a.ends_at.isoformat() if a.ends_at else None,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "updated_at": a.updated_at.isoformat() if a.updated_at else None,
                    "body_md": a.body_md,
                }
                for a in anns
            ]
        }
    )


@admin_announcements.post("/api/admin/announcements")
def create_announcement():
    require_admin()
    d = request.get_json(silent=True) or {}

    title = (d.get("title") or "").strip()
    body_md = (d.get("body_md") or "").strip()
    a_type = (d.get("type") or "normal").strip()
    if a_type not in ("normal", "critical"):
        a_type = "normal"

    if not title or not body_md:
        return jsonify({"success": False, "error": "title and body_md are required"}), 400

    a = Announcement(
        title=title,
        body_md=body_md,
        type=a_type,
        is_active=bool(d.get("is_active", True)),
        is_pinned=bool(d.get("is_pinned", False)),
        starts_at=parse_dt(d.get("starts_at")),
        ends_at=parse_dt(d.get("ends_at")),
    )
    db.session.add(a)
    db.session.commit()
    return jsonify({"success": True, "id": a.id})


@admin_announcements.put("/api/admin/announcements/<int:aid>")
def update_announcement(aid: int):
    require_admin()
    a = Announcement.query.get_or_404(aid)
    d = request.get_json(silent=True) or {}

    title = (d.get("title") or "").strip()
    body_md = (d.get("body_md") or "").strip()
    a_type = (d.get("type") or "normal").strip()
    if a_type not in ("normal", "critical"):
        a_type = "normal"

    if not title or not body_md:
        return jsonify({"success": False, "error": "title and body_md are required"}), 400

    a.title = title
    a.body_md = body_md
    a.type = a_type
    a.is_active = bool(d.get("is_active", True))
    a.is_pinned = bool(d.get("is_pinned", False))
    a.starts_at = parse_dt(d.get("starts_at"))
    a.ends_at = parse_dt(d.get("ends_at"))

    db.session.commit()
    return jsonify({"success": True})


@admin_announcements.delete("/api/admin/announcements/<int:aid>")
def delete_announcement(aid: int):
    require_admin()
    a = Announcement.query.get_or_404(aid)
    db.session.delete(a)
    db.session.commit()
    return jsonify({"success": True})