"""Admin analytics dashboard for referral onboarding traffic."""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, render_template, request, session as flask_session, redirect, url_for
from sqlalchemy import text

from extensions import db


admin_analytics = Blueprint("admin_analytics", __name__)


def _admin_key() -> str:
    return (os.getenv("ADMIN_ANALYTICS_KEY") or os.getenv("ADMIN_API_KEY") or "").strip()


def _is_authed() -> bool:
    return bool(flask_session.get("admin_analytics"))


@admin_analytics.route("/admin/analytics")
def analytics_dashboard():
    if not _is_authed():
        return redirect(url_for("admin_analytics.analytics_login"))
    return render_template("admin_analytics.html")


@admin_analytics.route("/admin/analytics/login", methods=["GET", "POST"])
def analytics_login():
    if request.method == "POST":
        key = (request.form.get("key") or "").strip()
        if key and key == _admin_key():
            flask_session["admin_analytics"] = True
            return redirect(url_for("admin_analytics.analytics_dashboard"))
        return render_template("admin_section_login.html", title="Analytics Admin Login", error="Invalid key")
    return render_template("admin_section_login.html", title="Analytics Admin Login", error=None)


@admin_analytics.route("/admin/analytics/logout", methods=["POST"])
def analytics_logout():
    flask_session.pop("admin_analytics", None)
    return jsonify({"ok": True})


@admin_analytics.route("/api/admin/analytics/referrals")
def api_referral_analytics():
    if not _is_authed():
        return jsonify({"error": "unauthorized"}), 401

    days = int(request.args.get("days") or 14)
    days = max(1, min(days, 90))
    since = datetime.utcnow() - timedelta(days=days)

    rows = db.session.execute(
        text(
            """
            SELECT referral_code,
                   event,
                   COUNT(*) as cnt
            FROM referral_traffic_events
            WHERE created_at >= :since
            GROUP BY referral_code, event
            ORDER BY cnt DESC
            """
        ),
        {"since": since},
    ).fetchall()

    # shape into {code: {event: cnt}}
    out = {}
    for r in rows:
        code = (r[0] or "").upper()
        ev = r[1]
        cnt = int(r[2] or 0)
        out.setdefault(code, {})[ev] = cnt

    return jsonify({"since": since.isoformat() + "Z", "days": days, "data": out})
