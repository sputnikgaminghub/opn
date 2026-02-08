from __future__ import annotations

from datetime import datetime

import bleach
import markdown as md
from flask import Blueprint, jsonify, request
from sqlalchemy import and_, distinct, func, or_
from sqlalchemy.exc import IntegrityError

from extensions import db
from models_announcements import Announcement, AnnouncementView


announcements_api = Blueprint("announcements_api", __name__)


ALLOWED_TAGS = [
    "p",
    "br",
    "strong",
    "em",
    "ul",
    "ol",
    "li",
    "a",
    "code",
    "pre",
    "blockquote",
    "h1",
    "h2",
    "h3",
    "h4",
]
ALLOWED_ATTRS = {"a": ["href", "title", "target", "rel"]}


def render_markdown_safe(text: str) -> str:
    # Convert markdown to HTML, then sanitize.
    html = md.markdown(text or "", extensions=["fenced_code", "tables"])
    clean = bleach.clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)

    def _link_cb(attrs, new=False):
        # Ensure safe external link behavior.
        attrs[(None, "target")] = "_blank"
        # Preserve existing rel while enforcing noopener/noreferrer.
        rel = attrs.get((None, "rel"), "") or ""
        rel_parts = {p for p in rel.split() if p}
        rel_parts.update({"nofollow", "noopener", "noreferrer"})
        attrs[(None, "rel")] = " ".join(sorted(rel_parts))
        return attrs

    clean = bleach.linkify(clean, callbacks=[_link_cb])
    return clean


def active_filter(now: datetime):
    return and_(
        Announcement.is_active.is_(True),
        or_(Announcement.starts_at.is_(None), Announcement.starts_at <= now),
        or_(Announcement.ends_at.is_(None), Announcement.ends_at >= now),
    )


def compute_unique_views_map(ids: list[int]) -> dict[int, int]:
    if not ids:
        return {}

    wallet_counts = (
        db.session.query(
            AnnouncementView.announcement_id,
            func.count(distinct(AnnouncementView.wallet)).label("c"),
        )
        .filter(
            AnnouncementView.announcement_id.in_(ids),
            AnnouncementView.wallet.isnot(None),
        )
        .group_by(AnnouncementView.announcement_id)
        .all()
    )

    anon_counts = (
        db.session.query(
            AnnouncementView.announcement_id,
            func.count(distinct(AnnouncementView.viewer_key)).label("c"),
        )
        .filter(
            AnnouncementView.announcement_id.in_(ids),
            AnnouncementView.wallet.is_(None),
            AnnouncementView.viewer_key.isnot(None),
        )
        .group_by(AnnouncementView.announcement_id)
        .all()
    )

    out: dict[int, int] = {i: 0 for i in ids}
    for aid, c in wallet_counts:
        out[aid] = out.get(aid, 0) + int(c or 0)
    for aid, c in anon_counts:
        out[aid] = out.get(aid, 0) + int(c or 0)
    return out


@announcements_api.get("/api/announcements")
def get_announcements():
    """List active announcements (for drawer) + one critical banner candidate."""
    wallet = (request.args.get("wallet") or "").strip() or None
    viewer_key = (request.args.get("viewer_key") or "").strip() or None

    now = datetime.utcnow()

    anns = (
        Announcement.query.filter(active_filter(now))
        .order_by(Announcement.is_pinned.desc(), Announcement.created_at.desc())
        .all()
    )

    ids = [a.id for a in anns]
    views_map = compute_unique_views_map(ids)

    viewed_ids: set[int] = set()
    if wallet:
        rows = (
            db.session.query(AnnouncementView.announcement_id)
            .filter(
                AnnouncementView.announcement_id.in_(ids),
                AnnouncementView.wallet == wallet,
            )
            .all()
        )
        viewed_ids = {r[0] for r in rows}
    elif viewer_key:
        rows = (
            db.session.query(AnnouncementView.announcement_id)
            .filter(
                AnnouncementView.announcement_id.in_(ids),
                AnnouncementView.wallet.is_(None),
                AnnouncementView.viewer_key == viewer_key,
            )
            .all()
        )
        viewed_ids = {r[0] for r in rows}

    payload = []
    for a in anns:
        payload.append(
            {
                "id": a.id,
                "title": a.title,
                "type": a.type,
                "is_pinned": bool(a.is_pinned),
                "created_at": a.created_at.isoformat(),
                "unique_views": int(views_map.get(a.id, 0)),
                "has_viewed": a.id in viewed_ids,
            }
        )

    # Banner: pinned critical wins; else newest critical.
    critical = next((a for a in anns if a.type == "critical" and a.is_pinned), None)
    if not critical:
        critical = next((a for a in anns if a.type == "critical"), None)

    critical_payload = None
    if critical:
        critical_payload = {"id": critical.id, "title": critical.title}

    return jsonify({"announcements": payload, "critical_banner": critical_payload})


@announcements_api.get("/api/announcements/<int:aid>")
def get_announcement_detail(aid: int):
    a = Announcement.query.get_or_404(aid)
    body_html = render_markdown_safe(a.body_md)
    views_map = compute_unique_views_map([a.id])
    return jsonify(
        {
            "id": a.id,
            "title": a.title,
            "type": a.type,
            "created_at": a.created_at.isoformat(),
            "body_html": body_html,
            "unique_views": int(views_map.get(a.id, 0)),
        }
    )


@announcements_api.post("/api/announcements/<int:aid>/view")
def record_view(aid: int):
    data = request.get_json(silent=True) or {}
    wallet = (data.get("wallet") or "").strip() or None
    viewer_key = (data.get("viewer_key") or "").strip() or None

    if not wallet and not viewer_key:
        # Nothing to record; return current count.
        views_map = compute_unique_views_map([aid])
        return jsonify({"unique_views": int(views_map.get(aid, 0))})

    # Wallet takes precedence as identity.
    v = AnnouncementView(
        announcement_id=aid,
        wallet=wallet,
        viewer_key=None if wallet else viewer_key,
    )

    db.session.add(v)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()

    views_map = compute_unique_views_map([aid])
    return jsonify({"unique_views": int(views_map.get(aid, 0))})
