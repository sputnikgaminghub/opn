from __future__ import annotations

from datetime import date, datetime, timedelta

from sqlalchemy import text

from extensions import db


# Engagement rank tiers (internal identity system)
RANKS: list[tuple[str, int]] = [
    ("Explorer", 0),
    ("Operator", 50),
    ("Alpha", 150),
    ("Elite", 350),
    ("Insider", 700),
]


def compute_rank(points: int) -> str:
    tier = "Explorer"
    for name, threshold in RANKS:
        if points >= threshold:
            tier = name
    return tier


def touch_activity(wallet: str, action: str, points: int = 0, once_per_day: bool = False) -> None:
    """Update engagement fields (best-effort) and append an activity event.

    This must never raise: some deployments may not have the optional engagement columns yet.
    """

    wallet = (wallet or "").strip().lower()
    if not wallet:
        return

    # Always try to mirror into the dashboard activity stream (activity_logs).
    def _insert_activity_log():
        try:
            db.session.execute(
                text(
                    """
                    INSERT INTO activity_logs (wallet, type, message, metadata_json, created_at)
                    VALUES (:w, :t, :m, NULL, :c)
                    """
                ),
                {"w": wallet, "t": "event", "m": str(action)[:500], "c": datetime.utcnow()},
            )
        except Exception:
            pass

    # Try to update engagement columns if present.
    try:
        row = db.session.execute(
            text(
                """
                SELECT wallet, streak_days, longest_streak, last_active_date, activity_points
                FROM users
                WHERE wallet = :w
                LIMIT 1
                """
            ),
            {"w": wallet},
        ).first()

        if not row:
            _insert_activity_log()
            db.session.commit()
            return

        streak_days = int(getattr(row, "streak_days", 0) or 0)
        longest_streak = int(getattr(row, "longest_streak", 0) or 0)
        last_active_date = getattr(row, "last_active_date", None)
        activity_points = int(getattr(row, "activity_points", 0) or 0)

        today = date.today()
        already_today = last_active_date == today

        # ---- streak update (max once/day) ----
        if not already_today:
            if last_active_date is None:
                streak_days = 1
            elif last_active_date == today - timedelta(days=1):
                streak_days = streak_days + 1
            else:
                streak_days = 1

            if streak_days > longest_streak:
                longest_streak = streak_days

            last_active_date = today

        # ---- points update ----
        add_points = int(points or 0)
        if once_per_day and already_today:
            add_points = 0

        activity_points = activity_points + add_points
        rank_tier = compute_rank(activity_points)

        db.session.execute(
            text(
                """
                UPDATE users
                SET streak_days = :sd,
                    longest_streak = :ls,
                    last_active_date = :lad,
                    last_active = :la,
                    activity_points = :ap,
                    rank_tier = :rt
                WHERE wallet = :w
                """
            ),
            {
                "sd": streak_days,
                "ls": longest_streak,
                "lad": last_active_date,
                "la": datetime.utcnow(),
                "ap": activity_points,
                "rt": rank_tier,
                "w": wallet,
            },
        )

        db.session.execute(
            text(
                """
                INSERT INTO user_activity_events (wallet, action, points, created_at)
                VALUES (:w, :a, :p, :t)
                """
            ),
            {"w": wallet, "a": action, "p": add_points, "t": datetime.utcnow()},
        )

        _insert_activity_log()
        db.session.commit()
        return
    except Exception:
        # Schema mismatch or other DB issue: just log the event and move on.
        _insert_activity_log()
        try:
            db.session.commit()
        except Exception:
            pass
        return
