import re
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from sqlalchemy import func, text

from extensions import db
from models_claims import ClaimWindowClaim, ClaimWindowState


claims_api = Blueprint("claims_api", __name__)


def _normalize_wallet(wallet: str) -> str:
    return (wallet or "").strip().lower()


def _is_valid_wallet(wallet: str) -> bool:
    if not wallet:
        return False
    return re.fullmatch(r"0x[a-fA-F0-9]{40}", wallet) is not None


def _user_exists(wallet: str) -> bool:
    # Avoid importing User from app.py (prevents circular imports).
    row = db.session.execute(text("SELECT wallet FROM users WHERE wallet = :w LIMIT 1"), {"w": wallet}).fetchone()
    return row is not None


def _get_config():
    """Centralized config so you can tweak values later."""
    return {
        "WINDOW_HOURS": int(request.args.get("window_hours") or 6),
        "REWARD_APRO": float(request.args.get("reward_apro") or 1),
        "REWARD_POINTS": int(request.args.get("reward_points") or 2),
        "MAX_PER_DAY": int(request.args.get("max_per_day") or 4),
        # Milestone bonuses (streak days => bonus OPN)
        "STREAK_BONUSES": {
            3: 3,
            7: 10,
            14: 25,
            30: 60,
        },
    }


def _utc_day_bounds(now: datetime):
    day_start = datetime(now.year, now.month, now.day)
    day_end = day_start + timedelta(days=1)
    return day_start, day_end


def _claims_today(wallet: str, now: datetime) -> int:
    day_start, day_end = _utc_day_bounds(now)
    return (
        db.session.query(ClaimWindowClaim)
        .filter(ClaimWindowClaim.wallet == wallet)
        .filter(ClaimWindowClaim.claimed_at >= day_start)
        .filter(ClaimWindowClaim.claimed_at < day_end)
        .count()
    )


def _get_state(wallet: str) -> ClaimWindowState:
    state = ClaimWindowState.query.get(wallet)
    if not state:
        state = ClaimWindowState(wallet=wallet, last_claim_at=None, last_claim_day=None, streak_days=0)
        db.session.add(state)
        db.session.commit()
    return state


def _compute_status(wallet: str, now: datetime):
    cfg = _get_config()
    state = _get_state(wallet)
    today_count = _claims_today(wallet, now)

    window = timedelta(hours=cfg["WINDOW_HOURS"])
    next_claim_at = None
    seconds_remaining = 0
    can_claim = True
    reasons = []

    if today_count >= cfg["MAX_PER_DAY"]:
        can_claim = False
        reasons.append("daily_limit")
        # next reset at next UTC midnight
        _, day_end = _utc_day_bounds(now)
        next_claim_at = day_end
        seconds_remaining = int((day_end - now).total_seconds())
    elif state.last_claim_at is not None:
        next_claim_at = state.last_claim_at + window
        if now < next_claim_at:
            can_claim = False
            reasons.append("cooldown")
            seconds_remaining = int((next_claim_at - now).total_seconds())

    return {
        "cfg": cfg,
        "state": state,
        "can_claim": can_claim,
        "reasons": reasons,
        "next_claim_at": next_claim_at,
        "seconds_remaining": max(0, seconds_remaining),
        "claims_today": today_count,
    }


@claims_api.route("/api/claim-window/status", methods=["GET"])
def claim_window_status():
    wallet = _normalize_wallet(request.args.get("wallet"))
    if not _is_valid_wallet(wallet):
        return jsonify({"success": False, "message": "Valid wallet is required"}), 400
    if not _user_exists(wallet):
        return jsonify({"success": False, "message": "User not found. Please connect wallet first."}), 404

    now = datetime.utcnow()
    st = _compute_status(wallet, now)
    state: ClaimWindowState = st["state"]
    cfg = st["cfg"]

    return jsonify(
        {
            "success": True,
            "wallet": wallet,
            "can_claim": st["can_claim"],
            "reasons": st["reasons"],
            "window_hours": cfg["WINDOW_HOURS"],
            "reward_apro": cfg["REWARD_APRO"],
            "reward_points": cfg["REWARD_POINTS"],
            "max_per_day": cfg["MAX_PER_DAY"],
            "claims_today": st["claims_today"],
            "streak_days": int(state.streak_days or 0),
            "seconds_remaining": st["seconds_remaining"],
            "next_claim_at": st["next_claim_at"].isoformat() if st["next_claim_at"] else None,
            "last_claim_at": state.last_claim_at.isoformat() if state.last_claim_at else None,
        }
    )


@claims_api.route("/api/claim-window/claim", methods=["POST"])
def claim_window_claim():
    data = request.json or {}
    wallet = _normalize_wallet(data.get("wallet"))
    if not _is_valid_wallet(wallet):
        return jsonify({"success": False, "message": "Valid wallet is required"}), 400
    if not _user_exists(wallet):
        return jsonify({"success": False, "message": "User not found. Please connect wallet first."}), 404

    now = datetime.utcnow()
    st = _compute_status(wallet, now)
    cfg = st["cfg"]
    state: ClaimWindowState = st["state"]

    if not st["can_claim"]:
        return jsonify(
            {
                "success": False,
                "message": "Not ready yet",
                "reasons": st["reasons"],
                "seconds_remaining": st["seconds_remaining"],
                "next_claim_at": st["next_claim_at"].isoformat() if st["next_claim_at"] else None,
                "claims_today": st["claims_today"],
                "max_per_day": cfg["MAX_PER_DAY"],
                "streak_days": int(state.streak_days or 0),
            }
        ), 429

    # ---- streak update ----
    today = now.date().isoformat()
    yesterday = (now.date() - timedelta(days=1)).isoformat()
    streak = int(state.streak_days or 0)
    if state.last_claim_day == today:
        # same day claim (allowed via 6-hour windows) keeps streak unchanged
        pass
    elif state.last_claim_day == yesterday:
        streak += 1
    else:
        streak = 1

    # ---- rewards ----
    base_amount = float(cfg["REWARD_APRO"])
    bonus_amount = float(cfg["STREAK_BONUSES"].get(streak, 0))
    total_amount = base_amount + bonus_amount
    points = int(cfg["REWARD_POINTS"])

    # Persist
    state.last_claim_at = now
    state.last_claim_day = today
    state.streak_days = streak

    claim = ClaimWindowClaim(wallet=wallet, amount=total_amount, points=points, claimed_at=now)
    db.session.add(claim)
    db.session.commit()

    # Return updated totals (the frontend uses this to update the sticky balance fast)
    total_earned = (
        db.session.query(func.coalesce(func.sum(ClaimWindowClaim.amount), 0.0))
        .filter(ClaimWindowClaim.wallet == wallet)
        .scalar()
        or 0.0
    )

    next_claim_at = now + timedelta(hours=cfg["WINDOW_HOURS"])
    return jsonify(
        {
            "success": True,
            "message": "Claimed successfully",
            "claimed_amount": total_amount,
            "base_amount": base_amount,
            "bonus_amount": bonus_amount,
            "points": points,
            "streak_days": streak,
            "claims_today": _claims_today(wallet, now),
            "max_per_day": cfg["MAX_PER_DAY"],
            "next_claim_at": next_claim_at.isoformat(),
            "claim_window_earnings": float(total_earned),
        }
    )
