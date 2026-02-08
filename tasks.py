"""User-facing task APIs.

Routes:
- GET  /api/tasks?wallet=0x...
- POST /api/tasks/submit

Assumptions:
- Users are identified by wallet address (users.wallet primary key).
- Proof is a URL.
- One submission per (wallet, task) enforced by unique constraint.
- Resubmission allowed only if status == declined; we overwrite the existing row.
"""

import re
from datetime import datetime

from flask import Blueprint, jsonify, request
from sqlalchemy import and_, text

from extensions import db
from models_tasks import (
    Task,
    TaskSubmission,
    TASK_STATUS_APPROVED,
    TASK_STATUS_DECLINED,
    TASK_STATUS_PENDING,
)


tasks_api = Blueprint("tasks_api", __name__)

_WALLET_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _norm_wallet(wallet: str) -> str:
    return (wallet or "").strip().lower()


def _is_valid_wallet(wallet: str) -> bool:
    return bool(_WALLET_RE.match(wallet or ""))

def _user_exists(wallet: str) -> bool:
    row = db.session.execute(text("SELECT 1 FROM users WHERE wallet = :w LIMIT 1"), {"w": wallet}).first()
    return row is not None


def _get_task_points(wallet: str) -> int:
    # Read task_points without importing User model to avoid circular imports.
    row = db.session.execute(
        text("SELECT task_points FROM users WHERE wallet = :w LIMIT 1"),
        {"w": wallet},
    ).first()
    if not row:
        return 0
    try:
        return int(row[0] or 0)
    except Exception:
        return 0


@tasks_api.get("/api/tasks")
def get_tasks():
    wallet = _norm_wallet(request.args.get("wallet", ""))
    if not _is_valid_wallet(wallet):
        return jsonify({"success": False, "error": "Invalid wallet address"}), 400

    if not _user_exists(wallet):
        # For the first app UX, the dashboard should only be accessible after wallet entry.
        # But we still keep this explicit.
        return jsonify({"success": False, "error": "User not found. Please login with your wallet."}), 404

    tasks = Task.query.order_by(Task.created_at.desc()).all()
    submissions = TaskSubmission.query.filter_by(user_wallet=wallet).all()
    sub_by_task = {s.task_id: s for s in submissions}

    # UX requirement:
    # - Once a task is approved, it should disappear from the main list.
    # - Approved items are still available in a compact archive.
    active_items = []
    completed_items = []

    for t in tasks:
        sub = sub_by_task.get(t.id)
        payload = {**t.to_dict(), "submission": sub.to_dict() if sub else None}

        if sub and sub.status == TASK_STATUS_APPROVED:
            completed_items.append(payload)
        else:
            active_items.append(payload)

    return jsonify(
        {
            "success": True,
            "wallet": wallet,
            "task_points": _get_task_points(wallet),
            # Backward compatible: keep `tasks` as the main list.
            "tasks": active_items,
            # New: compact archive data.
            "completed_tasks": completed_items,
        }
    )


@tasks_api.post("/api/tasks/submit")
def submit_task():
    data = request.get_json(silent=True) or {}
    wallet = _norm_wallet(data.get("wallet", ""))
    task_id = data.get("task_id")
    proof_url = (data.get("proof_url") or "").strip()

    if not _is_valid_wallet(wallet):
        return jsonify({"success": False, "error": "Invalid wallet address"}), 400
    if not isinstance(task_id, int):
        # Frontend should send int. We guard anyway.
        try:
            task_id = int(task_id)
        except Exception:
            return jsonify({"success": False, "error": "Invalid task_id"}), 400
    if not proof_url:
        return jsonify({"success": False, "error": "proof_url is required"}), 400

    if not _user_exists(wallet):
        return jsonify({"success": False, "error": "User not found. Please login with your wallet."}), 404

    task = Task.query.get(task_id)
    if not task or not task.is_active:
        return jsonify({"success": False, "error": "Task not found or inactive"}), 404

    submission = TaskSubmission.query.filter(
        and_(TaskSubmission.user_wallet == wallet, TaskSubmission.task_id == task_id)
    ).one_or_none()

    if submission:
        if submission.status != TASK_STATUS_DECLINED:
            return jsonify(
                {
                    "success": False,
                    "error": "You already submitted this task. Only declined submissions can be resubmitted.",
                    "status": submission.status,
                }
            ), 400

        # Overwrite declined submission (locked spec)
        submission.proof_url = proof_url
        submission.status = TASK_STATUS_PENDING
        submission.review_note = None
        submission.submitted_at = datetime.utcnow()
        submission.reviewed_at = None
    else:
        submission = TaskSubmission(
            user_wallet=wallet,
            task_id=task_id,
            proof_url=proof_url,
            status=TASK_STATUS_PENDING,
        )
        db.session.add(submission)

    db.session.commit()

    return jsonify({"success": True, "submission": submission.to_dict()})
