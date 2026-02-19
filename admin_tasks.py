"""Admin task dashboard + admin APIs.

Admin access rules:
- Each dashboard has its own login endpoint and key (separate access for security).
- Tasks dashboard uses ADMIN_TASKS_KEY (fallback to ADMIN_API_KEY for backward compatibility).

We store an 'admin_tasks' flag in the flask session after key validation.

Routes:
- GET  /admin/tasks
- GET  /api/admin/tasks
- POST /api/admin/tasks
- PUT  /api/admin/tasks/<id>
- DELETE /api/admin/tasks/<id>
- GET  /api/admin/submissions
- POST /api/admin/submissions/<id>/approve
- POST /api/admin/submissions/<id>/decline
"""

import re
from datetime import datetime
import os

from flask import Blueprint, jsonify, render_template, request, session as flask_session, redirect, url_for
from extensions import db
from sqlalchemy import and_, text



def _admin_key() -> str:
    """Read the per-dashboard admin key from environment.

    Backward compatibility: if ADMIN_TASKS_KEY is not set, fall back to ADMIN_API_KEY.
    """
    return os.getenv("ADMIN_TASKS_KEY") or os.getenv("ADMIN_API_KEY", "admin123")


from models_tasks import (
    TASK_STATUS_APPROVED,
    TASK_STATUS_DECLINED,
    TASK_STATUS_PENDING,
    Task,
    TaskRewardTransaction,
    TaskSubmission,
)


admin_tasks = Blueprint("admin_tasks", __name__)

_WALLET_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def _is_admin() -> bool:
    return bool(flask_session.get("admin_tasks"))


def _require_admin():

    if not _is_admin():
        return jsonify({"success": False, "error": "Admin access required"}), 403
    return None



@admin_tasks.get("/admin/tasks/login")
def admin_tasks_login_page():
    if _is_admin():
        return redirect(url_for("admin_tasks.admin_tasks_page"))
    return render_template(
        "admin_section_login.html",
        section_title="Admin • Tasks",
        post_url=url_for("admin_tasks.admin_tasks_login"),
    )


@admin_tasks.post("/admin/tasks/login")
def admin_tasks_login():
    key = (request.form.get("key") or "").strip()
    if key and str(key) == str(_admin_key()):
        flask_session["admin_tasks"] = True
        return redirect(url_for("admin_tasks.admin_tasks_page"))
    return render_template(
        "admin_section_login.html",
        section_title="Admin • Tasks",
        post_url=url_for("admin_tasks.admin_tasks_login"),
        error="Invalid key",
    ), 403


@admin_tasks.post("/admin/tasks/logout")
def admin_tasks_logout():
    flask_session.pop("admin_tasks", None)
    return redirect(url_for("admin_tasks.admin_tasks_login_page"))


@admin_tasks.get("/admin/tasks")
def admin_tasks_page():
    if not _is_admin():
        return redirect(url_for("admin_tasks.admin_tasks_login_page"))
    return render_template("admin_tasks.html")


@admin_tasks.get("/api/admin/tasks")
def api_admin_list_tasks():
    err = _require_admin()
    if err:
        return err

    tasks = Task.query.order_by(Task.created_at.desc()).all()
    return jsonify({"success": True, "tasks": [t.to_dict() for t in tasks]})


@admin_tasks.post("/api/admin/tasks")
def api_admin_create_task():
    err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    description = (data.get("description") or "").strip()
    task_link = (data.get("task_link") or "").strip()
    reward = data.get("reward")
    is_active = bool(data.get("is_active", True))

    if not title or not description:
        return jsonify({"success": False, "error": "title and description are required"}), 400

    try:
        reward = int(reward)
    except Exception:
        return jsonify({"success": False, "error": "reward must be an integer"}), 400

    if reward < 0:
        return jsonify({"success": False, "error": "reward must be >= 0"}), 400

    task = Task(
        title=title,
        description=description,
        task_link=(task_link or None),
        reward=reward,
        is_active=is_active,
    )
    db.session.add(task)
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        # Return a useful error instead of a generic 500.
        return jsonify({"success": False, "error": f"Database error while creating task: {str(e)}"}), 500

    return jsonify({"success": True, "task": task.to_dict()})


@admin_tasks.put("/api/admin/tasks/<int:task_id>")
def api_admin_update_task(task_id: int):
    err = _require_admin()
    if err:
        return err

    task = Task.query.get(task_id)
    if not task:
        return jsonify({"success": False, "error": "Task not found"}), 404

    data = request.get_json(silent=True) or {}
    return _apply_task_update(task, data)


@admin_tasks.post("/api/admin/tasks/<int:task_id>")
def api_admin_update_task_post(task_id: int):
    """POST variant of update for hosts/proxies that mishandle PUT."""
    err = _require_admin()
    if err:
        return err

    task = Task.query.get(task_id)
    if not task:
        return jsonify({"success": False, "error": "Task not found"}), 404

    data = request.get_json(silent=True) or {}
    return _apply_task_update(task, data)


def _apply_task_update(task: Task, data: dict):
    """Apply validated updates to a task and commit."""

    if "title" in data:
        task.title = (data.get("title") or "").strip() or task.title
    if "description" in data:
        task.description = (data.get("description") or "").strip() or task.description
    if "reward" in data:
        reward_val = data.get("reward")
        if reward_val is None:
            return jsonify({"success": False, "error": "reward is required"}), 400
        try:
            task.reward = int(reward_val)
        except Exception:
            return jsonify({"success": False, "error": "reward must be an integer"}), 400

    # Allow updating task_link from the admin UI.
    if "task_link" in data:
        task_link = (data.get("task_link") or "").strip()
        task.task_link = task_link or None
    if "is_active" in data:
        task.is_active = bool(data.get("is_active"))

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": f"Database error while updating task: {str(e)}"}), 500

    return jsonify({"success": True, "task": task.to_dict()})


@admin_tasks.delete("/api/admin/tasks/<int:task_id>")
def api_admin_delete_task(task_id: int):
    err = _require_admin()
    if err:
        return err

    task = Task.query.get(task_id)
    if not task:
        return jsonify({"success": False, "error": "Task not found"}), 404

    db.session.delete(task)
    db.session.commit()
    return jsonify({"success": True})


@admin_tasks.get("/api/admin/submissions")
def api_admin_list_submissions():
    err = _require_admin()
    if err:
        return err

    status = (request.args.get("status") or "").strip().lower()
    wallet = (request.args.get("wallet") or "").strip().lower()
    task_id = request.args.get("task_id")

    q = TaskSubmission.query

    if status in {TASK_STATUS_PENDING, TASK_STATUS_APPROVED, TASK_STATUS_DECLINED}:
        q = q.filter(TaskSubmission.status == status)

    if wallet:
        if not _WALLET_RE.match(wallet):
            return jsonify({"success": False, "error": "Invalid wallet"}), 400
        q = q.filter(TaskSubmission.user_wallet == wallet)

    if task_id:
        try:
            task_id = int(task_id)
            q = q.filter(TaskSubmission.task_id == task_id)
        except Exception:
            return jsonify({"success": False, "error": "Invalid task_id"}), 400

    subs = q.order_by(TaskSubmission.submitted_at.desc()).limit(500).all()

    # Attach task title and reward to help admin UI.
    task_ids = {s.task_id for s in subs}
    tasks = Task.query.filter(Task.id.in_(task_ids)).all() if task_ids else []
    task_map = {t.id: t for t in tasks}

    out = []
    for s in subs:
        t = task_map.get(s.task_id)
        item = s.to_dict()
        if t:
            item["task"] = {"id": t.id, "title": t.title, "reward": t.reward, "is_active": t.is_active}
        out.append(item)

    return jsonify({"success": True, "submissions": out})


@admin_tasks.post("/api/admin/submissions/<int:submission_id>/approve")
def api_admin_approve_submission(submission_id: int):
    err = _require_admin()
    if err:
        return err

    submission = TaskSubmission.query.get(submission_id)
    if not submission:
        return jsonify({"success": False, "error": "Submission not found"}), 404

    if submission.status == TASK_STATUS_APPROVED:
        return jsonify({"success": False, "error": "Already approved"}), 400

    task = Task.query.get(submission.task_id)
    if not task:
        return jsonify({"success": False, "error": "Task not found"}), 404

    # Mark approved
    submission.status = TASK_STATUS_APPROVED
    submission.review_note = None
    submission.reviewed_at = datetime.utcnow()

    reward = int(task.reward or 0)
    if reward < 0:
        reward = 0

    # Audit ledger entry
    ledger = TaskRewardTransaction(user_wallet=submission.user_wallet, task_id=task.id, amount=reward)
    db.session.add(ledger)

    # Increment task_points without importing User to avoid circular imports
    res = db.session.execute(
        text("UPDATE users SET task_points = COALESCE(task_points,0) + :amt WHERE wallet = :w"),
        {"amt": reward, "w": submission.user_wallet},
    )
    if res.rowcount == 0:
        db.session.rollback()
        return jsonify({"success": False, "error": "User not found"}), 404

    # Fetch updated points for response
    row = db.session.execute(
        text("SELECT COALESCE(task_points,0) FROM users WHERE wallet = :w"),
        {"w": submission.user_wallet},
    ).first()
    task_points = int(row[0]) if row else 0

    db.session.commit()
    return jsonify({"success": True, "submission": submission.to_dict(), "task_points": task_points})
@admin_tasks.post("/api/admin/submissions/<int:submission_id>/decline")
def api_admin_decline_submission(submission_id: int):
    err = _require_admin()
    if err:
        return err

    submission = TaskSubmission.query.get(submission_id)
    if not submission:
        return jsonify({"success": False, "error": "Submission not found"}), 404

    data = request.get_json(silent=True) or {}
    note = (data.get("review_note") or "").strip() or None

    submission.status = TASK_STATUS_DECLINED
    submission.review_note = note
    submission.reviewed_at = datetime.utcnow()

    db.session.commit()

    return jsonify({"success": True, "submission": submission.to_dict()})
