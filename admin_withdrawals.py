"""Admin withdrawals dashboard + APIs."""

import os
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, session as flask_session, Response, redirect, url_for
from extensions import db
from sqlalchemy import text




def _admin_key() -> str:
    """Per-dashboard key for Withdrawals.

    Backward compatibility: if ADMIN_WITHDRAWALS_KEY is not set, fall back to ADMIN_API_KEY.
    """
    return os.getenv("ADMIN_WITHDRAWALS_KEY") or os.getenv("ADMIN_API_KEY", "admin123")


admin_withdrawals = Blueprint("admin_withdrawals", __name__)


def _is_admin() -> bool:
    return bool(flask_session.get("admin_withdrawals"))


def _require_admin():
    if not _is_admin():
        return jsonify({"success": False, "error": "Admin access required"}), 403
    return None


@admin_withdrawals.get("/admin/withdrawals/login")
def admin_withdrawals_login_page():
    if _is_admin():
        return redirect(url_for("admin_withdrawals.admin_withdrawals_page"))
    return render_template(
        "admin_section_login.html",
        section_title="Admin • Withdrawals",
        post_url=url_for("admin_withdrawals.admin_withdrawals_login"),
    )


@admin_withdrawals.post("/admin/withdrawals/login")
def admin_withdrawals_login():
    key = (request.form.get("key") or "").strip()
    if key and str(key) == str(_admin_key()):
        flask_session["admin_withdrawals"] = True
        return redirect(url_for("admin_withdrawals.admin_withdrawals_page"))
    return render_template(
        "admin_section_login.html",
        section_title="Admin • Withdrawals",
        post_url=url_for("admin_withdrawals.admin_withdrawals_login"),
        error="Invalid key",
    ), 403


@admin_withdrawals.post("/admin/withdrawals/logout")
def admin_withdrawals_logout():
    flask_session.pop("admin_withdrawals", None)
    return redirect(url_for("admin_withdrawals.admin_withdrawals_login_page"))


@admin_withdrawals.get("/admin/withdrawals")
def admin_withdrawals_page():
    if not _is_admin():
        return redirect(url_for("admin_withdrawals.admin_withdrawals_login_page"))
    return render_template("admin_withdrawals.html")


@admin_withdrawals.get("/api/admin/withdrawals")
def api_admin_list_withdrawals():
    err = _require_admin()
    if err:
        return err

    status = (request.args.get("status") or "").strip().lower()
    wallet = (request.args.get("wallet") or "").strip().lower()
    chain = (request.args.get("chain") or "").strip().lower()

    where = []
    params = {}
    if status in {"queued", "paid", "rejected"}:
        where.append("status = :status")
        params["status"] = status
    if chain in {"eth", "bsc"}:
        where.append("chain = :chain")
        params["chain"] = chain
    if wallet:
        where.append("wallet = :wallet")
        params["wallet"] = wallet

    sql = "SELECT id, wallet, amount, chain, fee_tx_hash, fee_from, fee_to, fee_value_wei, fee_confirmations, status, created_at, updated_at FROM withdrawal_requests"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT 500"

    rows = db.session.execute(text(sql), params).mappings().all()
    out = []
    for r in rows:
        created_at = r.get("created_at")
        updated_at = r.get("updated_at")
        out.append({
            "id": r.get("id"),
            "wallet": r.get("wallet"),
            "amount": r.get("amount"),
            "chain": r.get("chain"),
            "fee_tx_hash": r.get("fee_tx_hash"),
            "fee_from": r.get("fee_from"),
            "fee_to": r.get("fee_to"),
            "fee_value_wei": r.get("fee_value_wei"),
            "fee_confirmations": r.get("fee_confirmations"),
            "status": r.get("status"),
            "created_at": (created_at.isoformat() if hasattr(created_at, "isoformat") else (str(created_at) if created_at else None)),
            "updated_at": (updated_at.isoformat() if hasattr(updated_at, "isoformat") else (str(updated_at) if updated_at else None)),
        })

    return jsonify({"success": True, "withdrawals": out})


@admin_withdrawals.post("/api/admin/withdrawals/<int:withdrawal_id>/mark-paid")
def api_admin_mark_paid(withdrawal_id: int):
    err = _require_admin()
    if err:
        return err

    ts = datetime.utcnow()
    row = db.session.execute(
        text("SELECT wallet, amount, chain FROM withdrawal_requests WHERE id=:id"),
        {"id": withdrawal_id},
    ).mappings().first()
    if not row:
        return jsonify({"success": False, "error": "Not found"}), 404

    res = db.session.execute(
        text("UPDATE withdrawal_requests SET status='paid', updated_at=:ts WHERE id=:id"),
        {"ts": ts, "id": withdrawal_id},
    )

    # Best-effort: append to activity logs (safe to ignore if table isn't present).
    try:
        db.session.execute(
            text(
                "INSERT INTO activity_logs (wallet, type, message, metadata_json, created_at) "
                "VALUES (:wallet, :type, :message, :metadata_json, :created_at)"
            ),
            {
                "wallet": (row.get("wallet") or "").lower(),
                "type": "withdrawal_paid",
                "message": f"Withdrawal marked paid ({row.get('amount')} OPN)",
                "metadata_json": None,
                "created_at": ts,
            },
        )
    except Exception:
        pass

    db.session.commit()
    if res.rowcount == 0:
        return jsonify({"success": False, "error": "Not found"}), 404
    return jsonify({"success": True})


@admin_withdrawals.post("/api/admin/withdrawals/<int:withdrawal_id>/reject")
def api_admin_reject(withdrawal_id: int):
    err = _require_admin()
    if err:
        return err

    ts = datetime.utcnow()
    row = db.session.execute(
        text("SELECT wallet, amount, chain FROM withdrawal_requests WHERE id=:id"),
        {"id": withdrawal_id},
    ).mappings().first()
    if not row:
        return jsonify({"success": False, "error": "Not found"}), 404

    res = db.session.execute(
        text("UPDATE withdrawal_requests SET status='rejected', updated_at=:ts WHERE id=:id"),
        {"ts": ts, "id": withdrawal_id},
    )

    try:
        db.session.execute(
            text(
                "INSERT INTO activity_logs (wallet, type, message, metadata_json, created_at) "
                "VALUES (:wallet, :type, :message, :metadata_json, :created_at)"
            ),
            {
                "wallet": (row.get("wallet") or "").lower(),
                "type": "withdrawal_rejected",
                "message": f"Withdrawal rejected ({row.get('amount')} OPN)",
                "metadata_json": None,
                "created_at": ts,
            },
        )
    except Exception:
        pass

    db.session.commit()
    if res.rowcount == 0:
        return jsonify({"success": False, "error": "Not found"}), 404
    return jsonify({"success": True})


@admin_withdrawals.get("/api/admin/withdrawals/export.csv")
def api_admin_export_csv():
    err = _require_admin()
    if err:
        return err

    rows = db.session.execute(
        text(
            "SELECT id, wallet, amount, chain, fee_tx_hash, fee_value_wei, fee_confirmations, status, created_at, updated_at "
            "FROM withdrawal_requests ORDER BY created_at DESC LIMIT 5000"
        )
    ).mappings().all()

    lines = ["id,wallet,amount,chain,fee_tx_hash,fee_value_wei,fee_confirmations,status,created_at,updated_at"]
    for r in rows:
        ca = r.get('created_at')
        ua = r.get('updated_at')
        ca_s = ca.isoformat() if hasattr(ca, 'isoformat') else (str(ca) if ca else '')
        ua_s = ua.isoformat() if hasattr(ua, 'isoformat') else (str(ua) if ua else '')
        lines.append(
            f"{r.get('id')},{r.get('wallet')},{r.get('amount')},{r.get('chain')},{r.get('fee_tx_hash')},{r.get('fee_value_wei')},{r.get('fee_confirmations')},{r.get('status')},{ca_s},{ua_s}"
        )
    return Response("\n".join(lines), mimetype="text/csv")
