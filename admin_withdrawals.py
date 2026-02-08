"""Admin withdrawals dashboard + APIs."""

import os
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, session as flask_session, Response
from extensions import db
from sqlalchemy import text


def _admin_key() -> str:
    return os.getenv("ADMIN_API_KEY", "admin123")


admin_withdrawals = Blueprint("admin_withdrawals", __name__)


def _is_admin() -> bool:
    return bool(flask_session.get("is_admin"))


def _maybe_set_admin_from_key(key: str) -> bool:
    if key and str(key) == str(_admin_key()):
        flask_session["is_admin"] = True
        return True
    return _is_admin()


def _require_admin():
    if not _is_admin():
        return jsonify({"success": False, "error": "Admin access required"}), 403
    return None


@admin_withdrawals.get("/admin/withdrawals")
def admin_withdrawals_page():
    key = request.args.get("key")
    if key:
        _maybe_set_admin_from_key(key)
    if not _is_admin():
        return "Forbidden", 403
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

    res = db.session.execute(
        text("UPDATE withdrawal_requests SET status='paid', updated_at=:ts WHERE id=:id"),
        {"ts": datetime.utcnow(), "id": withdrawal_id},
    )
    db.session.commit()
    if res.rowcount == 0:
        return jsonify({"success": False, "error": "Not found"}), 404
    return jsonify({"success": True})


@admin_withdrawals.post("/api/admin/withdrawals/<int:withdrawal_id>/reject")
def api_admin_reject(withdrawal_id: int):
    err = _require_admin()
    if err:
        return err

    res = db.session.execute(
        text("UPDATE withdrawal_requests SET status='rejected', updated_at=:ts WHERE id=:id"),
        {"ts": datetime.utcnow(), "id": withdrawal_id},
    )
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
