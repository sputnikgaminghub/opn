from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import os
import secrets

from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, abort

from eth_account import Account
from eth_account.messages import encode_defunct

from extensions import db
from models_staking import (
    StakingNonce, StakingBalance, StakingDeposit, StakingWithdrawal,
    STAKE_CHAIN_ETH, STAKE_CHAIN_BSC,
    STAKE_WDRAW_SUBMITTED, STAKE_WDRAW_APPROVED,
    STAKE_WDRAW_EARNED, STAKE_WDRAW_PRINCIPAL_ETH, STAKE_WDRAW_PRINCIPAL_BNB,
    STAKE_DEPOSIT_PENDING
)

# ---- Config ----
NONCE_TTL_MINUTES = 10

HOLDING_WALLET_ETH = os.getenv("STAKE_HOLDING_WALLET_ETH", "0xa84e6D0Fa3B35b18FF7C65568C711A85Ac1A9FC7")
HOLDING_WALLET_BSC = os.getenv("STAKE_HOLDING_WALLET_BSC", "0xa84e6D0Fa3B35b18FF7C65568C711A85Ac1A9FC7")

ETH_CHAIN_ID = int(os.getenv("STAKE_ETH_CHAIN_ID", os.getenv("ETH_CHAIN_ID", "1")))
BSC_CHAIN_ID = int(os.getenv("STAKE_BSC_CHAIN_ID", os.getenv("BSC_CHAIN_ID", "56")))

ADMIN_GATE_KEY = os.getenv("STAKE_ADMIN_GATE_KEY", "admin123")
ADMIN_PASSWORD = os.getenv("STAKE_ADMIN_PASSWORD", os.getenv("ADMIN_PASSWORD", os.getenv("ADMIN_API_KEY", "CHANGE_ME")))

CONFIRMATIONS_ETH = int(os.getenv("STAKE_ETH_CONFIRMATIONS", "12"))
CONFIRMATIONS_BSC = int(os.getenv("STAKE_BSC_CONFIRMATIONS", "15"))

REWARD_PER_BNB = Decimal(os.getenv("STAKE_REWARD_PER_BNB_PER_DAY", "50"))
REWARD_PER_ETH = Decimal(os.getenv("STAKE_REWARD_PER_ETH_PER_DAY", "200"))

staking_bp = Blueprint("staking", __name__, template_folder="templates")

def _normalize(a: str) -> str:
    return (a or "").strip().lower()

def _get_user_model():
    # Avoid importing the running module as 'app' when executed as a script (python app.py),
    # which can cause the User model/table to be defined twice (module '__main__' vs 'app').
    try:
        reg = getattr(db.Model, "registry", None)
        if reg and hasattr(reg, "_class_registry"):
            cls = reg._class_registry.get("User")
            if cls is not None:
                return cls
    except Exception:
        pass
    # Fallback (should be safe when running via WSGI / module import)
    from app import User  # noqa
    return User


def _ensure_user(wallet: str):
    # Leverage existing users table used across the site.
    User = _get_user_model()
    wallet = _normalize(wallet)
    u = User.query.get(wallet)
    if not u:
        # Create minimal user record compatible with existing schema.
        referral_code = secrets.token_hex(5)
        u = User(wallet=wallet, referral_code=referral_code, created_at=datetime.utcnow(), last_active=datetime.utcnow())
        db.session.add(u)
        db.session.commit()
    bal = StakingBalance.query.get(wallet)
    if not bal:
        bal = StakingBalance(wallet=wallet, principal_eth=Decimal("0"), principal_bnb=Decimal("0"), earned_tokens=Decimal("0"), updated_at=datetime.utcnow())
        db.session.add(bal)
        db.session.commit()
    return u, bal

def _stake_wallet() -> str | None:
    return session.get("stake_wallet")

def _require_stake_login() -> str:
    w = _stake_wallet()
    if not w:
        abort(401)
    return w

def _tokens_per_day(bal: StakingBalance) -> Decimal:
    pe = Decimal(bal.principal_eth or 0)
    pb = Decimal(bal.principal_bnb or 0)
    return (pb * REWARD_PER_BNB) + (pe * REWARD_PER_ETH)

@staking_bp.get("/stake")
def stake_home():
    return render_template(
        "stake/index.html",
        title="Staking",
        meta_title="Stake ETH/BNB • Earn daily rewards",
        meta_description="Deposit ETH or BNB to our holding wallet, earn tokens daily, and request withdrawals manually.",
        wallet=_stake_wallet(),
        holding_eth=HOLDING_WALLET_ETH,
        holding_bsc=HOLDING_WALLET_BSC,
        eth_chain_id=ETH_CHAIN_ID,
        bsc_chain_id=BSC_CHAIN_ID,
    )

@staking_bp.get("/stake/dashboard")
def stake_dashboard():
    w = _stake_wallet()
    if not w:
        return redirect(url_for("staking.stake_home"))
    _ensure_user(w)
    bal = StakingBalance.query.get(_normalize(w))
    deposits = StakingDeposit.query.filter_by(wallet=_normalize(w)).order_by(StakingDeposit.created_at.desc()).limit(50).all()
    pending = (
        StakingWithdrawal.query.filter(
            StakingWithdrawal.wallet == _normalize(w),
            StakingWithdrawal.status.in_([STAKE_WDRAW_SUBMITTED, STAKE_WDRAW_APPROVED]),
        )
        .order_by(StakingWithdrawal.created_at.desc())
        .first()
    )
    return render_template(
        "stake/dashboard.html",
        title="Staking Dashboard",
        wallet=_stake_wallet(),
        holding_eth=HOLDING_WALLET_ETH,
        holding_bsc=HOLDING_WALLET_BSC,
        eth_chain_id=ETH_CHAIN_ID,
        bsc_chain_id=BSC_CHAIN_ID,
        balance=bal,
        tokens_per_day=_tokens_per_day(bal),
        deposits=deposits,
        pending_withdrawal=pending,
        reward_per_eth=REWARD_PER_ETH,
        reward_per_bnb=REWARD_PER_BNB,
    )

# ---------- Signature login (nonce + verify) ----------
@staking_bp.post("/api/stake/nonce")
def stake_nonce():
    try:
        data = request.get_json(silent=True) or {}
        wallet = _normalize(data.get("wallet"))
        if not wallet.startswith("0x") or len(wallet) != 42:
            return jsonify({"ok": False, "error": "Invalid wallet"}), 400
        nonce = secrets.token_hex(16)
        expires_at = datetime.utcnow() + timedelta(minutes=NONCE_TTL_MINUTES)
        db.session.add(StakingNonce(wallet=wallet, nonce=nonce, expires_at=expires_at, used=0))
        db.session.commit()
        return jsonify({"ok": True, "nonce": nonce})
    except Exception:
        try:
            import flask
            flask.current_app.logger.exception("Stake nonce failed")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "Internal server error"}), 500
@staking_bp.post("/api/stake/verify")
def stake_verify():
    """Verify signature login and establish a staking session.

    Important: Always returns JSON (never HTML), so the frontend can safely parse the response.
    """
    try:
        data = request.get_json(silent=True) or {}
        wallet = _normalize(data.get("wallet"))
        signature = data.get("signature") or ""
        nonce = data.get("nonce") or ""

        if not wallet.startswith("0x") or len(wallet) != 42:
            return jsonify({"ok": False, "error": "Invalid wallet"}), 400
        if not signature or not nonce:
            return jsonify({"ok": False, "error": "Missing signature or nonce"}), 400

        ln = (
            StakingNonce.query.filter_by(wallet=wallet, nonce=nonce, used=0)
            .order_by(StakingNonce.created_at.desc())
            .first()
        )
        if not ln or ln.expires_at < datetime.utcnow():
            return jsonify({"ok": False, "error": "Nonce expired"}), 400

        msg = encode_defunct(text=f"Login nonce: {nonce}")
        try:
            recovered = Account.recover_message(msg, signature=signature)
        except Exception:
            return jsonify({"ok": False, "error": "Bad signature"}), 400

        if _normalize(recovered) != wallet:
            return jsonify({"ok": False, "error": "Signature does not match wallet"}), 400

        ln.used = 1
        db.session.add(ln)
        db.session.commit()

        _ensure_user(wallet)

        # Requires SECRET_KEY to be set on the Flask app.
        session["stake_wallet"] = wallet

        return jsonify({"ok": True})

    except Exception:
        # Prevent Flask from returning an HTML 500 page (breaks frontend JSON parsing)
        try:
            import flask
            flask.current_app.logger.exception("Stake verify failed")
        except Exception:
            pass
        return jsonify({"ok": False, "error": "Internal server error"}), 500
@staking_bp.post("/api/stake/logout")
def stake_logout():
    session.pop("stake_wallet", None)
    return jsonify({"ok": True})

# ---------- Deposit announce ----------
@staking_bp.post("/api/stake/deposits/announce")
def stake_announce_deposit():
    try:
            w = _require_stake_login()
            data = request.get_json(silent=True) or {}
            tx_hash = (data.get("tx_hash") or "").strip()
            chain = (data.get("chain") or "").upper()
            asset = (data.get("asset") or "").upper()

            if not (tx_hash.startswith("0x") and len(tx_hash) >= 10):
                return jsonify({"ok": False, "error": "Invalid tx hash"}), 400
            if chain not in [STAKE_CHAIN_ETH, STAKE_CHAIN_BSC]:
                return jsonify({"ok": False, "error": "Invalid chain"}), 400
            if asset not in ["ETH", "BNB"]:
                return jsonify({"ok": False, "error": "Invalid asset"}), 400

            if StakingDeposit.query.filter_by(tx_hash=tx_hash).first():
                return jsonify({"ok": True})

            to_addr = HOLDING_WALLET_ETH if chain == STAKE_CHAIN_ETH else HOLDING_WALLET_BSC

            dep = StakingDeposit(
                wallet=_normalize(w),
                chain=chain,
                asset=asset,
                tx_hash=tx_hash,
                from_address=_normalize(w),
                to_address=_normalize(to_addr),
                amount=Decimal("0"),
                block_number=0,
                confirmations=0,
                status=STAKE_DEPOSIT_PENDING,
                created_at=datetime.utcnow(),
            )
            db.session.add(dep)
            db.session.commit()
            return jsonify({"ok": True})

        # ---------- Withdrawal submit (manual processing) ----------
    except Exception:
        try:
            import flask
            flask.current_app.logger.exception('Stake stake_announce_deposit failed')
        except Exception:
            pass
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@staking_bp.post("/api/stake/withdrawals/submit")
def stake_submit_withdrawal():
    try:
            w = _require_stake_login()
            data = request.get_json(silent=True) or {}

            wtype = (data.get("type") or "").upper()
            amount_s = str(data.get("amount") or "").strip()
            dest = _normalize(data.get("destination_address") or "")

            if wtype not in [STAKE_WDRAW_EARNED, STAKE_WDRAW_PRINCIPAL_ETH, STAKE_WDRAW_PRINCIPAL_BNB]:
                return jsonify({"ok": False, "error": "Invalid withdrawal type"}), 400
            if not (dest.startswith("0x") and len(dest) == 42):
                return jsonify({"ok": False, "error": "Invalid destination address"}), 400
            try:
                amt = Decimal(amount_s)
            except InvalidOperation:
                return jsonify({"ok": False, "error": "Invalid amount"}), 400
            if amt <= 0:
                return jsonify({"ok": False, "error": "Amount must be > 0"}), 400

            pending = StakingWithdrawal.query.filter(
                StakingWithdrawal.wallet == _normalize(w),
                StakingWithdrawal.status.in_([STAKE_WDRAW_SUBMITTED, STAKE_WDRAW_APPROVED]),
            ).first()
            if pending:
                return jsonify({"ok": False, "error": "You already have a pending withdrawal request."}), 400

            _ensure_user(w)
            bal = StakingBalance.query.get(_normalize(w))

            pe = Decimal(bal.principal_eth or 0)
            pb = Decimal(bal.principal_bnb or 0)
            et = Decimal(bal.earned_tokens or 0)

            if wtype == STAKE_WDRAW_EARNED and amt > et:
                return jsonify({"ok": False, "error": "Insufficient earned tokens"}), 400
            if wtype == STAKE_WDRAW_PRINCIPAL_ETH and amt > pe:
                return jsonify({"ok": False, "error": "Insufficient ETH principal"}), 400
            if wtype == STAKE_WDRAW_PRINCIPAL_BNB and amt > pb:
                return jsonify({"ok": False, "error": "Insufficient BNB principal"}), 400

            wr = StakingWithdrawal(
                wallet=_normalize(w),
                type=wtype,
                amount=amt,
                destination_address=dest,
                status=STAKE_WDRAW_SUBMITTED,
                admin_note="",
                payout_tx_hash="",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.session.add(wr)
            db.session.commit()
            return jsonify({"ok": True})

        # ---------- Admin gate + panel ----------
    except Exception:
        try:
            import flask
            flask.current_app.logger.exception('Stake stake_submit_withdrawal failed')
        except Exception:
            pass
        return jsonify({'ok': False, 'error': 'Internal server error'}), 500

@staking_bp.get("/admin/stake")
def stake_admin_gate():
    key = request.args.get("key","")
    if key != ADMIN_GATE_KEY:
        abort(404)
    session["stake_admin_gate"] = True
    return redirect(url_for("staking.stake_admin_login"))

@staking_bp.get("/admin/staking/login")
def stake_admin_login():
    if not session.get("stake_admin_gate"):
        abort(404)
    return render_template("stake/admin_login.html", title="Staking Admin Login")

@staking_bp.post("/admin/staking/login")
def stake_admin_login_post():
    if not session.get("stake_admin_gate"):
        abort(404)
    pw = request.form.get("password","")
    if pw != ADMIN_PASSWORD:
        return redirect(url_for("staking.stake_admin_login", err=1))
    session["stake_is_admin"] = True
    return redirect(url_for("staking.stake_admin_withdrawals"))

@staking_bp.post("/admin/staking/logout")
def stake_admin_logout():
    session.pop("stake_is_admin", None)
    session.pop("stake_admin_gate", None)
    return redirect(url_for("staking.stake_home"))

def _require_admin():
    if not session.get("stake_is_admin"):
        abort(404)

@staking_bp.get("/admin/staking/withdrawals")
def stake_admin_withdrawals():
    _require_admin()
    items = StakingWithdrawal.query.order_by(StakingWithdrawal.created_at.desc()).limit(300).all()
    return render_template("stake/admin_withdrawals.html", title="Staking Withdrawals", items=items)

def _update_withdrawal(wid: int, status: str, note: str = "", payout_tx: str = ""):
    wr = StakingWithdrawal.query.get(wid)
    if not wr:
        return
    wr.status = status
    wr.admin_note = note or ""
    wr.payout_tx_hash = payout_tx or ""
    wr.updated_at = datetime.utcnow()
    db.session.add(wr)

    if status == "paid":
        bal = StakingBalance.query.get(wr.wallet)
        amt = Decimal(wr.amount)
        if wr.type == STAKE_WDRAW_EARNED:
            bal.earned_tokens = Decimal(bal.earned_tokens or 0) - amt
        elif wr.type == STAKE_WDRAW_PRINCIPAL_ETH:
            bal.principal_eth = Decimal(bal.principal_eth or 0) - amt
        elif wr.type == STAKE_WDRAW_PRINCIPAL_BNB:
            bal.principal_bnb = Decimal(bal.principal_bnb or 0) - amt
        bal.updated_at = datetime.utcnow()
        db.session.add(bal)

    db.session.commit()

@staking_bp.post("/admin/staking/withdrawals/<int:wid>/approve")
def stake_admin_approve(wid: int):
    _require_admin()
    note = request.form.get("note","")
    _update_withdrawal(wid, "approved", note=note)
    return redirect(url_for("staking.stake_admin_withdrawals"))

@staking_bp.post("/admin/staking/withdrawals/<int:wid>/reject")
def stake_admin_reject(wid: int):
    _require_admin()
    note = request.form.get("note","")
    _update_withdrawal(wid, "rejected", note=note)
    return redirect(url_for("staking.stake_admin_withdrawals"))

@staking_bp.post("/admin/staking/withdrawals/<int:wid>/paid")
def stake_admin_paid(wid: int):
    _require_admin()
    payout_tx = request.form.get("payout_tx_hash","")
    note = request.form.get("note","")
    _update_withdrawal(wid, "paid", note=note, payout_tx=payout_tx)
    return redirect(url_for("staking.stake_admin_withdrawals"))
