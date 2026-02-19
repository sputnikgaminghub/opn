from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify, render_template, session as flask_session, redirect, url_for, make_response
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Float, DateTime, Date, Boolean, Text, Index, func, distinct, text
from datetime import datetime, timedelta
import hashlib
import secrets
import random
import os
import redis
import json
import time
from dotenv import load_dotenv
from flask_limiter import Limiter
from werkzeug.middleware.proxy_fix import ProxyFix
try:
    from flask_compress import Compress
except Exception:
    Compress = None

from urllib import request as urlrequest
from urllib.error import URLError


# -------------------------------
# Simple JSON-RPC helper (no web3.py)
# -------------------------------
def _rpc_post(url: str, method: str, params=None, timeout=12):
    params = params or []
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode("utf-8")
    req = urlrequest.Request(url, data=payload, headers={"Content-Type":"application/json"})
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if "error" in data:
        raise RuntimeError(data["error"])
    return data.get("result")

def _hex_to_int(x):
    if x is None:
        return 0
    return int(x, 16)

def _normalize_addr(a: str) -> str:
    return (a or "").lower()

def _decode_erc20_transfer_input(input_hex: str):
    # transfer(address,uint256) method id: a9059cbb
    if not input_hex or not input_hex.startswith("0x"):
        return None
    h = input_hex[2:]
    if len(h) < 8 or h[:8].lower() != "a9059cbb":
        return None
    # next 32 bytes: recipient (right-most 20 bytes)
    if len(h) < 8 + 64 + 64:
        return None
    to_word = h[8:8+64]
    amt_word = h[8+64:8+64+64]
    to_addr = "0x" + to_word[-40:]
    amount = int(amt_word, 16)
    return {"to": _normalize_addr(to_addr), "amount": amount}

def verify_presale_tx(data: dict):
    """Best-effort verification. Returns (status, reason). status in {'confirmed','unverified','rejected'}."""
    tx_hash = data.get("tx_hash")
    network = (data.get("network") or "").lower()
    token = data.get("token")
    user_addr = _normalize_addr(data.get("user_address"))
    presale_wallet = _normalize_addr(os.getenv("PRESALE_WALLET", "0xa84e6D0Fa3B35b18FF7C65568C711A85Ac1A9FC7"))
    # RPC urls
    rpc = None
    if network in ["ethereum","eth"]:
        rpc = os.getenv("ETH_RPC_URL","")
    elif network in ["bsc","binance","bnb"]:
        rpc = os.getenv("BSC_RPC_URL","")
    if not rpc:
        return ("unverified", "RPC not configured")
    try:
        tx = _rpc_post(rpc, "eth_getTransactionByHash", [tx_hash])
        if not tx:
            return ("unverified", "Transaction not found yet")
        receipt = _rpc_post(rpc, "eth_getTransactionReceipt", [tx_hash])
        if not receipt or receipt.get("status") is None:
            return ("unverified", "Receipt not available yet")
        if _hex_to_int(receipt.get("status")) != 1:
            return ("rejected", "Transaction failed")
        tx_from = _normalize_addr(tx.get("from"))
        if user_addr and tx_from and user_addr != tx_from:
            return ("rejected", "Sender mismatch")
        tx_to = _normalize_addr(tx.get("to"))
        # Native payments
        if token in ["ETH","BNB"] and data.get("token_name","").lower() in ["ethereum","bnb","binance coin","binancecoin"]:
            if tx_to != presale_wallet:
                return ("rejected", "Recipient mismatch")
            # Do not enforce exact value match (price conversions may differ); require non-zero
            if _hex_to_int(tx.get("value")) <= 0:
                return ("rejected", "Zero value")
            return ("confirmed", "Verified native transfer")
        # USDT transfers
        if token in ["USDT_ERC20","USDT_BEP20"]:
            # tx_to should be contract
            usdt_contract = None
            if token == "USDT_ERC20":
                usdt_contract = _normalize_addr(os.getenv("USDT_ERC20_CONTRACT","0xdAC17F958D2ee523a2206206994597C13D831ec7"))
                decimals = 6
            else:
                usdt_contract = _normalize_addr(os.getenv("USDT_BEP20_CONTRACT","0x55d398326f99059fF775485246999027B3197955"))
                decimals = 18
            if tx_to != usdt_contract:
                return ("rejected", "USDT contract mismatch")
            decoded = _decode_erc20_transfer_input(tx.get("input",""))
            if not decoded:
                return ("rejected", "Not an ERC20 transfer()")
            if decoded["to"] != presale_wallet:
                return ("rejected", "Recipient mismatch")
            # compare amount (best effort)
            # submitted crypto_amount is string like '12.34'
            submitted = str(data.get("crypto_amount","")).strip()
            try:
                if submitted:
                    if "." in submitted:
                        whole, frac = submitted.split(".",1)
                        frac = (frac + "0"*decimals)[:decimals]
                        submitted_int = int(whole)* (10**decimals) + int(frac)
                    else:
                        submitted_int = int(submitted) * (10**decimals)
                    # allow small tolerance for formatting; exact match preferred
                    if abs(decoded["amount"] - submitted_int) > 0:
                        # tolerate if submitted empty; otherwise mismatch
                        return ("rejected", "Amount mismatch")
            except Exception:
                pass
            return ("confirmed", "Verified USDT transfer")
        # Unknown token: can't verify reliably
        return ("unverified", "Unsupported token verification")
    except Exception as e:
        return ("unverified", f"Verification error: {str(e)}")

# Import tasks module blueprints/models (split files).
# NOTE: These imports are placed later (after model declarations) to avoid circular imports.

# Load environment variables
load_dotenv()

# Use Flask-SQLAlchemy's default declarative base.
# This avoids edge-case mapper errors in some environments.
from extensions import db

app = Flask(__name__)

# --- Ensure SECRET_KEY for sessions (required by staking signature login) ---
secret_key = os.getenv('SECRET_KEY') or os.getenv('FLASK_SECRET_KEY')
if not secret_key:
    # Safe dev fallback to prevent 500s locally. Set SECRET_KEY on Render for production.
    secret_key = 'dev-secret-key-change-me'
app.config['SECRET_KEY'] = secret_key
app.secret_key = secret_key

# --- Session & cookie hardening ---
# Enforce a strong SECRET_KEY in production (do not allow dev fallbacks).
if (os.getenv("RENDER") or os.getenv("FLASK_ENV") == "production") and secret_key.startswith("dev-secret-key-change"):
    raise RuntimeError("SECRET_KEY must be set to a strong random value in production (Render/FLASK_ENV=production).")

# Cookie flags (Render serves over HTTPS).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
if os.getenv("RENDER") or os.getenv("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

# Session expiry controls
# NOTE: PERMANENT_SESSION_LIFETIME only applies when session.permanent=True (we set this in before_request).
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=int(os.getenv("SESSION_LIFETIME_HOURS", "1")))
app.config["SESSION_IDLE_TIMEOUT_MINUTES"] = int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "15"))


# Optional: server-side sessions (allows true revocation when using a shared store like Redis).
# Enable by setting USE_SERVER_SIDE_SESSIONS=1 and SESSION_REDIS_URL (or REDIS_URL).
if os.getenv("USE_SERVER_SIDE_SESSIONS", "0") == "1":
    try:
        from flask_session import Session  # type: ignore
        redis_url = os.getenv("SESSION_REDIS_URL") or os.getenv("REDIS_URL")
        if not redis_url:
            raise RuntimeError("USE_SERVER_SIDE_SESSIONS=1 but SESSION_REDIS_URL/REDIS_URL is not set")
        app.config["SESSION_TYPE"] = "redis"
        app.config["SESSION_REDIS"] = redis.from_url(redis_url)
        app.config["SESSION_USE_SIGNER"] = True
        app.config["SESSION_PERMANENT"] = True
        # Optional: keep server-side session objects from growing forever
        app.config["SESSION_KEY_PREFIX"] = os.getenv("SESSION_KEY_PREFIX", "opn:")
        Session(app)
    except Exception as e:
        # Fail closed in production if explicitly enabled but misconfigured.
        if os.getenv("RENDER") or os.getenv("FLASK_ENV") == "production":
            raise
        print(f"[warn] Server-side sessions not enabled: {e}")

# Static asset versioning (cache-busting)
app.config["STATIC_VER"] = os.getenv("STATIC_VER") or str(int(os.path.getmtime(__file__)))

# --- Feature flags (additive UX enhancements; safe to disable quickly) ---
FEATURE_NEXT_ACTION = (os.getenv("FEATURE_NEXT_ACTION", "1") == "1")
FEATURE_MILESTONES = (os.getenv("FEATURE_MILESTONES", "1") == "1")
FEATURE_TELEGRAM_CTA = (os.getenv("FEATURE_TELEGRAM_CTA", "1") == "1")


# -------------------------------
# Client IP resolution
# -------------------------------
# Render (and most PaaS) runs behind a reverse proxy. Without ProxyFix,
# request.remote_addr will often be the proxy IP, collapsing many users into one.
# We enable ProxyFix only in production/Render contexts.
if os.getenv("RENDER") or os.getenv("FLASK_ENV") == "production":
    # Trust a single proxy hop (Render's edge proxy)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
def get_client_ip() -> str:
    """Return the best-effort client IP.

    After ProxyFix, request.access_route[0] should be the real client IP.
    Falls back to request.remote_addr for local development.
    """
    try:
        if request.access_route:
            return request.access_route[0]
    except Exception:
        pass
    return request.remote_addr or "0.0.0.0"

_db_url = os.getenv("DATABASE_URL")
if not _db_url:
    if os.getenv("RENDER") == "true":
        raise RuntimeError("DATABASE_URL missing on Render; refusing to use SQLite.")
    _db_url = "sqlite:///airdrop.db"

if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize extensions
db.init_app(app)
CORS(app)

# Rate limiting
# Rate limiting
# - In production (Render), set RATE_LIMIT_STORAGE_URL to a Redis URL for multi-instance correctness.
# - Defaults to in-memory storage for simplicity.
limiter = Limiter(
    get_client_ip,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URL", "memory://"),
)


# -------------------------------
# Session lifetime + idle timeout enforcement
# -------------------------------
# Flask only applies PERMANENT_SESSION_LIFETIME when session.permanent=True.
# We set it automatically when the session contains auth-sensitive state.

def _session_has_auth() -> bool:
    if flask_session.get("stake_wallet"):
        return True
    # Admin sections use per-dashboard flags like admin_tasks/admin_withdrawals/...
    for k, v in list(flask_session.items()):
        if k.startswith("admin_") and v:
            return True
    # Back-compat legacy flag (should be removed over time)
    if flask_session.get("is_admin"):
        return True
    return False


@app.before_request
def _enforce_session_expiry_and_idle_timeout():
    if not _session_has_auth():
        return

    flask_session.permanent = True

    idle_minutes = int(app.config.get("SESSION_IDLE_TIMEOUT_MINUTES", 15))
    try:
        now_ts = int(time.time())
    except Exception:
        return

    last_seen = flask_session.get("_last_seen_ts")
    if isinstance(last_seen, int) and idle_minutes > 0:
        if now_ts - last_seen > idle_minutes * 60:
            # Idle timeout: clear all session state.
            flask_session.clear()
            return

    flask_session["_last_seen_ts"] = now_ts

# Make static version available in all templates
@app.context_processor
def inject_static_ver():
    return {"static_ver": app.config.get("STATIC_VER", "1")}

# Performance-minded headers (safe defaults)
@app.after_request
def add_perf_headers(resp):
    try:
        path = request.path or ""
        if path.startswith("/static/"):
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            # avoid caching dynamic pages by default (prevents user-specific caching issues)
            resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    except Exception:
        pass
    return resp


# -------------------------------
# Price feed (server-side cached)
# -------------------------------
# Avoids client-side CoinGecko 429 rate limits by caching responses.
_PRICE_CACHE = {
    "ts": 0.0,
    "data": {"ethereum": None, "binancecoin": None, "tether": 1.0, "solana": None},
    "error": None,
}

COINGECKO_SIMPLE_PRICE_URL = (
    "https://api.coingecko.com/api/v3/simple/price"
    "?ids=ethereum,binancecoin,tether,solana&vs_currencies=usd"
)

def _fetch_prices_from_coingecko(timeout=10):
    req = urlrequest.Request(
        COINGECKO_SIMPLE_PRICE_URL,
        headers={"Accept": "application/json", "User-Agent": "aprowith-presale/1.0"},
    )
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")
    data = json.loads(raw) if raw else {}
    return {
        "ethereum": (data.get("ethereum") or {}).get("usd"),
        "binancecoin": (data.get("binancecoin") or {}).get("usd"),
        "tether": (data.get("tether") or {}).get("usd") or 1.0,
        "solana": (data.get("solana") or {}).get("usd"),
    }

# Environment variables
ADMIN_WALLET = os.getenv('ADMIN_WALLET', '0x252cC763F8ae67500C96F0946aC4F64844c987B1')
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY', 'admin123')

# Separate per-dashboard admin keys (recommended). If not set, dashboards fall back to ADMIN_API_KEY.
ADMIN_TASKS_KEY = os.getenv('ADMIN_TASKS_KEY')
ADMIN_WITHDRAWALS_KEY = os.getenv('ADMIN_WITHDRAWALS_KEY')
ADMIN_ANNOUNCEMENTS_KEY = os.getenv('ADMIN_ANNOUNCEMENTS_KEY')
ADMIN_PRESALE_KEY = os.getenv('ADMIN_PRESALE_KEY')

MAX_WALLETS_PER_IP = int(os.getenv('MAX_WALLETS_PER_IP', 5))
IP_BAN_HOURS = int(os.getenv('IP_BAN_HOURS', 6))
PRESALE_WALLET = os.getenv('PRESALE_WALLET', '0xa84e6D0Fa3B35b18FF7C65568C711A85Ac1A9FC7')

# Withdrawal / fee validation
ETH_RPC_URL = os.getenv('ETH_RPC_URL', '').strip()
BSC_RPC_URL = os.getenv('BSC_RPC_URL', '').strip()

# Safe defaults (editable in DB config later)
WITHDRAWAL_OPEN_AT_DEFAULT = os.getenv('WITHDRAWAL_OPEN_AT', '2026-02-20T00:00:00Z')
WITHDRAWAL_FEE_WALLET_DEFAULT = os.getenv('WITHDRAWAL_FEE_WALLET', ADMIN_WALLET)
# 0.0050 ETH and 0.016 BNB
ETH_FEE_WEI_DEFAULT = os.getenv('WITHDRAWAL_ETH_FEE_WEI', '5000000000000000')
BSC_FEE_WEI_DEFAULT = os.getenv('WITHDRAWAL_BSC_FEE_WEI', '16000000000000000')
WITHDRAWAL_SUPPORT_URL_DEFAULT = os.getenv('WITHDRAWAL_SUPPORT_URL', 'https://t.me/opinion_labsxyz')

# Public community channel (for onboarding/CTAs). Kept separate from the support URL above.
TELEGRAM_CHANNEL_URL_DEFAULT = os.getenv('TELEGRAM_CHANNEL_URL', 'https://t.me/opinion_token')

# Achievement definitions
ACHIEVEMENTS = [
    {"id": "first_claim", "name": "Airdrop Pioneer", "icon": "🚀", "requirement": 0, "reward": 1},
    {"id": "first_ref", "name": "First Referral", "icon": "🥇", "requirement": 1, "reward": 11},
    {"id": "active_network", "name": "Network Builder", "icon": "🌐", "requirement": 3, "reward": 111},
    {"id": "five_ref", "name": "Referral Master", "icon": "🏆", "requirement": 5, "reward": 500},
    # Withdrawal eligibility is based on *direct* referrals (see _withdrawal_eligibility()).
    {"id": "withdrawal_ready", "name": "Ready to Cash Out", "icon": "💰", "requirement": 7, "reward": 1500}
]

# Welcome bonus (base rewards)
# New behavior: a per-wallet welcome bonus is assigned ONCE on the first
# /api/check-wallet ("Check eligibility") call, and is then reused everywhere
# (claim, balances, leaderboard, etc.) to prevent rerolls.
WELCOME_BONUS_MIN = int(os.getenv('WELCOME_BONUS_MIN', 100))
WELCOME_BONUS_MAX = int(os.getenv('WELCOME_BONUS_MAX', 1500))

# Tiered rarity distribution: higher ranges are progressively rarer.
# Probabilities should sum to 1.0 (fallback logic exists for rounding errors).
WELCOME_BONUS_TIERS = [
    (100, 300, 0.55),
    (301, 600, 0.25),
    (601, 900, 0.12),
    (901, 1200, 0.06),
    (1201, 1500, 0.02),
]

def generate_weighted_welcome_bonus() -> int:
    """Return an integer welcome bonus in [WELCOME_BONUS_MIN, WELCOME_BONUS_MAX].

    Distribution is skewed so higher rewards are rarer.
    """
    import random

    r = random.random()
    cumulative = 0.0
    for lo, hi, p in WELCOME_BONUS_TIERS:
        cumulative += float(p)
        if r < cumulative:
            return int(random.randint(int(lo), int(hi)))
    # Fallback (misconfigured tiers or floating error)
    return int(random.randint(int(WELCOME_BONUS_MIN), int(WELCOME_BONUS_MAX)))


def assign_welcome_bonus_if_needed(user: 'User') -> int:
    """Assign and persist a welcome bonus once per wallet.

    Rule: assign immediately on the first eligibility check ("Check eligibility"),
    and never reroll for the same wallet.
    """
    try:
        current = int(getattr(user, 'welcome_bonus', 0) or 0)
    except Exception:
        current = 0

    if current > 0:
        return current

    user.welcome_bonus = int(generate_weighted_welcome_bonus())
    user.welcome_bonus_assigned_at = datetime.utcnow()
    db.session.add(user)
    db.session.commit()
    return int(user.welcome_bonus)

# Database Models
class User(db.Model):
    __tablename__ = 'users'
    
    wallet = Column(String(42), primary_key=True, nullable=False)
    referral_code = Column(String(20), unique=True, nullable=False, index=True)
    referral_count = Column(Integer, default=0, nullable=False)
    link_clicks = Column(Integer, default=0, nullable=False)
    link_conversions = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    referrer = Column(String(42), nullable=True)
    active = Column(Boolean, default=False, nullable=False)
    ip_address = Column(String(45), nullable=True)
    last_active = Column(DateTime, default=datetime.utcnow, nullable=False)
    # Task system (ported from tasks.zip): separate from referrals/presale.
    task_points = Column(Integer, default=0, nullable=False)
    # Gamification: levels / streaks / rank (additive, safe defaults)
    level = Column(Integer, default=1, nullable=False)
    xp = Column(Integer, default=0, nullable=False)  # mirrors task_points by default, can diverge later
    streak_current = Column(Integer, default=0, nullable=False)
    streak_longest = Column(Integer, default=0, nullable=False)
    streak_last_date = Column(Date, nullable=True)
    rank_tier = Column(String(30), default='Rookie', nullable=False)

    # Welcome bonus (base rewards). Assigned ONCE on first eligibility check.
    # 0 means "not assigned yet".
    welcome_bonus = Column(Integer, default=0, nullable=False)
    welcome_bonus_assigned_at = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_referrer', 'referrer'),
        Index('idx_created_at', 'created_at'),
    )
    
    def to_dict(self):
        return {
            'wallet': self.wallet,
            'referral_code': self.referral_code,
            'referral_count': self.referral_count,
            'link_clicks': self.link_clicks,
            'link_conversions': self.link_conversions,
            'created_at': self.created_at.isoformat(),
            'referrer': self.referrer,
            'active': self.active,
            'ip_address': self.ip_address,
            'last_active': self.last_active.isoformat(),
            'task_points': self.task_points,
            'level': self.level,
            'xp': self.xp,
            'streak_current': self.streak_current,
            'streak_longest': self.streak_longest,
            'streak_last_date': self.streak_last_date.isoformat() if self.streak_last_date else None,
            'rank_tier': self.rank_tier
            ,
            'welcome_bonus': int(self.welcome_bonus or 0),
            'welcome_bonus_assigned_at': self.welcome_bonus_assigned_at.isoformat() if self.welcome_bonus_assigned_at else None
        }

class AirdropClaim(db.Model):
    __tablename__ = 'airdrop_claims'
    
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    # Token accounting is whole-number integer (avoid Float rounding drift).
    # NOTE: If you already have a DB with Float columns, you must migrate these columns.
    amount = Column(Integer, nullable=False)
    # Stored base amount used for this claim. Always set explicitly on insert.
    base_amount = Column(Integer, nullable=False, default=0)
    referral_bonus = Column(Integer, nullable=False, default=0)
    achievement_rewards = Column(Integer, nullable=False, default=0)
    referral_count = Column(Integer, nullable=False, default=0)
    referrer = Column(String(42), nullable=True)
    tx_hash = Column(String(128), unique=True, nullable=False)
    claimed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default='completed', nullable=False)
    
    __table_args__ = (
        Index('idx_claimed_at', 'claimed_at'),
        Index('idx_wallet_status', 'wallet', 'status'),
    )
    
    def to_dict(self):
        return {
            'amount': int(self.amount or 0),
            'base_amount': int(self.base_amount or 0),
            'referral_bonus': int(self.referral_bonus or 0),
            'achievement_rewards': int(self.achievement_rewards or 0),
            'referral_count': self.referral_count,
            'referrer': self.referrer,
            'tx_hash': self.tx_hash,
            'claimed_at': self.claimed_at.isoformat(),
            'status': self.status
        }

class Referral(db.Model):
    __tablename__ = 'referrals'
    
    id = Column(String(100), primary_key=True)
    referrer = Column(String(42), nullable=False, index=True)
    referee = Column(String(42), nullable=False, index=True)
    code_used = Column(String(20), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_referrer_timestamp', 'referrer', 'timestamp'),
        Index('idx_code_used', 'code_used'),
    )

class Achievement(db.Model):
    __tablename__ = 'achievements'
    
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    achievement_id = Column(String(50), nullable=False)
    unlocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index('idx_wallet_achievement', 'wallet', 'achievement_id', unique=True),
    )

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = Column(String(50), primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    type = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    read = Column(Boolean, default=False, nullable=False)
    
    __table_args__ = (
        Index('idx_wallet_read', 'wallet', 'read'),
        Index('idx_timestamp', 'timestamp'),
    )


class ActivityLog(db.Model):
    """Append-only activity stream used for the dashboard 'Recent activity' UI."""

    __tablename__ = 'activity_logs'

    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    type = Column(String(32), nullable=False)
    message = Column(Text, nullable=False)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index('idx_activity_wallet_created', 'wallet', 'created_at'),
        Index('idx_activity_created', 'created_at'),
    )

    def to_dict(self):
        md = None
        if self.metadata_json:
            try:
                md = json.loads(self.metadata_json)
            except Exception:
                md = None
        return {
            'id': self.id,
            'wallet': self.wallet,
            'type': self.type,
            'message': self.message,
            'metadata': md,
            'created_at': self.created_at.isoformat(),
        }


def _log_activity(wallet: str, event_type: str, message: str, metadata: dict | None = None):
    """Best-effort activity logger (never raises)."""
    try:
        w = (wallet or '').strip().lower()
        if not w:
            return
        md_json = None
        if metadata is not None:
            try:
                md_json = json.dumps(metadata, separators=(",", ":"), ensure_ascii=False)
            except Exception:
                md_json = None
        db.session.add(ActivityLog(
            wallet=w,
            type=(event_type or 'event')[:32],
            message=(message or '')[:500],
            metadata_json=md_json,
            created_at=datetime.utcnow(),
        ))
    except Exception:
        # Never break critical flows for analytics.
        return

class IPRestriction(db.Model):
    __tablename__ = 'ip_restrictions'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    wallet_count = Column(Integer, default=0, nullable=False)
    last_wallet_created = Column(DateTime, default=datetime.utcnow, nullable=False)
    banned_until = Column(DateTime, nullable=True)
    
    __table_args__ = (
        Index('idx_ip_banned', 'ip_address', 'banned_until'),
    )

class PresaleContribution(db.Model):
    __tablename__ = 'presale_contributions'
    
    id = Column(String(100), primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    amount_eth = Column(Float, nullable=False)
    amount_usd = Column(Float, nullable=False)
    tx_hash = Column(String(128), unique=True, nullable=False)
    chain_id = Column(Integer, nullable=False)
    contributed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    tokens_allocated = Column(Float, nullable=False, default=0.0)
    
    __table_args__ = (
        Index('idx_wallet_chain', 'wallet', 'chain_id'),
        Index('idx_contributed_at', 'contributed_at'),
    )

class WithdrawalAttempt(db.Model):
    __tablename__ = 'withdrawal_attempts'
    
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    referral_count = Column(Integer, nullable=False)
    eligible = Column(Boolean, nullable=False)
    attempted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default='checked', nullable=False)
    notes = Column(Text, nullable=True)
    
    __table_args__ = (
        Index('idx_wallet_attempted', 'wallet', 'attempted_at'),
        Index('idx_eligible_status', 'eligible', 'status'),
    )


class WithdrawalConfig(db.Model):
    """Singleton config row used for withdrawal feature flags/settings.

    We keep it in DB so the referral threshold and fee amounts can be edited later
    without code changes.
    """

    __tablename__ = 'withdrawal_config'

    id = Column(Integer, primary_key=True)  # always 1
    withdrawals_enabled = Column(Boolean, default=True, nullable=False)
    withdrawal_open_at = Column(DateTime, nullable=False)

    min_referrals_to_withdraw = Column(Integer, default=7, nullable=False)

    fee_wallet_address = Column(String(42), nullable=False)
    eth_fee_wei = Column(String(40), nullable=False)  # store as string to avoid int overflow edge cases
    bsc_fee_wei = Column(String(40), nullable=False)
    eth_min_confirmations = Column(Integer, default=8, nullable=False)
    bsc_min_confirmations = Column(Integer, default=15, nullable=False)

    support_url = Column(String(250), nullable=False, default='https://t.me/opinion_token')

    spam_ban_minutes = Column(Integer, default=60, nullable=False)
    max_invalid_attempts_per_hour = Column(Integer, default=10, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WithdrawalWalletGuard(db.Model):
    """Per-wallet guardrail for rate limiting + temporary bans."""

    __tablename__ = 'withdrawal_wallet_guard'

    wallet = Column(String(42), primary_key=True, nullable=False)
    invalid_attempts = Column(Integer, default=0, nullable=False)
    window_started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    banned_until = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class WithdrawalRequest(db.Model):
    __tablename__ = 'withdrawal_requests'

    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    amount = Column(Integer, nullable=False)  # whole number OPN
    chain = Column(String(10), nullable=False)  # 'eth' or 'bsc'

    fee_tx_hash = Column(String(128), unique=True, nullable=False)
    fee_from = Column(String(42), nullable=False)
    fee_to = Column(String(42), nullable=False)
    fee_value_wei = Column(String(40), nullable=False)
    fee_confirmations = Column(Integer, nullable=False, default=0)

    status = Column(String(20), nullable=False, default='queued')  # queued/paid/rejected
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index('idx_withdrawal_wallet_status', 'wallet', 'status'),
        Index('idx_withdrawal_created_at', 'created_at'),
    )

class PresaleTransaction(db.Model):
    __tablename__ = 'presale_transactions'
    
    id = Column(Integer, primary_key=True)
    user_address = Column(String(64), nullable=False, index=True)
    usd_amount = Column(Float, nullable=False)
    crypto_amount = Column(String(50), nullable=False)
    token = Column(String(20), nullable=False)
    token_name = Column(String(50), nullable=False)
    tx_hash = Column(String(128), unique=True, nullable=False, index=True)
    network = Column(String(20), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    
    __table_args__ = (
        Index('idx_tx_hash', 'tx_hash', unique=True),
        Index('idx_user_timestamp', 'user_address', 'timestamp'),
        Index('idx_network_status', 'network', 'status'),
    )
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_address': self.user_address,
            'usd_amount': self.usd_amount,
            'crypto_amount': self.crypto_amount,
            'token': self.token,
            'token_name': self.token_name,
            'tx_hash': self.tx_hash,
            'network': self.network,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status
        }



# Helper class
class AirdropSystem:
    @staticmethod
    def generate_referral_code(wallet_address):
        return f"REF-{hashlib.md5(wallet_address.encode()).hexdigest()[:8].upper()}"
    
    @staticmethod
    def calculate_airdrop_amount(base_amount: int, referral_count: int, achievement_rewards: int = 0) -> int:
        """Compute total claim amount (whole-number tokens)."""
        referral_bonus = int(referral_count or 0) * 121
        return int(base_amount or 0) + int(referral_bonus) + int(achievement_rewards or 0)
    
    @staticmethod
    def generate_tx_hash():
        return f"0x{secrets.token_hex(32)}"
    
    @staticmethod
    def generate_notification_id():
        return f"NOTIF_{secrets.token_hex(8)}"
    
    @staticmethod
    def generate_referral_id(referrer, referee):
        return f"{referrer}_{referee}"
    
    @staticmethod
    def validate_wallet_address(wallet_address):
        if not wallet_address:
            return False, "Wallet address is required"
        
        wallet = wallet_address.strip().lower()
        
        if not wallet.startswith('0x'):
            return False, "Wallet address must start with '0x'"
        
        if len(wallet) != 42:
            return False, "Wallet address must be 42 characters (including '0x')"
        
        hex_part = wallet[2:]
        if not all(c in '0123456789abcdef' for c in hex_part):
            return False, "Wallet address contains invalid characters"
        
        return True, wallet

# FIXED: Achievement calculation function
def check_and_award_achievements(wallet_address):
    user = User.query.get(wallet_address)
    if not user:
        return
    
    referral_count = user.referral_count
    
    current_achievements = Achievement.query.filter_by(wallet=wallet_address).all()
    current_achievement_ids = [a.achievement_id for a in current_achievements]
    
    for achievement in ACHIEVEMENTS:
        if achievement['id'] not in current_achievement_ids:
            should_award = False
            
            if achievement['id'] == 'first_claim':
                claim = AirdropClaim.query.filter_by(wallet=wallet_address).first()
                if claim:
                    should_award = True
            elif achievement['requirement'] <= referral_count:
                should_award = True
            
            if should_award:
                achievement_record = Achievement(
                    wallet=wallet_address,
                    achievement_id=achievement['id']
                )
                db.session.add(achievement_record)
                
                notification = Notification(
                    id=AirdropSystem.generate_notification_id(),
                    wallet=wallet_address,
                    type='achievement',
                    message=f'🏆 Achievement unlocked: {achievement["name"]}! +{achievement["reward"]} OPN',
                    timestamp=datetime.utcnow(),
                    read=False
                )
                db.session.add(notification)
    
    db.session.commit()

def calculate_achievement_rewards(wallet_address):
    user_achievements = Achievement.query.filter_by(wallet=wallet_address).all()
    achievement_ids = [a.achievement_id for a in user_achievements]
    
    achievement_rewards = 0
    for achievement in ACHIEVEMENTS:
        if achievement['id'] in achievement_ids:
            achievement_rewards += achievement['reward']
    
    return achievement_rewards


def calculate_claim_window_earnings(wallet_address: str) -> int:
    """Sum of all claim window rewards credited to a wallet (whole numbers)."""
    try:
        from models_claims import ClaimWindowClaim  # local import to avoid any circular edge cases

        total = (
            db.session.query(func.coalesce(func.sum(ClaimWindowClaim.amount), 0))
            .filter(ClaimWindowClaim.wallet == wallet_address)
            .scalar()
        )
        return int(total or 0)
    except Exception:
        return 0

# ==================== WEB3 PRESALE TRANSACTION ENDPOINTS ====================


class AnalyticsEvent(db.Model):
    __tablename__ = 'analytics_events'
    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_name = Column(String(120), nullable=False, index=True)
    page_path = Column(String(255), nullable=True, index=True)
    page_type = Column(String(40), nullable=True, index=True)
    device_type = Column(String(40), nullable=True)
    source_medium = Column(String(40), nullable=True)
    cta_position = Column(String(60), nullable=True)
    wallet = Column(String(42), nullable=True, index=True)
    props_json = Column(Text, nullable=True)


@app.route('/api/transaction', methods=['POST'])
@limiter.limit("10 per minute")
def record_transaction():
    try:
        data = request.get_json(silent=True) or {}
        
        required_fields = ['user_address', 'usd_amount', 'crypto_amount', 
                          'token', 'token_name', 'tx_hash', 'network']
        
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False, 
                    'error': f'Missing field: {field}'
                }), 400
        

        network = (data.get('network') or '').lower()
        if network == 'solana':
            wallet_address = (data.get('user_address') or '').strip()
            if len(wallet_address) < 32 or len(wallet_address) > 60:
                return jsonify({'success': False, 'error': 'Invalid Solana address length'}), 400
        else:
            is_valid, wallet_or_error = AirdropSystem.validate_wallet_address(data['user_address'])
            if not is_valid:
                return jsonify({'success': False, 'error': wallet_or_error}), 400
            wallet_address = wallet_or_error
        
        existing = PresaleTransaction.query.filter_by(tx_hash=data['tx_hash']).first()
        if existing:
            return jsonify({
                'success': False, 
                'error': 'Transaction already recorded'
            }), 400
        
        transaction = PresaleTransaction(
            user_address=wallet_address,
            usd_amount=float(data['usd_amount']),
            crypto_amount=str(data['crypto_amount']),
            token=data['token'],
            token_name=data['token_name'],
            tx_hash=data['tx_hash'],
            network=data['network'],
            timestamp=datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat())),
            status='unverified'
        )

        # Best-effort on-chain verification (requires ETH_RPC_URL / BSC_RPC_URL)
        v_status, v_reason = verify_presale_tx(data)
        transaction.status = v_status

        
        db.session.add(transaction)
        
        user = User.query.get(wallet_address)
        if not user:
            referral_code = AirdropSystem.generate_referral_code(wallet_address)
            user = User(
                wallet=wallet_address,
                referral_code=referral_code,
                referral_count=0,
                link_clicks=0,
                link_conversions=0,
                referrer=None,
                active=False,
                ip_address=get_client_ip(),
                last_active=datetime.utcnow()
            )
            db.session.add(user)
            _touch_user_activity(user, datetime.utcnow())
        
        notification = Notification(
            id=AirdropSystem.generate_notification_id(),
            wallet=wallet_address,
            type='presale',
            message=f'✅ Presale contribution confirmed! ${float(data["usd_amount"]):.2f} USD via {data["token_name"]}',
            timestamp=datetime.utcnow(),
            read=False
        )
        db.session.add(notification)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Transaction recorded successfully',
            'id': transaction.id,
            'data': transaction.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    try:
        if not flask_session.get('admin_presale') is True:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        transactions = PresaleTransaction.query.order_by(
            PresaleTransaction.timestamp.desc()
        ).all()
        
        total_usd = db.session.query(db.func.sum(PresaleTransaction.usd_amount)).scalar() or 0
        total_transactions = len(transactions)
        
        unique_users = db.session.query(
            db.func.count(db.func.distinct(PresaleTransaction.user_address))
        ).scalar() or 0
        
        return jsonify({
            'success': True,
            'stats': {
                'total_transactions': total_transactions,
                'total_usd': float(total_usd),
                'unique_users': unique_users
            },
            'transactions': [t.to_dict() for t in transactions]
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500

@app.route('/api/user-transactions/<wallet_address>', methods=['GET'])
def get_user_transactions(wallet_address):
    try:
        is_valid, wallet_or_error = AirdropSystem.validate_wallet_address(wallet_address)
        if not is_valid:
            return jsonify({
                'success': False, 
                'error': wallet_or_error
            }), 400
        
        wallet_address = wallet_or_error
        
        transactions = PresaleTransaction.query.filter_by(
            user_address=wallet_address
        ).order_by(
            PresaleTransaction.timestamp.desc()
        ).all()
        
        total_usd = sum(t.usd_amount for t in transactions)
        
        return jsonify({
            'success': True,
            'user_address': wallet_address,
            'total_contributions': len(transactions),
            'total_usd': total_usd,
            'transactions': [t.to_dict() for t in transactions]
        })
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500

# ==================== WITHDRAWAL ENDPOINTS ====================

def _parse_dt(dt_str: str) -> datetime:
    """Parse ISO-ish datetime strings.

    Accepts '2026-02-20T00:00:00Z' or '2026-02-20T00:00:00' etc.
    Defaults to UTC.
    """
    s = (dt_str or '').strip()
    if not s:
        return datetime.utcnow()
    try:
        if s.endswith('Z'):
            s = s[:-1]
        return datetime.fromisoformat(s)
    except Exception:
        # Very defensive fallback
        try:
            return datetime.strptime(s, '%Y-%m-%d')
        except Exception:
            return datetime.utcnow()


def _get_withdrawal_config() -> WithdrawalConfig:
    cfg = WithdrawalConfig.query.get(1)
    if cfg:
        return cfg

    cfg = WithdrawalConfig(
        id=1,
        withdrawals_enabled=True,
        withdrawal_open_at=_parse_dt(WITHDRAWAL_OPEN_AT_DEFAULT),
        min_referrals_to_withdraw=7,
        fee_wallet_address=(WITHDRAWAL_FEE_WALLET_DEFAULT or ADMIN_WALLET).lower(),
        eth_fee_wei=str(ETH_FEE_WEI_DEFAULT),
        bsc_fee_wei=str(BSC_FEE_WEI_DEFAULT),
        eth_min_confirmations=8,
        bsc_min_confirmations=15,
        support_url=WITHDRAWAL_SUPPORT_URL_DEFAULT,
        spam_ban_minutes=60,
        max_invalid_attempts_per_hour=10,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(cfg)
    db.session.commit()
    return cfg


def _withdrawals_open(cfg: WithdrawalConfig) -> bool:
    if not cfg.withdrawals_enabled:
        return False
    return datetime.utcnow() >= (cfg.withdrawal_open_at or datetime.utcnow())


def _withdrawal_eligibility(wallet_address: str, cfg: 'WithdrawalConfig' = None) -> dict:
    """Single source of truth for withdrawal eligibility.

    Eligibility policy:
    - Based on *direct* referrals only: user.referral_count >= min_referrals_to_withdraw.
    - Withdrawals must be open.
    - Only one queued withdrawal at a time.

    Returns a dict safe for API responses.
    """
    wallet_address = (wallet_address or '').strip().lower()
    cfg = cfg or _get_withdrawal_config()
    user = User.query.get(wallet_address)

    required = int(cfg.min_referrals_to_withdraw or 7)
    withdrawals_open = bool(_withdrawals_open(cfg))
    direct_referrals = int(getattr(user, 'referral_count', 0) or 0) if user else 0

    pending = WithdrawalRequest.query.filter(
        WithdrawalRequest.wallet == wallet_address,
        WithdrawalRequest.status == 'queued'
    ).first() if user else None

    eligible_by_referrals = direct_referrals >= required
    has_pending_withdrawal = pending is not None
    is_eligible = bool(user) and withdrawals_open and eligible_by_referrals and (not has_pending_withdrawal)

    if not user:
        reason_code = 'user_not_found'
        message = 'User not found'
    elif not withdrawals_open:
        reason_code = 'not_open'
        message = 'Withdrawals are not open yet.'
    elif not eligible_by_referrals:
        reason_code = 'not_eligible'
        message = f'Need {max(0, required - direct_referrals)} more direct referral(s) to withdraw.'
    elif has_pending_withdrawal:
        reason_code = 'pending_exists'
        message = 'You already have a queued withdrawal request.'
    else:
        reason_code = 'ok'
        message = 'Eligible for withdrawal'

    return {
        'wallet': wallet_address,
        'withdrawals_open': withdrawals_open,
        'withdrawals_open_at': cfg.withdrawal_open_at.isoformat() if cfg.withdrawal_open_at else None,
        'required_referrals': required,
        'direct_referrals': direct_referrals,
        'eligible_by_referrals': eligible_by_referrals,
        'has_pending_withdrawal': has_pending_withdrawal,
        'pending_withdrawal_id': pending.id if pending else None,
        'is_eligible': is_eligible,
        'reason_code': reason_code,
        'message': message,
    }


def _compute_withdrawable_balance(wallet_address: str) -> dict:
    """Compute withdrawable balance (whole numbers).

    Per spec: joining bonus + referral rewards + achievements + task rewards + claim-window rewards
    minus queued/paid withdrawal amounts.
    """
    user = User.query.get(wallet_address)
    if not user:
        return {
            'welcome_bonus': 0,
            'referral_earnings': 0,
            'achievement_earnings': 0,
            'task_earnings': 0,
            'claim_window_earnings': 0,
            'total_earned': 0,
            'total_withdrawn': 0,
            'withdrawable': 0,
        }

    # Welcome bonus is assigned once on first eligibility check.
    welcome_bonus = int(getattr(user, 'welcome_bonus', 0) or 0)
    referral_earnings = int(user.referral_count or 0) * 121
    achievement_earnings = int(calculate_achievement_rewards(wallet_address) or 0)
    task_earnings = int(getattr(user, 'task_points', 0) or 0)
    claim_window_earnings = int(calculate_claim_window_earnings(wallet_address) or 0)
    total_earned = int(welcome_bonus + referral_earnings + achievement_earnings + task_earnings + claim_window_earnings)

    withdrawn_sum = db.session.query(func.coalesce(func.sum(WithdrawalRequest.amount), 0)).filter(
        WithdrawalRequest.wallet == wallet_address,
        WithdrawalRequest.status.in_(['queued', 'paid'])
    ).scalar() or 0
    total_withdrawn = int(withdrawn_sum)
    withdrawable = max(0, total_earned - total_withdrawn)

    return {
        'welcome_bonus': int(welcome_bonus),
        'referral_earnings': int(referral_earnings),
        'achievement_earnings': int(achievement_earnings),
        'task_earnings': int(task_earnings),
        'claim_window_earnings': int(claim_window_earnings),
        'total_earned': int(total_earned),
        'total_withdrawn': int(total_withdrawn),
        'withdrawable': int(withdrawable),
    }
def _compute_balances_v1(wallet_address: str) -> dict:
    """Canonical balance computation used for uniform dashboard display.

    Notes:
    - Withdrawal eligibility + withdrawable amount are based on _compute_withdrawable_balance().
      Claim-window earnings are included in withdrawable.
    - This is safe to call for any wallet already known to the system.
    """
    wallet_address = (wallet_address or '').strip().lower()
    user = User.query.get(wallet_address)

    # Welcome bonus is assigned once on first eligibility check.
    welcome_bonus = int(getattr(user, 'welcome_bonus', 0) or 0) if user else 0
    referral_earnings = int((getattr(user, 'referral_count', 0) or 0)) * 121 if user else 0
    achievement_earnings = int(calculate_achievement_rewards(wallet_address) or 0) if user else 0
    task_earnings = int(getattr(user, 'task_points', 0) or 0) if user else 0
    claim_window_earnings = int(calculate_claim_window_earnings(wallet_address) or 0) if user else 0

    # Gross "portfolio" total (what the sticky header should consistently show)
    total_gross = int(welcome_bonus + referral_earnings + achievement_earnings + task_earnings + claim_window_earnings)

    # Withdrawals remain per existing rule set
    wd = _compute_withdrawable_balance(wallet_address)

    return {
        'welcome_bonus': int(welcome_bonus),
        'referral_earnings': int(referral_earnings),
        'achievement_earnings': int(achievement_earnings),
        'task_earnings': int(task_earnings),
        'claim_window_earnings': int(claim_window_earnings),
        'total_gross': int(total_gross),
        'total_withdrawn': int(wd.get('total_withdrawn', 0) or 0),
        'withdrawable': int(wd.get('withdrawable', 0) or 0),
        # Single source of truth for the dashboard sticky balance.
        'display_total': int(total_gross),
        'version': 1,
        'computed_at': datetime.utcnow().isoformat() + 'Z',
    }


def _active_referrals_count(wallet_address: str) -> int:
    """Active referrals = *direct* referrals that have **2+ downlines**.

    Downlines are defined as referrals made by the referred wallet (i.e. rows in `referrals`
    where `referrer = referee_wallet`).
    """
    direct = Referral.query.filter_by(referrer=wallet_address).all()
    if not direct:
        return 0

    referee_wallets = [r.referee for r in direct]
    # Count how many referrals each referee has made (their downlines).
    rows = db.session.query(Referral.referrer, func.count(Referral.id)) \
        .filter(Referral.referrer.in_(referee_wallets)) \
        .group_by(Referral.referrer).all()
    downline_counts = {ref: int(cnt) for ref, cnt in rows}

    return sum(1 for r in direct if downline_counts.get(r.referee, 0) >= 2)




# ------------------------------
# Gamification helpers (level / streak / rank)
# ------------------------------
_LEVEL_THRESHOLDS = [0, 100, 250, 500, 900, 1400, 2000, 2700, 3500, 4400, 5400, 6500]

def _compute_level_from_xp(xp: int) -> int:
    xp = int(xp or 0)
    lvl = 1
    for i, t in enumerate(_LEVEL_THRESHOLDS, start=1):
        if xp >= t:
            lvl = i
        else:
            break
    return max(1, lvl)

def _compute_rank_tier(active_referrals: int, level: int) -> str:
    # Primary driver: active referrals; level is a small kicker.
    a = int(active_referrals or 0)
    l = int(level or 1)
    if a >= 30:
        return "Titan"
    if a >= 15:
        return "Leader"
    if a >= 7:
        return "Influencer"
    if a >= 3:
        return "Connector"
    if a >= 1:
        return "Builder"
    # Higher level but no active referrals yet: still Rookie.
    return "Rookie"

def _update_streak(user: 'User', now: datetime) -> None:
    try:
        today = now.date()
    except Exception:
        return
    last = getattr(user, 'streak_last_date', None)

    if not last:
        user.streak_current = max(int(user.streak_current or 0), 1)
        user.streak_longest = max(int(user.streak_longest or 0), int(user.streak_current or 1))
        user.streak_last_date = today
        return

    if today == last:
        return  # already counted today

    # Consecutive day?
    if today == (last + timedelta(days=1)):
        user.streak_current = int(user.streak_current or 0) + 1
    else:
        user.streak_current = 1

    user.streak_longest = max(int(user.streak_longest or 0), int(user.streak_current or 1))
    user.streak_last_date = today

def _sync_gamification_fields(user: 'User') -> None:
    # Default xp mirrors task_points (keeps schema flexible for future XP sources).
    user.xp = int(getattr(user, 'xp', 0) or 0)
    if user.xp == 0 and int(getattr(user, 'task_points', 0) or 0) > 0:
        user.xp = int(user.task_points or 0)

    user.level = _compute_level_from_xp(user.xp)

    # Rank tier uses active referrals + level
    active_cnt = _active_referrals_count(user.wallet)
    user.rank_tier = _compute_rank_tier(active_cnt, user.level)



def _touch_user_activity(user: 'User', now: datetime | None = None) -> None:
    now = now or datetime.utcnow()
    user.last_active = now
    _update_streak(user, now)
    _sync_gamification_fields(user)


def _rpc_post_json(url: str, payload: dict) -> dict:
    body = json.dumps(payload).encode('utf-8')
    req = urlrequest.Request(url, data=body, headers={'Content-Type': 'application/json'})
    with urlrequest.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode('utf-8', errors='ignore')
    return json.loads(raw)


def _get_chain_rpc(chain: str) -> str:
    if chain == 'eth':
        return ETH_RPC_URL
    if chain == 'bsc':
        return BSC_RPC_URL
    return ''


def _validate_fee_tx(chain: str, tx_hash: str, wallet_address: str, cfg: WithdrawalConfig) -> dict:
    """Validate a native-coin fee tx via JSON-RPC.

    Returns: {ok: bool, code: str, message: str, data?: {...}}
    """
    chain = (chain or '').strip().lower()
    tx_hash = (tx_hash or '').strip()
    wallet_address = (wallet_address or '').strip().lower()

    if chain not in {'eth', 'bsc'}:
        return {'ok': False, 'code': 'bad_chain', 'message': 'Invalid chain'}

    if not tx_hash or not tx_hash.startswith('0x') or len(tx_hash) < 10:
        return {'ok': False, 'code': 'bad_hash', 'message': 'Invalid transaction hash'}

    rpc_url = _get_chain_rpc(chain)
    if not rpc_url:
        return {'ok': False, 'code': 'rpc_missing', 'message': 'RPC provider not configured for this network'}

    # Fetch tx
    try:
        tx_resp = _rpc_post_json(rpc_url, {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'eth_getTransactionByHash',
            'params': [tx_hash]
        })
        tx = tx_resp.get('result')
        if not tx:
            return {'ok': False, 'code': 'not_found', 'message': 'Transaction not found on selected network'}

        receipt_resp = _rpc_post_json(rpc_url, {
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'eth_getTransactionReceipt',
            'params': [tx_hash]
        })
        receipt = receipt_resp.get('result')
        if not receipt:
            return {'ok': False, 'code': 'pending', 'message': 'Transaction pending. Try again in ~1 minute.'}

        # status: '0x1' success
        if str(receipt.get('status') or '').lower() not in {'0x1', '1'}:
            return {'ok': False, 'code': 'failed', 'message': 'Transaction failed'}

        fee_to = (tx.get('to') or '').lower()
        fee_from = (tx.get('from') or '').lower()
        fee_wallet = (cfg.fee_wallet_address or '').lower()

        if fee_to != fee_wallet:
            return {'ok': False, 'code': 'wrong_recipient', 'message': 'Fee was sent to the wrong address'}

        if fee_from != wallet_address:
            return {
                'ok': False,
                'code': 'wrong_sender',
                'message': 'Fee must be paid from the same wallet you are withdrawing from',
                'support_url': cfg.support_url,
            }

        required_fee = int(cfg.eth_fee_wei) if chain == 'eth' else int(cfg.bsc_fee_wei)
        value_wei = int(tx.get('value') or '0x0', 16)
        if value_wei < required_fee:
            return {'ok': False, 'code': 'fee_too_low', 'message': 'Gas fee paid is too low'}

        # confirmations
        block_hex = receipt.get('blockNumber')
        if not block_hex:
            return {'ok': False, 'code': 'pending', 'message': 'Transaction pending. Try again in ~1 minute.'}
        tx_block = int(block_hex, 16)

        latest_block_resp = _rpc_post_json(rpc_url, {
            'jsonrpc': '2.0',
            'id': 3,
            'method': 'eth_blockNumber',
            'params': []
        })
        latest_block = int(latest_block_resp.get('result') or '0x0', 16)
        confirmations = max(0, latest_block - tx_block + 1)

        min_confs = int(cfg.eth_min_confirmations) if chain == 'eth' else int(cfg.bsc_min_confirmations)
        if confirmations < min_confs:
            return {
                'ok': False,
                'code': 'need_confirmations',
                'message': f'Transaction found but needs more confirmations ({confirmations}/{min_confs}). Try again soon.'
            }

        return {
            'ok': True,
            'code': 'ok',
            'message': 'Fee transaction validated',
            'data': {
                'fee_from': fee_from,
                'fee_to': fee_to,
                'fee_value_wei': str(value_wei),
                'confirmations': int(confirmations),
            }
        }
    except URLError:
        return {'ok': False, 'code': 'rpc_error', 'message': 'RPC error. Please try again.'}
    except Exception as e:
        return {'ok': False, 'code': 'rpc_error', 'message': f'Validation error: {str(e)}'}


def _wallet_guard(wallet_address: str) -> WithdrawalWalletGuard:
    guard = WithdrawalWalletGuard.query.get(wallet_address)
    if guard:
        return guard
    guard = WithdrawalWalletGuard(wallet=wallet_address, invalid_attempts=0, window_started_at=datetime.utcnow())
    db.session.add(guard)
    db.session.commit()
    return guard


def _guard_check_ban(guard: WithdrawalWalletGuard) -> bool:
    return bool(guard.banned_until and datetime.utcnow() < guard.banned_until)


def _guard_record_invalid(wallet_address: str, cfg: WithdrawalConfig) -> WithdrawalWalletGuard:
    guard = _wallet_guard(wallet_address)

    now = datetime.utcnow()
    # reset rolling window if > 1 hour
    if guard.window_started_at and (now - guard.window_started_at) > timedelta(hours=1):
        guard.window_started_at = now
        guard.invalid_attempts = 0

    guard.invalid_attempts = int(guard.invalid_attempts or 0) + 1
    guard.updated_at = now

    if guard.invalid_attempts >= int(cfg.max_invalid_attempts_per_hour):
        guard.banned_until = now + timedelta(minutes=int(cfg.spam_ban_minutes))

    db.session.commit()
    return guard


def _guard_clear_invalid(wallet_address: str):
    guard = WithdrawalWalletGuard.query.get(wallet_address)
    if not guard:
        return
    guard.invalid_attempts = 0
    guard.window_started_at = datetime.utcnow()
    guard.updated_at = datetime.utcnow()
    db.session.commit()

@app.route('/api/check-withdrawal-eligibility', methods=['GET'])
def check_withdrawal_eligibility():
    wallet_address = request.args.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'})
    
    elig = _withdrawal_eligibility(wallet_address)
    if elig.get('reason_code') == 'user_not_found':
        return jsonify({'success': False, 'message': 'User not found'}), 404

    remaining = max(0, int(elig.get('required_referrals', 7)) - int(elig.get('direct_referrals', 0)))
    return jsonify({
        'success': True,
        'is_eligible': bool(elig.get('is_eligible')),
        'withdrawals_open': bool(elig.get('withdrawals_open')),
        'withdrawals_open_at': elig.get('withdrawals_open_at'),
        'referral_count': int(elig.get('direct_referrals', 0)),
        'required_count': int(elig.get('required_referrals', 7)),
        'remaining_needed': int(remaining),
        'message': elig.get('message'),
        'reason_code': elig.get('reason_code'),
    })

@app.route('/api/next-action', methods=['GET'])
def next_action():
    if not FEATURE_NEXT_ACTION:
        return jsonify({'success': True, 'disabled': True, 'data': None})

    wallet_address = request.args.get('wallet', '').strip().lower()
    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'}), 400

    user = User.query.get(wallet_address)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    cfg = _get_withdrawal_config()
    elig = _withdrawal_eligibility(wallet_address, cfg=cfg)
    direct_cnt = int(elig.get('direct_referrals', 0) or 0)
    required = int(elig.get('required_referrals', 7) or 7)

    claim = AirdropClaim.query.filter_by(wallet=wallet_address).first()
    pending = WithdrawalRequest.query.filter_by(wallet=wallet_address, status='queued').first()

    now = datetime.utcnow()
    withdrawals_open = bool(cfg.withdrawals_enabled) and (cfg.withdrawal_open_at is None or now >= cfg.withdrawal_open_at)

    # Default response
    title = "Your next step"
    body = "Keep your dashboard up to date."
    cta_text = "Go to Overview"
    cta_target = "overview"
    severity = "info"

    # If withdrawals are not yet open, always show the Telegram safety banner
    # (prevents the "claim" CTA from occupying this slot).
    if (not withdrawals_open) and bool(cfg.withdrawals_enabled):
        open_at = cfg.withdrawal_open_at.isoformat() if cfg.withdrawal_open_at else None
        title = "Withdrawals aren't open yet"
        body = "Join the official Telegram for withdrawal schedule updates and scam alerts."
        cta_text = "Open Telegram"
        cta_target = "telegram"
        severity = "warning"
        return jsonify({'success': True, 'data': {
            'title': title, 'body': body, 'cta_text': cta_text, 'cta_target': cta_target,
            'severity': severity, 'direct_referrals': direct_cnt, 'required_referrals': required,
            'withdrawals_open_at': open_at, 'has_claim': (claim is not None), 'has_pending_withdrawal': False
        }})

    # Remove the redundant "Claim your welcome allocation" card.
    # The main Overview already provides a dedicated welcome-claim CTA.
    if claim is None:
        return jsonify({'success': True, 'data': None})

    if pending is not None:
        title = "Withdrawal in progress"
        body = "You already have a queued withdrawal request. We'll post status updates in the dashboard."
        cta_text = "View Withdrawals"
        cta_target = "withdrawals"
        severity = "info"
    elif withdrawals_open and direct_cnt >= required:
        title = "You're eligible to withdraw"
        body = f"You have {direct_cnt} direct referrals (need {required}). Submit a withdrawal request when ready."
        cta_text = "Withdraw"
        cta_target = "withdrawals"
        severity = "success"
    else:
        remaining = max(0, required - direct_cnt)
        title = "Grow your direct referrals"
        body = f"You need {remaining} more direct referral(s) to withdraw."
        cta_text = "Open Network"
        cta_target = "network"
        severity = "info"

    return jsonify({'success': True, 'data': {
        'title': title,
        'body': body,
        'cta_text': cta_text,
        'cta_target': cta_target,
        'severity': severity,
        'direct_referrals': direct_cnt,
        'required_referrals': required,
        'withdrawals_open_at': (cfg.withdrawal_open_at.isoformat() if cfg.withdrawal_open_at else None),
        'has_claim': claim is not None,
        'has_pending_withdrawal': pending is not None
    }})


@app.route('/api/milestones', methods=['GET'])
def milestones():
    """Read-only computed milestones used to make progress feel tangible.

    Additive endpoint: does NOT modify balances/referrals/withdrawals logic.
    """
    if not FEATURE_MILESTONES:
        return jsonify({'success': True, 'disabled': True, 'data': []})

    wallet_address = request.args.get('wallet', '').strip().lower()
    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'}), 400

    user = User.query.get(wallet_address)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Core inputs
    direct_referrals = Referral.query.filter_by(referrer=wallet_address).count()
    claim = AirdropClaim.query.filter_by(wallet=wallet_address).first()
    cfg = _get_withdrawal_config()
    required_direct = int(cfg.min_referrals_to_withdraw or 7)

    # Milestones are intentionally simple and mobile-friendly.
    items = []

    def add_item(_id: str, title: str, current: int, target: int, subtitle: str = ''):
        pct = 0
        if target > 0:
            pct = int(min(100, round((current / target) * 100)))
        items.append({
            'id': _id,
            'title': title,
            'subtitle': subtitle,
            'current': int(current),
            'target': int(target),
            'pct': pct,
            'done': bool(current >= target)
        })

    # Claim readiness
    add_item('claim', 'Claimed', 1 if claim else 0, 1, 'Claiming initializes your allocation and dashboard.')

    # Referral growth
    add_item('ref_3', 'Direct referrals', direct_referrals, 3, 'Build your first small network.')
    add_item('ref_5', 'Direct referrals', direct_referrals, 5, 'Strengthen your network base.')
    add_item('ref_10', 'Direct referrals', direct_referrals, 10, 'You’re building momentum.')

    # Active referrals (separate from withdrawal eligibility)
    active_referrals = _active_referrals_count(wallet_address)
    add_item('active_ref_1', 'Active referrals', active_referrals, 1, 'Active = a direct referral with 2+ downlines.')
    add_item('active_ref_3', 'Active referrals', active_referrals, 3, 'A healthy core of active users.')

    # Withdrawal eligibility
    add_item('withdraw', 'Withdrawal eligibility', direct_referrals, required_direct,
             f'Requires {required_direct} direct referrals to withdraw.')

    return jsonify({'success': True, 'data': {
        'wallet': wallet_address,
        'required_referrals': required_direct,
        'items': items
    }})


@app.route('/api/simulate-withdrawal', methods=['POST'])
@limiter.limit("5 per minute")
def simulate_withdrawal():
    data = request.json or {}
    wallet_address = data.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'})
    
    user = User.query.get(wallet_address)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})

    cfg = _get_withdrawal_config()
    elig = _withdrawal_eligibility(wallet_address, cfg=cfg)
    balances = _compute_withdrawable_balance(wallet_address)
    balances['claim_window_earnings'] = int(calculate_claim_window_earnings(wallet_address) or 0)
    direct_referrals_count = int(elig.get('direct_referrals', 0) or 0)
    required = int(elig.get('required_referrals', 7) or 7)
    
    withdrawal_attempt = WithdrawalAttempt(
        wallet=wallet_address,
        referral_count=direct_referrals_count,
        eligible=(direct_referrals_count >= required),
        attempted_at=datetime.utcnow(),
        status='checked',
        notes='User checked withdrawal eligibility'
    )
    db.session.add(withdrawal_attempt)
    db.session.commit()
    
    if direct_referrals_count < required:
        return jsonify({
            'success': True,
            'is_eligible': False,
            'referral_count': direct_referrals_count,
            'required_count': required,
            'remaining_needed': max(0, required - direct_referrals_count),
            'balances': {
                'welcome_bonus': balances['welcome_bonus'],
                'referral_earnings': balances['referral_earnings'],
                'achievement_earnings': balances['achievement_earnings'],
                'task_earnings': balances['task_earnings'],
                'total_balance': balances['total_earned'],
                'available_for_withdrawal': 0,
            },
            'message': f'❌ You are not yet eligible for withdrawals. Ensure you invite at least {required} friends to unlock withdrawal access ✨',
            'progress_message': f'📈 Progress to Unlock Withdrawals\nYou need {max(0, required - direct_referrals_count)} more referrals to unlock withdrawal access.\nInvite friends now to secure your airdrop position!\nCurrent Referrals: [{direct_referrals_count}/{required}]'
        })
    
    return jsonify({
        'success': True,
        'is_eligible': True,
        'referral_count': direct_referrals_count,
        'balances': {
            'welcome_bonus': balances['welcome_bonus'],
            'referral_earnings': balances['referral_earnings'],
            'achievement_earnings': balances['achievement_earnings'],
            'task_earnings': balances['task_earnings'],
            'total_balance': balances['total_earned'],
            'total_withdrawn': balances['total_withdrawn'],
            'available_for_withdrawal': balances['withdrawable'],
        },
        'message': f'🎉 Congratulations! You\'ve unlocked withdrawal eligibility!\n\nWithdrawals will be available starting {cfg.withdrawal_open_at.strftime("%B %d, %Y")}.\nCurrent Referrals: [{direct_referrals_count}/{required}]',
        'withdrawal_open_at': cfg.withdrawal_open_at.isoformat(),
        'withdrawals_open': _withdrawals_open(cfg),
        'note': 'Withdrawals are processed manually after fee verification.'
    })


@app.route('/api/withdrawal/config', methods=['GET'])
def api_withdrawal_config():
    wallet_address = request.args.get('wallet', '').strip().lower()
    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'}), 400

    cfg = _get_withdrawal_config()
    user = User.query.get(wallet_address)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    balances = _compute_withdrawable_balance(wallet_address)
    # For UI breakdown only (does not affect withdrawable rules)
    balances['claim_window_earnings'] = int(calculate_claim_window_earnings(wallet_address) or 0)
    elig = _withdrawal_eligibility(wallet_address, cfg=cfg)
    direct_refs = int(elig.get('direct_referrals', 0) or 0)
    required = int(elig.get('required_referrals', 7) or 7)

    guard = _wallet_guard(wallet_address)
    banned = _guard_check_ban(guard)

    pending = WithdrawalRequest.query.filter(
        WithdrawalRequest.wallet == wallet_address,
        WithdrawalRequest.status == 'queued'
    ).order_by(WithdrawalRequest.created_at.desc()).first()

    return jsonify({
        'success': True,
        'withdrawals_enabled': bool(cfg.withdrawals_enabled),
        'withdrawal_open_at': cfg.withdrawal_open_at.isoformat(),
        'withdrawals_open': _withdrawals_open(cfg),
        'min_referrals_to_withdraw': required,
        'referral_count': direct_refs,
        'eligible_by_referrals': direct_refs >= required,
        'balances': balances,
        'fee_wallet': cfg.fee_wallet_address,
        'fees': {
            'eth_fee_wei': str(cfg.eth_fee_wei),
            'bsc_fee_wei': str(cfg.bsc_fee_wei),
        },
        'confirmations_required': {
            'eth': int(cfg.eth_min_confirmations),
            'bsc': int(cfg.bsc_min_confirmations),
        },
        'support_url': cfg.support_url,
        'pending_withdrawal': pending.id if pending else None,
        'banned_until': guard.banned_until.isoformat() if (banned and guard.banned_until) else None,
    })


@app.route('/api/withdrawals/submit', methods=['POST'])
@limiter.limit("10 per minute")
def api_withdrawal_submit():
    data = request.get_json(silent=True) or {}
    wallet_address = (data.get('wallet') or '').strip().lower()
    chain = (data.get('chain') or '').strip().lower()
    tx_hash = (data.get('tx_hash') or '').strip()
    amount = data.get('amount')

    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'}), 400

    user = User.query.get(wallet_address)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    cfg = _get_withdrawal_config()

    # Ban check
    guard = _wallet_guard(wallet_address)
    if _guard_check_ban(guard):
        return jsonify({
            'success': False,
            'code': 'banned',
            'message': 'Too many attempts. Please try again later.',
            'banned_until': guard.banned_until.isoformat() if guard.banned_until else None,
        }), 429

    # Open-date check
    if not _withdrawals_open(cfg):
        return jsonify({
            'success': False,
            'code': 'not_open',
            'message': 'Withdrawals are not open yet.',
            'withdrawal_open_at': cfg.withdrawal_open_at.isoformat(),
        }), 400

    # Referral threshold check (direct referrals only)
    elig = _withdrawal_eligibility(wallet_address, cfg=cfg)
    direct_refs = int(elig.get('direct_referrals', 0) or 0)
    required = int(elig.get('required_referrals', 7) or 7)
    if direct_refs < required:
        return jsonify({
            'success': False,
            'code': 'not_eligible',
            'message': f'You need {max(0, required - direct_refs)} more direct referrals to withdraw.',
            'referral_count': direct_refs,
            'required_count': required,
        }), 400

    # One queued withdrawal at a time
    existing = WithdrawalRequest.query.filter(
        WithdrawalRequest.wallet == wallet_address,
        WithdrawalRequest.status == 'queued'
    ).first()
    if existing:
        return jsonify({
            'success': False,
            'code': 'pending_exists',
            'message': 'You already have a pending withdrawal request.',
            'withdrawal_id': existing.id,
        }), 400

    # Amount
    try:
        amount_int = int(amount)
    except Exception:
        return jsonify({'success': False, 'code': 'bad_amount', 'message': 'Amount must be a whole number'}), 400

    if amount_int <= 0:
        return jsonify({'success': False, 'code': 'bad_amount', 'message': 'Amount must be greater than 0'}), 400

    balances = _compute_withdrawable_balance(wallet_address)
    if amount_int > int(balances['withdrawable']):
        return jsonify({
            'success': False,
            'code': 'insufficient',
            'message': 'Insufficient withdrawable balance.',
            'withdrawable': balances['withdrawable'],
        }), 400

    # tx hash reuse check
    if WithdrawalRequest.query.filter_by(fee_tx_hash=tx_hash).first():
        _guard_record_invalid(wallet_address, cfg)
        return jsonify({'success': False, 'code': 'hash_used', 'message': 'This transaction hash was already used.'}), 400

    # Validate tx on-chain
    v = _validate_fee_tx(chain, tx_hash, wallet_address, cfg)
    if not v.get('ok'):
        # rate-limit invalid attempts
        _guard_record_invalid(wallet_address, cfg)
        status_code = 400
        if v.get('code') == 'pending':
            status_code = 202
        elif v.get('code') == 'rpc_error':
            status_code = 502
        elif v.get('code') == 'wrong_sender':
            status_code = 400
        return jsonify({
            'success': False,
            'code': v.get('code'),
            'message': v.get('message'),
            'support_url': v.get('support_url') or cfg.support_url,
        }), status_code

    # Passed validation: clear invalid attempt counter
    _guard_clear_invalid(wallet_address)

    txdata = v.get('data') or {}
    req = WithdrawalRequest(
        wallet=wallet_address,
        amount=int(amount_int),
        chain=chain,
        fee_tx_hash=tx_hash,
        fee_from=txdata.get('fee_from', wallet_address),
        fee_to=txdata.get('fee_to', cfg.fee_wallet_address),
        fee_value_wei=str(txdata.get('fee_value_wei') or '0'),
        fee_confirmations=int(txdata.get('confirmations') or 0),
        status='queued',
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.session.add(req)

    # Activity feed: withdrawal requested (status is queued at this point).
    _log_activity(
        wallet_address,
        'withdrawal_requested',
        f'Withdrawal request submitted ({amount_int} OPN)',
        {'amount': int(amount_int), 'chain': chain, 'fee_tx_hash': tx_hash}
    )
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Withdrawal request submitted. Tokens will be sent manually after review.',
        'withdrawal_id': req.id,
        'balances': _compute_withdrawable_balance(wallet_address),
    })

# ==================== EXISTING API ENDPOINTS ====================

@app.route('/api/get-referral-stats', methods=['GET'])
def get_referral_stats():
    wallet_address = request.args.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({
            'success': False,
            'message': 'Wallet address is required'
        })
    
    user = User.query.get(wallet_address)
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        })

    # Keep this consistent with the definition used across the app:
    # "Active" = a direct referral that has >= 2 downline referrals.
    active_cnt = _active_referrals_count(wallet_address)
    
    conversion_rate = 0
    if user.link_clicks > 0:
        conversion_rate = round((user.link_conversions / user.link_clicks) * 100, 1)
    
    return jsonify({
        'success': True,
        'data': {
            'referral_count': user.referral_count,
            'active_referrals_count': active_cnt,
            'level': user.level,
            'xp': user.xp,
            'rank_tier': user.rank_tier,
            'streak_current': user.streak_current,
            'streak_longest': user.streak_longest,
            'streak_last_date': user.streak_last_date.isoformat() if user.streak_last_date else None,
            'link_clicks': user.link_clicks,
            'link_conversions': user.link_conversions,
            'conversion_rate': conversion_rate,
            'total_bonus': user.referral_count * 121,
            'referral_code': user.referral_code,
            'is_active': user.active
        }
    })

@app.route('/api/get-network-analysis', methods=['GET'])
def get_network_analysis():
    wallet_address = request.args.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({
            'success': False,
            'message': 'Wallet address is required'
        })
    
    user = User.query.get(wallet_address)
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        })
    
    direct_referrals = Referral.query.filter_by(referrer=wallet_address).all()
    direct_referrals_count = len(direct_referrals)
    
    active_referrals_count = 0
    # "Active" referrals: direct referrals that have >= 2 downline referrals of their own.
    referee_wallets = [r.referee for r in direct_referrals]
    downline_counts = {}
    if referee_wallets:
        rows = db.session.query(Referral.referrer, func.count(Referral.id))\
            .filter(Referral.referrer.in_(referee_wallets))\
            .group_by(Referral.referrer).all()
        downline_counts = {w: int(c) for (w, c) in rows}

    for referral in direct_referrals:
        if downline_counts.get(referral.referee, 0) >= 2:
            active_referrals_count += 1
    
    inactive_referrals_count = direct_referrals_count - active_referrals_count
    
    # Total amount breakdown (include task_points as task earnings).
    # Welcome bonus is the assigned per-wallet base reward.
    welcome_bonus = float(int(getattr(user, 'welcome_bonus', 0) or 0))
    referral_earnings = float(int(user.referral_count or 0) * 121)
    achievement_earnings = float(int(calculate_achievement_rewards(wallet_address) or 0))
    task_earnings = float(int(getattr(user, 'task_points', 0) or 0))
    claim_window_earnings = float(int(calculate_claim_window_earnings(wallet_address) or 0))
    total_amount = float(welcome_bonus + referral_earnings + achievement_earnings + task_earnings + claim_window_earnings)
    
    can_withdraw = direct_referrals_count >= 7
    available_for_withdrawal = total_amount if can_withdraw else 0
    
    return jsonify({
        'success': True,
        'data': {
            'direct_referrals_count': direct_referrals_count,
            'active_referrals_count': active_referrals_count,
            'inactive_referrals_count': inactive_referrals_count,
            'total_amount': total_amount,
            'balances': {
                'welcome_bonus': welcome_bonus,
                'referral_earnings': referral_earnings,
                'achievement_earnings': achievement_earnings,
                'task_earnings': task_earnings,
                'claim_window_earnings': claim_window_earnings,
                'total_balance': total_amount,
            },
            'can_withdraw': can_withdraw,
            'available_for_withdrawal': available_for_withdrawal,
            'withdrawal_message': f'Need {7 - direct_referrals_count} more active referrals to withdraw' if not can_withdraw else 'Eligible for withdrawal'
        }
    })

@app.route('/api/get-achievements', methods=['GET'])
def get_achievements():
    wallet_address = request.args.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({
            'success': False,
            'message': 'Wallet address is required'
        })
    
    user = User.query.get(wallet_address)
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        })

    # Keep this consistent with the definition used across the app:
    # "Active" = a direct referral that has >= 2 downline referrals.
    active_cnt = _active_referrals_count(wallet_address)
    
    unlocked_achievements = Achievement.query.filter_by(wallet=wallet_address).all()
    unlocked_ids = [a.achievement_id for a in unlocked_achievements]
    
    achievements_list = []
    total_unlocked = 0
    total_rewards = 0
    
    for achievement_def in ACHIEVEMENTS:
        unlocked = achievement_def['id'] in unlocked_ids
        if unlocked:
            total_unlocked += 1
            total_rewards += achievement_def['reward']
        
        achievements_list.append({
            'id': achievement_def['id'],
            'name': achievement_def['name'],
            'icon': achievement_def['icon'],
            'requirement': achievement_def['requirement'],
            'reward': achievement_def['reward'],
            'unlocked': unlocked,
            'description': f"Earn {achievement_def['reward']} OPN bonus for {achievement_def['name'].lower()}"
        })
    
    return jsonify({
        'success': True,
        'data': {
            'achievements': achievements_list,
            'total_unlocked': total_unlocked,
            'total_rewards': total_rewards,
            'referral_count': user.referral_count,
            'active_referrals_count': active_cnt,
            'level': user.level,
            'xp': user.xp,
            'rank_tier': user.rank_tier,
            'streak_current': user.streak_current,
            'streak_longest': user.streak_longest,
            'progress_percentage': round((total_unlocked / len(ACHIEVEMENTS)) * 100)
        }
    })


@app.route('/api/track-event', methods=['POST'])
def track_event():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    name = (data.get('event_name') or '').strip()[:120]
    if not name:
        return jsonify({"ok": False, "error": "missing event_name"}), 400
    ev = AnalyticsEvent(
        event_name=name,
        page_path=(data.get('page_path') or '')[:255],
        page_type=(data.get('page_type') or '')[:40],
        device_type=(data.get('device_type') or '')[:40],
        source_medium=(data.get('source_medium') or '')[:40],
        cta_position=(data.get('cta_position') or '')[:60],
        wallet=_normalize_addr(data.get('wallet')) if data.get('wallet') else None,
        props_json=json.dumps(data.get('props') or {})
    )
    try:
        db.session.add(ev)
        db.session.commit()
    except Exception:
        db.session.rollback()
    return jsonify({"ok": True})

@app.route('/api/track-link-click', methods=['POST'])
@limiter.limit("50 per minute")
def track_link_click():
    data = request.json or {}
    referral_code = data.get('referral_code', '').strip().upper()
    
    if not referral_code:
        return jsonify({
            'success': False,
            'message': 'Referral code is required'
        })
    
    user = User.query.filter_by(referral_code=referral_code).first()
    if not user:
        return jsonify({
            'success': False,
            'message': 'Invalid referral code'
        })
    
    user.link_clicks += 1
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Link click tracked',
        'data': {
            'referral_code': referral_code,
            'total_clicks': user.link_clicks
        }
    })


@app.route('/api/telegram-click', methods=['POST'])
@limiter.limit("60 per minute")
def telegram_click():
    """Lightweight analytics for Telegram CTA clicks (no gating, no rewards)."""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    wallet = (data.get('wallet') or '').strip().lower()
    source = (data.get('source') or '').strip()[:80]
    deep_link = (data.get('deep_link') or '').strip()[:255]

    # Reuse AnalyticsEvent to avoid schema changes.
    ev = AnalyticsEvent(
        event_name='telegram_click',
        page_path=request.path,
        page_type='app',
        device_type=(data.get('device_type') or '')[:40],
        source_medium=source or None,
        cta_position='telegram_block',
        wallet=wallet or None,
        props_json=json.dumps({'source': source, 'deep_link': deep_link}, ensure_ascii=False) if (source or deep_link) else None
    )
    db.session.add(ev)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/get-notifications', methods=['GET'])
def get_notifications():
    wallet_address = request.args.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({
            'success': False,
            'message': 'Wallet address is required'
        })
    
    notifications = Notification.query.filter_by(wallet=wallet_address)\
        .order_by(Notification.timestamp.desc())\
        .limit(50)\
        .all()
    
    unread_count = Notification.query.filter_by(wallet=wallet_address, read=False).count()
    
    return jsonify({
        'success': True,
        'data': {
            'notifications': [{
                'id': n.id,
                'type': n.type,
                'message': n.message,
                'timestamp': n.timestamp.isoformat(),
                'read': n.read
            } for n in notifications],
            'unread_count': unread_count,
            'total_count': len(notifications)
        }
    })


@app.route('/api/activity', methods=['GET'])
def api_get_activity():
    """Return recent activity entries for a given wallet (mobile-friendly payload)."""
    wallet_address = request.args.get('wallet', '').strip().lower()
    try:
        limit = int(request.args.get('limit', 10))
    except Exception:
        limit = 10
    limit = max(1, min(limit, 50))

    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address is required'}), 400

    rows = ActivityLog.query.filter_by(wallet=wallet_address) \
        .order_by(ActivityLog.created_at.desc()) \
        .limit(limit).all()

    return jsonify({
        'success': True,
        'data': {
            'activity': [r.to_dict() for r in rows],
            'count': len(rows)
        }
    })

@app.route('/api/mark-notification-read', methods=['POST'])
@limiter.limit("20 per minute")
def mark_notification_read():
    data = request.json or {}
    notification_id = data.get('notification_id', '')
    
    if not notification_id:
        return jsonify({
            'success': False,
            'message': 'Notification ID is required'
        })
    
    notification = Notification.query.get(notification_id)
    if not notification:
        return jsonify({
            'success': False,
            'message': 'Notification not found'
        })
    
    notification.read = True
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Notification marked as read'
    })

# ==================== PRESALE ENDPOINTS ====================

@app.route('/api/get-presale-address', methods=['GET'])
def get_presale_address():
    return jsonify({
        'success': True,
        'address': PRESALE_WALLET,
        'network': 'Ethereum Mainnet',
        'chain_id': 1,
        'note': 'Send ETH only from personal wallet (not exchange)'
    })

@app.route('/api/record-presale-contribution', methods=['POST'])
@limiter.limit("5 per minute")
def record_presale_contribution():
    data = request.json or {}
    # Support both POST (JSON) and GET (querystring) to avoid 405s from clients
    wallet_address = (data.get('wallet_address') or data.get('wallet') or request.args.get('wallet_address') or request.args.get('wallet') or '').strip().lower()
    amount_eth = float(data.get('amount_eth', 0.0))
    tx_hash = data.get('tx_hash', '')
    chain_id = int(data.get('chain_id', 1))
    
    if not wallet_address or amount_eth <= 0 or not tx_hash:
        return jsonify({
            'success': False,
            'message': 'Invalid data'
        })
    
    return jsonify({
        'success': False,
        'message': 'This endpoint is deprecated. Use Web3 payment gateway instead.'
    })

@app.route('/api/get-presale-contributions', methods=['GET'])
def get_presale_contributions():
    wallet_address = request.args.get('wallet', '').strip().lower()
    
    if not wallet_address:
        return jsonify({'success': False, 'message': 'Wallet address required'})
    
    old_contributions = PresaleContribution.query.filter_by(
        wallet=wallet_address
    ).order_by(
        PresaleContribution.contributed_at.desc()
    ).all()
    
    new_transactions = PresaleTransaction.query.filter_by(
        user_address=wallet_address
    ).order_by(
        PresaleTransaction.timestamp.desc()
    ).all()
    
    total_eth = sum(c.amount_eth for c in old_contributions)
    total_tokens = sum(c.tokens_allocated for c in old_contributions)
    total_usd_new = sum(t.usd_amount for t in new_transactions)
    
    return jsonify({
        'success': True,
        'data': {
            'old_contributions': [{
                'amount_eth': c.amount_eth,
                'amount_usd': c.amount_usd,
                'tokens_allocated': c.tokens_allocated,
                'tx_hash': c.tx_hash,
                'chain_id': c.chain_id,
                'timestamp': c.contributed_at.isoformat(),
                'status': c.status
            } for c in old_contributions],
            'web3_transactions': [{
                'usd_amount': t.usd_amount,
                'crypto_amount': t.crypto_amount,
                'token': t.token,
                'token_name': t.token_name,
                'tx_hash': t.tx_hash,
                'network': t.network,
                'timestamp': t.timestamp.isoformat(),
                'status': t.status
            } for t in new_transactions],
            'total_eth': total_eth,
            'total_tokens': total_tokens,
            'total_usd_web3': total_usd_new,
            'total_contributions': len(old_contributions) + len(new_transactions)
        }
    })

# ==================== EXISTING AIRDROP ENDPOINTS ====================

def _render_index():
    wc_project_id = os.getenv('WALLETCONNECT_PROJECT_ID','')
    sol_presale_wallet = os.getenv('SOL_PRESALE_WALLET','')
    sol_rpc_url = os.getenv('SOL_RPC_URL','').strip()
    return render_template(
        'index.html',
        wc_project_id=wc_project_id,
        sol_presale_wallet=sol_presale_wallet,
        sol_rpc_url=sol_rpc_url,
    )



@app.route('/app')
@app.route('/app/<path:section>')
def app_shell(section=None):
    # Existing single-page app shell (unchanged)
    return _render_index()

def _canonical_url(path: str) -> str:
    base = request.url_root.rstrip('/')
    return f"{base}{path}"

def _render_seo(template_name: str, *, meta_title: str, meta_description: str, h1: str, lead: str, canonical_path: str, noindex: bool=False):
    return render_template(
        template_name,
        meta_title=meta_title,
        meta_description=meta_description,
        h1=h1,
        lead=lead,
        canonical_url=_canonical_url(canonical_path),
        noindex=noindex,
        now_year=datetime.utcnow().year,
    )

# ====================
# Primary app routes (preserve existing look + functionality)
# ====================

@app.route('/')
def index():
    # Keep the SPA as the homepage to preserve existing UX.
    return _render_index()


# ====================
# Referral onboarding (Phase 2, additive)
# ====================

@app.route('/r/<referral_code>')
def referral_onboarding(referral_code: str):
    """Referral onboarding page.

    - Mobile-first orientation page with 4 CTAs (Presale, Airdrop, Staking, Telegram)
    - Server-side click tracking (cookie guarded)
    - If code is invalid: show a friendly error but still allow navigation
    """
    code = (referral_code or '').strip().upper()
    if not code:
        return redirect(url_for('index'))

    referrer = User.query.filter_by(referral_code=code).first()
    valid = bool(referrer)

    # ---- server-side click tracking (only for valid codes) ----
    cookie_key = f"ref_click_{code}"
    already_counted = request.cookies.get(cookie_key) == '1'
    if valid and not already_counted:
        try:
            referrer.link_clicks = int(referrer.link_clicks or 0) + 1
            db.session.commit()
        except Exception:
            db.session.rollback()

    # Build 4 CTA urls
    if valid:
        presale_url = url_for('index') + f"?ref={code}"
        airdrop_url = f"/airdrop?ref={code}"
        staking_url = f"/stake?ref={code}"
    else:
        presale_url = url_for('index')
        airdrop_url = "/airdrop"
        staking_url = "/stake"

    resp = make_response(render_template(
        'referral_onboarding.html',
        referral_code=code,
        valid_referral=valid,
        presale_url=presale_url,
        airdrop_url=airdrop_url,
        staking_url=staking_url,
        telegram_channel_url=TELEGRAM_CHANNEL_URL_DEFAULT,
        referrer_wallet=(getattr(referrer, 'wallet_address', None) or getattr(referrer, 'wallet', '') or '') if referrer else '',
    ))
    if valid and not already_counted:
        resp.set_cookie(cookie_key, '1', max_age=30*24*60*60, samesite='Lax')
    return resp




@app.post("/api/track/referral")
def track_referral_event():
    """Anonymous analytics endpoint for the referral onboarding page."""
    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    code = (payload.get("referral_code") or "").strip().upper()
    event = (payload.get("event") or "").strip()

    allowed = {"landing_view", "click_presale", "click_airdrop", "click_staking", "click_telegram"}
    if not code or event not in allowed:
        return jsonify({"ok": False}), 400

    # Hash IP for basic dedupe without storing raw IP.
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    salt = (os.getenv("ANALYTICS_SALT") or "opn").encode("utf-8")
    ip_hash = None
    try:
        if ip:
            ip_hash = hashlib.sha256(salt + ip.encode("utf-8")).hexdigest()
    except Exception:
        ip_hash = None

    ua = (request.headers.get("User-Agent") or "")[:300]

    try:
        db.session.add(ReferralTrafficEvent(
            referral_code=code,
            event=event,
            ua=ua,
            ip_hash=ip_hash,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"ok": False}), 500

    return jsonify({"ok": True})


# SEO-friendly section URLs (frontend uses these to open sections)
@app.route('/tokenomics')
@app.route('/roadmap')
@app.route('/partners')
@app.route('/team')
@app.route('/airdrop')
def section_pages():
    return _render_index()


@app.route('/presale')
def presale_alias():
    # Keep presale canonical on homepage (existing behavior)
    return redirect(url_for('index'), code=301)


# ====================
# SEO pages (indexable) live under /learn/* so we don't break the SPA routes.
# ====================

@app.route('/learn')
def seo_home():
    return _render_seo(
        'seo_home.html',
        meta_title='Official Site • Airdrop, Presale, Referrals & Updates',
        meta_description='Learn how the airdrop, referrals, presale contributions, withdrawals, and security work — clearly and transparently.',
        h1='Official project overview',
        lead='Airdrop details, presale info, referral program, and security guidance — all in one place.',
        canonical_path='/learn'
    )

@app.route('/learn/airdrop')
def seo_airdrop():
    return _render_seo(
        'seo_airdrop.html',
        meta_title='Airdrop • Eligibility, Rewards & How It Works',
        meta_description='Understand the airdrop mechanics, eligibility, referral impact, and where to check your status.',
        h1='Airdrop overview',
        lead='Eligibility, rewards, referrals, and common questions.',
        canonical_path='/learn/airdrop'
    )

@app.route('/learn/presale')
def seo_presale():
    return _render_seo(
        'seo_presale.html',
        meta_title='Presale • Contribution Options & Verification',
        meta_description='Presale participation overview, contribution options, and how verification is handled.',
        h1='Presale overview',
        lead='Contribution options, transparency, and verification expectations.',
        canonical_path='/learn/presale'
    )

@app.route('/learn/how-it-works')
def seo_how_it_works():
    return _render_seo(
        'seo_how_it_works.html',
        meta_title='How It Works • Airdrop, Referrals, Tasks & Status',
        meta_description='A clear, end-to-end explanation of how the system works from participation to tracking status.',
        h1='How it works',
        lead='A simple end-to-end walkthrough.',
        canonical_path='/learn/how-it-works'
    )

@app.route('/learn/referral-program')
def seo_referral_program():
    return _render_seo(
        'seo_referral_program.html',
        meta_title='Referral Program • How Referrals Affect Rewards',
        meta_description='Learn how referrals can increase rewards and where to view your referral stats.',
        h1='Referral program',
        lead='How referrals work and what to expect.',
        canonical_path='/learn/referral-program'
    )

@app.route('/learn/withdrawals')
def seo_withdrawals():
    return _render_seo(
        'seo_withdrawals.html',
        meta_title='Withdrawals • Requirements, Fees & Timing',
        meta_description='Understand withdrawal requirements and fee transparency, and where to check your status.',
        h1='Withdrawals overview',
        lead='Requirements, fee transparency, and what to check in the app.',
        canonical_path='/learn/withdrawals'
    )

@app.route('/learn/faq')
def seo_faq():
    return _render_seo(
        'seo_faq.html',
        meta_title='FAQ • Common Questions Answered',
        meta_description='Fast answers to common questions about eligibility, safety, and participation.',
        h1='FAQ',
        lead='Common questions and clear answers.',
        canonical_path='/learn/faq'
    )

@app.route('/learn/security')
def seo_security():
    return _render_seo(
        'seo_security.html',
        meta_title='Security • Safety Rules & What We Never Ask For',
        meta_description='Security guidance: what we never ask for, and how to verify transactions safely.',
        h1='Security & safety',
        lead='Practical rules to protect yourself and verify intent.',
        canonical_path='/learn/security'
    )

# Existing sections converted into real SEO pages (kept under /learn so we don't shadow SPA routes)
@app.route('/learn/tokenomics')
def seo_tokenomics():
    return _render_seo(
        'seo_tokenomics.html',
        meta_title='Tokenomics • Distribution & Utility',
        meta_description='Tokenomics overview: distribution, utility, and economics.',
        h1='Tokenomics',
        lead='Distribution, utility, and economics overview.',
        canonical_path='/learn/tokenomics'
    )

@app.route('/learn/roadmap')
def seo_roadmap():
    return _render_seo(
        'seo_roadmap.html',
        meta_title='Roadmap • Milestones & Progress',
        meta_description='Roadmap and milestones: what’s planned and what’s shipping.',
        h1='Roadmap',
        lead='Milestones and progress.',
        canonical_path='/learn/roadmap'
    )

@app.route('/learn/partners')
def seo_partners():
    return _render_seo(
        'seo_partners.html',
        meta_title='Partners • Ecosystem',
        meta_description='Partner and ecosystem overview.',
        h1='Partners',
        lead='Ecosystem and partner overview.',
        canonical_path='/learn/partners'
    )

@app.route('/learn/team')
def seo_team():
    return _render_seo(
        'seo_team.html',
        meta_title='Team • Contributors',
        meta_description='Team and contributors overview.',
        h1='Team',
        lead='Team and contributors overview.',
        canonical_path='/learn/team'
    )

@app.route('/learn/about')
def seo_about():
    return _render_seo(
        'seo_about.html',
        meta_title='About • Project Overview',
        meta_description='Project background and mission.',
        h1='About',
        lead='Project background and mission.',
        canonical_path='/learn/about'
    )

@app.route('/learn/contact')
def seo_contact():
    return _render_seo(
        'seo_contact.html',
        meta_title='Contact • Support',
        meta_description='How to reach support and official channels.',
        h1='Contact',
        lead='Support and official channels.',
        canonical_path='/learn/contact'
    )

@app.route('/learn/privacy')
def seo_privacy():
    return _render_seo(
        'seo_privacy.html',
        meta_title='Privacy Policy',
        meta_description='Privacy policy and data handling.',
        h1='Privacy Policy',
        lead='How data is handled.',
        canonical_path='/learn/privacy'
    )

@app.route('/learn/terms')
def seo_terms():
    return _render_seo(
        'seo_terms.html',
        meta_title='Terms of Use',
        meta_description='Terms of use and disclaimers.',
        h1='Terms',
        lead='Terms of use and disclaimers.',
        canonical_path='/learn/terms'
    )

@app.route('/robots.txt')
def robots_txt():
    lines = [
        "User-agent: *",
        "Disallow: /app",
        "Disallow: /app/",
        "Disallow: /admin",
        "Disallow: /admin/",
        "Disallow: /api",
        "Disallow: /api/",
        "Sitemap: " + _canonical_url('/sitemap.xml'),
    ]
    return ("\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"})

@app.route('/sitemap.xml')
def sitemap_xml():
    # Keep this list aligned with SEO routes above
    urls = [
        '/learn',
        '/learn/airdrop',
        '/learn/presale',
        '/learn/how-it-works',
        '/learn/referral-program',
        '/learn/withdrawals',
        '/learn/faq',
        '/learn/security',
        '/learn/tokenomics',
        '/learn/roadmap',
        '/learn/partners',
        '/learn/team',
        '/learn/about',
        '/learn/contact',
        '/learn/privacy',
        '/learn/terms'
    ]
    lastmod = datetime.utcnow().date().isoformat()
    xml_items = []
    for p in urls:
        xml_items.append(f"<url><loc>{_canonical_url(p)}</loc><lastmod>{lastmod}</lastmod></url>")
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(xml_items)
        + '\n</urlset>\n'
    )
    return (xml, 200, {"Content-Type": "application/xml; charset=utf-8"})



@app.after_request
def add_robots_headers(resp):
    # Ensure app/admin are not indexed even if linked
    path = request.path or ""
    noindex_paths = {
        '/', '/airdrop', '/tokenomics', '/roadmap', '/partners', '/team'
    }
    if path in noindex_paths or path.startswith('/app') or path.startswith('/admin') or path.startswith('/api'):
        resp.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return resp

@app.before_request

def check_ip_restriction():
    if request.endpoint in ['check_wallet', 'claim_airdrop']:
        ip_address = get_client_ip()
        
        wallet_address = None
        if request.is_json:
            data = request.get_json(silent=True) or {}
            wallet_address = data.get('wallet_address', '').strip().lower()
        
        if wallet_address == ADMIN_WALLET.lower():
            return
        
        restriction = IPRestriction.query.filter_by(ip_address=ip_address).first()
        
        if restriction:
            # If a temporary ban has expired, clear it and reset the counter.
            # This keeps "temporary" bans from becoming effectively permanent.
            if restriction.banned_until and datetime.utcnow() >= restriction.banned_until:
                restriction.banned_until = None
                restriction.wallet_count = 0
                db.session.commit()

            if restriction.banned_until and datetime.utcnow() < restriction.banned_until:
                return jsonify({
                    'success': False,
                    'message': f'IP temporarily restricted. Try again after {restriction.banned_until.strftime("%Y-%m-%d %H:%M UTC")}'
                }), 429
            
            if restriction.wallet_count >= MAX_WALLETS_PER_IP:
                restriction.banned_until = datetime.utcnow() + timedelta(hours=IP_BAN_HOURS)
                db.session.commit()
                return jsonify({
                    'success': False,
                    'message': f'Maximum wallet limit ({MAX_WALLETS_PER_IP}) reached from this IP address. Temporary restriction applied.'
                }), 429

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/api/check-wallet', methods=['GET','POST'])
@limiter.limit("10 per minute")
def check_wallet():
    data = request.get_json(silent=True) or {}
    # Support both POST (JSON) and GET (querystring) to avoid 405s from clients
    wallet_address = (data.get('wallet_address') or data.get('wallet') or request.args.get('wallet_address') or request.args.get('wallet') or '').strip()
    
    is_valid, wallet_or_error = AirdropSystem.validate_wallet_address(wallet_address)
    if not is_valid:
        return jsonify({
            'success': False,
            'eligible': False,
            'message': wallet_or_error
        })
    
    wallet_address = wallet_or_error
    
    ip_address = get_client_ip()
    
    claim = AirdropClaim.query.filter_by(wallet=wallet_address).first()
    
    if claim:
        user = User.query.get(wallet_address)
        current_referral_count = user.referral_count if user else 0
        
        achievement_rewards = calculate_achievement_rewards(wallet_address)
        
        # Base amount is fixed per wallet. Prefer persisted claim value.
        base_amount = int(getattr(claim, 'base_amount', 0) or (getattr(user, 'welcome_bonus', 0) if user else 0) or 1005)
        total_amount = AirdropSystem.calculate_airdrop_amount(
            base_amount,
            int(current_referral_count or 0),
            int(achievement_rewards or 0)
        )
        
        return jsonify({
            'success': True,
            'eligible': False,
            'message': 'Wallet has already claimed tokens',
            'already_claimed': True,
            'claim_data': {
                'amount': total_amount,
                'base_amount': int(base_amount),
                'referral_bonus': current_referral_count * 121,
                'achievement_rewards': int(achievement_rewards or 0),
                'referral_count': current_referral_count,
                'tx_hash': claim.tx_hash,
                'timestamp': claim.claimed_at.isoformat(),
                'referrer': claim.referrer
            },
            'referral_code': user.referral_code if user else None,
            'can_still_refer': True
        })
    
    is_eligible = True
    reasons = []
    
    if len(wallet_address.replace('0x', '')) < 40:
        is_eligible = False
        reasons.append("Invalid wallet format")
    
    if is_eligible:
        restriction = IPRestriction.query.filter_by(ip_address=ip_address).first()
        if restriction and restriction.wallet_count >= MAX_WALLETS_PER_IP:
            is_eligible = False
            reasons.append(f"Maximum wallets ({MAX_WALLETS_PER_IP}) reached from this IP")
    
    referral_code = None
    user = User.query.get(wallet_address)
    user_exists = user is not None
    
    if is_eligible:
        if not user_exists:
            referral_code = AirdropSystem.generate_referral_code(wallet_address)
            user = User(
                wallet=wallet_address,
                referral_code=referral_code,
                referral_count=0,
                link_clicks=0,
                link_conversions=0,
                referrer=None,
                active=False,
                ip_address=ip_address,
                last_active=datetime.utcnow()
            )
            db.session.add(user)
            _touch_user_activity(user, datetime.utcnow())
            
            restriction = IPRestriction.query.filter_by(ip_address=ip_address).first()
            if restriction:
                restriction.wallet_count += 1
                restriction.last_wallet_created = datetime.utcnow()
            else:
                restriction = IPRestriction(
                    ip_address=ip_address,
                    wallet_count=1,
                    last_wallet_created=datetime.utcnow()
                )
                db.session.add(restriction)
            
            notification = Notification(
                id=AirdropSystem.generate_notification_id(),
                wallet=wallet_address,
                type='welcome',
                message='Welcome to Opinion (OPN) Airdrop! Claim your first tokens.',
                timestamp=datetime.utcnow(),
                read=False
            )
            db.session.add(notification)
            
            db.session.commit()
        else:
            referral_code = user.referral_code
            _touch_user_activity(user, datetime.utcnow())
            db.session.commit()

    # Assign welcome bonus ONCE on the first eligibility check.
    base_amount = 0
    if is_eligible and user:
        base_amount = int(assign_welcome_bonus_if_needed(user))
    
    return jsonify({
        'success': True,
        'eligible': is_eligible,
        'message': 'Wallet is eligible for airdrop' if is_eligible else 'Not eligible: ' + ', '.join(reasons),
        'referral_code': referral_code,
        'base_amount': int(base_amount),
        'user_exists': user_exists
    })


@app.route('/api/balances', methods=['GET'])
@limiter.limit("60 per minute")
def api_balances():
    """Canonical balances endpoint for uniform dashboard display.

    This endpoint is additive and does not change existing endpoint semantics.
    The UI should use data.balances.display_total as the single source of truth
    for the sticky balance header.
    """
    wallet_address = (request.args.get('wallet') or '').strip()
    is_valid, wallet_or_error = AirdropSystem.validate_wallet_address(wallet_address)
    if not is_valid:
        return jsonify({'success': False, 'message': wallet_or_error, 'balances': None}), 400

    wallet_address = wallet_or_error
    balances = _compute_balances_v1(wallet_address)
    return jsonify({'success': True, 'wallet': wallet_address, 'balances': balances})

@app.route('/api/claim-airdrop', methods=['POST'])
@limiter.limit("5 per minute")
def claim_airdrop():
    data = request.json or {}
    # Support both POST (JSON) and GET (querystring) to avoid 405s from clients
    wallet_address = (data.get('wallet_address') or data.get('wallet') or request.args.get('wallet_address') or request.args.get('wallet') or '').strip()
    referral_code_used = data.get('referral_code', '').strip().upper()
    
    is_valid, wallet_or_error = AirdropSystem.validate_wallet_address(wallet_address)
    if not is_valid:
        return jsonify({
            'success': False,
            'message': wallet_or_error
        })
    
    wallet_address = wallet_or_error
    
    existing_claim = AirdropClaim.query.filter_by(wallet=wallet_address).first()
    if existing_claim:
        user = User.query.get(wallet_address)
        current_referral_count = user.referral_count if user else 0
        
        achievement_rewards = calculate_achievement_rewards(wallet_address)
        
        base_amount = int(getattr(existing_claim, 'base_amount', 0) or (getattr(user, 'welcome_bonus', 0) if user else 0) or 1005)
        total_amount = AirdropSystem.calculate_airdrop_amount(
            base_amount,
            int(current_referral_count or 0),
            int(achievement_rewards or 0)
        )
        
        claim_data = {
            'amount': total_amount,
            'base_amount': int(base_amount),
            'referral_bonus': current_referral_count * 121,
            'achievement_rewards': int(achievement_rewards or 0),
            'referral_count': current_referral_count,
            'tx_hash': existing_claim.tx_hash,
            'timestamp': existing_claim.claimed_at.isoformat()
        }
        
        return jsonify({
            'success': True,
            'message': 'Airdrop already claimed',
            'already_claimed': True,
            'data': claim_data
        })
    
    user = User.query.get(wallet_address)
    if not user:
        referral_code = AirdropSystem.generate_referral_code(wallet_address)
        user = User(
            wallet=wallet_address,
            referral_code=referral_code,
            referral_count=0,
            link_clicks=0,
            link_conversions=0,
            referrer=None,
            active=False,
            ip_address=get_client_ip(),
            last_active=datetime.utcnow()
        )
        db.session.add(user)
        _touch_user_activity(user, datetime.utcnow())

    # Ensure the wallet has a persisted welcome bonus (assigned once).
    base_amount = int(assign_welcome_bonus_if_needed(user))
    
    referrer_wallet = None
    if referral_code_used:
        referrer = User.query.filter_by(referral_code=referral_code_used).first()
        if referrer and referrer.wallet != wallet_address:
            referrer_wallet = referrer.wallet
            
            referrer.referral_count += 1
            referrer.link_conversions += 1
            
            if referrer.referral_count >= 2:
                referrer.active = True
            
            referral = Referral(
                id=AirdropSystem.generate_referral_id(referrer_wallet, wallet_address),
                referrer=referrer_wallet,
                referee=wallet_address,
                code_used=referral_code_used,
                timestamp=datetime.utcnow()
            )
            db.session.add(referral)
            
            user.referrer = referrer_wallet
            
            check_and_award_achievements(referrer_wallet)
            
            notification = Notification(
                id=AirdropSystem.generate_notification_id(),
                wallet=referrer_wallet,
                type='referral',
                message=f'🎉 New referral! {wallet_address[:6]}... claimed using your code',
                timestamp=datetime.utcnow(),
                read=False
            )
            db.session.add(notification)

            # Activity feed: referrer gained a new direct referral conversion.
            _log_activity(
                referrer_wallet,
                'referral_joined',
                f'New referral claimed: {wallet_address[:6]}...{wallet_address[-4:]}',
                {'referee': wallet_address, 'code_used': referral_code_used}
            )
    
    referral_count = int(user.referral_count or 0)

    # Ensure "first_claim" achievement exists BEFORE computing achievement rewards,
    # so the claim amount and returned achievement_rewards stay consistent.
    if Achievement.query.filter_by(wallet=wallet_address, achievement_id='first_claim').first() is None:
        achievement = Achievement(
            wallet=wallet_address,
            achievement_id='first_claim'
        )
        db.session.add(achievement)
        db.session.flush()  # visible within this transaction

    achievement_rewards = int(calculate_achievement_rewards(wallet_address) or 0)

    total_amount = AirdropSystem.calculate_airdrop_amount(
        int(base_amount),
        int(referral_count),
        int(achievement_rewards)
    )

    claim = AirdropClaim(
        wallet=wallet_address,
        amount=int(total_amount),
        base_amount=int(base_amount),
        referral_bonus=int(referral_count * 121),
        achievement_rewards=int(achievement_rewards),
        referral_count=referral_count,
        referrer=referrer_wallet,
        tx_hash=AirdropSystem.generate_tx_hash(),
        claimed_at=datetime.utcnow(),
        status='completed'
    )
    db.session.add(claim)

    notification = Notification(

        id=AirdropSystem.generate_notification_id(),
        wallet=wallet_address,
        type='claim',
        message=f'✅ Successfully claimed {int(total_amount)} OPN tokens!',
        timestamp=datetime.utcnow(),
        read=False
    )
    db.session.add(notification)

    # Activity feed: user claimed.
    _log_activity(
        wallet_address,
        'claim',
        f'Claimed {int(total_amount)} OPN',
        {'amount': float(total_amount)}
    )
    
    db.session.commit()
    
    check_and_award_achievements(wallet_address)
    
    return jsonify({
        'success': True,
        'message': 'Airdrop claimed successfully!',
        'data': {
            'amount': int(total_amount),
            'base_amount': int(base_amount),
            'referral_bonus': referral_count * 121,
            'achievement_rewards': int(achievement_rewards or 0),
            'referral_count': referral_count,
            'tx_hash': claim.tx_hash,
            'timestamp': claim.claimed_at.isoformat()
        },
        'referral_code': user.referral_code
    })

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    try:
        users = User.query.order_by(
            User.referral_count.desc(),
            User.created_at.asc()
        ).limit(20).all()
        
        top_referrers = []
        for user in users:
            achievement_rewards = calculate_achievement_rewards(user.wallet)
            task_earnings = float(getattr(user, 'task_points', 0) or 0)
            claim_window_earnings = float(calculate_claim_window_earnings(user.wallet) or 0)

            claim = AirdropClaim.query.filter_by(wallet=user.wallet).first()
            
            # Keep leaderboard metric as referrals, but show a richer total tokens number.
            welcome_bonus = float(int(getattr(user, 'welcome_bonus', 0) or 0))
            total_tokens = welcome_bonus + float(user.referral_count * 121) + float(achievement_rewards) + task_earnings + claim_window_earnings
            
            top_referrers.append({
                'wallet': user.wallet,
                'display_wallet': f"{user.wallet[:6]}...{user.wallet[-4:]}",
                'referral_count': user.referral_count,
                'referral_bonus': user.referral_count * 121,
                'achievement_rewards': float(achievement_rewards),
                'total_tokens': total_tokens,
                'is_active': user.active,
                'claimed': claim is not None
            })
        
        for i, ref in enumerate(top_referrers):
            ref['rank'] = i + 1
        
        current_wallet = request.args.get('wallet', '').strip().lower()
        current_user_rank = None
        
        if current_wallet:
            current_user = User.query.get(current_wallet)
            if current_user:
                all_users = User.query.order_by(
                    User.referral_count.desc(),
                    User.created_at.asc()
                ).all()
                
                user_rank = 1
                for user in all_users:
                    if user.wallet == current_wallet:
                        break
                    user_rank += 1
                
                achievement_rewards = calculate_achievement_rewards(current_wallet)
                task_earnings = float(getattr(current_user, 'task_points', 0) or 0)
                claim_window_earnings = float(calculate_claim_window_earnings(current_wallet) or 0)

                claim = AirdropClaim.query.filter_by(wallet=current_wallet).first()
                
                welcome_bonus = float(int(getattr(current_user, 'welcome_bonus', 0) or 0))
                total_tokens = welcome_bonus + float(current_user.referral_count * 121) + float(achievement_rewards) + task_earnings + claim_window_earnings
                
                current_user_rank = {
                    'wallet': current_wallet,
                    'display_wallet': f"{current_wallet[:6]}...{current_wallet[-4:]}",
                    'referral_count': current_user.referral_count,
                    'referral_bonus': current_user.referral_count * 121,
                    'achievement_rewards': float(achievement_rewards),
                    'total_tokens': total_tokens,
                    'rank': user_rank,
                    'is_active': current_user.active,
                    'claimed': claim is not None
                }
        
        total_participants = User.query.count()
        total_referrals = Referral.query.count()
        total_claims = AirdropClaim.query.count()
        
        active_referrers = User.query.filter(User.referral_count > 0).count()
        
        avg_referrals = total_referrals / max(total_participants, 1)
        
        return jsonify({
            'success': True,
            'data': {
                'top_referrers': top_referrers,
                'current_user': current_user_rank,
                'total_participants': total_participants,
                'total_claims': total_claims,
                'total_referrals': total_referrals,
                'active_referrers': active_referrers,
                'avg_referrals': round(avg_referrals, 2),
                'last_updated': datetime.utcnow().isoformat()
            }
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error generating leaderboard: {str(e)}'
        })

# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # SQLAlchemy 2.x requires raw SQL to be wrapped in text().
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'success': True,
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'database': 'connected',
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500


# ==================== PRICE FEED (CACHED) ====================

@app.route('/api/prices', methods=['GET'])
@limiter.limit("60 per minute")
def get_prices():
    """Return cached USD prices for ETH, BNB, USDT, SOL.

    This endpoint exists to prevent CoinGecko rate-limiting (429) on the client.
    """
    ttl_s = int(os.getenv('PRICE_CACHE_TTL_SECONDS', '25'))
    now = time.time()

    # Serve cache if still fresh and has at least partial data
    if _PRICE_CACHE["ts"] and (now - _PRICE_CACHE["ts"]) < ttl_s:
        return jsonify({
            'success': True,
            'cached': True,
            'timestamp': _PRICE_CACHE["ts"],
            'prices': _PRICE_CACHE["data"],
            'error': _PRICE_CACHE.get('error')
        })

    # Refresh from CoinGecko
    try:
        prices = _fetch_prices_from_coingecko(timeout=10)
        # Keep last good values if CoinGecko returns None
        merged = dict(_PRICE_CACHE["data"])
        for k, v in prices.items():
            if v is not None:
                merged[k] = v
        _PRICE_CACHE["data"] = merged
        _PRICE_CACHE["ts"] = now
        _PRICE_CACHE["error"] = None
        return jsonify({
            'success': True,
            'cached': False,
            'timestamp': _PRICE_CACHE["ts"],
            'prices': _PRICE_CACHE["data"],
            'error': None
        })
    except Exception as e:
        # On error, serve stale cache (if any) rather than failing hard.
        _PRICE_CACHE["error"] = str(e)
        status = 200  # Always return 200; include success flag + error message for offline environments
        return jsonify({
            'success': bool(_PRICE_CACHE["ts"]),
            'cached': True,
            'timestamp': _PRICE_CACHE["ts"],
            'prices': _PRICE_CACHE["data"],
            'error': _PRICE_CACHE["error"]
        }), status



# -------------------------------
# Compatibility / tracking endpoints
# -------------------------------

@app.route('/api/track-share', methods=['POST'])
@limiter.limit("60 per minute")
def track_share():
    """Track share events from the front-end.

    Intentionally lightweight: records minimal metadata when present and
    returns a success response even if optional fields are missing.
    """
    data = request.get_json(silent=True) or {}
    # These fields are optional; we keep this endpoint as a no-op if models aren't available.
    wallet = (data.get('wallet') or data.get('wallet_address') or '').strip().lower()
    platform = (data.get('platform') or data.get('source') or '').strip()
    try:
        # If an Activity model exists, we can store it; otherwise just ignore.
        # (Avoid import errors in deployments that don't use activity logging.)
        from activity import log_activity  # type: ignore
        if wallet:
            log_activity(wallet, 'share', platform or None)
    except Exception:
        pass
    return jsonify({'success': True})


@app.route('/api/v3/simple/price', methods=['GET'])
@limiter.limit("60 per minute")
def coingecko_simple_price_proxy():
    """Proxy-compatible endpoint matching CoinGecko's simple/price path.

    Some front-ends (or copied snippets) may accidentally call a relative
    /api/v3/simple/price. We map it to our cached /api/prices values.
    """
    ids_raw = (request.args.get('ids') or 'ethereum,binancecoin,tether,solana').strip()
    vs_raw = (request.args.get('vs_currencies') or 'usd').strip()
    ids = [i.strip() for i in ids_raw.split(',') if i.strip()]
    vs = [v.strip() for v in vs_raw.split(',') if v.strip()]

    # Ensure cache is warm by calling the same internal fetch logic
    # without making this endpoint fail hard if the network is unavailable.
    try:
        # Reuse cached values
        prices = _PRICE_CACHE.get('data') or {}
    except Exception:
        prices = {}

    out = {}
    for asset in ids:
        if asset not in prices:
            continue
        out[asset] = {}
        for cur in vs:
            # We only support usd in our cache; return None for others.
            out[asset][cur] = prices.get(asset) if cur == 'usd' else None

    return jsonify(out)

# ==================== ADMIN DASHBOARD ====================

# Presale admin is gated via session flag 'admin_presale'.
# Login uses ADMIN_PRESALE_KEY (fallback to ADMIN_API_KEY).

def _presale_admin_key() -> str:
    return os.getenv('ADMIN_PRESALE_KEY') or os.getenv('ADMIN_API_KEY', 'admin123')


@app.get('/admin/presale/login')
def admin_presale_login_page():
    if flask_session.get('admin_presale') is True:
        return redirect(url_for('admin_presale_dashboard'))
    return render_template(
        'admin_section_login.html',
        section_title='Admin • Presale',
        post_url=url_for('admin_presale_login'),
    )


@app.post('/admin/presale/login')
def admin_presale_login():
    key = (request.form.get('key') or '').strip()
    if key and str(key) == str(_presale_admin_key()):
        flask_session['admin_presale'] = True
        return redirect(url_for('admin_presale_dashboard'))
    return render_template(
        'admin_section_login.html',
        section_title='Admin • Presale',
        post_url=url_for('admin_presale_login'),
        error='Invalid key',
    ), 403


@app.post('/admin/presale/logout')
def admin_presale_logout():
    flask_session.pop('admin_presale', None)
    return redirect(url_for('admin_presale_login_page'))


@app.route('/admin/presale', methods=['GET'])
def admin_presale_dashboard():
    if not flask_session.get('admin_presale') is True:
        return redirect(url_for('admin_presale_login_page'))
    
    try:
        total_usd = db.session.query(db.func.sum(PresaleTransaction.usd_amount)).scalar() or 0
        total_transactions = PresaleTransaction.query.count()
        unique_users = db.session.query(
            db.func.count(db.func.distinct(PresaleTransaction.user_address))
        ).scalar() or 0
        
        recent_transactions = PresaleTransaction.query.order_by(
            PresaleTransaction.timestamp.desc()
        ).limit(50).all()
        
        html = f'''
        <html>
        <head>
            <title>Presale Admin Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #0a0b2d; color: white; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .stats {{ display: flex; gap: 20px; margin-bottom: 30px; }}
                .stat-box {{ background: rgba(255,255,255,0.05); padding: 20px; border-radius: 12px; min-width: 200px; border: 1px solid rgba(255,255,255,0.1); }}
                .stat-box h3 {{ color: #00ff88; margin: 0 0 10px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; background: rgba(255,255,255,0.05); border-radius: 8px; overflow: hidden; }}
                th, td {{ border: 1px solid rgba(255,255,255,0.1); padding: 12px; text-align: left; }}
                th {{ background: rgba(0,255,136,0.1); color: #00ff88; }}
                tr:hover {{ background: rgba(255,255,255,0.02); }}
                a {{ color: #667eea; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                .network-badge {{ padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
                .eth {{ background: rgba(108, 99, 255, 0.2); color: #6c63ff; }}
                .bsc {{ background: rgba(240, 185, 11, 0.2); color: #f0b90b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Presale Admin Dashboard</h1>
                <form method="post" action="/admin/presale/logout" style="margin:10px 0 20px 0;">
                    <button type="submit" style="padding:8px 12px;border-radius:10px;border:1px solid rgba(255,255,255,0.15);background:rgba(255,255,255,0.06);color:white;cursor:pointer;">Logout</button>
                </form>
                <p>Presale Wallet: <code>{PRESALE_WALLET}</code></p>
                
                <div class="stats">
                    <div class="stat-box">
                        <h3>{total_transactions}</h3>
                        <p>Total Transactions</p>
                    </div>
                    <div class="stat-box">
                        <h3>${total_usd:,.2f}</h3>
                        <p>Total USD Raised</p>
                    </div>
                    <div class="stat-box">
                        <h3>{unique_users}</h3>
                        <p>Unique Contributors</p>
                    </div>
                </div>
                
                <h2>Recent Transactions</h2>
                <table>
                    <tr>
                        <th>Date</th>
                        <th>User</th>
                        <th>USD Amount</th>
                        <th>Crypto Amount</th>
                        <th>Token</th>
                        <th>Network</th>
                        <th>TX Hash</th>
                    </tr>
        '''
        
        for tx in recent_transactions:
            network_class = 'eth' if tx.network == 'ethereum' else 'bsc'
            explorer_url = f"https://{'etherscan.io' if tx.network == 'ethereum' else 'bscscan.com'}/tx/{tx.tx_hash}"
            html += f'''
                    <tr>
                        <td>{tx.timestamp.strftime('%Y-%m-%d %H:%M')}</td>
                        <td title="{tx.user_address}">{tx.user_address[:6]}...{tx.user_address[-4:]}</td>
                        <td>${tx.usd_amount:,.2f}</td>
                        <td>{tx.crypto_amount} {tx.token_name}</td>
                        <td>{tx.token}</td>
                        <td><span class="network-badge {network_class}">{tx.network.upper()}</span></td>
                        <td><a href="{explorer_url}" target="_blank">View</a></td>
                    </tr>
            '''
        
        html += '''
                </table>
            </div>
        </body>
        </html>
        '''
        
        return html
    
    except Exception as e:
        return f"Error: {str(e)}", 500

# Create tables

# ==================== TASK SYSTEM (SPLIT MODULES) ====================
# Import and register task blueprints.
# These imports must come after the base User model exists.
from models_tasks import Task, TaskSubmission, TaskRewardTransaction  # noqa: F401
from tasks import tasks_api
from admin_tasks import admin_tasks
from admin_withdrawals import admin_withdrawals
from admin_analytics import admin_analytics
from models_referral_analytics import ReferralTrafficEvent  # noqa: F401

# ==================== ANNOUNCEMENTS (WIDGET + ADMIN) ====================
from models_announcements import Announcement, AnnouncementView  # noqa: F401
from announcements import announcements_api
from admin_announcements import admin_announcements

# ==================== 1-HOUR CLAIM WINDOW (SPLIT MODULE) ====================
from models_claims import ClaimWindowClaim, ClaimWindowState  # noqa: F401
from claims import claims_api
from models_push import PushSubscription  # noqa: F401
from push_api import push_api

# ==================== STAKING MODULE ====================
from models_staking import StakingBalance, StakingDeposit, StakingWithdrawal, StakingAccrual, StakingNonce, StakingChainState  # noqa: F401
from staking import staking_bp


app.register_blueprint(tasks_api)
app.register_blueprint(admin_tasks)
app.register_blueprint(admin_withdrawals)
app.register_blueprint(announcements_api)
app.register_blueprint(admin_announcements)
app.register_blueprint(admin_analytics)
app.register_blueprint(claims_api)
app.register_blueprint(push_api)
app.register_blueprint(staking_bp)

with app.app_context():
    db.create_all()

    # ---- Lightweight schema upgrade (prod-friendly) ----
    # SQLAlchemy create_all() does not add new columns to existing tables.
    # If you deploy with an existing database (Render Postgres, etc.), missing columns will
    # crash critical endpoints like /api/check-wallet (eligibility) because SQLAlchemy will
    # SELECT columns that don't exist (e.g., users.task_points).
    def _ensure_columns(table_name: str, columns_sql: dict[str, str]):
        """Best-effort: add missing columns for SQLite/Postgres without a full migration tool."""
        dialect = db.engine.dialect.name

        if dialect == 'sqlite':
            existing = [r[1] for r in db.session.execute(text(f'PRAGMA table_info({table_name})')).fetchall()]
            for col, col_sql in columns_sql.items():
                if col not in existing:
                    db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {col_sql}'))
            db.session.commit()
            return

        if dialect in ('postgresql', 'postgres'):
            # Postgres supports ADD COLUMN IF NOT EXISTS (safe to run repeatedly).
            for _col, col_sql in columns_sql.items():
                db.session.execute(text(f'ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col_sql}'))
            db.session.commit()
            return

    try:
        # Users table: keep these in sync with the User model.
        _ensure_columns('users', {
            'task_points': 'task_points INTEGER NOT NULL DEFAULT 0',
            # The following are historically added fields; safe to ensure too.
            'active': 'active BOOLEAN NOT NULL DEFAULT FALSE',
            'ip_address': 'ip_address VARCHAR(45)',
            'last_active': 'last_active TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP',
            'level': "level INTEGER NOT NULL DEFAULT 1",
            'xp': "xp INTEGER NOT NULL DEFAULT 0",
            'streak_current': "streak_current INTEGER NOT NULL DEFAULT 0",
            'streak_longest': "streak_longest INTEGER NOT NULL DEFAULT 0",
            'streak_last_date': "streak_last_date DATE",
            'rank_tier': "rank_tier VARCHAR(30) NOT NULL DEFAULT 'Rookie'",
            'welcome_bonus': f"welcome_bonus INTEGER NOT NULL DEFAULT 0",
            'welcome_bonus_assigned_at': "welcome_bonus_assigned_at TIMESTAMP",
        })

        # Tasks table: some deployments may pre-date the task system.
        _ensure_columns('tasks', {
            'task_link': 'task_link VARCHAR(500)',
        })
    except Exception:
        # If the DB user lacks privileges or the table doesn't exist yet, ignore.
        # Proper schema migration is still recommended for long-term maintenance.
        db.session.rollback()

    # Create admin user if doesn't exist
    admin_user = User.query.get(ADMIN_WALLET.lower())
    if not admin_user:
        admin_user = User(
            wallet=ADMIN_WALLET.lower(),
            referral_code='ADMIN-REF',
            referral_count=0,
            link_clicks=0,
            link_conversions=0,
            referrer=None,
            active=True,
            ip_address='127.0.0.1',
            last_active=datetime.utcnow()
        )
        # Admin wallet uses a fixed welcome bonus for consistency in dashboards.
        admin_user.welcome_bonus = 1005
        admin_user.welcome_bonus_assigned_at = datetime.utcnow()
        db.session.add(admin_user)
        
        admin_claim = AirdropClaim(
            wallet=ADMIN_WALLET.lower(),
            amount=10000,
            base_amount=1005,
            referral_bonus=0,
            achievement_rewards=0,
            referral_count=0,
            referrer=None,
            tx_hash='0x' + '0' * 64,
            claimed_at=datetime.utcnow(),
            status='admin'
        )
        db.session.add(admin_claim)
        
        db.session.commit()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    
    print("=" * 60)
    print("Opinion (OPN) Presale & Airdrop Platform")
    print("=" * 60)
    print(f"Presale Wallet: {PRESALE_WALLET}")
    print(f"Admin Presale: http://localhost:{port}/admin/presale/login")
    print(f"Admin Tasks: http://localhost:{port}/admin/tasks/login")
    print(f"Admin Withdrawals: http://localhost:{port}/admin/withdrawals/login")
    print(f"Admin Announcements: http://localhost:{port}/admin/announcements/login")
    print(f"Admin Staking: http://localhost:{port}/admin/staking/login")
    print(f"Main Site: http://localhost:{port}")
    print("=" * 60)
    print(f"Achievements System: {len(ACHIEVEMENTS)} achievements")
    print("=" * 60)
    
    app.run(debug=debug, port=port)