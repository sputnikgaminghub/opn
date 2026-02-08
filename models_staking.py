"""Staking models (ETH/BNB principal + daily token rewards).

This module is designed to integrate cleanly with the existing wallet-first User model:
- users.wallet is the identity key
- staking_* tables namespace avoids collisions with presale/airdrop models
"""

from datetime import datetime, date
from decimal import Decimal
from sqlalchemy import (
    Column, Integer, String, DateTime, Numeric, ForeignKey, Index, UniqueConstraint
)
from extensions import db

STAKE_CHAIN_ETH = "ETH"
STAKE_CHAIN_BSC = "BSC"

STAKE_DEPOSIT_PENDING = "pending"
STAKE_DEPOSIT_CONFIRMED = "confirmed"

STAKE_WDRAW_SUBMITTED = "submitted"
STAKE_WDRAW_APPROVED = "approved"
STAKE_WDRAW_REJECTED = "rejected"
STAKE_WDRAW_PAID = "paid"

STAKE_WDRAW_EARNED = "EARNED_TOKENS"
STAKE_WDRAW_PRINCIPAL_ETH = "PRINCIPAL_ETH"
STAKE_WDRAW_PRINCIPAL_BNB = "PRINCIPAL_BNB"


class StakingNonce(db.Model):
    __tablename__ = "staking_nonces"
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), nullable=False, index=True)
    nonce = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_staking_nonce_wallet_created", "wallet", "created_at"),
    )


class StakingBalance(db.Model):
    __tablename__ = "staking_balances"
    wallet = Column(String(42), ForeignKey("users.wallet"), primary_key=True)
    principal_eth = Column(Numeric(38, 18), nullable=False, default=Decimal("0"))
    principal_bnb = Column(Numeric(38, 18), nullable=False, default=Decimal("0"))
    earned_tokens = Column(Numeric(38, 18), nullable=False, default=Decimal("0"))
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class StakingDeposit(db.Model):
    __tablename__ = "staking_deposits"
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), ForeignKey("users.wallet"), nullable=False, index=True)

    chain = Column(String(8), nullable=False)   # ETH / BSC
    asset = Column(String(8), nullable=False)   # ETH / BNB

    tx_hash = Column(String(80), nullable=False, unique=True, index=True)
    from_address = Column(String(42), nullable=False)
    to_address = Column(String(42), nullable=False)

    amount = Column(Numeric(38, 18), nullable=False, default=Decimal("0"))
    block_number = Column(Integer, nullable=False, default=0)  # 0 = announced only
    confirmations = Column(Integer, nullable=False, default=0)
    status = Column(String(20), nullable=False, default=STAKE_DEPOSIT_PENDING)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_staking_deposits_wallet_created", "wallet", "created_at"),
    )


class StakingAccrual(db.Model):
    __tablename__ = "staking_accruals"
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), ForeignKey("users.wallet"), nullable=False, index=True)
    accrual_date = Column(db.Date, nullable=False)

    principal_eth_snapshot = Column(Numeric(38, 18), nullable=False)
    principal_bnb_snapshot = Column(Numeric(38, 18), nullable=False)
    tokens_added = Column(Numeric(38, 18), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("wallet", "accrual_date", name="uq_staking_accrual_wallet_date"),
        Index("idx_staking_accrual_wallet_date", "wallet", "accrual_date"),
    )


class StakingWithdrawal(db.Model):
    __tablename__ = "staking_withdrawals"
    id = Column(Integer, primary_key=True)
    wallet = Column(String(42), ForeignKey("users.wallet"), nullable=False, index=True)

    type = Column(String(32), nullable=False)  # EARNED_TOKENS / PRINCIPAL_ETH / PRINCIPAL_BNB
    amount = Column(Numeric(38, 18), nullable=False)
    destination_address = Column(String(42), nullable=False)

    status = Column(String(20), nullable=False, default=STAKE_WDRAW_SUBMITTED)
    admin_note = Column(String(400), nullable=False, default="")
    payout_tx_hash = Column(String(90), nullable=False, default="")

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_staking_withdrawals_status_created", "status", "created_at"),
        Index("idx_staking_withdrawals_wallet_created", "wallet", "created_at"),
    )


class StakingChainState(db.Model):
    __tablename__ = "staking_chain_state"
    id = Column(Integer, primary_key=True)
    chain = Column(String(8), nullable=False, unique=True)  # ETH / BSC
    last_scanned_block = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
