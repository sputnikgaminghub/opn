"""Staking worker for Render (scan deposits + accrue daily rewards).

Run this as a Render 'worker' service:
  python staking_worker.py

Environment:
- DATABASE_URL (already configured in Render)
- STAKE_HOLDING_WALLET_ETH / STAKE_HOLDING_WALLET_BSC
- ETH_RPC_URL / BSC_RPC_URL
- STAKE_ETH_CONFIRMATIONS / STAKE_BSC_CONFIRMATIONS
- STAKE_REWARD_PER_*_PER_DAY
"""

from datetime import datetime, date, timezone
from decimal import Decimal
import os
import time

from extensions import db
from models_staking import (
    StakingChainState, StakingDeposit, StakingBalance, StakingAccrual,
    STAKE_CHAIN_ETH, STAKE_CHAIN_BSC,
    STAKE_DEPOSIT_PENDING, STAKE_DEPOSIT_CONFIRMED,
)
from app import app, _rpc_post, _hex_to_int, _normalize_addr

HOLDING_ETH = _normalize_addr(os.getenv("STAKE_HOLDING_WALLET_ETH", "0xa84e6D0Fa3B35b18FF7C65568C711A85Ac1A9FC7"))
HOLDING_BSC = _normalize_addr(os.getenv("STAKE_HOLDING_WALLET_BSC", "0xa84e6D0Fa3B35b18FF7C65568C711A85Ac1A9FC7"))

ETH_RPC = os.getenv("ETH_RPC_URL", "")
BSC_RPC = os.getenv("BSC_RPC_URL", "")

CONF_ETH = int(os.getenv("STAKE_ETH_CONFIRMATIONS", "12"))
CONF_BSC = int(os.getenv("STAKE_BSC_CONFIRMATIONS", "15"))

REWARD_BNB = Decimal(os.getenv("STAKE_REWARD_PER_BNB_PER_DAY", "50"))
REWARD_ETH = Decimal(os.getenv("STAKE_REWARD_PER_ETH_PER_DAY", "200"))

INTERVAL = int(os.getenv("STAKE_WATCHER_INTERVAL_SECONDS", "25"))

def _wei_to_dec(wei: int) -> Decimal:
    return Decimal(wei) / Decimal(10**18)

def _get_chain_state(chain: str) -> StakingChainState:
    st = StakingChainState.query.filter_by(chain=chain).first()
    if not st:
        st = StakingChainState(chain=chain, last_scanned_block=0, updated_at=datetime.utcnow())
        db.session.add(st)
        db.session.commit()
    return st

def _scan_chain(chain: str, rpc: str, holding: str, min_conf: int):
    if not rpc:
        return
    latest_hex = _rpc_post(rpc, "eth_blockNumber", [])
    latest = _hex_to_int(latest_hex)
    st = _get_chain_state(chain)
    start = st.last_scanned_block + 1
    if st.last_scanned_block == 0:
        start = max(1, latest - 250)

    if start > latest:
        return

    for bn in range(start, latest + 1):
        block_hex = hex(bn)
        block = _rpc_post(rpc, "eth_getBlockByNumber", [block_hex, True])
        txs = block.get("transactions") or []
        for tx in txs:
            to_addr = _normalize_addr(tx.get("to") or "")
            if to_addr != holding:
                continue
            value = _hex_to_int(tx.get("value"))
            if value <= 0:
                continue
            tx_hash = tx.get("hash")
            if not tx_hash:
                continue
            tx_hash = tx_hash.lower()
            if StakingDeposit.query.filter_by(tx_hash=tx_hash).first():
                continue

            from_addr = _normalize_addr(tx.get("from") or "")
            # Only credit if we have a user + staking balance
            bal = StakingBalance.query.get(from_addr)
            if not bal:
                continue

            asset = "ETH" if chain == STAKE_CHAIN_ETH else "BNB"
            dep = StakingDeposit(
                wallet=from_addr,
                chain=chain,
                asset=asset,
                tx_hash=tx_hash,
                from_address=from_addr,
                to_address=holding,
                amount=_wei_to_dec(value),
                block_number=bn,
                confirmations=max(0, latest - bn),
                status=STAKE_DEPOSIT_PENDING,
                created_at=datetime.utcnow(),
            )
            db.session.add(dep)

        st.last_scanned_block = bn
        st.updated_at = datetime.utcnow()
        db.session.add(st)
        db.session.commit()

    _update_confirmations_and_credit(chain, latest, min_conf)

def _update_confirmations_and_credit(chain: str, latest: int, min_conf: int):
    deps = StakingDeposit.query.filter_by(chain=chain, status=STAKE_DEPOSIT_PENDING).all()
    for dep in deps:
        if int(dep.block_number or 0) == 0:
            continue
        conf = max(0, latest - int(dep.block_number))
        dep.confirmations = conf
        if conf >= min_conf:
            dep.status = STAKE_DEPOSIT_CONFIRMED
            bal = StakingBalance.query.get(dep.wallet)
            if dep.asset == "ETH":
                bal.principal_eth = Decimal(bal.principal_eth or 0) + Decimal(dep.amount)
            else:
                bal.principal_bnb = Decimal(bal.principal_bnb or 0) + Decimal(dep.amount)
            bal.updated_at = datetime.utcnow()
            db.session.add(bal)
        db.session.add(dep)
    db.session.commit()

def _run_daily_accrual():
    today = date.today()
    bals = StakingBalance.query.all()
    for bal in bals:
        if StakingAccrual.query.filter_by(wallet=bal.wallet, accrual_date=today).first():
            continue
        pe = Decimal(bal.principal_eth or 0)
        pb = Decimal(bal.principal_bnb or 0)
        tokens = (pb * REWARD_BNB) + (pe * REWARD_ETH)
        if tokens < 0:
            tokens = Decimal("0")
        db.session.add(StakingAccrual(
            wallet=bal.wallet,
            accrual_date=today,
            principal_eth_snapshot=pe,
            principal_bnb_snapshot=pb,
            tokens_added=tokens,
            created_at=datetime.utcnow(),
        ))
        bal.earned_tokens = Decimal(bal.earned_tokens or 0) + tokens
        bal.updated_at = datetime.utcnow()
        db.session.add(bal)
    db.session.commit()

def main():
    print("Staking worker started")
    last_accrual_day = None
    while True:
        with app.app_context():
            try:
                _scan_chain(STAKE_CHAIN_ETH, ETH_RPC, HOLDING_ETH, CONF_ETH)
                _scan_chain(STAKE_CHAIN_BSC, BSC_RPC, HOLDING_BSC, CONF_BSC)
                # accrue once/day (UTC aligned by using local date; OK for prototype)
                today = date.today()
                if last_accrual_day != today:
                    _run_daily_accrual()
                    last_accrual_day = today
            except Exception as e:
                print("Worker error:", str(e))
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
