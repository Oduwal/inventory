"""
remove_mock_data.py  —  Run from your project root:

    $env:SESSION_SECRET = "local-dev-secret-at-least-32-chars-long"
    .venv\Scripts\python.exe remove_mock_data.py

Removes ALL records inserted by seed_mock_data.py.
Identified by the [MOCK] tag in names/notes.
Does NOT touch your real data.
"""

import os, sys
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("SESSION_SECRET", "local-dev-secret-at-least-32-chars-long-seed")

from app.database import engine
from app.models import Branch, User, Item, Transaction, Delivery, DeliveryItem, CashEntry, StockTransfer, StockTransferItem
from sqlalchemy.orm import Session
from sqlalchemy import select

TAG = "[MOCK]"

with Session(engine) as db:

    # ── find mock branches ───────────────────────────────────────────────────
    mock_branches = db.scalars(select(Branch).where(Branch.name.like(f"{TAG}%"))).all()
    mock_branch_ids = [b.id for b in mock_branches]

    if not mock_branch_ids:
        print("No mock data found. Nothing to remove.")
        exit(0)

    print(f"Found {len(mock_branch_ids)} mock branch(es): {[b.name for b in mock_branches]}")

    # ── stock transfer items + transfers ─────────────────────────────────────
    mock_transfers = db.scalars(
        select(StockTransfer).where(
            (StockTransfer.from_branch_id.in_(mock_branch_ids)) |
            (StockTransfer.to_branch_id.in_(mock_branch_ids))
        )
    ).all()
    transfer_ids = [t.id for t in mock_transfers]
    if transfer_ids:
        db.query(StockTransferItem).filter(StockTransferItem.transfer_id.in_(transfer_ids)).delete(synchronize_session=False)
        db.query(StockTransfer).filter(StockTransfer.id.in_(transfer_ids)).delete(synchronize_session=False)
    print(f"  Removed {len(transfer_ids)} stock transfer(s)")

    # ── delivery items + deliveries ──────────────────────────────────────────
    mock_deliveries = db.scalars(
        select(Delivery).where(Delivery.branch_id.in_(mock_branch_ids))
    ).all()
    delivery_ids = [d.id for d in mock_deliveries]
    if delivery_ids:
        db.query(DeliveryItem).filter(DeliveryItem.delivery_id.in_(delivery_ids)).delete(synchronize_session=False)
        db.query(Delivery).filter(Delivery.id.in_(delivery_ids)).delete(synchronize_session=False)
    print(f"  Removed {len(delivery_ids)} delivery record(s)")

    # ── cash entries ─────────────────────────────────────────────────────────
    n_cash = db.query(CashEntry).filter(CashEntry.branch_id.in_(mock_branch_ids)).delete(synchronize_session=False)
    print(f"  Removed {n_cash} cash entry/entries")

    # ── transactions ─────────────────────────────────────────────────────────
    n_tx = db.query(Transaction).filter(Transaction.branch_id.in_(mock_branch_ids)).delete(synchronize_session=False)
    print(f"  Removed {n_tx} transaction(s)")

    # ── items ────────────────────────────────────────────────────────────────
    n_items = db.query(Item).filter(Item.branch_id.in_(mock_branch_ids)).delete(synchronize_session=False)
    print(f"  Removed {n_items} item(s)")

    # ── users (agents + admins) for mock branches ────────────────────────────
    n_users = db.query(User).filter(
        User.branch_id.in_(mock_branch_ids),
        User.full_name.like(f"{TAG}%")
    ).delete(synchronize_session=False)
    print(f"  Removed {n_users} user(s)")

    # ── branches ─────────────────────────────────────────────────────────────
    for b in mock_branches:
        db.delete(b)
    print(f"  Removed {len(mock_branches)} branch(es)")

    db.commit()
    print("\n✅ All mock data removed cleanly.\n")
