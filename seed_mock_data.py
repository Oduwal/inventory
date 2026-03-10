"""
seed_mock_data.py  —  Run from your project root:

    $env:SESSION_SECRET = "local-dev-secret-at-least-32-chars-long"
    .venv\Scripts\python.exe seed_mock_data.py

Inserts realistic mock data so you can inspect every screen.
Run remove_mock_data.py to wipe it all cleanly.

All mock records are tagged with  full_name starting with "[MOCK]"
or item names starting with "[MOCK]" so they are easy to find and delete.
"""

import os, sys, random
from datetime import datetime, timedelta

# ── make sure app package is importable ──────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("SESSION_SECRET", "local-dev-secret-at-least-32-chars-long-seed")

from app.database import engine, Base, get_db
# Models must be imported BEFORE create_all so SQLAlchemy knows the schema
from app.models import Branch, User, Item, Transaction, Delivery, DeliveryItem, CashEntry, StockTransfer, StockTransferItem

# Create tables if they don't exist yet (e.g. fresh local SQLite)
Base.metadata.create_all(bind=engine)
from sqlalchemy.orm import Session
from passlib.context import CryptContext

pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def h(p): return pwd.hash(p)

TAG = "[MOCK]"

def tag(name): return f"{TAG} {name}"

with Session(engine) as db:

    # ── 1. BRANCHES ──────────────────────────────────────────────────────────
    b1 = Branch(name=tag("Lagos Island"))
    b2 = Branch(name=tag("Abuja Central"))
    b3 = Branch(name=tag("Port Harcourt"))
    db.add_all([b1, b2, b3])
    db.flush()

    # ── 2. ADMINS (one per branch) ───────────────────────────────────────────
    a1 = User(username="mock_admin_lagos",   password_hash=h("Password1!"), role="ADMIN",
              full_name=tag("Admin Lagos"),   branch_id=b1.id)
    a2 = User(username="mock_admin_abuja",   password_hash=h("Password1!"), role="ADMIN",
              full_name=tag("Admin Abuja"),   branch_id=b2.id)
    a3 = User(username="mock_admin_ph",      password_hash=h("Password1!"), role="ADMIN",
              full_name=tag("Admin PH"),      branch_id=b3.id)
    db.add_all([a1, a2, a3])
    db.flush()

    # ── 3. AGENTS (two per branch) ───────────────────────────────────────────
    agents_b1 = [
        User(username="mock_agent_lagos1", password_hash=h("Password1!"), role="AGENT",
             full_name=tag("Emeka Obi"),    branch_id=b1.id, phone="08011111111"),
        User(username="mock_agent_lagos2", password_hash=h("Password1!"), role="AGENT",
             full_name=tag("Chisom Eze"),   branch_id=b1.id, phone="08022222222"),
    ]
    agents_b2 = [
        User(username="mock_agent_abuja1", password_hash=h("Password1!"), role="AGENT",
             full_name=tag("Musa Danjuma"), branch_id=b2.id, phone="08033333333"),
        User(username="mock_agent_abuja2", password_hash=h("Password1!"), role="AGENT",
             full_name=tag("Amina Bello"),  branch_id=b2.id, phone="08044444444"),
    ]
    agents_b3 = [
        User(username="mock_agent_ph1",    password_hash=h("Password1!"), role="AGENT",
             full_name=tag("Chidi Nwosu"),  branch_id=b3.id, phone="08055555555"),
        User(username="mock_agent_ph2",    password_hash=h("Password1!"), role="AGENT",
             full_name=tag("Ngozi Okafor"), branch_id=b3.id, phone="08066666666"),
    ]
    all_agents = agents_b1 + agents_b2 + agents_b3
    db.add_all(all_agents)
    db.flush()

    # ── 4. ITEMS (across branches) ───────────────────────────────────────────
    item_templates = [
        ("Paracetamol 500mg",    "Pharmaceuticals",  150,  200),
        ("Amoxicillin 250mg",    "Pharmaceuticals",  300,  500),
        ("Ibuprofen 400mg",      "Pharmaceuticals",  120,  180),
        ("Hand Sanitizer 500ml", "Hygiene",           80,  120),
        ("Face Mask (box/50)",   "Hygiene",          250,  400),
        ("IV Cannula 20G",       "Medical Supplies",  90,  150),
        ("Surgical Gloves M",    "Medical Supplies",  60,  100),
        ("Blood Glucose Strips", "Diagnostics",      500,  800),
        ("Pregnancy Test Kit",   "Diagnostics",      200,  350),
        ("Vitamin C 1000mg",     "Supplements",      100,  160),
        ("Zinc Tablets",         "Supplements",       80,  130),
        ("ORS Sachets",          "Pharmacy",          40,   70),
    ]

    all_items = []
    for branch in [b1, b2, b3]:
        for (name, cat, cost, sell) in item_templates:
            it = Item(
                name=tag(name), category=cat,
                cost_price=cost, selling_price=sell,
                reorder_level=random.randint(5, 20),
                branch_id=branch.id
            )
            all_items.append(it)
    db.add_all(all_items)
    db.flush()

    # ── 5. TRANSACTIONS (stock IN for all items) ─────────────────────────────
    txns = []
    now = datetime.utcnow()
    for it in all_items:
        qty = random.randint(30, 200)
        txns.append(Transaction(
            item_id=it.id, branch_id=it.branch_id,
            type="IN", quantity=qty,
            note="Opening stock",
            created_at=now - timedelta(days=random.randint(10, 30)),
        ))
        # some OUT transactions too
        out_qty = random.randint(5, qty // 3)
        txns.append(Transaction(
            item_id=it.id, branch_id=it.branch_id,
            type="OUT", quantity=out_qty,
            note="Mock sale",
            created_at=now - timedelta(days=random.randint(1, 9)),
        ))
    db.add_all(txns)
    db.flush()

    # ── 6. DELIVERIES + DELIVERY ITEMS ──────────────────────────────────────
    statuses = ["PENDING", "PENDING", "DELIVERED", "DELIVERED", "RETURNED"]
    deliveries = []
    for branch, admin, agents, branch_items in [
        (b1, a1, agents_b1, [i for i in all_items if i.branch_id == b1.id]),
        (b2, a2, agents_b2, [i for i in all_items if i.branch_id == b2.id]),
        (b3, a3, agents_b3, [i for i in all_items if i.branch_id == b3.id]),
    ]:
        for i in range(6):
            agent = random.choice(agents)
            status = random.choice(statuses)
            d = Delivery(
                customer_name=tag(random.choice([
                    "City Pharmacy", "HealthPlus Store", "MedHub Clinic",
                    "Sunrise Hospital", "Grace Dispensary", "Unity Drugstore",
                ])),
                customer_phone=f"080{random.randint(10000000,99999999)}",
                address=f"{random.randint(1,50)} {random.choice(['Lagos St','Abuja Rd','PH Ave','Market Sq'])}",
                status=status,
                branch_id=branch.id,
                agent_id=agent.id,
                delivery_date=(now + timedelta(days=random.randint(1, 7))).date() if status == "PENDING" else (now - timedelta(days=random.randint(1, 5))).date(),
                created_at=now - timedelta(days=random.randint(1, 14)),
            )
            db.add(d)
            db.flush()
            # add 2-3 items to each delivery
            for item in random.sample(branch_items, min(3, len(branch_items))):
                qty = random.randint(1, 10)
                db.add(DeliveryItem(
                    delivery_id=d.id,
                    item_id=item.id,
                    quantity=qty,
                    line_amount=qty * (item.selling_price or 0),
                ))
            deliveries.append(d)

    db.flush()

    # ── 7. CASH ENTRIES ──────────────────────────────────────────────────────
    kinds = ["COLLECTION", "EXPENSE", "OFFICE_EXPENSE"]
    for branch, agents in [(b1, agents_b1), (b2, agents_b2), (b3, agents_b3)]:
        for agent in agents:
            for k in range(5):
                kind = random.choice(kinds)
                db.add(CashEntry(
                    agent_id=agent.id,
                    branch_id=branch.id,
                    kind=kind,
                    amount=random.randint(500, 50000),
                    note=tag(f"Mock {kind.lower()} entry"),
                    created_at=now - timedelta(days=random.randint(0, 14)),
                ))

    # ── 8. STOCK TRANSFERS (between branches) ────────────────────────────────
    for (src, dst) in [(b1, b2), (b2, b3)]:
        src_items = [i for i in all_items if i.branch_id == src.id]
        t = StockTransfer(
            from_branch_id=src.id,
            to_branch_id=dst.id,
            status="PENDING",
            note=tag("Mock inter-branch transfer"),
            created_by_id=a1.id,
            created_at=now - timedelta(days=2),
        )
        db.add(t)
        db.flush()
        for item in random.sample(src_items, 3):
            db.add(StockTransferItem(
                transfer_id=t.id,
                item_id=item.id,
                quantity=random.randint(5, 20),
            ))

    db.commit()
    print("\n✅ Mock data inserted successfully!\n")
    print("  Branches  : [MOCK] Lagos Island, Abuja Central, Port Harcourt")
    print("  Admins    : mock_admin_lagos / mock_admin_abuja / mock_admin_ph")
    print("  Agents    : mock_agent_lagos1/2, mock_agent_abuja1/2, mock_agent_ph1/2")
    print("  Password  : Password1!  (all mock accounts)")
    print("  Items     : 36 items (12 per branch)")
    print("  Deliveries: 18 (6 per branch)")
    print("  Cash      : 30 entries")
    print("  Transfers : 2 pending transfers")
    print("\nRun remove_mock_data.py to wipe all of this.\n")
