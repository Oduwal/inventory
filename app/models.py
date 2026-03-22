from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Numeric,
    CheckConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


# ─────────────────────────────────────────────────────────────────────────────
# BRANCH
# ─────────────────────────────────────────────────────────────────────────────

class Branch(Base):
    __tablename__ = "branches"

    id:         Mapped[int]          = mapped_column(Integer, primary_key=True)
    name:       Mapped[str]          = mapped_column(String(120), nullable=False, unique=True)
    code:       Mapped[str | None]   = mapped_column(String(20), unique=True, nullable=True)
    address:    Mapped[str | None]   = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    users:         Mapped[list["User"]]         = relationship(back_populates="branch")
    items:         Mapped[list["Item"]]         = relationship(back_populates="branch")
    deliveries:    Mapped[list["Delivery"]]     = relationship(back_populates="branch")
    transactions:  Mapped[list["Transaction"]]  = relationship(back_populates="branch")
    cash_entries:  Mapped[list["CashEntry"]]    = relationship(back_populates="branch")
    transfers_out: Mapped[list["StockTransfer"]] = relationship(
        back_populates="from_branch", foreign_keys="StockTransfer.from_branch_id"
    )
    transfers_in:  Mapped[list["StockTransfer"]] = relationship(
        back_populates="to_branch", foreign_keys="StockTransfer.to_branch_id"
    )


# ─────────────────────────────────────────────────────────────────────────────
# USER
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id:            Mapped[int]        = mapped_column(Integer, primary_key=True)
    username:      Mapped[str]        = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str]        = mapped_column(String(255), nullable=False)
    # ADMIN = branch admin | AGENT = field agent | SUPERVISOR = cross-branch read
    role:          Mapped[str]        = mapped_column(String(20), default="AGENT", nullable=False)
    branch_id:     Mapped[int | None] = mapped_column(ForeignKey("branches.id"), nullable=True)
    full_name:     Mapped[str | None] = mapped_column(String(140), nullable=True)
    phone:         Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at:    Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    branch:       Mapped["Branch | None"]   = relationship(back_populates="users")
    deliveries:   Mapped[list["Delivery"]]  = relationship(back_populates="agent")
    cash_entries: Mapped[list["CashEntry"]] = relationship(back_populates="agent")

    __table_args__ = (
        CheckConstraint("role IN ('ADMIN','AGENT','SUPERVISOR')", name="ck_user_role"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ITEM
# ─────────────────────────────────────────────────────────────────────────────

class Item(Base):
    __tablename__ = "items"

    id:            Mapped[int]        = mapped_column(Integer, primary_key=True)
    branch_id:     Mapped[int]        = mapped_column(ForeignKey("branches.id"), nullable=False)
    name:          Mapped[str]        = mapped_column(String(200), nullable=False)
    category:      Mapped[str | None] = mapped_column(String(120), nullable=True)
    unit:          Mapped[str]        = mapped_column(String(20), default="pcs", nullable=False)
    reorder_level: Mapped[int]        = mapped_column(Integer, default=0, nullable=False)
    cost_price:    Mapped[float]      = mapped_column(Numeric(12, 2), default=0, nullable=False)
    selling_price: Mapped[float]      = mapped_column(Numeric(12, 2), default=0, nullable=False)
    created_at:    Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at:    Mapped[datetime]   = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    branch:         Mapped["Branch"]             = relationship(back_populates="items")
    transactions:   Mapped[list["Transaction"]]  = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )
    delivery_items: Mapped[list["DeliveryItem"]] = relationship(back_populates="item")

    __table_args__ = (
        CheckConstraint("reorder_level >= 0", name="ck_item_reorder_nonneg"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# DELIVERY
# ─────────────────────────────────────────────────────────────────────────────

class Delivery(Base):
    __tablename__ = "deliveries"

    id:             Mapped[int]          = mapped_column(Integer, primary_key=True)
    branch_id:      Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    agent_id:       Mapped[int]          = mapped_column(ForeignKey("users.id"), nullable=False)
    customer_name:  Mapped[str]          = mapped_column(String(160), nullable=False)
    customer_phone: Mapped[str | None]   = mapped_column(String(40), nullable=True)
    address:        Mapped[str | None]   = mapped_column(String(300), nullable=True)
    status:         Mapped[str]          = mapped_column(String(25), default="PENDING", nullable=False)
    note:           Mapped[str | None]   = mapped_column(String(400), nullable=True)
    delivery_date:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at:     Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    delivered_at:   Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    branch:       Mapped["Branch"]             = relationship(back_populates="deliveries")
    agent:        Mapped["User"]               = relationship(back_populates="deliveries")
    items:        Mapped[list["DeliveryItem"]] = relationship(
        back_populates="delivery", cascade="all, delete-orphan"
    )
    cash_entries: Mapped[list["CashEntry"]]    = relationship(back_populates="delivery")

    # Note: ADJUSTMENT_PENDING is enforced via DDL migration at startup (main.py)
    # because ALTER CONSTRAINT is used to add it after initial table creation.
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','OUT_FOR_DELIVERY','DELIVERED','FAILED','RETURNED','ADJUSTMENT_PENDING')",
            name="ck_delivery_status",
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# DELIVERY ITEM
# ─────────────────────────────────────────────────────────────────────────────

class DeliveryItem(Base):
    __tablename__ = "delivery_items"

    id:          Mapped[int]   = mapped_column(Integer, primary_key=True)
    delivery_id: Mapped[int]   = mapped_column(ForeignKey("deliveries.id"), nullable=False)
    item_id:     Mapped[int]   = mapped_column(ForeignKey("items.id"), nullable=False)
    quantity:    Mapped[int]   = mapped_column(Integer, nullable=False)
    line_amount: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)

    delivery: Mapped["Delivery"] = relationship(back_populates="items")
    item:     Mapped["Item"]     = relationship(back_populates="delivery_items")

    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_delivery_item_qty_positive"),
        CheckConstraint("line_amount >= 0", name="ck_delivery_item_amount_nonneg"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# TRANSACTION
# ─────────────────────────────────────────────────────────────────────────────

class Transaction(Base):
    __tablename__ = "transactions"

    id:          Mapped[int]          = mapped_column(Integer, primary_key=True)
    created_at:  Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    branch_id:   Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    item_id:     Mapped[int]          = mapped_column(ForeignKey("items.id"), nullable=False)
    delivery_id: Mapped[int | None]   = mapped_column(ForeignKey("deliveries.id"), nullable=True)
    type:        Mapped[str]          = mapped_column(String(10), nullable=False)   # IN or OUT
    quantity:    Mapped[int]          = mapped_column(Integer, nullable=False)
    reference:   Mapped[str | None]   = mapped_column(String(120), nullable=True)
    note:        Mapped[str | None]   = mapped_column(String(400), nullable=True)

    branch: Mapped["Branch"] = relationship(back_populates="transactions")
    item:   Mapped["Item"]   = relationship(back_populates="transactions")

    __table_args__ = (
        CheckConstraint("type IN ('IN','OUT')", name="ck_tx_type_in_out"),
        CheckConstraint("quantity > 0", name="ck_tx_quantity_positive"),
        Index("ix_transactions_item_id", "item_id"),
        Index("ix_transactions_delivery_id", "delivery_id"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# CASH ENTRY
# ─────────────────────────────────────────────────────────────────────────────

class CashEntry(Base):
    __tablename__ = "cash_entries"

    id:                 Mapped[int]          = mapped_column(Integer, primary_key=True)
    created_at:         Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    branch_id:          Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    agent_id:           Mapped[int]          = mapped_column(ForeignKey("users.id"), nullable=False)
    delivery_id:        Mapped[int | None]   = mapped_column(ForeignKey("deliveries.id"), nullable=True)
    # Allowed kinds:
    # COLLECTION | EXPENSE | OPERATING_CASH | OFFICE_EXPENSE |
    # RETURN_OPERATING_CASH | CASH_PAYMENT | TRANSFER_PAYMENT
    kind:               Mapped[str]          = mapped_column(String(30), nullable=False)
    amount:             Mapped[float]        = mapped_column(Numeric(12, 2), nullable=False)
    note:               Mapped[str | None]   = mapped_column(String(400), nullable=True)
    confirmed_by_admin: Mapped[bool]         = mapped_column(
        Boolean, default=False, nullable=False, server_default="FALSE"
    )
    confirmed_at:       Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    branch:   Mapped["Branch"]          = relationship(back_populates="cash_entries")
    agent:    Mapped["User"]            = relationship(back_populates="cash_entries")
    delivery: Mapped["Delivery | None"] = relationship(back_populates="cash_entries")

    __table_args__ = (
        CheckConstraint(
            "kind IN ('COLLECTION','EXPENSE','OPERATING_CASH','OFFICE_EXPENSE',"
            "'RETURN_OPERATING_CASH','CASH_PAYMENT','TRANSFER_PAYMENT')",
            name="ck_cash_kind",
        ),
        CheckConstraint("amount > 0", name="ck_cash_amount_positive"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# STOCK TRANSFER
# ─────────────────────────────────────────────────────────────────────────────

class StockTransfer(Base):
    __tablename__ = "stock_transfers"

    id:             Mapped[int]          = mapped_column(Integer, primary_key=True)
    from_branch_id: Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    to_branch_id:   Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    # PENDING → OUT_FOR_DELIVERY → RECEIVED or CANCELLED
    status:         Mapped[str]          = mapped_column(String(20), default="PENDING", nullable=False)
    note:           Mapped[str | None]   = mapped_column(String(400), nullable=True)

    created_by_id:   Mapped[int]          = mapped_column(ForeignKey("users.id"), nullable=False)
    received_by_id:  Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    cancelled_by_id: Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at:   Mapped[datetime]        = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    received_at:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Delegation — agent responsible for packing & sending
    delegated_agent_id:    Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    # Delegation — agent responsible for receiving
    delegated_receiver_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    # Send-side expense
    expense_amount: Mapped[float | None]  = mapped_column(Numeric(12, 2), nullable=True, default=0)
    expense_kind:   Mapped[str | None]    = mapped_column(String(30), nullable=True)
    expense_note:   Mapped[str | None]    = mapped_column(String(400), nullable=True)

    # Receive-side expense
    receive_expense_amount: Mapped[float | None] = mapped_column(Numeric(12, 2), nullable=True, default=0)
    receive_expense_kind:   Mapped[str | None]   = mapped_column(String(30), nullable=True)
    receive_expense_note:   Mapped[str | None]   = mapped_column(String(400), nullable=True)

    from_branch:        Mapped["Branch"]        = relationship(back_populates="transfers_out", foreign_keys=[from_branch_id])
    to_branch:          Mapped["Branch"]        = relationship(back_populates="transfers_in",  foreign_keys=[to_branch_id])
    created_by:         Mapped["User"]          = relationship(foreign_keys=[created_by_id])
    received_by:        Mapped["User | None"]   = relationship(foreign_keys=[received_by_id])
    cancelled_by:       Mapped["User | None"]   = relationship(foreign_keys=[cancelled_by_id])
    delegated_agent:    Mapped["User | None"]   = relationship(foreign_keys=[delegated_agent_id])
    delegated_receiver: Mapped["User | None"]   = relationship(foreign_keys=[delegated_receiver_id])

    items: Mapped[list["StockTransferItem"]] = relationship(
        back_populates="transfer", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','OUT_FOR_DELIVERY','RECEIVED','CANCELLED')",
            name="ck_transfer_status",
        ),
        Index("ix_stock_transfers_from",   "from_branch_id"),
        Index("ix_stock_transfers_to",     "to_branch_id"),
        Index("ix_stock_transfers_status", "status"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# STOCK TRANSFER ITEM
# ─────────────────────────────────────────────────────────────────────────────

class StockTransferItem(Base):
    __tablename__ = "stock_transfer_items"

    id:          Mapped[int] = mapped_column(Integer, primary_key=True)
    transfer_id: Mapped[int] = mapped_column(ForeignKey("stock_transfers.id"), nullable=False)
    item_id:     Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)
    quantity:    Mapped[int] = mapped_column(Integer, nullable=False)

    transfer: Mapped["StockTransfer"] = relationship(back_populates="items")
    item:     Mapped["Item"]          = relationship()

    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_transfer_item_qty_positive"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT LOG  [SEC-7]
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id:         Mapped[int]        = mapped_column(Integer, primary_key=True)
    user_id:    Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action:     Mapped[str]        = mapped_column(String(100), nullable=False)
    detail:     Mapped[str]        = mapped_column(String(500), default="")
    ip:         Mapped[str]        = mapped_column(String(45), default="")
    created_at: Mapped[datetime]   = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_audit_logs_user_id",    "user_id"),
        Index("ix_audit_logs_created_at", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# NOTIFICATION
# ─────────────────────────────────────────────────────────────────────────────

class Notification(Base):
    __tablename__ = "notifications"

    id:         Mapped[int]          = mapped_column(Integer, primary_key=True)
    user_id:    Mapped[int]          = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    title:      Mapped[str]          = mapped_column(String(200), nullable=False)
    body:       Mapped[str]          = mapped_column(String(500), default="")
    link:       Mapped[str]          = mapped_column(String(300), default="")
    kind:       Mapped[str]          = mapped_column(String(50), default="info")
    read_at:    Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship()

    __table_args__ = (
        Index("ix_notifications_user_unread", "user_id", "read_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# STOCK RETURN VETTING
# ─────────────────────────────────────────────────────────────────────────────

class StockReturnVetting(Base):
    """Tracks physical return confirmation of items from unsuccessful deliveries.
    
    resolved=False  → vetted but shortfall exists — stays on vetting page
    resolved=True   → fully settled (full return OR written off)
    resolve_action  → 'returned' | 'written_off'
    """
    __tablename__ = "stock_return_vettings"

    id:               Mapped[int]          = mapped_column(Integer, primary_key=True)
    delivery_id:      Mapped[int]          = mapped_column(
        ForeignKey("deliveries.id", ondelete="CASCADE"), nullable=False
    )
    delivery_item_id: Mapped[int]          = mapped_column(
        ForeignKey("delivery_items.id", ondelete="CASCADE"), nullable=False
    )
    vetted_by:        Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    qty_returned:     Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    transaction_id:   Mapped[int | None]   = mapped_column(ForeignKey("transactions.id"), nullable=True)
    created_at:       Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)
    # Shortfall resolution
    resolved:         Mapped[bool]         = mapped_column(Boolean, default=False, nullable=False, server_default="FALSE")
    resolve_action:   Mapped[str | None]   = mapped_column(String(20), nullable=True)   # 'returned' | 'written_off'
    resolved_at:      Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by:      Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)

    __table_args__ = (
        Index("ix_stock_return_vetting", "delivery_item_id"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ADJUSTMENT REQUEST
# ─────────────────────────────────────────────────────────────────────────────

class AdjustmentRequest(Base):
    """Price/item adjustment request by agent — must be approved by admin before delivery."""
    __tablename__ = "adjustment_requests"

    id:             Mapped[int]          = mapped_column(Integer, primary_key=True)
    delivery_id:    Mapped[int]          = mapped_column(
        ForeignKey("deliveries.id", ondelete="CASCADE"), nullable=False
    )
    requested_by:   Mapped[int]          = mapped_column(ForeignKey("users.id"), nullable=False)
    reason:         Mapped[str]          = mapped_column(String(500), default="")
    status:         Mapped[str]          = mapped_column(String(20), default="PENDING")
    reviewed_by:    Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    rejection_note: Mapped[str]          = mapped_column(String(500), default="")
    created_at:     Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)
    reviewed_at:    Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','APPROVED','REJECTED')",
            name="ck_adjustment_status",
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# ADJUSTMENT REQUEST ITEM
# ─────────────────────────────────────────────────────────────────────────────

class AdjustmentRequestItem(Base):
    """Individual line item within an adjustment request."""
    __tablename__ = "adjustment_request_items"

    id:               Mapped[int]   = mapped_column(Integer, primary_key=True)
    request_id:       Mapped[int]   = mapped_column(
        ForeignKey("adjustment_requests.id", ondelete="CASCADE"), nullable=False
    )
    delivery_item_id: Mapped[int]   = mapped_column(
        ForeignKey("delivery_items.id", ondelete="CASCADE"), nullable=False
    )
    item_name:        Mapped[str]   = mapped_column(String(200), default="")
    original_amount:  Mapped[float] = mapped_column(Numeric(12, 2), default=0)
    new_amount:       Mapped[float] = mapped_column(Numeric(12, 2), default=0)
    remove_item:      Mapped[bool]  = mapped_column(Boolean, default=False)

# ─────────────────────────────────────────────────────────────────────────────
# FAULTY STOCK
# ─────────────────────────────────────────────────────────────────────────────

class FaultyStock(Base):
    """Tracks faulty/bad units flagged by admin. Stock count is NOT reduced until resolved.
    resolve_action: 'remove' | 'return_merchant'
    """
    __tablename__ = "faulty_stock"

    id:             Mapped[int]          = mapped_column(Integer, primary_key=True)
    item_id:        Mapped[int]          = mapped_column(ForeignKey("items.id", ondelete="CASCADE"), nullable=False)
    branch_id:      Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    qty_faulty:     Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    reason:         Mapped[str]          = mapped_column(String(400), default="")
    flagged_by:     Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    flagged_at:     Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)
    resolved:       Mapped[bool]         = mapped_column(Boolean, default=False, nullable=False, server_default="FALSE")
    resolve_action: Mapped[str | None]   = mapped_column(String(20), nullable=True)   # 'remove' | 'return_merchant'
    resolved_at:    Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_by:    Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    resolve_note:   Mapped[str]          = mapped_column(String(400), default="")

    item:   Mapped["Item"]        = relationship()
    branch: Mapped["Branch"]      = relationship()

    __table_args__ = (
        CheckConstraint("qty_faulty > 0", name="ck_faulty_qty_positive"),
        Index("ix_faulty_stock_item",   "item_id"),
        Index("ix_faulty_stock_branch", "branch_id"),
    )

# ─────────────────────────────────────────────────────────────────────────────
# AGENT STOCK ASSIGNMENT
# ─────────────────────────────────────────────────────────────────────────────

class AgentStockAssignment(Base):
    """Extra stock given to an agent for urgent delivery.
    Stock is deducted immediately (OUT transaction).
    Admin vets return on the vetting page.
    """
    __tablename__ = "agent_stock_assignments"

    id:                  Mapped[int]          = mapped_column(Integer, primary_key=True)
    agent_id:            Mapped[int]          = mapped_column(ForeignKey("users.id"), nullable=False)
    item_id:             Mapped[int]          = mapped_column(ForeignKey("items.id"), nullable=False)
    branch_id:           Mapped[int]          = mapped_column(ForeignKey("branches.id"), nullable=False)
    qty_assigned:        Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    note:                Mapped[str]          = mapped_column(String(400), nullable=False, default="")
    assigned_by:         Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_at:         Mapped[datetime]     = mapped_column(DateTime, default=datetime.utcnow)
    returned:            Mapped[bool]         = mapped_column(Boolean, default=False, nullable=False, server_default="FALSE")
    qty_returned:        Mapped[int]          = mapped_column(Integer, nullable=False, default=0)
    vetted_by:           Mapped[int | None]   = mapped_column(ForeignKey("users.id"), nullable=True)
    vetted_at:           Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    transaction_out_id:  Mapped[int | None]   = mapped_column(ForeignKey("transactions.id"), nullable=True)
    transaction_in_id:   Mapped[int | None]   = mapped_column(ForeignKey("transactions.id"), nullable=True)
    delivery_id:         Mapped[int | None]   = mapped_column(ForeignKey("deliveries.id"), nullable=True)

    __table_args__ = (
        CheckConstraint("qty_assigned > 0", name="ck_asgn_qty_positive"),
        Index("ix_agent_stock_asgn_agent",  "agent_id"),
        Index("ix_agent_stock_asgn_branch", "branch_id"),
    )
