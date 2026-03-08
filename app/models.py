from __future__ import annotations

from datetime import datetime
from sqlalchemy import (
    String,
    Integer,
    DateTime,
    ForeignKey,
    Numeric,
    CheckConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Branch(Base):
    __tablename__ = "branches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    code: Mapped[str | None] = mapped_column(String(20), unique=True, nullable=True)
    address: Mapped[str | None] = mapped_column(String(200), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="branch")
    items: Mapped[list["Item"]] = relationship(back_populates="branch")
    deliveries: Mapped[list["Delivery"]] = relationship(back_populates="branch")
    transactions: Mapped[list["Transaction"]] = relationship(back_populates="branch")
    cash_entries: Mapped[list["CashEntry"]] = relationship(back_populates="branch")
    transfers_out: Mapped[list["StockTransfer"]] = relationship(back_populates="from_branch", foreign_keys="StockTransfer.from_branch_id")
    transfers_in: Mapped[list["StockTransfer"]] = relationship(back_populates="to_branch", foreign_keys="StockTransfer.to_branch_id")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # ADMIN = branch admin
    # AGENT = branch agent
    # SUPERVISOR = read-only across branches
    role: Mapped[str] = mapped_column(String(20), default="AGENT", nullable=False)

    branch_id: Mapped[int | None] = mapped_column(ForeignKey("branches.id"), nullable=True)

    full_name: Mapped[str | None] = mapped_column(String(140), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    branch: Mapped["Branch | None"] = relationship(back_populates="users")
    deliveries: Mapped[list["Delivery"]] = relationship(back_populates="agent")
    cash_entries: Mapped[list["CashEntry"]] = relationship(back_populates="agent")

    __table_args__ = (
        CheckConstraint(
            "role IN ('ADMIN','AGENT','SUPERVISOR')",
            name="ck_user_role",
        ),
    )


class Item(Base):
    __tablename__ = "items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True)

    unit: Mapped[str] = mapped_column(String(20), default="pcs", nullable=False)
    reorder_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    cost_price: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)
    selling_price: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    branch: Mapped["Branch"] = relationship(back_populates="items")

    transactions: Mapped[list["Transaction"]] = relationship(
        back_populates="item",
        cascade="all, delete-orphan",
    )

    delivery_items: Mapped[list["DeliveryItem"]] = relationship(back_populates="item")

    __table_args__ = (
        CheckConstraint("reorder_level >= 0", name="ck_item_reorder_nonneg"),
    )


class Delivery(Base):
    __tablename__ = "deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), nullable=False)
    agent_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    customer_name: Mapped[str] = mapped_column(String(160), nullable=False)
    customer_phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    address: Mapped[str | None] = mapped_column(String(300), nullable=True)

    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)

    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    branch: Mapped["Branch"] = relationship(back_populates="deliveries")
    agent: Mapped["User"] = relationship(back_populates="deliveries")

    items: Mapped[list["DeliveryItem"]] = relationship(
        back_populates="delivery",
        cascade="all, delete-orphan",
    )

    cash_entries: Mapped[list["CashEntry"]] = relationship(back_populates="delivery")

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','OUT_FOR_DELIVERY','DELIVERED','FAILED','RETURNED')",
            name="ck_delivery_status",
        ),
    )


class DeliveryItem(Base):
    __tablename__ = "delivery_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delivery_id: Mapped[int] = mapped_column(ForeignKey("deliveries.id"), nullable=False)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    line_amount: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)

    delivery: Mapped["Delivery"] = relationship(back_populates="items")
    item: Mapped["Item"] = relationship(back_populates="delivery_items")

    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_delivery_item_qty_positive"),
        CheckConstraint("line_amount >= 0", name="ck_delivery_item_amount_nonneg"),
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), nullable=False)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)
    delivery_id: Mapped[int | None] = mapped_column(ForeignKey("deliveries.id"), nullable=True)

    type: Mapped[str] = mapped_column(String(10), nullable=False)  # IN or OUT
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    branch: Mapped["Branch"] = relationship(back_populates="transactions")
    item: Mapped["Item"] = relationship(back_populates="transactions")

    __table_args__ = (
        CheckConstraint("type IN ('IN','OUT')", name="ck_tx_type_in_out"),
        CheckConstraint("quantity > 0", name="ck_tx_quantity_positive"),
    )


class CashEntry(Base):
    __tablename__ = "cash_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), nullable=False)
    agent_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    delivery_id: Mapped[int | None] = mapped_column(ForeignKey("deliveries.id"), nullable=True)

    # COLLECTION | EXPENSE | OPERATING_CASH | OFFICE_EXPENSE | RETURN_OPERATING_CASH
    kind: Mapped[str] = mapped_column(String(30), nullable=False)

    amount: Mapped[float] = mapped_column(Numeric(12, 2), nullable=False)

    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    branch: Mapped["Branch"] = relationship(back_populates="cash_entries")
    agent: Mapped["User"] = relationship(back_populates="cash_entries")
    delivery: Mapped["Delivery | None"] = relationship(back_populates="cash_entries")

    __table_args__ = (
        CheckConstraint(
            "kind IN ('COLLECTION','EXPENSE','OPERATING_CASH','OFFICE_EXPENSE','RETURN_OPERATING_CASH')",
            name="ck_cash_kind",
        ),
        CheckConstraint("amount > 0", name="ck_cash_amount_positive"),
    )

class StockTransfer(Base):
    __tablename__ = "stock_transfers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    from_branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), nullable=False)
    to_branch_id: Mapped[int] = mapped_column(ForeignKey("branches.id"), nullable=False)

    # PENDING → RECEIVED or CANCELLED
    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)

    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    received_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    cancelled_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    received_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    from_branch: Mapped["Branch"] = relationship(back_populates="transfers_out", foreign_keys=[from_branch_id])
    to_branch: Mapped["Branch"] = relationship(back_populates="transfers_in", foreign_keys=[to_branch_id])
    created_by: Mapped["User"] = relationship(foreign_keys=[created_by_id])
    received_by: Mapped["User | None"] = relationship(foreign_keys=[received_by_id])
    cancelled_by: Mapped["User | None"] = relationship(foreign_keys=[cancelled_by_id])

    items: Mapped[list["StockTransferItem"]] = relationship(
        back_populates="transfer", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING','RECEIVED','CANCELLED')",
            name="ck_transfer_status",
        ),
    )


class StockTransferItem(Base):
    __tablename__ = "stock_transfer_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    transfer_id: Mapped[int] = mapped_column(ForeignKey("stock_transfers.id"), nullable=False)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    transfer: Mapped["StockTransfer"] = relationship(back_populates="items")
    item: Mapped["Item"] = relationship()

    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_transfer_item_qty_positive"),
    )