<<<<<<< HEAD
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


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # "ADMIN" or "AGENT"
    role: Mapped[str] = mapped_column(String(10), default="AGENT", nullable=False)

    full_name: Mapped[str | None] = mapped_column(String(140), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    deliveries: Mapped[list["Delivery"]] = relationship(back_populates="agent")


class Item(Base):
    __tablename__ = "items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    sku: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True)

    unit: Mapped[str] = mapped_column(String(20), default="pcs", nullable=False)

    reorder_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    cost_price: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)
    selling_price: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    transactions: Mapped[list["Transaction"]] = relationship(
        back_populates="item",
        cascade="all, delete-orphan",
    )

    delivery_items: Mapped[list["DeliveryItem"]] = relationship(back_populates="item")


class Delivery(Base):
    __tablename__ = "deliveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    agent_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    customer_name: Mapped[str] = mapped_column(String(160), nullable=False)
    customer_phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    address: Mapped[str | None] = mapped_column(String(300), nullable=True)

    # PENDING, OUT_FOR_DELIVERY, DELIVERED, FAILED, RETURNED
    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)

    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    agent: Mapped[User] = relationship(back_populates="deliveries")
    items: Mapped[list["DeliveryItem"]] = relationship(
        back_populates="delivery",
        cascade="all, delete-orphan",
    )

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

    delivery: Mapped[Delivery] = relationship(back_populates="items")
    item: Mapped[Item] = relationship(back_populates="delivery_items")

    __table_args__ = (
        CheckConstraint("quantity > 0", name="ck_delivery_item_qty_positive"),
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)

    # Optional link back to delivery
    delivery_id: Mapped[int | None] = mapped_column(ForeignKey("deliveries.id"), nullable=True)

    type: Mapped[str] = mapped_column(String(10), nullable=False)  # "IN" or "OUT"
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    item: Mapped[Item] = relationship(back_populates="transactions")

    __table_args__ = (
        CheckConstraint("type IN ('IN','OUT')", name="ck_tx_type_in_out"),
        CheckConstraint("quantity > 0", name="ck_tx_quantity_positive"),
=======
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


class Item(Base):
    __tablename__ = "items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    sku: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str | None] = mapped_column(String(120), nullable=True)

    # Your shop uses pcs only
    unit: Mapped[str] = mapped_column(String(20), default="pcs", nullable=False)

    reorder_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    cost_price: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)
    selling_price: Mapped[float] = mapped_column(Numeric(12, 2), default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    transactions: Mapped[list["Transaction"]] = relationship(
        back_populates="item",
        cascade="all, delete-orphan",
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    item_id: Mapped[int] = mapped_column(ForeignKey("items.id"), nullable=False)

    # IN adds stock, OUT subtracts stock
    type: Mapped[str] = mapped_column(String(10), nullable=False)  # "IN" or "OUT"

    # pcs-only: integer quantity, must be > 0
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    note: Mapped[str | None] = mapped_column(String(400), nullable=True)

    item: Mapped[Item] = relationship(back_populates="transactions")

    __table_args__ = (
        CheckConstraint("type IN ('IN','OUT')", name="ck_tx_type_in_out"),
        CheckConstraint("quantity > 0", name="ck_tx_quantity_positive"),
>>>>>>> c9a55714199331d544c6b3f8a0847ddabb00c6af
    )