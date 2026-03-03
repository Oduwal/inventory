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
    )