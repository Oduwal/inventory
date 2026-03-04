from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String, nullable=False)

    role = Column(String, default="AGENT")
    full_name = Column(String)

    deliveries = relationship("Delivery", back_populates="agent")


class Item(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True)
    sku = Column(String, index=True)
    name = Column(String)
    category = Column(String)

    cost_price = Column(Float, default=0)
    reorder_level = Column(Integer, default=0)


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id"))
    delivery_id = Column(Integer, nullable=True)

    type = Column(String)
    quantity = Column(Integer)

    reference = Column(String)
    note = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)

    item = relationship("Item")


class Delivery(Base):
    __tablename__ = "deliveries"

    id = Column(Integer, primary_key=True)

    agent_id = Column(Integer, ForeignKey("users.id"))

    customer_name = Column(String)
    customer_phone = Column(String)
    address = Column(String)

    status = Column(String, default="PENDING")

    note = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)
    delivered_at = Column(DateTime)

    agent = relationship("User", back_populates="deliveries")
    items = relationship("DeliveryItem", back_populates="delivery")


class DeliveryItem(Base):
    __tablename__ = "delivery_items"

    id = Column(Integer, primary_key=True)

    delivery_id = Column(Integer, ForeignKey("deliveries.id"))
    item_id = Column(Integer, ForeignKey("items.id"))

    quantity = Column(Integer)

    delivery = relationship("Delivery", back_populates="items")
    item = relationship("Item")


class CashLog(Base):
    __tablename__ = "cash_logs"

    id = Column(Integer, primary_key=True)

    agent_id = Column(Integer, ForeignKey("users.id"))
    delivery_id = Column(Integer, ForeignKey("deliveries.id"), nullable=True)

    kind = Column(String)  # EXPENSE or COLLECTION
    amount = Column(Float)

    note = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)