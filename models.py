from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Text, Boolean, func
)
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func as sqlfunc
import uuid
from datetime import datetime

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email_hash = Column(String(128), nullable=True)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(20), default="client")
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now())

    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    email_verified = Column(Boolean, default=False)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)

    is_blocked = Column(Boolean, default=False)

    is_verified = Column(Boolean, default=False)

    bookings = relationship("Booking", back_populates="client", foreign_keys='Booking.client_id')
    notifications = relationship("Notification", back_populates="user")

    claimed_bookings = relationship("Booking", back_populates="worker", foreign_keys='Booking.worker_id')

class ServiceType(Base):
    __tablename__ = "service_types"
    id = Column(Integer, primary_key=True)
    name = Column(String(120))
    description = Column(Text)

class Booking(Base):
    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("users.id"))
    service_type_id = Column(Integer, ForeignKey("service_types.id"))
    description = Column(Text)
    scheduled_time = Column(String(120))
    status = Column(String(30), default="requested")
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now())
    ephemeral_visit_id = Column(String(120), default=generate_uuid)

    client = relationship("User", back_populates="bookings", foreign_keys=[client_id])
    service_type = relationship("ServiceType")
    worker_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    worker = relationship("User", back_populates="claimed_bookings", foreign_keys=[worker_id])

class VisitMapping(Base):
    """
    Sensitive mapping kept encrypted in DB for limited retention.
    This table stores encrypted mapping from ephemeral_visit_id -> user_id
    and is deleted after retention period.
    """
    __tablename__ = "visit_mappings"
    id = Column(Integer, primary_key=True)
    ephemeral_visit_id = Column(String(120), unique=True, nullable=False)
    encrypted_user_id = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now())

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    message = Column(Text)
    read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now())

    user = relationship("User", back_populates="notifications")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(200))
    details = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=sqlfunc.now())
