"""SQLAlchemy model for SBC devices in the managed fleet."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all SBC Guardian models."""
    pass


class VendorType(str, enum.Enum):
    """Supported SBC vendor types."""
    ACME = "acme"
    AUDIOCODES = "audiocodes"
    CISCO_CUBE = "cisco_cube"
    GENERIC_SNMP = "generic_snmp"


class DeviceStatus(str, enum.Enum):
    """Operational status of an SBC device."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class SBCDevice(Base):
    """Represents a managed Session Border Controller in the fleet.

    Each device entry tracks connectivity information, operational status,
    firmware version, and links to its associated SIP trunks, ACLs, and
    alert history.
    """

    __tablename__ = "sbc_devices"
    __table_args__ = (
        UniqueConstraint("ip_address", name="uq_sbc_devices_ip"),
        UniqueConstraint("hostname", name="uq_sbc_devices_hostname"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    management_ip = Column(String(45), nullable=True)
    vendor = Column(Enum(VendorType), nullable=False, index=True)
    model = Column(String(128), nullable=False)
    firmware_version = Column(String(64), nullable=True)
    serial_number = Column(String(128), nullable=True)
    location = Column(String(255), nullable=True)
    datacenter = Column(String(128), nullable=True)
    rack_position = Column(String(64), nullable=True)

    # Operational state
    status = Column(
        Enum(DeviceStatus),
        nullable=False,
        default=DeviceStatus.UNKNOWN,
        index=True,
    )
    last_seen = Column(DateTime(timezone=True), nullable=True)
    uptime_seconds = Column(Integer, nullable=True)

    # Connectivity
    ssh_port = Column(Integer, default=22)
    snmp_port = Column(Integer, default=161)
    snmp_community = Column(String(128), nullable=True)
    api_port = Column(Integer, nullable=True)
    api_protocol = Column(String(10), default="https")

    # Credentials stored as encrypted JSONB
    credentials_encrypted = Column(Text, nullable=True)

    # Capacity
    max_sessions = Column(Integer, nullable=True)
    max_cps = Column(Integer, nullable=True)
    current_sessions = Column(Integer, default=0)
    current_cps = Column(Float, default=0.0)
    cpu_utilization = Column(Float, nullable=True)
    memory_utilization = Column(Float, nullable=True)

    # HA cluster
    ha_enabled = Column(Boolean, default=False)
    ha_role = Column(String(32), nullable=True)  # primary, secondary, standalone
    ha_peer_id = Column(UUID(as_uuid=True), nullable=True)

    # Configuration tracking
    config_version = Column(String(64), nullable=True)
    last_config_change = Column(DateTime(timezone=True), nullable=True)
    config_hash = Column(String(128), nullable=True)

    # Tags and metadata
    tags = Column(JSONB, default=dict)
    notes = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    sip_trunks = relationship("SIPTrunk", back_populates="device", cascade="all, delete-orphan")
    acl_rules = relationship("AccessControlRule", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<SBCDevice(hostname={self.hostname!r}, vendor={self.vendor!r}, status={self.status!r})>"

    @property
    def session_utilization_pct(self) -> Optional[float]:
        """Calculate current session utilization as a percentage."""
        if self.max_sessions and self.max_sessions > 0:
            return round((self.current_sessions / self.max_sessions) * 100, 2)
        return None

    @property
    def cps_utilization_pct(self) -> Optional[float]:
        """Calculate current CPS utilization as a percentage."""
        if self.max_cps and self.max_cps > 0:
            return round((self.current_cps / self.max_cps) * 100, 2)
        return None

    @property
    def is_healthy(self) -> bool:
        """Determine if the device is in a healthy operational state."""
        return self.status == DeviceStatus.ONLINE

    @property
    def needs_attention(self) -> bool:
        """Determine if the device requires operator attention."""
        if self.status in (DeviceStatus.DEGRADED, DeviceStatus.UNREACHABLE):
            return True
        if self.cpu_utilization and self.cpu_utilization > 85.0:
            return True
        if self.memory_utilization and self.memory_utilization > 90.0:
            return True
        session_util = self.session_utilization_pct
        if session_util and session_util > 90.0:
            return True
        return False
