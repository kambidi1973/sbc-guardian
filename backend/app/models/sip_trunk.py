"""SQLAlchemy model for SIP trunk configurations."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.models.sbc_device import Base


class TrunkStatus(str, enum.Enum):
    """Operational status of a SIP trunk."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    FAILED = "failed"
    MAINTENANCE = "maintenance"


class TransportProtocol(str, enum.Enum):
    """SIP transport protocol."""
    UDP = "UDP"
    TCP = "TCP"
    TLS = "TLS"
    WS = "WS"
    WSS = "WSS"


class SIPTrunk(Base):
    """Represents a SIP trunk configured on a managed SBC.

    Tracks the peering relationship between the SBC and a remote SIP endpoint
    including transport, codec, and capacity parameters along with real-time
    performance metrics.
    """

    __tablename__ = "sip_trunks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sbc_devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Peering configuration
    remote_ip = Column(String(45), nullable=False)
    remote_port = Column(Integer, default=5060)
    local_port = Column(Integer, default=5060)
    transport = Column(Enum(TransportProtocol), default=TransportProtocol.UDP)
    realm = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)

    # Authentication
    auth_enabled = Column(Boolean, default=False)
    auth_username = Column(String(128), nullable=True)
    auth_password_encrypted = Column(Text, nullable=True)
    registration_enabled = Column(Boolean, default=False)
    registration_interval = Column(Integer, default=3600)

    # Capacity
    max_sessions = Column(Integer, nullable=True)
    max_cps = Column(Float, nullable=True)
    current_sessions = Column(Integer, default=0)

    # Codec and media
    preferred_codecs = Column(JSONB, default=lambda: ["G.711u", "G.711a", "G.729"])
    dtmf_mode = Column(String(32), default="rfc2833")
    fax_mode = Column(String(32), default="t38")
    media_encryption = Column(String(32), default="none")  # none, srtp, srtp-optional

    # TLS
    tls_enabled = Column(Boolean, default=False)
    tls_cert_cn = Column(String(255), nullable=True)
    tls_cert_expiry = Column(DateTime(timezone=True), nullable=True)
    tls_version_min = Column(String(16), default="1.2")
    mutual_tls = Column(Boolean, default=False)

    # Performance metrics (updated by monitoring)
    status = Column(Enum(TrunkStatus), default=TrunkStatus.INACTIVE, index=True)
    asr = Column(Float, nullable=True)  # Answer-Seizure Ratio
    acd = Column(Float, nullable=True)  # Average Call Duration (seconds)
    ner = Column(Float, nullable=True)  # Network Effectiveness Ratio
    current_cps = Column(Float, default=0.0)

    # SIP options ping
    options_ping_enabled = Column(Boolean, default=True)
    options_ping_interval = Column(Integer, default=30)
    last_options_response = Column(Integer, nullable=True)  # SIP response code
    last_options_latency_ms = Column(Float, nullable=True)

    # Routing
    route_priority = Column(Integer, default=100)
    route_weight = Column(Integer, default=100)
    manipulation_rules = Column(JSONB, default=list)

    # Tags and metadata
    carrier = Column(String(255), nullable=True)
    tags = Column(JSONB, default=dict)

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
    device = relationship("SBCDevice", back_populates="sip_trunks")

    def __repr__(self) -> str:
        return f"<SIPTrunk(name={self.name!r}, remote={self.remote_ip}:{self.remote_port}, status={self.status!r})>"

    @property
    def is_healthy(self) -> bool:
        """Trunk is considered healthy if active with acceptable ASR."""
        if self.status != TrunkStatus.ACTIVE:
            return False
        if self.asr is not None and self.asr < 0.40:
            return False
        return True

    @property
    def tls_cert_days_remaining(self) -> int | None:
        """Days until the TLS certificate expires, or None if no cert."""
        if self.tls_cert_expiry is None:
            return None
        delta = self.tls_cert_expiry - datetime.now(timezone.utc)
        return max(0, delta.days)

    @property
    def session_utilization_pct(self) -> float | None:
        """Current session count as a percentage of maximum."""
        if self.max_sessions and self.max_sessions > 0:
            return round((self.current_sessions / self.max_sessions) * 100, 2)
        return None
