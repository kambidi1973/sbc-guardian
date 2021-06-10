"""SQLAlchemy model for SBC Access Control List rules."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.models.sbc_device import Base


class ACLAction(str, enum.Enum):
    """ACL rule action."""
    ALLOW = "allow"
    DENY = "deny"


class ACLProtocol(str, enum.Enum):
    """Network protocol for ACL matching."""
    SIP = "sip"
    RTP = "rtp"
    SNMP = "snmp"
    SSH = "ssh"
    HTTPS = "https"
    ANY = "any"


class ACLDirection(str, enum.Enum):
    """Traffic direction for ACL rule."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BOTH = "both"


class AccessControlRule(Base):
    """Represents an Access Control List entry on an SBC device.

    ACL rules control which source and destination networks may send or
    receive SIP, RTP, and management traffic through the SBC. Rules are
    evaluated in priority order (lower number = higher priority).
    """

    __tablename__ = "acl_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sbc_devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(Integer, nullable=False, default=100)
    enabled = Column(Boolean, default=True)

    # Match criteria
    source_network = Column(String(45), nullable=False)  # CIDR notation
    source_prefix_length = Column(Integer, nullable=False, default=32)
    destination_network = Column(String(45), nullable=True)
    destination_prefix_length = Column(Integer, nullable=True)
    protocol = Column(Enum(ACLProtocol), default=ACLProtocol.SIP)
    port_range_start = Column(Integer, nullable=True)
    port_range_end = Column(Integer, nullable=True)
    direction = Column(Enum(ACLDirection), default=ACLDirection.INBOUND)

    # Action
    action = Column(Enum(ACLAction), nullable=False, default=ACLAction.DENY)

    # Rate limiting (optional)
    rate_limit_cps = Column(Integer, nullable=True)
    rate_limit_burst = Column(Integer, nullable=True)

    # SIP-specific matching
    sip_method_filter = Column(JSONB, nullable=True)  # ["INVITE", "REGISTER", ...]
    from_uri_pattern = Column(String(512), nullable=True)
    to_uri_pattern = Column(String(512), nullable=True)
    user_agent_pattern = Column(String(512), nullable=True)

    # Topology hiding
    topology_hiding_enabled = Column(Boolean, default=False)
    topology_hiding_profile = Column(String(128), nullable=True)

    # Hit counters
    hit_count = Column(Integer, default=0)
    last_hit_at = Column(DateTime(timezone=True), nullable=True)

    # Audit
    created_by = Column(String(128), nullable=True)
    updated_by = Column(String(128), nullable=True)

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
    device = relationship("SBCDevice", back_populates="acl_rules")

    def __repr__(self) -> str:
        return (
            f"<AccessControlRule(name={self.name!r}, "
            f"action={self.action!r}, "
            f"src={self.source_network}/{self.source_prefix_length})>"
        )

    @property
    def source_cidr(self) -> str:
        """Return source network in CIDR notation."""
        return f"{self.source_network}/{self.source_prefix_length}"

    @property
    def destination_cidr(self) -> str | None:
        """Return destination network in CIDR notation, or None."""
        if self.destination_network and self.destination_prefix_length is not None:
            return f"{self.destination_network}/{self.destination_prefix_length}"
        return None

    def matches_source(self, ip_address: str) -> bool:
        """Check whether a given IP address falls within this rule's source range.

        This is a simplified check. In production, use ipaddress.ip_network
        to properly handle CIDR matching.
        """
        import ipaddress

        try:
            network = ipaddress.ip_network(self.source_cidr, strict=False)
            return ipaddress.ip_address(ip_address) in network
        except ValueError:
            return False
