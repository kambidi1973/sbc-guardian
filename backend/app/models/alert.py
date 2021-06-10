"""SQLAlchemy model for SBC monitoring alerts."""

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


class AlertSeverity(str, enum.Enum):
    """Alert severity levels aligned with syslog severity."""
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    WARNING = "warning"
    INFO = "info"


class AlertCategory(str, enum.Enum):
    """Categorization of alert types."""
    DEVICE_HEALTH = "device_health"
    SIP_TRUNK = "sip_trunk"
    CAPACITY = "capacity"
    SECURITY = "security"
    CERTIFICATE = "certificate"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    REACHABILITY = "reachability"


class AlertState(str, enum.Enum):
    """Current state of the alert."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class Alert(Base):
    """Represents a monitoring alert generated for an SBC device.

    Alerts are created when monitored thresholds are breached (e.g., high
    CPU, trunk failure, certificate expiry approaching). They follow a
    lifecycle from ACTIVE through ACKNOWLEDGED to RESOLVED.
    """

    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sbc_devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    trunk_id = Column(UUID(as_uuid=True), nullable=True, index=True)

    # Alert identification
    alert_key = Column(String(255), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(AlertSeverity), nullable=False, index=True)
    category = Column(Enum(AlertCategory), nullable=False, index=True)
    state = Column(Enum(AlertState), default=AlertState.ACTIVE, index=True)

    # Threshold details
    metric_name = Column(String(255), nullable=True)
    metric_value = Column(String(128), nullable=True)
    threshold_value = Column(String(128), nullable=True)
    threshold_operator = Column(String(16), nullable=True)  # gt, lt, eq, gte, lte

    # Deduplication
    fingerprint = Column(String(256), nullable=False, index=True)
    occurrence_count = Column(Integer, default=1)
    first_occurrence = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_occurrence = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    # Lifecycle
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_by = Column(String(128), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(128), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Notification
    notification_sent = Column(Boolean, default=False)
    notification_channels = Column(JSONB, default=list)  # ["email", "slack", "pagerduty"]
    escalation_level = Column(Integer, default=0)
    suppressed = Column(Boolean, default=False)
    suppressed_until = Column(DateTime(timezone=True), nullable=True)

    # Context
    context = Column(JSONB, default=dict)
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
    device = relationship("SBCDevice", back_populates="alerts")

    def __repr__(self) -> str:
        return f"<Alert(title={self.title!r}, severity={self.severity!r}, state={self.state!r})>"

    @property
    def is_active(self) -> bool:
        return self.state == AlertState.ACTIVE

    @property
    def duration_seconds(self) -> float:
        """Seconds elapsed since the alert was first raised."""
        now = datetime.now(timezone.utc)
        ref = self.resolved_at or now
        return (ref - self.first_occurrence).total_seconds()

    def acknowledge(self, user: str) -> None:
        """Transition alert to acknowledged state."""
        self.state = AlertState.ACKNOWLEDGED
        self.acknowledged_at = datetime.now(timezone.utc)
        self.acknowledged_by = user

    def resolve(self, user: str, notes: str | None = None) -> None:
        """Transition alert to resolved state."""
        self.state = AlertState.RESOLVED
        self.resolved_at = datetime.now(timezone.utc)
        self.resolved_by = user
        self.resolution_notes = notes

    def increment_occurrence(self) -> None:
        """Record another occurrence of the same alert condition."""
        self.occurrence_count += 1
        self.last_occurrence = datetime.now(timezone.utc)

    def suppress(self, until: datetime) -> None:
        """Suppress this alert until the specified time."""
        self.state = AlertState.SUPPRESSED
        self.suppressed = True
        self.suppressed_until = until
