"""SQLAlchemy model for SBC media and codec policies."""

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


class MediaPolicyType(str, enum.Enum):
    """Type of media policy."""
    CODEC = "codec"
    SRTP = "srtp"
    FAX = "fax"
    DTMF = "dtmf"
    RECORDING = "recording"
    TRANSCODING = "transcoding"


class MediaPolicy(Base):
    """Defines media handling policies applied to SBC call flows.

    Media policies control codec negotiation, SRTP enforcement, T.38 fax
    relay, DTMF interworking, and call recording triggers. They can be
    applied globally or per-trunk.
    """

    __tablename__ = "media_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    device_id = Column(
        UUID(as_uuid=True),
        ForeignKey("sbc_devices.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    policy_type = Column(Enum(MediaPolicyType), nullable=False, index=True)
    enabled = Column(Boolean, default=True)

    # Codec negotiation
    allowed_codecs = Column(
        JSONB,
        default=lambda: [
            {"name": "G.711u", "payload_type": 0, "bitrate": 64000},
            {"name": "G.711a", "payload_type": 8, "bitrate": 64000},
            {"name": "G.729", "payload_type": 18, "bitrate": 8000},
            {"name": "G.722", "payload_type": 9, "bitrate": 64000},
            {"name": "OPUS", "payload_type": 111, "bitrate": 48000},
        ],
    )
    codec_preference_order = Column(
        JSONB,
        default=lambda: ["G.711u", "G.711a", "G.722", "G.729", "OPUS"],
    )
    transcode_allowed = Column(Boolean, default=True)
    transcode_codecs = Column(
        JSONB,
        default=lambda: ["G.711u", "G.729"],
    )

    # RTP/SRTP
    srtp_mode = Column(String(32), default="optional")  # disabled, optional, mandatory
    srtp_profiles = Column(
        JSONB,
        default=lambda: ["AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"],
    )
    rtp_timeout_seconds = Column(Integer, default=30)
    rtcp_enabled = Column(Boolean, default=True)
    rtcp_interval_ms = Column(Integer, default=5000)

    # Silence suppression / VAD
    silence_suppression = Column(Boolean, default=False)
    comfort_noise = Column(Boolean, default=True)

    # Fax
    fax_mode = Column(String(32), default="t38")  # t38, passthrough, off
    t38_version = Column(Integer, default=0)
    t38_max_bitrate = Column(Integer, default=14400)
    t38_ecm = Column(Boolean, default=True)

    # DTMF
    dtmf_mode = Column(String(32), default="rfc2833")  # rfc2833, inband, sip-info
    dtmf_payload_type = Column(Integer, default=101)

    # Jitter buffer
    jitter_buffer_mode = Column(String(32), default="adaptive")  # fixed, adaptive
    jitter_buffer_min_ms = Column(Integer, default=20)
    jitter_buffer_max_ms = Column(Integer, default=200)

    # QoS
    dscp_audio = Column(Integer, default=46)  # EF
    dscp_video = Column(Integer, default=34)  # AF41
    dscp_signaling = Column(Integer, default=24)  # CS3

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

    def __repr__(self) -> str:
        return f"<MediaPolicy(name={self.name!r}, type={self.policy_type!r})>"

    @property
    def codec_names(self) -> list[str]:
        """Return flat list of allowed codec names."""
        return [c["name"] for c in (self.allowed_codecs or [])]

    @property
    def supports_srtp(self) -> bool:
        """Whether this policy enables SRTP in any mode."""
        return self.srtp_mode in ("optional", "mandatory")
