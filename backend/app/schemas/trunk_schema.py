"""Pydantic schemas for SIP trunk API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class TrunkCreate(BaseModel):
    """Schema for creating a new SIP trunk on an SBC device."""
    device_id: UUID
    name: str = Field(..., min_length=1, max_length=255, examples=["Carrier-A-Primary"])
    description: Optional[str] = None
    remote_ip: str = Field(..., min_length=7, max_length=45, examples=["203.0.113.10"])
    remote_port: int = Field(5060, ge=1, le=65535)
    local_port: int = Field(5060, ge=1, le=65535)
    transport: str = Field("UDP", pattern=r"^(UDP|TCP|TLS|WS|WSS)$")
    realm: Optional[str] = Field(None, max_length=255)
    domain: Optional[str] = Field(None, max_length=255)
    auth_enabled: bool = False
    auth_username: Optional[str] = Field(None, max_length=128)
    auth_password: Optional[str] = Field(None, max_length=256)
    registration_enabled: bool = False
    registration_interval: int = Field(3600, ge=60, le=86400)
    max_sessions: Optional[int] = Field(None, ge=0)
    max_cps: Optional[float] = Field(None, ge=0)
    preferred_codecs: list[str] = Field(
        default_factory=lambda: ["G.711u", "G.711a", "G.729"]
    )
    dtmf_mode: str = Field("rfc2833", pattern=r"^(rfc2833|inband|sip-info)$")
    fax_mode: str = Field("t38", pattern=r"^(t38|passthrough|off)$")
    media_encryption: str = Field("none", pattern=r"^(none|srtp|srtp-optional)$")
    tls_enabled: bool = False
    tls_version_min: str = Field("1.2", pattern=r"^(1\.0|1\.1|1\.2|1\.3)$")
    mutual_tls: bool = False
    options_ping_enabled: bool = True
    options_ping_interval: int = Field(30, ge=5, le=300)
    route_priority: int = Field(100, ge=0, le=999)
    route_weight: int = Field(100, ge=0, le=999)
    manipulation_rules: list[dict[str, Any]] = Field(default_factory=list)
    carrier: Optional[str] = Field(None, max_length=255)
    tags: dict[str, Any] = Field(default_factory=dict)

    @field_validator("remote_ip")
    @classmethod
    def validate_remote_ip(cls, v: str) -> str:
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid remote IP address: {v}")
        return v


class TrunkUpdate(BaseModel):
    """Schema for updating an existing SIP trunk."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    remote_ip: Optional[str] = Field(None, min_length=7, max_length=45)
    remote_port: Optional[int] = Field(None, ge=1, le=65535)
    transport: Optional[str] = None
    max_sessions: Optional[int] = Field(None, ge=0)
    max_cps: Optional[float] = Field(None, ge=0)
    preferred_codecs: Optional[list[str]] = None
    tls_enabled: Optional[bool] = None
    options_ping_enabled: Optional[bool] = None
    options_ping_interval: Optional[int] = Field(None, ge=5, le=300)
    route_priority: Optional[int] = Field(None, ge=0, le=999)
    route_weight: Optional[int] = Field(None, ge=0, le=999)
    manipulation_rules: Optional[list[dict[str, Any]]] = None
    carrier: Optional[str] = None
    tags: Optional[dict[str, Any]] = None


class TrunkResponse(BaseModel):
    """Schema for SIP trunk API responses."""
    id: UUID
    device_id: UUID
    name: str
    description: Optional[str] = None
    remote_ip: str
    remote_port: int
    local_port: int
    transport: str
    realm: Optional[str] = None
    domain: Optional[str] = None
    auth_enabled: bool
    registration_enabled: bool
    max_sessions: Optional[int] = None
    max_cps: Optional[float] = None
    current_sessions: int = 0
    preferred_codecs: list[str] = []
    dtmf_mode: str = "rfc2833"
    fax_mode: str = "t38"
    media_encryption: str = "none"
    tls_enabled: bool = False
    tls_cert_cn: Optional[str] = None
    tls_cert_expiry: Optional[datetime] = None
    tls_cert_days_remaining: Optional[int] = None
    status: str
    asr: Optional[float] = None
    acd: Optional[float] = None
    ner: Optional[float] = None
    current_cps: float = 0.0
    last_options_response: Optional[int] = None
    last_options_latency_ms: Optional[float] = None
    session_utilization_pct: Optional[float] = None
    route_priority: int = 100
    route_weight: int = 100
    carrier: Optional[str] = None
    tags: dict[str, Any] = {}
    is_healthy: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TrunkStatsResponse(BaseModel):
    """Aggregated SIP trunk statistics."""
    trunk_id: UUID
    trunk_name: str
    period_start: datetime
    period_end: datetime
    total_calls: int = 0
    answered_calls: int = 0
    failed_calls: int = 0
    busy_calls: int = 0
    asr: float = 0.0
    acd: float = 0.0
    ner: float = 0.0
    max_concurrent_sessions: int = 0
    avg_concurrent_sessions: float = 0.0
    peak_cps: float = 0.0
    avg_post_dial_delay_ms: float = 0.0
    codec_distribution: dict[str, int] = {}
    response_code_distribution: dict[str, int] = {}
