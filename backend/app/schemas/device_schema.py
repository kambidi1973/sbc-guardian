"""Pydantic schemas for SBC device API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class DeviceCredentials(BaseModel):
    """Credentials for connecting to an SBC device."""
    username: str = Field(..., min_length=1, max_length=128)
    password: Optional[str] = Field(None, max_length=256)
    ssh_key: Optional[str] = None
    ssh_port: int = Field(22, ge=1, le=65535)
    enable_password: Optional[str] = None


class DeviceCreate(BaseModel):
    """Schema for creating a new SBC device entry."""
    hostname: str = Field(..., min_length=1, max_length=255, examples=["sbc-edge-01.dc-east.example.com"])
    ip_address: str = Field(..., min_length=7, max_length=45, examples=["10.10.1.50"])
    management_ip: Optional[str] = Field(None, max_length=45)
    vendor: str = Field(..., examples=["acme"])
    model: str = Field(..., max_length=128, examples=["Net-Net 4600"])
    firmware_version: Optional[str] = Field(None, max_length=64, examples=["SCZ9.0.0"])
    serial_number: Optional[str] = Field(None, max_length=128)
    location: Optional[str] = Field(None, max_length=255, examples=["DC-East"])
    datacenter: Optional[str] = Field(None, max_length=128)
    rack_position: Optional[str] = Field(None, max_length=64)
    snmp_port: int = Field(161, ge=1, le=65535)
    snmp_community: Optional[str] = Field(None, max_length=128)
    api_port: Optional[int] = Field(None, ge=1, le=65535)
    api_protocol: str = Field("https", pattern=r"^(http|https)$")
    max_sessions: Optional[int] = Field(None, ge=0)
    max_cps: Optional[int] = Field(None, ge=0)
    ha_enabled: bool = False
    ha_role: Optional[str] = Field(None, pattern=r"^(primary|secondary|standalone)$")
    credentials: Optional[DeviceCredentials] = None
    tags: dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        import ipaddress
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("vendor")
    @classmethod
    def validate_vendor(cls, v: str) -> str:
        allowed = {"acme", "audiocodes", "cisco_cube", "generic_snmp"}
        if v.lower() not in allowed:
            raise ValueError(f"Vendor must be one of: {', '.join(sorted(allowed))}")
        return v.lower()


class DeviceUpdate(BaseModel):
    """Schema for updating an existing SBC device."""
    hostname: Optional[str] = Field(None, min_length=1, max_length=255)
    ip_address: Optional[str] = Field(None, min_length=7, max_length=45)
    management_ip: Optional[str] = Field(None, max_length=45)
    model: Optional[str] = Field(None, max_length=128)
    firmware_version: Optional[str] = Field(None, max_length=64)
    serial_number: Optional[str] = Field(None, max_length=128)
    location: Optional[str] = Field(None, max_length=255)
    datacenter: Optional[str] = Field(None, max_length=128)
    rack_position: Optional[str] = Field(None, max_length=64)
    max_sessions: Optional[int] = Field(None, ge=0)
    max_cps: Optional[int] = Field(None, ge=0)
    ha_enabled: Optional[bool] = None
    ha_role: Optional[str] = None
    credentials: Optional[DeviceCredentials] = None
    tags: Optional[dict[str, Any]] = None
    notes: Optional[str] = None


class DeviceResponse(BaseModel):
    """Schema for SBC device API responses."""
    id: UUID
    hostname: str
    ip_address: str
    management_ip: Optional[str] = None
    vendor: str
    model: str
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None
    location: Optional[str] = None
    datacenter: Optional[str] = None
    rack_position: Optional[str] = None
    status: str
    last_seen: Optional[datetime] = None
    uptime_seconds: Optional[int] = None
    ssh_port: int
    snmp_port: int
    max_sessions: Optional[int] = None
    max_cps: Optional[int] = None
    current_sessions: int = 0
    current_cps: float = 0.0
    cpu_utilization: Optional[float] = None
    memory_utilization: Optional[float] = None
    session_utilization_pct: Optional[float] = None
    cps_utilization_pct: Optional[float] = None
    ha_enabled: bool = False
    ha_role: Optional[str] = None
    config_version: Optional[str] = None
    last_config_change: Optional[datetime] = None
    tags: dict[str, Any] = {}
    notes: Optional[str] = None
    is_healthy: bool = False
    needs_attention: bool = False
    trunk_count: int = 0
    active_alert_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DeviceListResponse(BaseModel):
    """Paginated list of SBC devices."""
    items: list[DeviceResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class DeviceHealthSummary(BaseModel):
    """Aggregated fleet health summary."""
    total_devices: int = 0
    online: int = 0
    offline: int = 0
    degraded: int = 0
    maintenance: int = 0
    unreachable: int = 0
    total_sessions: int = 0
    total_max_sessions: int = 0
    fleet_session_utilization_pct: float = 0.0
    avg_cpu_utilization: Optional[float] = None
    avg_memory_utilization: Optional[float] = None
    active_alerts: int = 0
    critical_alerts: int = 0
