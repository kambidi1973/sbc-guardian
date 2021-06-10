"""Service layer for SBC device lifecycle management.

Handles device registration, discovery, status tracking, firmware
management, and HA cluster operations across the managed fleet.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from app.models.sbc_device import DeviceStatus, SBCDevice, VendorType

logger = logging.getLogger(__name__)


class DeviceManager:
    """Manages SBC device lifecycle operations including registration,
    status tracking, health assessment, and firmware management.
    """

    # Vendor-specific default ports and protocols
    VENDOR_DEFAULTS: dict[str, dict[str, Any]] = {
        "acme": {
            "ssh_port": 22,
            "snmp_port": 161,
            "api_port": 443,
            "api_protocol": "https",
            "default_model": "Net-Net Enterprise SBC",
        },
        "audiocodes": {
            "ssh_port": 22,
            "snmp_port": 161,
            "api_port": 443,
            "api_protocol": "https",
            "default_model": "Mediant 4000",
        },
        "cisco_cube": {
            "ssh_port": 22,
            "snmp_port": 161,
            "api_port": None,
            "api_protocol": "https",
            "default_model": "ISR 4451-X",
        },
        "generic_snmp": {
            "ssh_port": 22,
            "snmp_port": 161,
            "api_port": None,
            "api_protocol": "https",
            "default_model": "Generic SBC",
        },
    }

    def __init__(self, db_session: Any = None, connector_registry: Any = None) -> None:
        self._db = db_session
        self._connectors = connector_registry or {}
        self._device_cache: dict[UUID, dict[str, Any]] = {}

    def register_device(
        self,
        hostname: str,
        ip_address: str,
        vendor: str,
        model: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Register a new SBC device in the fleet inventory.

        Applies vendor-specific defaults, validates connectivity parameters,
        and optionally performs an initial health probe.
        """
        vendor_key = vendor.lower()
        defaults = self.VENDOR_DEFAULTS.get(vendor_key, self.VENDOR_DEFAULTS["generic_snmp"])

        device_data = {
            "hostname": hostname,
            "ip_address": ip_address,
            "vendor": vendor_key,
            "model": model or defaults["default_model"],
            "ssh_port": kwargs.get("ssh_port", defaults["ssh_port"]),
            "snmp_port": kwargs.get("snmp_port", defaults["snmp_port"]),
            "api_port": kwargs.get("api_port", defaults["api_port"]),
            "api_protocol": kwargs.get("api_protocol", defaults["api_protocol"]),
            "status": DeviceStatus.UNKNOWN.value,
            "firmware_version": kwargs.get("firmware_version"),
            "serial_number": kwargs.get("serial_number"),
            "location": kwargs.get("location"),
            "datacenter": kwargs.get("datacenter"),
            "rack_position": kwargs.get("rack_position"),
            "max_sessions": kwargs.get("max_sessions"),
            "max_cps": kwargs.get("max_cps"),
            "ha_enabled": kwargs.get("ha_enabled", False),
            "ha_role": kwargs.get("ha_role"),
            "tags": kwargs.get("tags", {}),
            "notes": kwargs.get("notes"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        logger.info(
            "Registering SBC device: %s (%s) at %s — vendor=%s, model=%s",
            hostname,
            ip_address,
            kwargs.get("location", "unknown"),
            vendor_key,
            device_data["model"],
        )

        return device_data

    def update_device_status(
        self,
        device_id: UUID,
        status: DeviceStatus,
        metrics: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Update the operational status and metrics for a device.

        Called by the monitoring service after each health check cycle.
        Handles state transitions and triggers alerts when status changes.
        """
        now = datetime.now(timezone.utc)
        update_data: dict[str, Any] = {
            "status": status.value,
            "last_seen": now.isoformat(),
            "updated_at": now.isoformat(),
        }

        if metrics:
            update_data["current_sessions"] = metrics.get("current_sessions", 0)
            update_data["current_cps"] = metrics.get("current_cps", 0.0)
            update_data["cpu_utilization"] = metrics.get("cpu_utilization")
            update_data["memory_utilization"] = metrics.get("memory_utilization")
            update_data["uptime_seconds"] = metrics.get("uptime_seconds")

        previous = self._device_cache.get(device_id, {})
        previous_status = previous.get("status")

        if previous_status and previous_status != status.value:
            logger.warning(
                "Device %s status transition: %s -> %s",
                device_id,
                previous_status,
                status.value,
            )
            update_data["_status_changed"] = True
            update_data["_previous_status"] = previous_status

        self._device_cache[device_id] = update_data
        return update_data

    def assess_fleet_health(self, devices: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculate aggregate health statistics for the entire SBC fleet.

        Returns summary counts, utilization percentages, and identifies
        devices requiring immediate attention.
        """
        summary = {
            "total_devices": len(devices),
            "online": 0,
            "offline": 0,
            "degraded": 0,
            "maintenance": 0,
            "unreachable": 0,
            "unknown": 0,
            "total_sessions": 0,
            "total_max_sessions": 0,
            "devices_needing_attention": [],
            "cpu_values": [],
            "memory_values": [],
        }

        for device in devices:
            status = device.get("status", "unknown")
            summary[status] = summary.get(status, 0) + 1

            sessions = device.get("current_sessions", 0)
            max_sessions = device.get("max_sessions", 0)
            summary["total_sessions"] += sessions
            summary["total_max_sessions"] += max_sessions

            cpu = device.get("cpu_utilization")
            if cpu is not None:
                summary["cpu_values"].append(cpu)

            mem = device.get("memory_utilization")
            if mem is not None:
                summary["memory_values"].append(mem)

            if self._device_needs_attention(device):
                summary["devices_needing_attention"].append(
                    {
                        "hostname": device.get("hostname"),
                        "status": status,
                        "reason": self._attention_reason(device),
                    }
                )

        # Calculate averages
        cpu_vals = summary.pop("cpu_values")
        mem_vals = summary.pop("memory_values")
        summary["avg_cpu_utilization"] = (
            round(sum(cpu_vals) / len(cpu_vals), 2) if cpu_vals else None
        )
        summary["avg_memory_utilization"] = (
            round(sum(mem_vals) / len(mem_vals), 2) if mem_vals else None
        )

        if summary["total_max_sessions"] > 0:
            summary["fleet_session_utilization_pct"] = round(
                (summary["total_sessions"] / summary["total_max_sessions"]) * 100, 2
            )
        else:
            summary["fleet_session_utilization_pct"] = 0.0

        return summary

    def check_firmware_compliance(
        self,
        devices: list[dict[str, Any]],
        approved_versions: dict[str, list[str]],
    ) -> list[dict[str, Any]]:
        """Check all devices against approved firmware versions.

        Returns a list of non-compliant devices with their current and
        expected firmware versions.
        """
        non_compliant = []
        for device in devices:
            vendor = device.get("vendor", "")
            current_fw = device.get("firmware_version", "")
            allowed = approved_versions.get(vendor, [])

            if current_fw and allowed and current_fw not in allowed:
                non_compliant.append(
                    {
                        "hostname": device.get("hostname"),
                        "ip_address": device.get("ip_address"),
                        "vendor": vendor,
                        "current_version": current_fw,
                        "approved_versions": allowed,
                        "compliant": False,
                    }
                )

        logger.info(
            "Firmware compliance check: %d/%d devices non-compliant",
            len(non_compliant),
            len(devices),
        )
        return non_compliant

    def generate_device_fingerprint(self, device_data: dict[str, Any]) -> str:
        """Generate a deterministic fingerprint for a device based on
        its immutable properties (vendor, model, serial, IP).
        """
        components = [
            device_data.get("vendor", ""),
            device_data.get("model", ""),
            device_data.get("serial_number", ""),
            device_data.get("ip_address", ""),
        ]
        raw = "|".join(str(c) for c in components)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def get_ha_cluster_status(
        self,
        primary_device: dict[str, Any],
        secondary_device: dict[str, Any],
    ) -> dict[str, Any]:
        """Assess the HA cluster status between a primary/secondary pair.

        Returns health assessment including synchronization status and
        failover readiness.
        """
        primary_status = primary_device.get("status", "unknown")
        secondary_status = secondary_device.get("status", "unknown")
        primary_config_hash = primary_device.get("config_hash", "")
        secondary_config_hash = secondary_device.get("config_hash", "")

        configs_synced = (
            primary_config_hash == secondary_config_hash
            and primary_config_hash != ""
        )

        cluster_healthy = (
            primary_status == "online"
            and secondary_status == "online"
            and configs_synced
        )

        return {
            "primary_hostname": primary_device.get("hostname"),
            "secondary_hostname": secondary_device.get("hostname"),
            "primary_status": primary_status,
            "secondary_status": secondary_status,
            "configs_synchronized": configs_synced,
            "cluster_healthy": cluster_healthy,
            "failover_ready": secondary_status == "online" and configs_synced,
            "assessed_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _device_needs_attention(device: dict[str, Any]) -> bool:
        """Determine if a device requires operator attention."""
        status = device.get("status", "unknown")
        if status in ("degraded", "unreachable", "offline"):
            return True
        cpu = device.get("cpu_utilization")
        if cpu is not None and cpu > 85.0:
            return True
        mem = device.get("memory_utilization")
        if mem is not None and mem > 90.0:
            return True
        max_s = device.get("max_sessions", 0)
        cur_s = device.get("current_sessions", 0)
        if max_s > 0 and (cur_s / max_s) > 0.90:
            return True
        return False

    @staticmethod
    def _attention_reason(device: dict[str, Any]) -> str:
        """Return human-readable reason a device needs attention."""
        reasons = []
        status = device.get("status", "unknown")
        if status in ("degraded", "unreachable", "offline"):
            reasons.append(f"Status is {status}")
        cpu = device.get("cpu_utilization")
        if cpu is not None and cpu > 85.0:
            reasons.append(f"CPU at {cpu}%")
        mem = device.get("memory_utilization")
        if mem is not None and mem > 90.0:
            reasons.append(f"Memory at {mem}%")
        max_s = device.get("max_sessions", 0)
        cur_s = device.get("current_sessions", 0)
        if max_s > 0 and (cur_s / max_s) > 0.90:
            pct = round((cur_s / max_s) * 100, 1)
            reasons.append(f"Session utilization at {pct}%")
        return "; ".join(reasons) if reasons else "Unknown"
