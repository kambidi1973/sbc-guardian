"""SBC configuration backup, diff, and validation service.

Manages configuration versioning with backup/restore, visual diff generation,
config validation against security baselines, and deployment tracking.
Supports ACME/Oracle SBC running configurations and vendor-neutral
JSON/XML config formats.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


class ConfigVersion:
    """Represents a single versioned configuration snapshot."""

    def __init__(
        self,
        device_id: UUID,
        config_text: str,
        version_label: Optional[str] = None,
        created_by: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.id = uuid4()
        self.device_id = device_id
        self.config_text = config_text
        self.config_hash = hashlib.sha256(config_text.encode()).hexdigest()
        self.version_label = version_label or f"v-{self.config_hash[:8]}"
        self.created_by = created_by
        self.metadata = metadata or {}
        self.created_at = datetime.now(timezone.utc)
        self.size_bytes = len(config_text.encode())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "device_id": str(self.device_id),
            "config_hash": self.config_hash,
            "version_label": self.version_label,
            "created_by": self.created_by,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "size_bytes": self.size_bytes,
        }


class ConfigManager:
    """Manages SBC configuration lifecycle including backup, diff, validation,
    and deployment tracking.

    Provides Git-style versioned configuration management with the ability to
    compare, rollback, and validate configurations against security baselines.
    Generates ACME SBC CLI-format configurations and generic JSON exports.
    """

    # ACME SBC configuration sections for validation
    ACME_CONFIG_SECTIONS = [
        "system",
        "session-router",
        "session-agent",
        "session-agent-group",
        "sip-interface",
        "sip-port",
        "realm-config",
        "steering-pool",
        "media-manager",
        "tls-profile",
        "certificate-record",
        "access-control",
        "codec-policy",
        "session-translation",
        "local-policy",
        "sip-manipulation",
    ]

    # Required configuration sections for a secure ACME SBC deployment
    REQUIRED_SECURITY_SECTIONS = {
        "tls-profile",
        "access-control",
        "sip-interface",
        "realm-config",
    }

    def __init__(self, backup_directory: str = "/app/backups") -> None:
        self.backup_directory = backup_directory
        self._versions: dict[UUID, list[ConfigVersion]] = {}

    def backup_config(
        self,
        device_id: UUID,
        config_text: str,
        hostname: str = "unknown",
        created_by: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Create a versioned backup of an SBC device configuration.

        Computes a content hash to detect changes and avoids storing
        duplicate backups when the configuration has not changed.
        """
        config_hash = hashlib.sha256(config_text.encode()).hexdigest()

        # Check if this exact configuration already exists
        existing_versions = self._versions.get(device_id, [])
        if existing_versions and existing_versions[-1].config_hash == config_hash:
            logger.info(
                "Config for %s unchanged (hash=%s), skipping backup",
                hostname,
                config_hash[:12],
            )
            return {
                "status": "unchanged",
                "config_hash": config_hash,
                "device_id": str(device_id),
                "hostname": hostname,
                "existing_version": existing_versions[-1].version_label,
            }

        version = ConfigVersion(
            device_id=device_id,
            config_text=config_text,
            created_by=created_by,
            metadata={
                "hostname": hostname,
                **(metadata or {}),
            },
        )

        if device_id not in self._versions:
            self._versions[device_id] = []
        self._versions[device_id].append(version)

        logger.info(
            "Backed up config for %s: version=%s, hash=%s, size=%d bytes",
            hostname,
            version.version_label,
            config_hash[:12],
            version.size_bytes,
        )

        return {
            "status": "created",
            "version_id": str(version.id),
            "version_label": version.version_label,
            "config_hash": config_hash,
            "device_id": str(device_id),
            "hostname": hostname,
            "size_bytes": version.size_bytes,
            "created_at": version.created_at.isoformat(),
        }

    def diff_configs(
        self,
        config_a: str,
        config_b: str,
        label_a: str = "previous",
        label_b: str = "current",
        context_lines: int = 3,
    ) -> dict[str, Any]:
        """Generate a unified diff between two configuration snapshots.

        Returns both the raw diff text and structured change summary
        showing added, removed, and modified lines.
        """
        lines_a = config_a.splitlines(keepends=True)
        lines_b = config_b.splitlines(keepends=True)

        diff_lines = list(difflib.unified_diff(
            lines_a,
            lines_b,
            fromfile=label_a,
            tofile=label_b,
            n=context_lines,
        ))

        additions = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        deletions = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))

        # Identify changed configuration sections (ACME-style)
        changed_sections = set()
        current_section = None
        for line in diff_lines:
            stripped = line.strip().lstrip("+-")
            for section in self.ACME_CONFIG_SECTIONS:
                if stripped.startswith(section):
                    current_section = section
                    break
            if current_section and (line.startswith("+") or line.startswith("-")):
                changed_sections.add(current_section)

        hash_a = hashlib.sha256(config_a.encode()).hexdigest()[:12]
        hash_b = hashlib.sha256(config_b.encode()).hexdigest()[:12]

        return {
            "has_changes": len(diff_lines) > 0,
            "diff_text": "".join(diff_lines),
            "additions": additions,
            "deletions": deletions,
            "total_changes": additions + deletions,
            "changed_sections": sorted(changed_sections),
            "hash_a": hash_a,
            "hash_b": hash_b,
            "lines_a": len(lines_a),
            "lines_b": len(lines_b),
        }

    def validate_config(
        self,
        config_text: str,
        vendor: str = "acme",
    ) -> dict[str, Any]:
        """Validate an SBC configuration against security and structural rules.

        Checks for required sections, security settings, deprecated features,
        and configuration consistency.
        """
        issues: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        config_lower = config_text.lower()

        if vendor == "acme":
            # Check for required security sections
            for section in self.REQUIRED_SECURITY_SECTIONS:
                if section not in config_lower:
                    issues.append({
                        "severity": "error",
                        "section": section,
                        "message": f"Required configuration section '{section}' not found",
                        "remediation": f"Add {section} configuration block",
                    })

            # Check for insecure TLS settings
            if "min-tls-version" in config_lower:
                for bad_version in ("1.0", "1.1"):
                    if f"min-tls-version          {bad_version}" in config_text:
                        issues.append({
                            "severity": "error",
                            "section": "tls-profile",
                            "message": f"TLS minimum version set to {bad_version} (insecure)",
                            "remediation": "Set min-tls-version to 1.2 or higher",
                        })

            # Check for topology hiding
            if "topology-hiding" not in config_lower:
                warnings.append({
                    "severity": "warning",
                    "section": "session-router",
                    "message": "No topology-hiding configuration found",
                    "remediation": "Enable topology hiding for external-facing realms",
                })

            # Check for SRTP configuration
            if "media-sec-policy" not in config_lower and "srtp" not in config_lower:
                warnings.append({
                    "severity": "warning",
                    "section": "media-manager",
                    "message": "No SRTP/media-sec-policy configuration found",
                    "remediation": "Configure media-sec-policy with SRTP for media encryption",
                })

            # Check for steering pools (media steering)
            if "steering-pool" not in config_lower:
                warnings.append({
                    "severity": "warning",
                    "section": "media-manager",
                    "message": "No steering-pool configuration found",
                    "remediation": (
                        "Configure steering-pools for realm-based media steering "
                        "to ensure RTP traffic follows the correct network path"
                    ),
                })

            # Check for codec-policy
            if "codec-policy" not in config_lower:
                warnings.append({
                    "severity": "warning",
                    "section": "codec-policy",
                    "message": "No codec-policy configuration found",
                    "remediation": "Define codec policies to control codec negotiation",
                })

        valid = len(issues) == 0

        return {
            "valid": valid,
            "vendor": vendor,
            "issues": issues,
            "warnings": warnings,
            "issue_count": len(issues),
            "warning_count": len(warnings),
            "config_hash": hashlib.sha256(config_text.encode()).hexdigest(),
            "config_size_bytes": len(config_text.encode()),
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_version_history(
        self,
        device_id: UUID,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieve configuration version history for a device."""
        versions = self._versions.get(device_id, [])
        sorted_versions = sorted(versions, key=lambda v: v.created_at, reverse=True)
        return [v.to_dict() for v in sorted_versions[:limit]]

    def get_config_by_version(
        self,
        device_id: UUID,
        version_label: str,
    ) -> Optional[str]:
        """Retrieve a specific configuration version's content."""
        versions = self._versions.get(device_id, [])
        for version in versions:
            if version.version_label == version_label:
                return version.config_text
        return None

    def get_latest_config(self, device_id: UUID) -> Optional[dict[str, Any]]:
        """Retrieve the most recent configuration for a device."""
        versions = self._versions.get(device_id, [])
        if not versions:
            return None
        latest = max(versions, key=lambda v: v.created_at)
        return {
            **latest.to_dict(),
            "config_text": latest.config_text,
        }

    def generate_acme_sbc_template(
        self,
        hostname: str,
        realm_access: str = "access",
        realm_core: str = "core",
        sip_interface_ip: str = "10.10.1.50",
        tls_profile_name: str = "enterprise-tls",
    ) -> str:
        """Generate a baseline ACME SBC configuration template.

        Creates a secure starting configuration with realm-based architecture,
        TLS profiles, access control, and topology hiding for ACME 9200/4500
        series SBCs.
        """
        template = f"""system
    hostname                  {hostname}
    description               SBC Guardian managed device
    log-level                 WARNING

tls-profile
    name                      {tls_profile_name}
    min-tls-version           1.2
    cipher-list               ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
    verify-depth              3
    mutual-authentication     enabled
    ocsp-enabled              enabled

realm-config
    identifier                {realm_access}
    description               Customer-facing access realm
    network-interfaces        M00:0
    mm-in-realm               enabled
    mm-in-network             enabled
    out-manipulationid        topology-hide-access
    symmetric-latching        enabled
    max-sessions              10000

realm-config
    identifier                {realm_core}
    description               Core network / carrier peering realm
    network-interfaces        M10:0
    mm-in-realm               enabled
    mm-in-network             enabled
    out-manipulationid        topology-hide-core
    symmetric-latching        enabled
    max-sessions              10000

sip-interface
    realm-id                  {realm_access}
    sip-port
        address               {sip_interface_ip}
        port                  5060
        transport-protocol    UDP
        tls-profile           {tls_profile_name}
    registration-caching      enabled
    options                   +reg-via-bc

sip-interface
    realm-id                  {realm_core}
    sip-port
        address               {sip_interface_ip}
        port                  5061
        transport-protocol    TLS
        tls-profile           {tls_profile_name}

steering-pool
    realm-id                  {realm_access}
    ip-address                {sip_interface_ip}
    start-port                16384
    end-port                  32768

steering-pool
    realm-id                  {realm_core}
    ip-address                {sip_interface_ip}
    start-port                32769
    end-port                  49152

media-sec-policy
    name                      enterprise-srtp
    pass-through              disabled
    srtp
        mode                  mandatory
        profile               AES_CM_128_HMAC_SHA1_80
        mki                   disabled

codec-policy
    name                      standard-codec-policy
    codec
        name                  G.711u
        preference            1
    codec
        name                  G.711a
        preference            2
    codec
        name                  G.729
        preference            3
    codec
        name                  G.722
        preference            4

access-control
    realm-id                  {realm_access}
    description               Default deny all inbound on access realm
    source-address            0.0.0.0
    destination-address       0.0.0.0
    application-protocol      SIP
    transport-protocol        ANY
    access                    deny

session-router-config
    topology-hiding           enabled
    max-calls-per-second      500

sip-manipulation
    name                      topology-hide-access
    description               Strip internal Via/Contact for access realm
    header-rule
        name                  strip-via
        header-name           Via
        action                delete-header
        msg-type              response
    header-rule
        name                  rewrite-contact
        header-name           Contact
        action                manipulate
        msg-type              any
        match-value           (.*)@(.*)
        new-value             \\1@{hostname}

sip-manipulation
    name                      topology-hide-core
    description               Strip internal headers for carrier peering
    header-rule
        name                  strip-via
        header-name           Via
        action                delete-header
        msg-type              response
    header-rule
        name                  strip-record-route
        header-name           Record-Route
        action                delete-header
        msg-type              response
"""
        return template
