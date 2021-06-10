"""SBC security audit service for compliance and vulnerability assessment.

Audits SBC fleet security posture including TLS configuration, SRTP policies,
ACL rule analysis, topology hiding enforcement, rate limiting, SIP interface
hardening, and certificate lifecycle management. Designed for enterprise
environments managing ACME/Oracle, AudioCodes, and Cisco CUBE SBCs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

logger = logging.getLogger(__name__)


class SecurityFinding:
    """Represents a single security audit finding."""

    SEVERITY_CRITICAL = "critical"
    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_LOW = "low"
    SEVERITY_INFO = "info"

    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        category: str,
        description: str,
        remediation: str,
        device_hostname: Optional[str] = None,
        affected_component: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> None:
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.description = description
        self.remediation = remediation
        self.device_hostname = device_hostname
        self.affected_component = affected_component
        self.evidence = evidence or {}
        self.found_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
            "device_hostname": self.device_hostname,
            "affected_component": self.affected_component,
            "evidence": self.evidence,
            "found_at": self.found_at.isoformat(),
        }


class SecurityAuditor:
    """Performs comprehensive security audits on SBC fleet configurations.

    Checks cover TLS/SRTP policies, ACL rules, topology hiding, rate limiting,
    SIP interface hardening, certificate expiry, and vendor-specific security
    best practices for ACME SBCs at enterprise scale.
    """

    # Minimum acceptable TLS version per compliance standard
    TLS_MINIMUM_VERSIONS = {
        "pci_dss": "1.2",
        "nist_800_52": "1.2",
        "enterprise": "1.2",
        "strict": "1.3",
    }

    # ACME SBC recommended security settings
    ACME_SECURITY_BASELINE = {
        "sip_interface_tls_min": "1.2",
        "srtp_mode": "mandatory",
        "topology_hiding_mode": "full",
        "rate_limiting_enabled": True,
        "options_ping_required": True,
        "management_acl_required": True,
        "ssh_key_auth_recommended": True,
    }

    # Weak ciphers that should be disabled
    WEAK_CIPHERS = {
        "RC4",
        "DES",
        "3DES",
        "MD5",
        "NULL",
        "EXPORT",
        "anon",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
    }

    # Approved SRTP cipher suites
    APPROVED_SRTP_PROFILES = {
        "AES_CM_128_HMAC_SHA1_80",
        "AES_CM_128_HMAC_SHA1_32",
        "AEAD_AES_128_GCM",
        "AEAD_AES_256_GCM",
    }

    def __init__(self, compliance_level: str = "enterprise") -> None:
        self.compliance_level = compliance_level
        self._findings: list[SecurityFinding] = []

    def run_full_audit(
        self,
        devices: list[dict[str, Any]],
        trunks: list[dict[str, Any]],
        acl_rules: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Execute a comprehensive security audit across the SBC fleet.

        Returns a structured audit report with findings grouped by severity
        and category, along with an overall security score.
        """
        self._findings = []

        for device in devices:
            self.audit_device_security(device)

        for trunk in trunks:
            self.audit_trunk_tls(trunk)
            self.audit_trunk_srtp(trunk)
            self.audit_trunk_transport(trunk)

        self.audit_acl_rules(acl_rules, devices)
        self.audit_topology_hiding(devices, trunks)
        self.audit_rate_limiting(devices, trunks)

        report = self._compile_report(devices)
        logger.info(
            "Security audit complete: %d findings (%d critical, %d high)",
            report["summary"]["total_findings"],
            report["summary"]["by_severity"].get("critical", 0),
            report["summary"]["by_severity"].get("high", 0),
        )
        return report

    def audit_device_security(self, device: dict[str, Any]) -> list[dict[str, Any]]:
        """Audit a single SBC device's security configuration."""
        hostname = device.get("hostname", "unknown")
        findings = []

        # Check SNMP community string
        snmp_community = device.get("snmp_community", "")
        if snmp_community in ("public", "private", ""):
            finding = SecurityFinding(
                rule_id="SEC-DEV-001",
                title="Default or weak SNMP community string",
                severity=SecurityFinding.SEVERITY_HIGH,
                category="device_hardening",
                description=(
                    f"Device {hostname} uses a default/weak SNMP community "
                    f"string ('{snmp_community}'). This allows unauthorized "
                    "network management access."
                ),
                remediation=(
                    "Configure a strong, unique SNMP community string or "
                    "migrate to SNMPv3 with authentication and encryption."
                ),
                device_hostname=hostname,
                affected_component="SNMP",
                evidence={"current_community": snmp_community},
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        # Check firmware version freshness
        firmware = device.get("firmware_version", "")
        if not firmware:
            finding = SecurityFinding(
                rule_id="SEC-DEV-002",
                title="Unknown firmware version",
                severity=SecurityFinding.SEVERITY_MEDIUM,
                category="firmware",
                description=(
                    f"Device {hostname} has no tracked firmware version. "
                    "Cannot verify patch level or known vulnerability status."
                ),
                remediation=(
                    "Poll the device to retrieve its current firmware version "
                    "and compare against vendor security advisories."
                ),
                device_hostname=hostname,
                affected_component="Firmware",
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        # Check management access security
        ssh_port = device.get("ssh_port", 22)
        if ssh_port == 22:
            finding = SecurityFinding(
                rule_id="SEC-DEV-003",
                title="Default SSH port in use",
                severity=SecurityFinding.SEVERITY_LOW,
                category="device_hardening",
                description=(
                    f"Device {hostname} uses the default SSH port 22. "
                    "Using a non-standard port reduces automated scan exposure."
                ),
                remediation=(
                    "Consider changing the SSH port to a non-standard port "
                    "and restricting access via management ACLs."
                ),
                device_hostname=hostname,
                affected_component="SSH",
                evidence={"ssh_port": ssh_port},
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        # Check HA configuration
        ha_enabled = device.get("ha_enabled", False)
        if not ha_enabled:
            finding = SecurityFinding(
                rule_id="SEC-DEV-004",
                title="High availability not configured",
                severity=SecurityFinding.SEVERITY_MEDIUM,
                category="availability",
                description=(
                    f"Device {hostname} does not have HA clustering enabled. "
                    "Single points of failure increase outage risk."
                ),
                remediation=(
                    "Deploy an HA peer and configure active/standby or "
                    "active/active clustering per vendor guidelines."
                ),
                device_hostname=hostname,
                affected_component="HA Cluster",
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        return findings

    def audit_trunk_tls(self, trunk: dict[str, Any]) -> list[dict[str, Any]]:
        """Audit TLS configuration on a SIP trunk.

        Checks TLS version, certificate expiry, mutual TLS enforcement,
        and cipher suite strength. Maps to ACME SBC TLS profile and
        SIP interface security-policy configurations.
        """
        trunk_name = trunk.get("name", "unknown")
        findings = []

        tls_enabled = trunk.get("tls_enabled", False)
        transport = trunk.get("transport", "UDP")

        # Check if signaling transport uses encryption
        if transport in ("UDP", "TCP") and not tls_enabled:
            finding = SecurityFinding(
                rule_id="SEC-TLS-001",
                title="Unencrypted SIP signaling transport",
                severity=SecurityFinding.SEVERITY_HIGH,
                category="tls",
                description=(
                    f"Trunk {trunk_name} uses {transport} without TLS. "
                    "SIP signaling is transmitted in cleartext, exposing "
                    "call metadata, credentials, and routing information."
                ),
                remediation=(
                    "Enable TLS transport (SIP/TLS on port 5061) and configure "
                    "a TLS profile with minimum TLS 1.2. On ACME SBCs, configure "
                    "the sip-interface with tls-profile referencing appropriate certs."
                ),
                affected_component=f"Trunk: {trunk_name}",
                evidence={"transport": transport, "tls_enabled": tls_enabled},
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        # Check TLS minimum version
        if tls_enabled:
            tls_min = trunk.get("tls_version_min", "1.0")
            min_required = self.TLS_MINIMUM_VERSIONS.get(
                self.compliance_level, "1.2"
            )
            if self._tls_version_lt(tls_min, min_required):
                finding = SecurityFinding(
                    rule_id="SEC-TLS-002",
                    title="TLS minimum version below compliance requirement",
                    severity=SecurityFinding.SEVERITY_CRITICAL,
                    category="tls",
                    description=(
                        f"Trunk {trunk_name} allows TLS {tls_min} which is below "
                        f"the {self.compliance_level} minimum of TLS {min_required}. "
                        "Older TLS versions have known vulnerabilities."
                    ),
                    remediation=(
                        f"Set tls-version-min to {min_required} in the TLS profile. "
                        "On ACME SBCs: security > tls-profile > min-tls-version."
                    ),
                    affected_component=f"Trunk: {trunk_name}",
                    evidence={
                        "current_tls_min": tls_min,
                        "required_tls_min": min_required,
                        "compliance_level": self.compliance_level,
                    },
                )
                self._findings.append(finding)
                findings.append(finding.to_dict())

            # Check mutual TLS
            mutual_tls = trunk.get("mutual_tls", False)
            if not mutual_tls:
                finding = SecurityFinding(
                    rule_id="SEC-TLS-003",
                    title="Mutual TLS (mTLS) not enabled",
                    severity=SecurityFinding.SEVERITY_MEDIUM,
                    category="tls",
                    description=(
                        f"Trunk {trunk_name} does not enforce mutual TLS. "
                        "Without client certificate verification, any endpoint "
                        "can establish TLS sessions with the SBC."
                    ),
                    remediation=(
                        "Enable mutual-authentication in the TLS profile and "
                        "configure trusted CA certificates. On ACME SBCs: "
                        "tls-profile > mutual-authentication > enabled."
                    ),
                    affected_component=f"Trunk: {trunk_name}",
                )
                self._findings.append(finding)
                findings.append(finding.to_dict())

        # Check certificate expiry
        cert_expiry = trunk.get("tls_cert_expiry")
        if cert_expiry:
            if isinstance(cert_expiry, str):
                cert_expiry = datetime.fromisoformat(cert_expiry)
            now = datetime.now(timezone.utc)
            days_remaining = (cert_expiry - now).days

            if days_remaining <= 0:
                severity = SecurityFinding.SEVERITY_CRITICAL
                title = "TLS certificate expired"
            elif days_remaining <= 30:
                severity = SecurityFinding.SEVERITY_HIGH
                title = "TLS certificate expiring within 30 days"
            elif days_remaining <= 90:
                severity = SecurityFinding.SEVERITY_MEDIUM
                title = "TLS certificate expiring within 90 days"
            else:
                severity = None
                title = None

            if severity:
                finding = SecurityFinding(
                    rule_id="SEC-TLS-004",
                    title=title,
                    severity=severity,
                    category="certificate",
                    description=(
                        f"Trunk {trunk_name} TLS certificate "
                        f"({'has expired' if days_remaining <= 0 else f'expires in {days_remaining} days'}). "
                        "Expired certificates cause TLS handshake failures and trunk outages."
                    ),
                    remediation=(
                        "Renew the TLS certificate and deploy to the SBC. "
                        "On ACME SBCs: security > certificate-record > import."
                    ),
                    affected_component=f"Trunk: {trunk_name}",
                    evidence={
                        "cert_expiry": cert_expiry.isoformat(),
                        "days_remaining": days_remaining,
                        "cert_cn": trunk.get("tls_cert_cn"),
                    },
                )
                self._findings.append(finding)
                findings.append(finding.to_dict())

        return findings

    def audit_trunk_srtp(self, trunk: dict[str, Any]) -> list[dict[str, Any]]:
        """Audit SRTP (Secure RTP) configuration on a SIP trunk.

        Verifies media encryption mode, SRTP cipher suite selection, and
        key exchange mechanism. Maps to ACME SBC media-sec-policy and
        SRTP profile configurations.
        """
        trunk_name = trunk.get("name", "unknown")
        findings = []

        media_encryption = trunk.get("media_encryption", "none")

        if media_encryption == "none":
            finding = SecurityFinding(
                rule_id="SEC-SRTP-001",
                title="No media encryption (SRTP) configured",
                severity=SecurityFinding.SEVERITY_HIGH,
                category="srtp",
                description=(
                    f"Trunk {trunk_name} has no SRTP configured. RTP media "
                    "streams are transmitted in cleartext, allowing call "
                    "eavesdropping via packet capture."
                ),
                remediation=(
                    "Enable SRTP with at minimum AES_CM_128_HMAC_SHA1_80. "
                    "On ACME SBCs, configure a media-sec-policy with "
                    "srtp > mode set to 'optional' or 'mandatory' and attach "
                    "it to the realm or session-agent."
                ),
                affected_component=f"Trunk: {trunk_name}",
                evidence={"media_encryption": media_encryption},
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())
        elif media_encryption == "srtp-optional":
            finding = SecurityFinding(
                rule_id="SEC-SRTP-002",
                title="SRTP mode set to optional (not mandatory)",
                severity=SecurityFinding.SEVERITY_MEDIUM,
                category="srtp",
                description=(
                    f"Trunk {trunk_name} has SRTP in optional mode. "
                    "Calls may fall back to unencrypted RTP if the remote "
                    "endpoint does not support SRTP."
                ),
                remediation=(
                    "Set SRTP mode to mandatory if all endpoints support it. "
                    "On ACME SBCs: media-sec-policy > srtp > mode > mandatory."
                ),
                affected_component=f"Trunk: {trunk_name}",
                evidence={"media_encryption": media_encryption},
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        return findings

    def audit_trunk_transport(self, trunk: dict[str, Any]) -> list[dict[str, Any]]:
        """Audit SIP transport configuration for security concerns."""
        trunk_name = trunk.get("name", "unknown")
        findings = []

        # Check OPTIONS ping configuration
        options_enabled = trunk.get("options_ping_enabled", False)
        if not options_enabled:
            finding = SecurityFinding(
                rule_id="SEC-TRANS-001",
                title="SIP OPTIONS keepalive disabled",
                severity=SecurityFinding.SEVERITY_LOW,
                category="monitoring",
                description=(
                    f"Trunk {trunk_name} does not have OPTIONS ping enabled. "
                    "Without active health probing, trunk failures may go "
                    "undetected until call attempts fail."
                ),
                remediation=(
                    "Enable OPTIONS ping with a 30-60 second interval. "
                    "On ACME SBCs, set session-agent > ping-method > OPTIONS."
                ),
                affected_component=f"Trunk: {trunk_name}",
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        return findings

    def audit_acl_rules(
        self,
        acl_rules: list[dict[str, Any]],
        devices: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Audit ACL rules for security best practices.

        Checks for overly permissive rules, missing management ACLs,
        proper rule ordering, and rate limiting enforcement.
        """
        findings = []

        # Check for overly permissive rules (0.0.0.0/0)
        for rule in acl_rules:
            source = rule.get("source_network", "")
            prefix_len = rule.get("source_prefix_length", 32)
            action = rule.get("action", "deny")
            name = rule.get("name", "unknown")

            if source == "0.0.0.0" and prefix_len == 0 and action == "allow":
                finding = SecurityFinding(
                    rule_id="SEC-ACL-001",
                    title="Overly permissive ACL rule (allow all sources)",
                    severity=SecurityFinding.SEVERITY_CRITICAL,
                    category="acl",
                    description=(
                        f"ACL rule '{name}' allows traffic from any source "
                        "(0.0.0.0/0). This effectively disables source-based "
                        "access control for SIP traffic."
                    ),
                    remediation=(
                        "Restrict source networks to known carrier, peering "
                        "partner, and enterprise IP ranges. On ACME SBCs, "
                        "configure realm > access-control with specific subnets."
                    ),
                    affected_component=f"ACL Rule: {name}",
                    evidence={
                        "source_network": f"{source}/{prefix_len}",
                        "action": action,
                    },
                )
                self._findings.append(finding)
                findings.append(finding.to_dict())

            # Check for rate limiting on allow rules
            if action == "allow":
                rate_limit = rule.get("rate_limit_cps")
                if not rate_limit:
                    finding = SecurityFinding(
                        rule_id="SEC-ACL-002",
                        title="ACL allow rule without rate limiting",
                        severity=SecurityFinding.SEVERITY_MEDIUM,
                        category="acl",
                        description=(
                            f"ACL rule '{name}' allows traffic without "
                            "CPS rate limiting. This leaves the SBC vulnerable "
                            "to SIP flood attacks and resource exhaustion."
                        ),
                        remediation=(
                            "Add rate-limit-cps and burst thresholds to all "
                            "allow rules. On ACME SBCs, configure session-agent "
                            "max-burst-rate and max-sustain-rate."
                        ),
                        affected_component=f"ACL Rule: {name}",
                    )
                    self._findings.append(finding)
                    findings.append(finding.to_dict())

        # Check that a default deny rule exists
        has_default_deny = any(
            r.get("source_network") == "0.0.0.0"
            and r.get("source_prefix_length") == 0
            and r.get("action") == "deny"
            for r in acl_rules
        )
        if acl_rules and not has_default_deny:
            finding = SecurityFinding(
                rule_id="SEC-ACL-003",
                title="No default-deny ACL rule configured",
                severity=SecurityFinding.SEVERITY_HIGH,
                category="acl",
                description=(
                    "No default-deny rule found in the ACL set. Without an "
                    "explicit deny-all at the lowest priority, unmatched "
                    "traffic may be implicitly allowed."
                ),
                remediation=(
                    "Add a deny-all rule at the lowest priority (highest number) "
                    "to ensure only explicitly permitted traffic is allowed."
                ),
            )
            self._findings.append(finding)
            findings.append(finding.to_dict())

        return findings

    def audit_topology_hiding(
        self,
        devices: list[dict[str, Any]],
        trunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Audit topology hiding configuration across the fleet.

        Topology hiding prevents internal network information from leaking
        in SIP headers (Via, Contact, Record-Route, Route). On ACME SBCs,
        this is configured via the session-router-config and
        sip-manipulation rules.
        """
        findings = []

        for trunk in trunks:
            trunk_name = trunk.get("name", "unknown")
            transport = trunk.get("transport", "UDP")

            # Check if external-facing trunks have topology hiding
            realm = trunk.get("realm", "")
            if realm in ("core", "public", "external", "carrier"):
                hmr_rules = trunk.get("manipulation_rules", [])
                has_topology_hiding = any(
                    r.get("name", "").lower().find("topology") >= 0
                    or r.get("name", "").lower().find("hide") >= 0
                    for r in hmr_rules
                )
                if not has_topology_hiding:
                    finding = SecurityFinding(
                        rule_id="SEC-TOPO-001",
                        title="External trunk without topology hiding",
                        severity=SecurityFinding.SEVERITY_HIGH,
                        category="topology_hiding",
                        description=(
                            f"Trunk {trunk_name} faces realm '{realm}' but "
                            "has no topology hiding rules configured. Internal "
                            "IP addresses and network topology may leak in SIP "
                            "Via, Contact, and Record-Route headers."
                        ),
                        remediation=(
                            "Enable topology hiding via SIP manipulation rules. "
                            "On ACME SBCs, configure session-router-config > "
                            "topology-hiding with mode 'full' and appropriate "
                            "replacement hostnames/IPs for external-facing realms."
                        ),
                        affected_component=f"Trunk: {trunk_name}",
                        evidence={"realm": realm, "hmr_count": len(hmr_rules)},
                    )
                    self._findings.append(finding)
                    findings.append(finding.to_dict())

        return findings

    def audit_rate_limiting(
        self,
        devices: list[dict[str, Any]],
        trunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Audit rate limiting configuration for DDoS/flood protection.

        Verifies that CPS limits, session limits, and per-source rate
        controls are configured to protect against SIP flooding.
        """
        findings = []

        for device in devices:
            hostname = device.get("hostname", "unknown")
            max_cps = device.get("max_cps")
            max_sessions = device.get("max_sessions")

            if not max_cps:
                finding = SecurityFinding(
                    rule_id="SEC-RATE-001",
                    title="No device-level CPS limit configured",
                    severity=SecurityFinding.SEVERITY_HIGH,
                    category="rate_limiting",
                    description=(
                        f"Device {hostname} has no maximum CPS limit set. "
                        "Without rate limiting, the SBC is vulnerable to "
                        "SIP INVITE flood attacks that can exhaust resources."
                    ),
                    remediation=(
                        "Configure a device-level CPS limit based on the hardware "
                        "capacity. On ACME SBCs: session-router-config > "
                        "max-calls-per-second. For ACME 9200: typical limit 500-2000 CPS."
                    ),
                    device_hostname=hostname,
                    affected_component="Rate Limiting",
                )
                self._findings.append(finding)
                findings.append(finding.to_dict())

            if not max_sessions:
                finding = SecurityFinding(
                    rule_id="SEC-RATE-002",
                    title="No device-level session limit configured",
                    severity=SecurityFinding.SEVERITY_MEDIUM,
                    category="rate_limiting",
                    description=(
                        f"Device {hostname} has no maximum session limit set. "
                        "Unbounded session counts can lead to resource exhaustion."
                    ),
                    remediation=(
                        "Configure max-sessions based on licensed capacity. "
                        "For ACME 9200: up to 250,000 sessions. "
                        "For ACME 4500: up to 32,000 sessions."
                    ),
                    device_hostname=hostname,
                    affected_component="Session Limits",
                )
                self._findings.append(finding)
                findings.append(finding.to_dict())

        return findings

    def get_security_score(self) -> dict[str, Any]:
        """Calculate an overall security score based on audit findings.

        Score is 0-100 where 100 is fully compliant. Deductions are
        weighted by finding severity.
        """
        severity_weights = {
            SecurityFinding.SEVERITY_CRITICAL: 25,
            SecurityFinding.SEVERITY_HIGH: 15,
            SecurityFinding.SEVERITY_MEDIUM: 8,
            SecurityFinding.SEVERITY_LOW: 3,
            SecurityFinding.SEVERITY_INFO: 0,
        }

        total_deduction = sum(
            severity_weights.get(f.severity, 0) for f in self._findings
        )

        score = max(0, 100 - total_deduction)

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "grade": grade,
            "total_findings": len(self._findings),
            "total_deduction": total_deduction,
            "compliance_level": self.compliance_level,
        }

    def _compile_report(self, devices: list[dict[str, Any]]) -> dict[str, Any]:
        """Compile findings into a structured audit report."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for finding in self._findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1

        score_info = self.get_security_score()

        return {
            "audit_id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "compliance_level": self.compliance_level,
            "devices_audited": len(devices),
            "summary": {
                "total_findings": len(self._findings),
                "by_severity": by_severity,
                "by_category": by_category,
                "security_score": score_info["score"],
                "security_grade": score_info["grade"],
            },
            "findings": [f.to_dict() for f in self._findings],
        }

    @staticmethod
    def _tls_version_lt(version_a: str, version_b: str) -> bool:
        """Compare two TLS version strings (e.g., '1.2' < '1.3')."""
        version_order = {"1.0": 0, "1.1": 1, "1.2": 2, "1.3": 3}
        return version_order.get(version_a, 0) < version_order.get(version_b, 0)
