"""Alert generation, deduplication, and notification service.

Provides intelligent alerting for SBC fleet events including device health
transitions, trunk failures, capacity threshold breaches, certificate expiry,
security violations, and performance degradation. Supports alert deduplication,
severity escalation, and multi-channel notification.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


class AlertRule:
    """Defines a threshold-based alert rule for SBC monitoring."""

    def __init__(
        self,
        name: str,
        metric_name: str,
        operator: str,
        threshold: float,
        severity: str = "warning",
        category: str = "performance",
        cooldown_minutes: int = 5,
        escalation_after_minutes: int = 30,
        description_template: str = "",
    ) -> None:
        self.name = name
        self.metric_name = metric_name
        self.operator = operator  # gt, lt, eq, gte, lte
        self.threshold = threshold
        self.severity = severity
        self.category = category
        self.cooldown_minutes = cooldown_minutes
        self.escalation_after_minutes = escalation_after_minutes
        self.description_template = description_template

    def evaluate(self, metric_value: float) -> bool:
        """Check if the metric value breaches the threshold."""
        ops = {
            "gt": lambda v, t: v > t,
            "lt": lambda v, t: v < t,
            "eq": lambda v, t: v == t,
            "gte": lambda v, t: v >= t,
            "lte": lambda v, t: v <= t,
        }
        comparator = ops.get(self.operator)
        if comparator is None:
            return False
        return comparator(metric_value, self.threshold)


class AlertService:
    """Manages alert lifecycle including generation, deduplication,
    escalation, and notification dispatch.

    Integrates with SBC monitoring to generate actionable alerts for
    device health, trunk performance, capacity, and security events.
    """

    # Default alert rules for SBC monitoring
    DEFAULT_RULES: list[dict[str, Any]] = [
        {
            "name": "High CPU Utilization",
            "metric_name": "cpu_utilization",
            "operator": "gt",
            "threshold": 85.0,
            "severity": "major",
            "category": "performance",
            "description_template": "CPU utilization at {value}% exceeds threshold of {threshold}%",
        },
        {
            "name": "Critical CPU Utilization",
            "metric_name": "cpu_utilization",
            "operator": "gt",
            "threshold": 95.0,
            "severity": "critical",
            "category": "performance",
            "description_template": "CPU utilization critically high at {value}%",
        },
        {
            "name": "High Memory Utilization",
            "metric_name": "memory_utilization",
            "operator": "gt",
            "threshold": 90.0,
            "severity": "major",
            "category": "performance",
            "description_template": "Memory utilization at {value}% exceeds threshold of {threshold}%",
        },
        {
            "name": "High Session Utilization",
            "metric_name": "session_utilization_pct",
            "operator": "gt",
            "threshold": 85.0,
            "severity": "warning",
            "category": "capacity",
            "description_template": "Session utilization at {value}% approaching capacity",
        },
        {
            "name": "Critical Session Utilization",
            "metric_name": "session_utilization_pct",
            "operator": "gt",
            "threshold": 95.0,
            "severity": "critical",
            "category": "capacity",
            "description_template": "Session utilization critically high at {value}%",
        },
        {
            "name": "Low ASR (Answer-Seizure Ratio)",
            "metric_name": "asr",
            "operator": "lt",
            "threshold": 0.45,
            "severity": "major",
            "category": "sip_trunk",
            "description_template": "ASR dropped to {value} (threshold: {threshold})",
        },
        {
            "name": "Low NER (Network Effectiveness Ratio)",
            "metric_name": "ner",
            "operator": "lt",
            "threshold": 0.95,
            "severity": "warning",
            "category": "sip_trunk",
            "description_template": "NER at {value} indicates network issues (threshold: {threshold})",
        },
    ]

    def __init__(self) -> None:
        self._active_alerts: dict[str, dict[str, Any]] = {}
        self._alert_history: list[dict[str, Any]] = []
        self._notification_queue: list[dict[str, Any]] = []
        self._rules: list[AlertRule] = self._load_default_rules()
        self._suppression_windows: dict[str, datetime] = {}

    def check_device_metrics(
        self,
        device_id: UUID,
        hostname: str,
        metrics: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Evaluate all alert rules against device metrics.

        Returns a list of newly generated or updated alerts.
        """
        generated_alerts = []

        for rule in self._rules:
            metric_value = metrics.get(rule.metric_name)
            if metric_value is None:
                continue

            if rule.evaluate(metric_value):
                alert = self.generate_alert(
                    device_id=device_id,
                    hostname=hostname,
                    title=rule.name,
                    severity=rule.severity,
                    category=rule.category,
                    metric_name=rule.metric_name,
                    metric_value=str(metric_value),
                    threshold_value=str(rule.threshold),
                    threshold_operator=rule.operator,
                    description=rule.description_template.format(
                        value=metric_value,
                        threshold=rule.threshold,
                    ),
                )
                if alert:
                    generated_alerts.append(alert)

        return generated_alerts

    def generate_alert(
        self,
        device_id: UUID,
        hostname: str,
        title: str,
        severity: str,
        category: str,
        description: str = "",
        metric_name: Optional[str] = None,
        metric_value: Optional[str] = None,
        threshold_value: Optional[str] = None,
        threshold_operator: Optional[str] = None,
        trunk_id: Optional[UUID] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> Optional[dict[str, Any]]:
        """Generate a new alert or deduplicate with an existing active alert.

        Uses fingerprint-based deduplication to avoid alert storms. If an
        identical alert is already active, increments its occurrence count.
        """
        fingerprint = self._compute_fingerprint(
            device_id=device_id,
            category=category,
            metric_name=metric_name or title,
            threshold_operator=threshold_operator,
        )

        # Check suppression
        if self._is_suppressed(fingerprint):
            logger.debug("Alert suppressed: %s for device %s", title, hostname)
            return None

        # Deduplicate
        existing = self._active_alerts.get(fingerprint)
        if existing:
            existing["occurrence_count"] += 1
            existing["last_occurrence"] = datetime.now(timezone.utc).isoformat()
            existing["metric_value"] = metric_value
            logger.debug(
                "Alert deduplicated: %s (count=%d)",
                title,
                existing["occurrence_count"],
            )
            self._check_escalation(existing)
            return existing

        now = datetime.now(timezone.utc)
        alert_key = f"{category}:{metric_name or title}:{hostname}"

        alert_data = {
            "id": str(uuid4()),
            "device_id": str(device_id),
            "trunk_id": str(trunk_id) if trunk_id else None,
            "alert_key": alert_key,
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "state": "active",
            "metric_name": metric_name,
            "metric_value": metric_value,
            "threshold_value": threshold_value,
            "threshold_operator": threshold_operator,
            "fingerprint": fingerprint,
            "occurrence_count": 1,
            "first_occurrence": now.isoformat(),
            "last_occurrence": now.isoformat(),
            "acknowledged_at": None,
            "acknowledged_by": None,
            "resolved_at": None,
            "resolved_by": None,
            "notification_sent": False,
            "escalation_level": 0,
            "context": context or {"hostname": hostname},
            "created_at": now.isoformat(),
        }

        self._active_alerts[fingerprint] = alert_data
        self._alert_history.append(alert_data)
        self._enqueue_notification(alert_data)

        logger.info(
            "Alert generated: [%s] %s on %s — %s",
            severity.upper(),
            title,
            hostname,
            description,
        )

        return alert_data

    def generate_trunk_failure_alert(
        self,
        device_id: UUID,
        hostname: str,
        trunk_name: str,
        trunk_id: UUID,
        options_response_code: int,
        previous_status: str,
        new_status: str,
    ) -> Optional[dict[str, Any]]:
        """Generate alert for SIP trunk status change / failure."""
        if new_status in ("failed", "inactive"):
            severity = "critical"
            title = f"SIP Trunk Down: {trunk_name}"
            description = (
                f"Trunk {trunk_name} on {hostname} transitioned from "
                f"{previous_status} to {new_status}. "
                f"Last OPTIONS response: {options_response_code}."
            )
        elif new_status == "degraded":
            severity = "major"
            title = f"SIP Trunk Degraded: {trunk_name}"
            description = (
                f"Trunk {trunk_name} on {hostname} is in degraded state. "
                f"OPTIONS response code: {options_response_code}."
            )
        else:
            return None

        return self.generate_alert(
            device_id=device_id,
            hostname=hostname,
            title=title,
            severity=severity,
            category="sip_trunk",
            description=description,
            trunk_id=trunk_id,
            context={
                "hostname": hostname,
                "trunk_name": trunk_name,
                "options_response_code": options_response_code,
                "previous_status": previous_status,
                "new_status": new_status,
            },
        )

    def generate_certificate_expiry_alert(
        self,
        device_id: UUID,
        hostname: str,
        cert_cn: str,
        days_remaining: int,
        trunk_name: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Generate alert for approaching TLS certificate expiration."""
        if days_remaining <= 0:
            severity = "critical"
            title = f"TLS Certificate Expired: {cert_cn}"
        elif days_remaining <= 7:
            severity = "critical"
            title = f"TLS Certificate Expiring in {days_remaining} Days: {cert_cn}"
        elif days_remaining <= 30:
            severity = "major"
            title = f"TLS Certificate Expiring in {days_remaining} Days: {cert_cn}"
        elif days_remaining <= 90:
            severity = "warning"
            title = f"TLS Certificate Expiring in {days_remaining} Days: {cert_cn}"
        else:
            return None

        return self.generate_alert(
            device_id=device_id,
            hostname=hostname,
            title=title,
            severity=severity,
            category="certificate",
            description=(
                f"TLS certificate '{cert_cn}' on {hostname} "
                f"{'has expired' if days_remaining <= 0 else f'expires in {days_remaining} days'}. "
                "Certificate renewal required to maintain secure SIP/TLS transport."
            ),
            context={
                "hostname": hostname,
                "cert_cn": cert_cn,
                "days_remaining": days_remaining,
                "trunk_name": trunk_name,
            },
        )

    def acknowledge_alert(
        self,
        fingerprint: str,
        acknowledged_by: str,
        notes: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Acknowledge an active alert."""
        alert = self._active_alerts.get(fingerprint)
        if not alert:
            return None

        alert["state"] = "acknowledged"
        alert["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
        alert["acknowledged_by"] = acknowledged_by
        if notes:
            alert.setdefault("context", {})["acknowledgment_notes"] = notes

        logger.info(
            "Alert acknowledged: %s by %s",
            alert["title"],
            acknowledged_by,
        )
        return alert

    def resolve_alert(
        self,
        fingerprint: str,
        resolved_by: str,
        resolution_notes: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Resolve an active or acknowledged alert."""
        alert = self._active_alerts.pop(fingerprint, None)
        if not alert:
            return None

        alert["state"] = "resolved"
        alert["resolved_at"] = datetime.now(timezone.utc).isoformat()
        alert["resolved_by"] = resolved_by
        if resolution_notes:
            alert["resolution_notes"] = resolution_notes

        logger.info("Alert resolved: %s by %s", alert["title"], resolved_by)
        return alert

    def suppress_alert(
        self,
        fingerprint: str,
        duration_minutes: int = 60,
    ) -> bool:
        """Suppress an alert for the specified duration."""
        until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        self._suppression_windows[fingerprint] = until
        logger.info("Alert suppressed until %s", until.isoformat())
        return True

    def get_active_alerts(
        self,
        device_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Retrieve active alerts with optional filtering."""
        alerts = list(self._active_alerts.values())

        if device_id:
            alerts = [a for a in alerts if a["device_id"] == str(device_id)]
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        if category:
            alerts = [a for a in alerts if a["category"] == category]

        return sorted(alerts, key=lambda a: self._severity_order(a["severity"]))

    def get_alert_summary(self) -> dict[str, Any]:
        """Get aggregated alert counts by severity and state."""
        alerts = list(self._active_alerts.values())
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_state: dict[str, int] = {}

        for alert in alerts:
            sev = alert.get("severity", "info")
            cat = alert.get("category", "unknown")
            state = alert.get("state", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
            by_state[state] = by_state.get(state, 0) + 1

        return {
            "total": len(alerts),
            "active": by_state.get("active", 0),
            "acknowledged": by_state.get("acknowledged", 0),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    def get_pending_notifications(self) -> list[dict[str, Any]]:
        """Retrieve and flush the pending notification queue."""
        pending = list(self._notification_queue)
        self._notification_queue.clear()
        return pending

    def _check_escalation(self, alert: dict[str, Any]) -> None:
        """Check if an alert should be escalated based on duration."""
        first_occurrence = alert.get("first_occurrence", "")
        if not first_occurrence:
            return
        first_dt = datetime.fromisoformat(first_occurrence)
        elapsed = (datetime.now(timezone.utc) - first_dt).total_seconds() / 60

        current_level = alert.get("escalation_level", 0)
        if elapsed > 120 and current_level < 3:
            alert["escalation_level"] = 3
            alert["severity"] = "critical"
        elif elapsed > 60 and current_level < 2:
            alert["escalation_level"] = 2
            if alert["severity"] not in ("critical",):
                alert["severity"] = "major"
        elif elapsed > 30 and current_level < 1:
            alert["escalation_level"] = 1

    def _enqueue_notification(self, alert: dict[str, Any]) -> None:
        """Add alert to the notification dispatch queue."""
        severity = alert.get("severity", "info")
        channels = []
        if severity in ("critical", "major"):
            channels.extend(["email", "slack", "pagerduty"])
        elif severity == "warning":
            channels.extend(["email", "slack"])
        else:
            channels.append("email")

        self._notification_queue.append({
            "alert_id": alert["id"],
            "title": alert["title"],
            "severity": severity,
            "channels": channels,
            "queued_at": datetime.now(timezone.utc).isoformat(),
        })

    def _is_suppressed(self, fingerprint: str) -> bool:
        """Check if an alert fingerprint is currently suppressed."""
        suppressed_until = self._suppression_windows.get(fingerprint)
        if suppressed_until is None:
            return False
        if datetime.now(timezone.utc) > suppressed_until:
            del self._suppression_windows[fingerprint]
            return False
        return True

    @staticmethod
    def _compute_fingerprint(
        device_id: UUID,
        category: str,
        metric_name: str,
        threshold_operator: Optional[str] = None,
    ) -> str:
        """Generate a deterministic fingerprint for alert deduplication."""
        components = [str(device_id), category, metric_name, threshold_operator or ""]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    @staticmethod
    def _severity_order(severity: str) -> int:
        """Return numeric order for severity sorting (lower = more severe)."""
        order = {"critical": 0, "major": 1, "minor": 2, "warning": 3, "info": 4}
        return order.get(severity, 5)

    def _load_default_rules(self) -> list[AlertRule]:
        """Load default alert rules."""
        rules = []
        for rule_def in self.DEFAULT_RULES:
            rules.append(AlertRule(
                name=rule_def["name"],
                metric_name=rule_def["metric_name"],
                operator=rule_def["operator"],
                threshold=rule_def["threshold"],
                severity=rule_def["severity"],
                category=rule_def["category"],
                description_template=rule_def.get("description_template", ""),
            ))
        return rules
