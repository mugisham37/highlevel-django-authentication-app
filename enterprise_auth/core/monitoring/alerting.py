"""
Comprehensive alerting and notification system for monitoring.
Provides real-time monitoring, alerting, and escalation procedures.
"""

import logging
import smtplib
import json
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from .logging_config import get_structured_logger

logger = get_structured_logger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


@dataclass
class Alert:
    """Alert data structure."""
    id: str
    name: str
    severity: AlertSeverity
    status: AlertStatus
    message: str
    timestamp: datetime
    source: str
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    resolved_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None


@dataclass
class AlertRule:
    """Alert rule configuration."""
    name: str
    condition: str
    severity: AlertSeverity
    threshold: float
    duration_minutes: int = 5
    enabled: bool = True
    notification_channels: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)


class NotificationChannel:
    """Base class for notification channels."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = config.get('enabled', True)
    
    def send_notification(self, alert: Alert) -> bool:
        """Send notification for alert."""
        if not self.enabled:
            return False
        
        try:
            return self._send_notification(alert)
        except Exception as e:
            logger.error(f"Failed to send notification via {self.name}", error=str(e))
            return False
    
    def _send_notification(self, alert: Alert) -> bool:
        """Override this method to implement notification sending."""
        raise NotImplementedError


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel."""
    
    def _send_notification(self, alert: Alert) -> bool:
        """Send email notification."""
        recipients = self.config.get('recipients', [])
        if not recipients:
            logger.warning("No email recipients configured")
            return False
        
        subject = f"[{alert.severity.value.upper()}] {alert.name}"
        
        message = f"""
Alert: {alert.name}
Severity: {alert.severity.value.upper()}
Status: {alert.status.value}
Time: {alert.timestamp.isoformat()}
Source: {alert.source}

Message: {alert.message}

Labels: {json.dumps(alert.labels, indent=2)}
Annotations: {json.dumps(alert.annotations, indent=2)}
        """
        
        try:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=False
            )
            
            logger.info(f"Email notification sent for alert {alert.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification", error=str(e))
            return False


class SlackNotificationChannel(NotificationChannel):
    """Slack notification channel."""
    
    def _send_notification(self, alert: Alert) -> bool:
        """Send Slack notification."""
        webhook_url = self.config.get('webhook_url')
        if not webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False
        
        # Color mapping for severity
        color_map = {
            AlertSeverity.LOW: "#36a64f",      # green
            AlertSeverity.MEDIUM: "#ff9500",   # orange
            AlertSeverity.HIGH: "#ff0000",     # red
            AlertSeverity.CRITICAL: "#8B0000"  # dark red
        }
        
        payload = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity, "#36a64f"),
                    "title": f"{alert.severity.value.upper()}: {alert.name}",
                    "text": alert.message,
                    "fields": [
                        {
                            "title": "Source",
                            "value": alert.source,
                            "short": True
                        },
                        {
                            "title": "Status",
                            "value": alert.status.value,
                            "short": True
                        },
                        {
                            "title": "Time",
                            "value": alert.timestamp.isoformat(),
                            "short": False
                        }
                    ],
                    "footer": "Enterprise Auth Monitoring",
                    "ts": int(alert.timestamp.timestamp())
                }
            ]
        }
        
        try:
            import requests
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack notification sent for alert {alert.id}")
            return True
            
        except ImportError:
            logger.error("requests library not available for Slack notifications")
            return False
        except Exception as e:
            logger.error(f"Failed to send Slack notification", error=str(e))
            return False


class PagerDutyNotificationChannel(NotificationChannel):
    """PagerDuty notification channel."""
    
    def _send_notification(self, alert: Alert) -> bool:
        """Send PagerDuty notification."""
        integration_key = self.config.get('integration_key')
        if not integration_key:
            logger.warning("PagerDuty integration key not configured")
            return False
        
        # Only send critical and high severity alerts to PagerDuty
        if alert.severity not in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            return True
        
        payload = {
            "routing_key": integration_key,
            "event_action": "trigger",
            "dedup_key": alert.id,
            "payload": {
                "summary": f"{alert.name}: {alert.message}",
                "source": alert.source,
                "severity": alert.severity.value,
                "timestamp": alert.timestamp.isoformat(),
                "custom_details": {
                    "labels": alert.labels,
                    "annotations": alert.annotations
                }
            }
        }
        
        try:
            import requests
            response = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info(f"PagerDuty notification sent for alert {alert.id}")
            return True
            
        except ImportError:
            logger.error("requests library not available for PagerDuty notifications")
            return False
        except Exception as e:
            logger.error(f"Failed to send PagerDuty notification", error=str(e))
            return False


class WebhookNotificationChannel(NotificationChannel):
    """Generic webhook notification channel."""
    
    def _send_notification(self, alert: Alert) -> bool:
        """Send webhook notification."""
        webhook_url = self.config.get('url')
        if not webhook_url:
            logger.warning("Webhook URL not configured")
            return False
        
        payload = {
            "alert_id": alert.id,
            "name": alert.name,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat(),
            "source": alert.source,
            "labels": alert.labels,
            "annotations": alert.annotations
        }
        
        headers = self.config.get('headers', {})
        headers.setdefault('Content-Type', 'application/json')
        
        try:
            import requests
            response = requests.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info(f"Webhook notification sent for alert {alert.id}")
            return True
            
        except ImportError:
            logger.error("requests library not available for webhook notifications")
            return False
        except Exception as e:
            logger.error(f"Failed to send webhook notification", error=str(e))
            return False


class AlertManager:
    """Central alert management system."""
    
    def __init__(self):
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.notification_channels: Dict[str, NotificationChannel] = {}
        self.alert_history: List[Alert] = []
        self.suppression_rules: List[Dict[str, Any]] = []
        
        self._setup_default_rules()
        self._setup_notification_channels()
    
    def _setup_default_rules(self):
        """Setup default alert rules."""
        default_rules = [
            AlertRule(
                name="high_response_time",
                condition="response_time_ms > 1000",
                severity=AlertSeverity.HIGH,
                threshold=1000.0,
                duration_minutes=5,
                notification_channels=["email", "slack"],
                annotations={
                    "description": "API response time is above 1 second",
                    "runbook": "Check system load and database performance"
                }
            ),
            AlertRule(
                name="low_cache_hit_rate",
                condition="cache_hit_rate < 70",
                severity=AlertSeverity.MEDIUM,
                threshold=70.0,
                duration_minutes=10,
                notification_channels=["email"],
                annotations={
                    "description": "Cache hit rate is below 70%",
                    "runbook": "Check cache configuration and warming"
                }
            ),
            AlertRule(
                name="high_error_rate",
                condition="error_rate > 5",
                severity=AlertSeverity.CRITICAL,
                threshold=5.0,
                duration_minutes=2,
                notification_channels=["email", "slack", "pagerduty"],
                annotations={
                    "description": "Error rate is above 5%",
                    "runbook": "Investigate application errors immediately"
                }
            ),
            AlertRule(
                name="database_connection_high",
                condition="db_connections > 80",
                severity=AlertSeverity.HIGH,
                threshold=80.0,
                duration_minutes=5,
                notification_channels=["email", "slack"],
                annotations={
                    "description": "Database connection usage is above 80%",
                    "runbook": "Check for connection leaks and scale if needed"
                }
            ),
            AlertRule(
                name="security_threat_detected",
                condition="threats_per_minute > 10",
                severity=AlertSeverity.CRITICAL,
                threshold=10.0,
                duration_minutes=1,
                notification_channels=["email", "slack", "pagerduty"],
                annotations={
                    "description": "High number of security threats detected",
                    "runbook": "Investigate security incidents immediately"
                }
            ),
            AlertRule(
                name="failed_auth_spike",
                condition="failed_auth_rate > 50",
                severity=AlertSeverity.HIGH,
                threshold=50.0,
                duration_minutes=3,
                notification_channels=["email", "slack"],
                annotations={
                    "description": "Spike in failed authentication attempts",
                    "runbook": "Check for brute force attacks"
                }
            )
        ]
        
        for rule in default_rules:
            self.add_alert_rule(rule)
    
    def _setup_notification_channels(self):
        """Setup notification channels from settings."""
        # Email channel
        if hasattr(settings, 'ALERT_EMAIL_RECIPIENTS'):
            self.add_notification_channel(
                "email",
                EmailNotificationChannel("email", {
                    'recipients': settings.ALERT_EMAIL_RECIPIENTS,
                    'enabled': True
                })
            )
        
        # Slack channel
        if hasattr(settings, 'ALERT_SLACK_WEBHOOK_URL'):
            self.add_notification_channel(
                "slack",
                SlackNotificationChannel("slack", {
                    'webhook_url': settings.ALERT_SLACK_WEBHOOK_URL,
                    'enabled': True
                })
            )
        
        # PagerDuty channel
        if hasattr(settings, 'ALERT_PAGERDUTY_INTEGRATION_KEY'):
            self.add_notification_channel(
                "pagerduty",
                PagerDutyNotificationChannel("pagerduty", {
                    'integration_key': settings.ALERT_PAGERDUTY_INTEGRATION_KEY,
                    'enabled': True
                })
            )
    
    def add_alert_rule(self, rule: AlertRule):
        """Add an alert rule."""
        self.alert_rules[rule.name] = rule
        logger.info(f"Added alert rule: {rule.name}")
    
    def remove_alert_rule(self, rule_name: str):
        """Remove an alert rule."""
        if rule_name in self.alert_rules:
            del self.alert_rules[rule_name]
            logger.info(f"Removed alert rule: {rule_name}")
    
    def add_notification_channel(self, name: str, channel: NotificationChannel):
        """Add a notification channel."""
        self.notification_channels[name] = channel
        logger.info(f"Added notification channel: {name}")
    
    def create_alert(self, name: str, severity: AlertSeverity, message: str,
                    source: str, labels: Optional[Dict[str, str]] = None,
                    annotations: Optional[Dict[str, str]] = None) -> Alert:
        """Create a new alert."""
        alert_id = f"{name}_{int(timezone.now().timestamp())}"
        
        alert = Alert(
            id=alert_id,
            name=name,
            severity=severity,
            status=AlertStatus.ACTIVE,
            message=message,
            timestamp=timezone.now(),
            source=source,
            labels=labels or {},
            annotations=annotations or {}
        )
        
        # Check if alert should be suppressed
        if self._is_alert_suppressed(alert):
            alert.status = AlertStatus.SUPPRESSED
            logger.info(f"Alert suppressed: {alert.id}")
            return alert
        
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # Send notifications
        self._send_alert_notifications(alert)
        
        logger.warning(
            f"Alert created: {alert.name}",
            alert_id=alert.id,
            severity=alert.severity.value,
            message=alert.message
        )
        
        return alert
    
    def resolve_alert(self, alert_id: str, resolved_by: Optional[str] = None):
        """Resolve an alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = timezone.now()
            
            del self.active_alerts[alert_id]
            
            logger.info(
                f"Alert resolved: {alert.name}",
                alert_id=alert_id,
                resolved_by=resolved_by
            )
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str):
        """Acknowledge an alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = timezone.now()
            alert.acknowledged_by = acknowledged_by
            
            logger.info(
                f"Alert acknowledged: {alert.name}",
                alert_id=alert_id,
                acknowledged_by=acknowledged_by
            )
    
    def check_metric_against_rules(self, metric_name: str, value: float,
                                  labels: Optional[Dict[str, str]] = None):
        """Check a metric value against alert rules."""
        for rule_name, rule in self.alert_rules.items():
            if not rule.enabled:
                continue
            
            # Simple condition checking (in production, you'd want a more sophisticated rule engine)
            if self._evaluate_condition(rule.condition, metric_name, value):
                # Check if we already have an active alert for this rule
                existing_alert = None
                for alert in self.active_alerts.values():
                    if alert.name == rule.name and alert.status == AlertStatus.ACTIVE:
                        existing_alert = alert
                        break
                
                if not existing_alert:
                    self.create_alert(
                        name=rule.name,
                        severity=rule.severity,
                        message=f"{metric_name} = {value} (threshold: {rule.threshold})",
                        source="metric_monitor",
                        labels={**(labels or {}), **rule.labels},
                        annotations=rule.annotations
                    )
    
    def _evaluate_condition(self, condition: str, metric_name: str, value: float) -> bool:
        """Evaluate alert condition (simplified)."""
        # This is a simplified condition evaluator
        # In production, you'd want a more sophisticated rule engine
        
        if "response_time_ms" in condition and "response_time" in metric_name:
            if ">" in condition:
                threshold = float(condition.split(">")[1].strip())
                return value > threshold
        elif "cache_hit_rate" in condition and "cache_hit_rate" in metric_name:
            if "<" in condition:
                threshold = float(condition.split("<")[1].strip())
                return value < threshold
        elif "error_rate" in condition and "error_rate" in metric_name:
            if ">" in condition:
                threshold = float(condition.split(">")[1].strip())
                return value > threshold
        
        return False
    
    def _is_alert_suppressed(self, alert: Alert) -> bool:
        """Check if alert should be suppressed."""
        for rule in self.suppression_rules:
            if self._matches_suppression_rule(alert, rule):
                return True
        return False
    
    def _matches_suppression_rule(self, alert: Alert, rule: Dict[str, Any]) -> bool:
        """Check if alert matches suppression rule."""
        # Check if alert name matches
        if 'alert_name' in rule and alert.name != rule['alert_name']:
            return False
        
        # Check if labels match
        if 'labels' in rule:
            for key, value in rule['labels'].items():
                if alert.labels.get(key) != value:
                    return False
        
        # Check time-based suppression
        if 'time_range' in rule:
            now = timezone.now().time()
            start_time = rule['time_range']['start']
            end_time = rule['time_range']['end']
            
            if start_time <= now <= end_time:
                return True
        
        return True
    
    def _send_alert_notifications(self, alert: Alert):
        """Send notifications for an alert."""
        rule = self.alert_rules.get(alert.name)
        if not rule:
            return
        
        for channel_name in rule.notification_channels:
            channel = self.notification_channels.get(channel_name)
            if channel:
                success = channel.send_notification(alert)
                if success:
                    logger.info(f"Notification sent via {channel_name} for alert {alert.id}")
                else:
                    logger.error(f"Failed to send notification via {channel_name} for alert {alert.id}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        active_alerts = list(self.active_alerts.values())
        
        severity_counts = {
            AlertSeverity.LOW.value: 0,
            AlertSeverity.MEDIUM.value: 0,
            AlertSeverity.HIGH.value: 0,
            AlertSeverity.CRITICAL.value: 0
        }
        
        for alert in active_alerts:
            severity_counts[alert.severity.value] += 1
        
        return {
            'total_active_alerts': len(active_alerts),
            'severity_breakdown': severity_counts,
            'total_rules': len(self.alert_rules),
            'enabled_rules': sum(1 for rule in self.alert_rules.values() if rule.enabled),
            'notification_channels': len(self.notification_channels),
            'last_alert_time': max(
                (alert.timestamp for alert in active_alerts),
                default=None
            )
        }
    
    def add_suppression_rule(self, rule: Dict[str, Any]):
        """Add alert suppression rule."""
        self.suppression_rules.append(rule)
        logger.info(f"Added suppression rule: {rule}")
    
    def cleanup_old_alerts(self, days: int = 30):
        """Clean up old alerts from history."""
        cutoff_date = timezone.now() - timedelta(days=days)
        
        original_count = len(self.alert_history)
        self.alert_history = [
            alert for alert in self.alert_history
            if alert.timestamp >= cutoff_date
        ]
        
        cleaned_count = original_count - len(self.alert_history)
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old alerts")


# Global alert manager instance
alert_manager = AlertManager()

# Notification channels registry
notification_channels = alert_manager.notification_channels