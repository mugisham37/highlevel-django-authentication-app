"""
Celery tasks for monitoring and observability system.
"""

import logging
from celery import shared_task
from django.utils import timezone
from .metrics import (
    business_metrics_collector,
    compliance_metrics_collector,
    security_metrics_collector
)
from .health_checks import system_health_monitor
from .alerting import alert_manager
from .logging_config import get_structured_logger

logger = get_structured_logger(__name__)


@shared_task(bind=True, max_retries=3)
def update_daily_business_metrics(self):
    """Update daily business metrics."""
    try:
        logger.info("Starting daily business metrics update")
        
        # Update daily metrics
        business_metrics_collector.update_daily_metrics()
        
        logger.info("Daily business metrics update completed successfully")
        return {'status': 'success', 'timestamp': timezone.now().isoformat()}
        
    except Exception as e:
        logger.error("Failed to update daily business metrics", error=str(e))
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=e)
        
        # Create alert for persistent failure
        alert_manager.create_alert(
            name="daily_metrics_update_failed",
            severity=alert_manager.AlertSeverity.HIGH,
            message=f"Daily business metrics update failed after {self.max_retries} retries: {str(e)}",
            source="celery_task"
        )
        
        raise


@shared_task(bind=True, max_retries=3)
def update_monthly_business_metrics(self):
    """Update monthly business metrics."""
    try:
        logger.info("Starting monthly business metrics update")
        
        # Update monthly metrics
        business_metrics_collector.update_monthly_metrics()
        
        logger.info("Monthly business metrics update completed successfully")
        return {'status': 'success', 'timestamp': timezone.now().isoformat()}
        
    except Exception as e:
        logger.error("Failed to update monthly business metrics", error=str(e))
        
        # Retry with exponential backoff
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries), exc=e)
        
        # Create alert for persistent failure
        alert_manager.create_alert(
            name="monthly_metrics_update_failed",
            severity=alert_manager.AlertSeverity.HIGH,
            message=f"Monthly business metrics update failed after {self.max_retries} retries: {str(e)}",
            source="celery_task"
        )
        
        raise


@shared_task(bind=True, max_retries=2)
def run_system_health_checks(self):
    """Run comprehensive system health checks."""
    try:
        logger.info("Starting system health checks")
        
        # Run health monitoring
        health_summary = system_health_monitor.monitor_health()
        
        # Log health status
        logger.info(
            "System health check completed",
            overall_status=health_summary['overall_status'],
            health_score=health_summary['health_score'],
            unhealthy_checks=health_summary['unhealthy_checks']
        )
        
        # Create alerts for unhealthy systems
        if health_summary['overall_status'] == 'unhealthy':
            alert_manager.create_alert(
                name="system_health_critical",
                severity=alert_manager.AlertSeverity.CRITICAL,
                message=f"System health is critical. Health score: {health_summary['health_score']}%",
                source="health_monitor",
                labels={'health_score': str(health_summary['health_score'])}
            )
        elif health_summary['overall_status'] == 'degraded':
            alert_manager.create_alert(
                name="system_health_degraded",
                severity=alert_manager.AlertSeverity.HIGH,
                message=f"System health is degraded. Health score: {health_summary['health_score']}%",
                source="health_monitor",
                labels={'health_score': str(health_summary['health_score'])}
            )
        
        return {
            'status': 'success',
            'health_summary': health_summary,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to run system health checks", error=str(e))
        
        # Retry with shorter backoff for health checks
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=30 * (self.request.retries + 1), exc=e)
        
        # Create alert for health check failure
        alert_manager.create_alert(
            name="health_check_system_failed",
            severity=alert_manager.AlertSeverity.CRITICAL,
            message=f"System health check failed after {self.max_retries} retries: {str(e)}",
            source="celery_task"
        )
        
        raise


@shared_task(bind=True)
def cleanup_monitoring_data(self, days=30):
    """Clean up old monitoring data."""
    try:
        logger.info(f"Starting monitoring data cleanup (older than {days} days)")
        
        # Clean up old alerts
        alert_manager.cleanup_old_alerts(days=days)
        
        logger.info("Monitoring data cleanup completed successfully")
        return {'status': 'success', 'timestamp': timezone.now().isoformat()}
        
    except Exception as e:
        logger.error("Failed to cleanup monitoring data", error=str(e))
        raise


@shared_task(bind=True, max_retries=2)
def generate_compliance_report(self, regulation='gdpr'):
    """Generate compliance report."""
    try:
        logger.info(f"Starting compliance report generation for {regulation}")
        
        from .dashboards import business_intelligence_dashboard
        
        # Generate compliance report
        report = business_intelligence_dashboard.get_compliance_report(regulation)
        
        # Log compliance status
        logger.info(
            "Compliance report generated",
            regulation=regulation,
            compliance_score=report.get('compliance_score', 0)
        )
        
        # Create alert for low compliance scores
        compliance_score = report.get('compliance_score', 0)
        if compliance_score < 90:
            alert_manager.create_alert(
                name="compliance_score_low",
                severity=alert_manager.AlertSeverity.HIGH,
                message=f"{regulation.upper()} compliance score is low: {compliance_score}%",
                source="compliance_monitor",
                labels={'regulation': regulation, 'score': str(compliance_score)}
            )
        
        return {
            'status': 'success',
            'report': report,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to generate compliance report", error=str(e))
        
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (self.request.retries + 1), exc=e)
        
        raise


@shared_task(bind=True)
def analyze_security_metrics(self, hours=24):
    """Analyze security metrics and generate alerts."""
    try:
        logger.info(f"Starting security metrics analysis for last {hours} hours")
        
        from .dashboards import business_intelligence_dashboard
        
        # Get security analytics
        security_analytics = business_intelligence_dashboard.get_security_analytics(
            days=hours // 24 if hours >= 24 else 1
        )
        
        # Analyze threat levels
        total_threats = security_analytics.get('total_security_events', 0)
        
        # Create alerts based on threat analysis
        if total_threats > 100:  # Threshold for high threat activity
            alert_manager.create_alert(
                name="high_security_threat_activity",
                severity=alert_manager.AlertSeverity.HIGH,
                message=f"High security threat activity detected: {total_threats} events in {hours} hours",
                source="security_analyzer",
                labels={'threat_count': str(total_threats), 'time_window': f"{hours}h"}
            )
        
        logger.info(
            "Security metrics analysis completed",
            total_threats=total_threats,
            time_window_hours=hours
        )
        
        return {
            'status': 'success',
            'security_analytics': security_analytics,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to analyze security metrics", error=str(e))
        raise


@shared_task(bind=True)
def update_sla_compliance_metrics(self):
    """Update SLA compliance metrics."""
    try:
        logger.info("Starting SLA compliance metrics update")
        
        from .performance import sla_monitor
        
        # Get SLA compliance report
        sla_report = sla_monitor.get_sla_compliance_report(hours=24)
        
        # Check for SLA violations
        overall_compliance = sla_report.get('overall_compliance', 100)
        
        if overall_compliance < 95:  # SLA threshold
            alert_manager.create_alert(
                name="sla_compliance_violation",
                severity=alert_manager.AlertSeverity.HIGH,
                message=f"SLA compliance below threshold: {overall_compliance}%",
                source="sla_monitor",
                labels={'compliance_percent': str(overall_compliance)}
            )
        
        logger.info(
            "SLA compliance metrics updated",
            overall_compliance=overall_compliance
        )
        
        return {
            'status': 'success',
            'sla_report': sla_report,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to update SLA compliance metrics", error=str(e))
        raise


@shared_task(bind=True)
def export_monitoring_data(self, format='json', days=7):
    """Export monitoring data for external analysis."""
    try:
        logger.info(f"Starting monitoring data export (format: {format}, days: {days})")
        
        from .performance import performance_collector
        
        # Get recent metrics
        recent_metrics = performance_collector.get_recent_metrics(minutes=days * 24 * 60)
        
        # Format data for export
        export_data = {
            'export_timestamp': timezone.now().isoformat(),
            'time_range_days': days,
            'metrics_count': len(recent_metrics),
            'metrics': [
                {
                    'name': metric.name,
                    'value': metric.value,
                    'timestamp': metric.timestamp.isoformat(),
                    'labels': metric.labels,
                    'unit': metric.unit
                }
                for metric in recent_metrics
            ]
        }
        
        logger.info(
            "Monitoring data export completed",
            format=format,
            metrics_count=len(recent_metrics),
            days=days
        )
        
        return {
            'status': 'success',
            'export_data': export_data,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to export monitoring data", error=str(e))
        raise


@shared_task(bind=True)
def send_monitoring_digest(self, recipients=None):
    """Send daily monitoring digest email."""
    try:
        logger.info("Starting monitoring digest generation")
        
        from django.core.mail import send_mail
        from django.conf import settings
        
        # Get system health summary
        health_summary = system_health_monitor.monitor_health()
        
        # Get alert summary
        alert_summary = alert_manager.get_alert_summary()
        
        # Get business KPIs
        kpis = business_metrics_collector.get_business_kpis()
        
        # Create digest content
        subject = f"Enterprise Auth - Daily Monitoring Digest - {timezone.now().strftime('%Y-%m-%d')}"
        
        message = f"""
Daily Monitoring Digest - {timezone.now().strftime('%Y-%m-%d')}

SYSTEM HEALTH:
- Overall Status: {health_summary['overall_status']}
- Health Score: {health_summary['health_score']}%
- Total Checks: {health_summary['total_checks']}
- Unhealthy Checks: {health_summary['unhealthy_checks']}

ALERTS:
- Active Alerts: {alert_summary['total_active_alerts']}
- Critical: {alert_summary['severity_breakdown']['critical']}
- High: {alert_summary['severity_breakdown']['high']}
- Medium: {alert_summary['severity_breakdown']['medium']}
- Low: {alert_summary['severity_breakdown']['low']}

BUSINESS METRICS:
- Total Users: {kpis.get('total_users', 'N/A')}
- Daily Registrations: {kpis.get('daily_registrations', 'N/A')}
- Monthly Active Users: {kpis.get('monthly_active_users', 'N/A')}
- MFA Adoption Rate: {kpis.get('mfa_adoption_rate_percent', 'N/A')}%

Generated at: {timezone.now().isoformat()}
        """
        
        # Send email
        recipients = recipients or getattr(settings, 'MONITORING_DIGEST_RECIPIENTS', [])
        if recipients:
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=False
            )
            
            logger.info(
                "Monitoring digest sent successfully",
                recipients_count=len(recipients)
            )
        else:
            logger.warning("No recipients configured for monitoring digest")
        
        return {
            'status': 'success',
            'recipients_count': len(recipients) if recipients else 0,
            'timestamp': timezone.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to send monitoring digest", error=str(e))
        raise