"""
Custom business metrics and KPIs collection for enterprise authentication system.
Provides specialized metrics collectors for business intelligence, compliance, and security.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from django.conf import settings
from django.utils import timezone
from django.db import models
from django.contrib.auth import get_user_model
from .logging_config import get_structured_logger

logger = get_structured_logger(__name__)

# Try to import Prometheus client
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary, CollectorRegistry, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    logger.warning("Prometheus client not available")
    PROMETHEUS_AVAILABLE = False
    
    # Mock classes
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Summary:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self


@dataclass
class BusinessMetric:
    """Data class for business metrics."""
    name: str
    value: Union[int, float]
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BusinessMetricsCollector:
    """Collector for business intelligence metrics and KPIs."""
    
    def __init__(self):
        self.registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None
        self._setup_business_metrics()
        self._metrics_buffer = deque(maxlen=10000)
    
    def _setup_business_metrics(self):
        """Initialize business metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # User registration metrics
        self.user_registrations_total = Counter(
            'user_registrations_total',
            'Total number of user registrations',
            ['source', 'method', 'country'],
            registry=self.registry
        )
        
        self.user_registrations_daily = Gauge(
            'user_registrations_daily',
            'Daily user registrations',
            ['date'],
            registry=self.registry
        )
        
        # Authentication metrics
        self.authentication_attempts_total = Counter(
            'authentication_attempts_total',
            'Total authentication attempts',
            ['method', 'provider', 'success', 'device_type'],
            registry=self.registry
        )
        
        self.authentication_success_rate = Gauge(
            'authentication_success_rate_percent',
            'Authentication success rate percentage',
            ['method', 'provider'],
            registry=self.registry
        )
        
        # User engagement metrics
        self.active_users_daily = Gauge(
            'active_users_daily',
            'Daily active users',
            registry=self.registry
        )
        
        self.active_users_monthly = Gauge(
            'active_users_monthly',
            'Monthly active users',
            registry=self.registry
        )
        
        self.user_session_duration = Histogram(
            'user_session_duration_minutes',
            'User session duration in minutes',
            ['device_type', 'auth_method'],
            registry=self.registry,
            buckets=[1, 5, 15, 30, 60, 120, 240, 480, 960, 1440]  # minutes
        )
        
        # Feature usage metrics
        self.feature_usage_total = Counter(
            'feature_usage_total',
            'Total feature usage',
            ['feature', 'action', 'user_type'],
            registry=self.registry
        )
        
        self.mfa_adoption_rate = Gauge(
            'mfa_adoption_rate_percent',
            'MFA adoption rate percentage',
            ['mfa_type'],
            registry=self.registry
        )
        
        # OAuth provider metrics
        self.oauth_provider_usage = Counter(
            'oauth_provider_usage_total',
            'OAuth provider usage',
            ['provider', 'action'],
            registry=self.registry
        )
        
        self.oauth_provider_success_rate = Gauge(
            'oauth_provider_success_rate_percent',
            'OAuth provider success rate',
            ['provider'],
            registry=self.registry
        )
        
        # Conversion metrics
        self.user_conversion_funnel = Counter(
            'user_conversion_funnel_total',
            'User conversion funnel events',
            ['stage', 'source'],
            registry=self.registry
        )
        
        # Geographic metrics
        self.users_by_country = Gauge(
            'users_by_country_total',
            'Total users by country',
            ['country'],
            registry=self.registry
        )
        
        # Device and platform metrics
        self.users_by_device_type = Gauge(
            'users_by_device_type_total',
            'Users by device type',
            ['device_type'],
            registry=self.registry
        )
        
        self.users_by_browser = Gauge(
            'users_by_browser_total',
            'Users by browser',
            ['browser'],
            registry=self.registry
        )
    
    def record_user_registration(self, source: str, method: str, country: Optional[str] = None,
                               device_type: Optional[str] = None, user_agent: Optional[str] = None):
        """Record user registration event."""
        if PROMETHEUS_AVAILABLE:
            self.user_registrations_total.labels(
                source=source,
                method=method,
                country=country or 'unknown'
            ).inc()
        
        # Store in buffer for analysis
        self._metrics_buffer.append(BusinessMetric(
            name='user_registration',
            value=1,
            timestamp=timezone.now(),
            labels={
                'source': source,
                'method': method,
                'country': country or 'unknown'
            },
            metadata={
                'device_type': device_type,
                'user_agent': user_agent
            }
        ))
        
        logger.info(
            "User registration recorded",
            source=source,
            method=method,
            country=country,
            device_type=device_type
        )
    
    def record_authentication_attempt(self, method: str, provider: Optional[str],
                                    success: bool, device_type: Optional[str] = None):
        """Record authentication attempt."""
        if PROMETHEUS_AVAILABLE:
            self.authentication_attempts_total.labels(
                method=method,
                provider=provider or 'none',
                success=str(success).lower(),
                device_type=device_type or 'unknown'
            ).inc()
        
        self._metrics_buffer.append(BusinessMetric(
            name='authentication_attempt',
            value=1,
            timestamp=timezone.now(),
            labels={
                'method': method,
                'provider': provider or 'none',
                'success': str(success).lower(),
                'device_type': device_type or 'unknown'
            }
        ))
    
    def record_session_duration(self, duration_minutes: float, device_type: str, auth_method: str):
        """Record user session duration."""
        if PROMETHEUS_AVAILABLE:
            self.user_session_duration.labels(
                device_type=device_type,
                auth_method=auth_method
            ).observe(duration_minutes)
        
        self._metrics_buffer.append(BusinessMetric(
            name='session_duration',
            value=duration_minutes,
            timestamp=timezone.now(),
            labels={
                'device_type': device_type,
                'auth_method': auth_method
            }
        ))
    
    def record_feature_usage(self, feature: str, action: str, user_type: str = 'regular'):
        """Record feature usage."""
        if PROMETHEUS_AVAILABLE:
            self.feature_usage_total.labels(
                feature=feature,
                action=action,
                user_type=user_type
            ).inc()
        
        self._metrics_buffer.append(BusinessMetric(
            name='feature_usage',
            value=1,
            timestamp=timezone.now(),
            labels={
                'feature': feature,
                'action': action,
                'user_type': user_type
            }
        ))
    
    def record_oauth_usage(self, provider: str, action: str, success: bool = True):
        """Record OAuth provider usage."""
        if PROMETHEUS_AVAILABLE:
            self.oauth_provider_usage.labels(
                provider=provider,
                action=action
            ).inc()
        
        self._metrics_buffer.append(BusinessMetric(
            name='oauth_usage',
            value=1,
            timestamp=timezone.now(),
            labels={
                'provider': provider,
                'action': action,
                'success': str(success).lower()
            }
        ))
    
    def record_conversion_event(self, stage: str, source: str):
        """Record conversion funnel event."""
        if PROMETHEUS_AVAILABLE:
            self.user_conversion_funnel.labels(
                stage=stage,
                source=source
            ).inc()
        
        self._metrics_buffer.append(BusinessMetric(
            name='conversion_event',
            value=1,
            timestamp=timezone.now(),
            labels={
                'stage': stage,
                'source': source
            }
        ))
    
    def update_daily_metrics(self):
        """Update daily aggregated metrics."""
        try:
            User = get_user_model()
            today = timezone.now().date()
            
            # Daily registrations
            daily_registrations = User.objects.filter(
                date_joined__date=today
            ).count()
            
            if PROMETHEUS_AVAILABLE:
                self.user_registrations_daily.labels(
                    date=today.isoformat()
                ).set(daily_registrations)
            
            # Daily active users
            daily_active = User.objects.filter(
                last_login__date=today
            ).count()
            
            if PROMETHEUS_AVAILABLE:
                self.active_users_daily.set(daily_active)
            
            logger.info(
                "Daily metrics updated",
                daily_registrations=daily_registrations,
                daily_active_users=daily_active
            )
            
        except Exception as e:
            logger.error("Failed to update daily metrics", error=str(e))
    
    def update_monthly_metrics(self):
        """Update monthly aggregated metrics."""
        try:
            User = get_user_model()
            thirty_days_ago = timezone.now() - timedelta(days=30)
            
            # Monthly active users
            monthly_active = User.objects.filter(
                last_login__gte=thirty_days_ago
            ).count()
            
            if PROMETHEUS_AVAILABLE:
                self.active_users_monthly.set(monthly_active)
            
            logger.info("Monthly metrics updated", monthly_active_users=monthly_active)
            
        except Exception as e:
            logger.error("Failed to update monthly metrics", error=str(e))
    
    def get_business_kpis(self) -> Dict[str, Any]:
        """Get key business KPIs."""
        try:
            User = get_user_model()
            now = timezone.now()
            today = now.date()
            yesterday = today - timedelta(days=1)
            thirty_days_ago = now - timedelta(days=30)
            
            # User metrics
            total_users = User.objects.count()
            daily_registrations = User.objects.filter(date_joined__date=today).count()
            yesterday_registrations = User.objects.filter(date_joined__date=yesterday).count()
            monthly_active_users = User.objects.filter(last_login__gte=thirty_days_ago).count()
            
            # Calculate growth rates
            registration_growth = 0
            if yesterday_registrations > 0:
                registration_growth = ((daily_registrations - yesterday_registrations) / yesterday_registrations) * 100
            
            # MFA adoption
            mfa_enabled_users = 0
            try:
                # This would depend on your MFA model structure
                from enterprise_auth.core.models.mfa import MFADevice
                mfa_enabled_users = User.objects.filter(
                    mfadevice__is_confirmed=True
                ).distinct().count()
            except ImportError:
                pass
            
            mfa_adoption_rate = (mfa_enabled_users / total_users * 100) if total_users > 0 else 0
            
            return {
                'total_users': total_users,
                'daily_registrations': daily_registrations,
                'registration_growth_percent': round(registration_growth, 2),
                'monthly_active_users': monthly_active_users,
                'mfa_adoption_rate_percent': round(mfa_adoption_rate, 2),
                'user_engagement_rate': round((monthly_active_users / total_users * 100) if total_users > 0 else 0, 2),
                'timestamp': now.isoformat()
            }
            
        except Exception as e:
            logger.error("Failed to calculate business KPIs", error=str(e))
            return {}


class ComplianceMetricsCollector:
    """Collector for compliance and regulatory metrics."""
    
    def __init__(self):
        self.registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None
        self._setup_compliance_metrics()
    
    def _setup_compliance_metrics(self):
        """Initialize compliance metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # GDPR compliance metrics
        self.gdpr_requests_total = Counter(
            'gdpr_requests_total',
            'Total GDPR requests',
            ['request_type', 'status'],
            registry=self.registry
        )
        
        self.gdpr_request_processing_time = Histogram(
            'gdpr_request_processing_time_hours',
            'GDPR request processing time in hours',
            ['request_type'],
            registry=self.registry,
            buckets=[1, 6, 12, 24, 48, 72, 168, 720]  # hours
        )
        
        # Data retention metrics
        self.data_retention_compliance = Gauge(
            'data_retention_compliance_percent',
            'Data retention compliance percentage',
            ['data_type'],
            registry=self.registry
        )
        
        # Audit trail metrics
        self.audit_events_total = Counter(
            'audit_events_total',
            'Total audit events',
            ['event_type', 'severity'],
            registry=self.registry
        )
        
        # Security compliance metrics
        self.security_policy_violations = Counter(
            'security_policy_violations_total',
            'Security policy violations',
            ['policy_type', 'severity'],
            registry=self.registry
        )
        
        # Access control metrics
        self.access_control_checks = Counter(
            'access_control_checks_total',
            'Access control checks',
            ['resource_type', 'action', 'result'],
            registry=self.registry
        )
    
    def record_gdpr_request(self, request_type: str, status: str, processing_time_hours: Optional[float] = None):
        """Record GDPR request."""
        if PROMETHEUS_AVAILABLE:
            self.gdpr_requests_total.labels(
                request_type=request_type,
                status=status
            ).inc()
            
            if processing_time_hours is not None:
                self.gdpr_request_processing_time.labels(
                    request_type=request_type
                ).observe(processing_time_hours)
        
        logger.info(
            "GDPR request recorded",
            request_type=request_type,
            status=status,
            processing_time_hours=processing_time_hours
        )
    
    def record_audit_event(self, event_type: str, severity: str):
        """Record audit event."""
        if PROMETHEUS_AVAILABLE:
            self.audit_events_total.labels(
                event_type=event_type,
                severity=severity
            ).inc()
    
    def record_security_violation(self, policy_type: str, severity: str):
        """Record security policy violation."""
        if PROMETHEUS_AVAILABLE:
            self.security_policy_violations.labels(
                policy_type=policy_type,
                severity=severity
            ).inc()
        
        logger.warning(
            "Security policy violation",
            policy_type=policy_type,
            severity=severity
        )
    
    def record_access_control_check(self, resource_type: str, action: str, result: str):
        """Record access control check."""
        if PROMETHEUS_AVAILABLE:
            self.access_control_checks.labels(
                resource_type=resource_type,
                action=action,
                result=result
            ).inc()
    
    def update_data_retention_compliance(self, data_type: str, compliance_percent: float):
        """Update data retention compliance metric."""
        if PROMETHEUS_AVAILABLE:
            self.data_retention_compliance.labels(
                data_type=data_type
            ).set(compliance_percent)


class SecurityMetricsCollector:
    """Collector for security-specific metrics."""
    
    def __init__(self):
        self.registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None
        self._setup_security_metrics()
    
    def _setup_security_metrics(self):
        """Initialize security metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
        
        # Threat detection metrics
        self.threats_detected_total = Counter(
            'threats_detected_total',
            'Total threats detected',
            ['threat_type', 'severity', 'source'],
            registry=self.registry
        )
        
        self.threat_response_time = Histogram(
            'threat_response_time_seconds',
            'Threat response time in seconds',
            ['threat_type', 'response_type'],
            registry=self.registry,
            buckets=[1, 5, 10, 30, 60, 300, 600, 1800, 3600]
        )
        
        # Attack metrics
        self.attack_attempts_total = Counter(
            'attack_attempts_total',
            'Total attack attempts',
            ['attack_type', 'source_ip', 'blocked'],
            registry=self.registry
        )
        
        self.brute_force_attempts = Counter(
            'brute_force_attempts_total',
            'Brute force attack attempts',
            ['target_type', 'source_ip'],
            registry=self.registry
        )
        
        # Account security metrics
        self.account_lockouts_total = Counter(
            'account_lockouts_total',
            'Total account lockouts',
            ['reason', 'lockout_type'],
            registry=self.registry
        )
        
        self.password_policy_violations = Counter(
            'password_policy_violations_total',
            'Password policy violations',
            ['violation_type'],
            registry=self.registry
        )
        
        # Session security metrics
        self.suspicious_sessions_total = Counter(
            'suspicious_sessions_total',
            'Suspicious sessions detected',
            ['detection_reason', 'action_taken'],
            registry=self.registry
        )
        
        # Risk scoring metrics
        self.risk_scores = Histogram(
            'user_risk_scores',
            'User risk scores distribution',
            ['risk_category'],
            registry=self.registry,
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        )
    
    def record_threat_detection(self, threat_type: str, severity: str, source: str,
                              response_time_seconds: Optional[float] = None):
        """Record threat detection."""
        if PROMETHEUS_AVAILABLE:
            self.threats_detected_total.labels(
                threat_type=threat_type,
                severity=severity,
                source=source
            ).inc()
            
            if response_time_seconds is not None:
                self.threat_response_time.labels(
                    threat_type=threat_type,
                    response_type='automated'
                ).observe(response_time_seconds)
        
        logger.warning(
            "Threat detected",
            threat_type=threat_type,
            severity=severity,
            source=source,
            response_time_seconds=response_time_seconds
        )
    
    def record_attack_attempt(self, attack_type: str, source_ip: str, blocked: bool):
        """Record attack attempt."""
        if PROMETHEUS_AVAILABLE:
            self.attack_attempts_total.labels(
                attack_type=attack_type,
                source_ip=source_ip,
                blocked=str(blocked).lower()
            ).inc()
        
        logger.warning(
            "Attack attempt",
            attack_type=attack_type,
            source_ip=source_ip,
            blocked=blocked
        )
    
    def record_brute_force_attempt(self, target_type: str, source_ip: str):
        """Record brute force attempt."""
        if PROMETHEUS_AVAILABLE:
            self.brute_force_attempts.labels(
                target_type=target_type,
                source_ip=source_ip
            ).inc()
    
    def record_account_lockout(self, reason: str, lockout_type: str):
        """Record account lockout."""
        if PROMETHEUS_AVAILABLE:
            self.account_lockouts_total.labels(
                reason=reason,
                lockout_type=lockout_type
            ).inc()
    
    def record_password_violation(self, violation_type: str):
        """Record password policy violation."""
        if PROMETHEUS_AVAILABLE:
            self.password_policy_violations.labels(
                violation_type=violation_type
            ).inc()
    
    def record_suspicious_session(self, detection_reason: str, action_taken: str):
        """Record suspicious session detection."""
        if PROMETHEUS_AVAILABLE:
            self.suspicious_sessions_total.labels(
                detection_reason=detection_reason,
                action_taken=action_taken
            ).inc()
    
    def record_risk_score(self, risk_score: float, risk_category: str):
        """Record user risk score."""
        if PROMETHEUS_AVAILABLE:
            self.risk_scores.labels(
                risk_category=risk_category
            ).observe(risk_score)


# Global metrics collectors
business_metrics_collector = BusinessMetricsCollector()
compliance_metrics_collector = ComplianceMetricsCollector()
security_metrics_collector = SecurityMetricsCollector()