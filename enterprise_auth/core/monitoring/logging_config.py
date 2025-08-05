"""
Enhanced structured logging configuration with JSON format and correlation IDs.
Provides specialized loggers for different aspects of the system.
"""

import logging
import json
import uuid
import threading
from typing import Dict, Any, Optional
from datetime import datetime
from django.conf import settings
from django.utils import timezone
import structlog
from pythonjsonlogger import jsonlogger


class CorrelationIdProcessor:
    """Structlog processor to add correlation ID to log entries."""
    
    def __call__(self, logger, method_name, event_dict):
        event_dict['correlation_id'] = get_correlation_id()
        return event_dict


class RequestContextProcessor:
    """Structlog processor to add request context to log entries."""
    
    def __call__(self, logger, method_name, event_dict):
        # Try to get request context from thread local
        request_context = getattr(threading.current_thread(), 'request_context', {})
        if request_context:
            event_dict.update({
                'user_id': request_context.get('user_id'),
                'ip_address': request_context.get('ip_address'),
                'user_agent': request_context.get('user_agent'),
                'endpoint': request_context.get('endpoint'),
                'method': request_context.get('method')
            })
        return event_dict


class TimestampProcessor:
    """Structlog processor to add ISO timestamp."""
    
    def __call__(self, logger, method_name, event_dict):
        event_dict['timestamp'] = timezone.now().isoformat()
        return event_dict


class SeverityProcessor:
    """Structlog processor to normalize severity levels."""
    
    def __call__(self, logger, method_name, event_dict):
        # Map log levels to severity
        level_mapping = {
            'debug': 'low',
            'info': 'low',
            'warning': 'medium',
            'error': 'high',
            'critical': 'critical'
        }
        
        level = event_dict.get('level', '').lower()
        event_dict['severity'] = level_mapping.get(level, 'medium')
        return event_dict


def get_correlation_id() -> str:
    """Get or generate correlation ID for current thread."""
    if not hasattr(threading.current_thread(), 'correlation_id'):
        threading.current_thread().correlation_id = str(uuid.uuid4())
    return threading.current_thread().correlation_id


def set_correlation_id(correlation_id: str) -> None:
    """Set correlation ID for current thread."""
    threading.current_thread().correlation_id = correlation_id


def set_request_context(user_id: Optional[str] = None, ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None, endpoint: Optional[str] = None,
                       method: Optional[str] = None) -> None:
    """Set request context for current thread."""
    threading.current_thread().request_context = {
        'user_id': user_id,
        'ip_address': ip_address,
        'user_agent': user_agent,
        'endpoint': endpoint,
        'method': method
    }


def clear_request_context() -> None:
    """Clear request context for current thread."""
    if hasattr(threading.current_thread(), 'request_context'):
        delattr(threading.current_thread(), 'request_context')


def configure_structured_logging():
    """Configure structlog for comprehensive structured logging."""
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            TimestampProcessor(),
            CorrelationIdProcessor(),
            RequestContextProcessor(),
            SeverityProcessor(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


class CustomJSONFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields."""
    
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        
        # Add correlation ID
        log_record['correlation_id'] = get_correlation_id()
        
        # Add timestamp in ISO format
        log_record['timestamp'] = datetime.fromtimestamp(record.created).isoformat()
        
        # Add severity mapping
        level_mapping = {
            'DEBUG': 'low',
            'INFO': 'low', 
            'WARNING': 'medium',
            'ERROR': 'high',
            'CRITICAL': 'critical'
        }
        log_record['severity'] = level_mapping.get(record.levelname, 'medium')
        
        # Add request context if available
        request_context = getattr(threading.current_thread(), 'request_context', {})
        if request_context:
            log_record.update(request_context)


def get_structured_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance."""
    return structlog.get_logger(name)


class SecurityLogger:
    """Enhanced security event logger with structured logging."""
    
    def __init__(self):
        self.logger = get_structured_logger('enterprise_auth.security')
    
    def log_authentication_attempt(self, user_id: Optional[str], ip_address: str,
                                 user_agent: str, success: bool, method: str = 'password',
                                 provider: Optional[str] = None, risk_score: float = 0.0,
                                 additional_context: Optional[Dict[str, Any]] = None):
        """Log authentication attempt with comprehensive context."""
        context = {
            'event_type': 'authentication_attempt',
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'success': success,
            'auth_method': method,
            'provider': provider,
            'risk_score': risk_score,
            'session_id': getattr(threading.current_thread(), 'session_id', None)
        }
        
        if additional_context:
            context.update(additional_context)
        
        if success:
            self.logger.info("Authentication successful", **context)
        else:
            self.logger.warning("Authentication failed", **context)
    
    def log_mfa_attempt(self, user_id: str, mfa_type: str, success: bool,
                       device_id: Optional[str] = None, backup_code_used: bool = False):
        """Log MFA attempt."""
        context = {
            'event_type': 'mfa_attempt',
            'user_id': user_id,
            'mfa_type': mfa_type,
            'success': success,
            'device_id': device_id,
            'backup_code_used': backup_code_used
        }
        
        if success:
            self.logger.info("MFA verification successful", **context)
        else:
            self.logger.warning("MFA verification failed", **context)
    
    def log_password_change(self, user_id: str, ip_address: str, forced: bool = False):
        """Log password change event."""
        self.logger.info(
            "Password changed",
            event_type='password_change',
            user_id=user_id,
            ip_address=ip_address,
            forced=forced
        )
    
    def log_account_lockout(self, user_id: str, ip_address: str, reason: str,
                          lockout_duration: int, failed_attempts: int):
        """Log account lockout event."""
        self.logger.warning(
            "Account locked",
            event_type='account_lockout',
            user_id=user_id,
            ip_address=ip_address,
            reason=reason,
            lockout_duration_minutes=lockout_duration,
            failed_attempts=failed_attempts
        )
    
    def log_suspicious_activity(self, user_id: Optional[str], ip_address: str,
                              activity_type: str, risk_score: float,
                              threat_indicators: list, response_taken: str):
        """Log suspicious activity detection."""
        self.logger.warning(
            "Suspicious activity detected",
            event_type='suspicious_activity',
            user_id=user_id,
            ip_address=ip_address,
            activity_type=activity_type,
            risk_score=risk_score,
            threat_indicators=threat_indicators,
            response_taken=response_taken
        )
    
    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str, limit_type: str,
                              current_count: int, limit: int, window_seconds: int):
        """Log rate limit exceeded event."""
        self.logger.warning(
            "Rate limit exceeded",
            event_type='rate_limit_exceeded',
            ip_address=ip_address,
            endpoint=endpoint,
            limit_type=limit_type,
            current_count=current_count,
            limit=limit,
            window_seconds=window_seconds
        )
    
    def log_token_event(self, user_id: str, token_type: str, action: str,
                       token_id: Optional[str] = None, reason: Optional[str] = None):
        """Log token-related security events."""
        self.logger.info(
            f"Token {action}",
            event_type='token_event',
            user_id=user_id,
            token_type=token_type,
            action=action,
            token_id=token_id,
            reason=reason
        )


class AuditLogger:
    """Enhanced audit logger for compliance and governance."""
    
    def __init__(self):
        self.logger = get_structured_logger('enterprise_auth.audit')
    
    def log_user_creation(self, user_id: str, created_by: Optional[str],
                         user_data: Dict[str, Any], registration_method: str):
        """Log user creation with comprehensive audit trail."""
        # Sanitize sensitive data
        safe_user_data = {k: v for k, v in user_data.items() 
                         if k not in ['password', 'password_hash']}
        
        self.logger.info(
            "User created",
            event_type='user_creation',
            user_id=user_id,
            created_by=created_by,
            user_data=safe_user_data,
            registration_method=registration_method
        )
    
    def log_user_update(self, user_id: str, updated_by: str, changes: Dict[str, Any],
                       update_type: str = 'profile_update'):
        """Log user profile updates."""
        # Sanitize sensitive changes
        safe_changes = {k: v for k, v in changes.items() 
                       if k not in ['password', 'password_hash']}
        
        self.logger.info(
            "User updated",
            event_type='user_update',
            user_id=user_id,
            updated_by=updated_by,
            changes=safe_changes,
            update_type=update_type
        )
    
    def log_role_assignment(self, user_id: str, role: str, assigned_by: str,
                          expires_at: Optional[str] = None):
        """Log role assignment."""
        self.logger.info(
            "Role assigned",
            event_type='role_assignment',
            user_id=user_id,
            role=role,
            assigned_by=assigned_by,
            expires_at=expires_at
        )
    
    def log_permission_check(self, user_id: str, resource: str, action: str,
                           granted: bool, context: Dict[str, Any]):
        """Log permission check for audit trail."""
        self.logger.info(
            "Permission checked",
            event_type='permission_check',
            user_id=user_id,
            resource=resource,
            action=action,
            granted=granted,
            context=context
        )
    
    def log_data_access(self, user_id: str, resource_type: str, resource_id: str,
                       action: str, ip_address: str, success: bool = True):
        """Log data access for compliance."""
        self.logger.info(
            "Data accessed",
            event_type='data_access',
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            ip_address=ip_address,
            success=success
        )
    
    def log_compliance_event(self, event_type: str, user_id: Optional[str],
                           details: Dict[str, Any], regulation: str):
        """Log compliance-related events (GDPR, CCPA, etc.)."""
        self.logger.info(
            f"Compliance event: {event_type}",
            event_type='compliance_event',
            compliance_event_type=event_type,
            user_id=user_id,
            details=details,
            regulation=regulation
        )


class PerformanceLogger:
    """Performance and monitoring logger."""
    
    def __init__(self):
        self.logger = get_structured_logger('enterprise_auth.performance')
    
    def log_slow_request(self, endpoint: str, method: str, duration_ms: float,
                        user_id: Optional[str] = None, query_count: int = 0):
        """Log slow request performance."""
        self.logger.warning(
            "Slow request detected",
            event_type='slow_request',
            endpoint=endpoint,
            method=method,
            duration_ms=duration_ms,
            user_id=user_id,
            query_count=query_count
        )
    
    def log_slow_query(self, query_type: str, table: str, duration_ms: float,
                      query_hash: Optional[str] = None):
        """Log slow database query."""
        self.logger.warning(
            "Slow query detected",
            event_type='slow_query',
            query_type=query_type,
            table=table,
            duration_ms=duration_ms,
            query_hash=query_hash
        )
    
    def log_cache_miss(self, cache_key: str, cache_type: str, operation: str):
        """Log cache miss events."""
        self.logger.info(
            "Cache miss",
            event_type='cache_miss',
            cache_key=cache_key,
            cache_type=cache_type,
            operation=operation
        )
    
    def log_sla_violation(self, metric_name: str, target_value: float,
                         actual_value: float, severity: str):
        """Log SLA violations."""
        self.logger.error(
            "SLA violation",
            event_type='sla_violation',
            metric_name=metric_name,
            target_value=target_value,
            actual_value=actual_value,
            severity=severity
        )


class BusinessLogger:
    """Business intelligence and analytics logger."""
    
    def __init__(self):
        self.logger = get_structured_logger('enterprise_auth.business')
    
    def log_user_registration(self, user_id: str, registration_source: str,
                            user_agent: str, country: Optional[str] = None):
        """Log user registration for business analytics."""
        self.logger.info(
            "User registered",
            event_type='user_registration',
            user_id=user_id,
            registration_source=registration_source,
            user_agent=user_agent,
            country=country
        )
    
    def log_authentication_success(self, user_id: str, auth_method: str,
                                 provider: Optional[str] = None,
                                 device_type: Optional[str] = None):
        """Log successful authentication for business metrics."""
        self.logger.info(
            "Authentication success",
            event_type='auth_success',
            user_id=user_id,
            auth_method=auth_method,
            provider=provider,
            device_type=device_type
        )
    
    def log_feature_usage(self, user_id: str, feature: str, action: str,
                         metadata: Optional[Dict[str, Any]] = None):
        """Log feature usage for product analytics."""
        self.logger.info(
            "Feature used",
            event_type='feature_usage',
            user_id=user_id,
            feature=feature,
            action=action,
            metadata=metadata or {}
        )
    
    def log_conversion_event(self, user_id: str, event_type: str,
                           value: Optional[float] = None,
                           properties: Optional[Dict[str, Any]] = None):
        """Log conversion events for business intelligence."""
        self.logger.info(
            "Conversion event",
            event_type='conversion',
            conversion_type=event_type,
            user_id=user_id,
            value=value,
            properties=properties or {}
        )


# Initialize structured logging
configure_structured_logging()

# Create logger instances
security_logger = SecurityLogger()
audit_logger = AuditLogger()
performance_logger = PerformanceLogger()
business_logger = BusinessLogger()