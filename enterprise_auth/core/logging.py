"""
Structured logging utilities with correlation ID support.
"""

import logging
import uuid
from typing import Optional
import structlog
from django.conf import settings


class CorrelationIdFilter(logging.Filter):
    """
    Logging filter that adds correlation ID to log records.
    """
    
    def filter(self, record):
        # Get correlation ID from thread local storage or generate new one
        correlation_id = getattr(record, 'correlation_id', None)
        if not correlation_id:
            correlation_id = get_correlation_id()
        record.correlation_id = correlation_id
        return True


def get_correlation_id() -> str:
    """
    Get the current correlation ID from thread local storage.
    If none exists, generate a new one.
    """
    import threading
    
    if not hasattr(threading.current_thread(), 'correlation_id'):
        threading.current_thread().correlation_id = str(uuid.uuid4())
    
    return threading.current_thread().correlation_id


def set_correlation_id(correlation_id: str) -> None:
    """
    Set the correlation ID in thread local storage.
    """
    import threading
    threading.current_thread().correlation_id = correlation_id


def clear_correlation_id() -> None:
    """
    Clear the correlation ID from thread local storage.
    """
    import threading
    if hasattr(threading.current_thread(), 'correlation_id'):
        delattr(threading.current_thread(), 'correlation_id')


def configure_structlog():
    """
    Configure structlog for structured logging.
    """
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            add_correlation_id,
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def add_correlation_id(logger, method_name, event_dict):
    """
    Add correlation ID to structlog event dictionary.
    """
    event_dict['correlation_id'] = get_correlation_id()
    return event_dict


class SecurityLogger:
    """
    Specialized logger for security events.
    """
    
    def __init__(self):
        self.logger = structlog.get_logger('enterprise_auth.security')
    
    def log_authentication_attempt(self, user_id: Optional[str], ip_address: str, 
                                 user_agent: str, success: bool, method: str = 'password'):
        """Log authentication attempt."""
        self.logger.info(
            "authentication_attempt",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            method=method,
            event_type="auth_attempt"
        )
    
    def log_mfa_attempt(self, user_id: str, mfa_type: str, success: bool):
        """Log MFA attempt."""
        self.logger.info(
            "mfa_attempt",
            user_id=user_id,
            mfa_type=mfa_type,
            success=success,
            event_type="mfa_attempt"
        )
    
    def log_password_change(self, user_id: str, ip_address: str):
        """Log password change."""
        self.logger.info(
            "password_change",
            user_id=user_id,
            ip_address=ip_address,
            event_type="password_change"
        )
    
    def log_account_lockout(self, user_id: str, ip_address: str, reason: str):
        """Log account lockout."""
        self.logger.warning(
            "account_lockout",
            user_id=user_id,
            ip_address=ip_address,
            reason=reason,
            event_type="account_lockout"
        )
    
    def log_suspicious_activity(self, user_id: Optional[str], ip_address: str, 
                              activity_type: str, risk_score: float, details: dict):
        """Log suspicious activity."""
        self.logger.warning(
            "suspicious_activity",
            user_id=user_id,
            ip_address=ip_address,
            activity_type=activity_type,
            risk_score=risk_score,
            details=details,
            event_type="suspicious_activity"
        )
    
    def log_rate_limit_exceeded(self, ip_address: str, endpoint: str, limit_type: str):
        """Log rate limit exceeded."""
        self.logger.warning(
            "rate_limit_exceeded",
            ip_address=ip_address,
            endpoint=endpoint,
            limit_type=limit_type,
            event_type="rate_limit_exceeded"
        )


class AuditLogger:
    """
    Specialized logger for audit events.
    """
    
    def __init__(self):
        self.logger = structlog.get_logger('enterprise_auth.audit')
    
    def log_user_creation(self, user_id: str, created_by: Optional[str], user_data: dict):
        """Log user creation."""
        self.logger.info(
            "user_created",
            user_id=user_id,
            created_by=created_by,
            user_data=user_data,
            event_type="user_creation"
        )
    
    def log_user_update(self, user_id: str, updated_by: str, changes: dict):
        """Log user profile update."""
        self.logger.info(
            "user_updated",
            user_id=user_id,
            updated_by=updated_by,
            changes=changes,
            event_type="user_update"
        )
    
    def log_role_assignment(self, user_id: str, role: str, assigned_by: str):
        """Log role assignment."""
        self.logger.info(
            "role_assigned",
            user_id=user_id,
            role=role,
            assigned_by=assigned_by,
            event_type="role_assignment"
        )
    
    def log_permission_check(self, user_id: str, resource: str, action: str, 
                           granted: bool, context: dict):
        """Log permission check."""
        self.logger.info(
            "permission_check",
            user_id=user_id,
            resource=resource,
            action=action,
            granted=granted,
            context=context,
            event_type="permission_check"
        )
    
    def log_data_access(self, user_id: str, resource_type: str, resource_id: str, 
                       action: str, ip_address: str):
        """Log data access."""
        self.logger.info(
            "data_access",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            ip_address=ip_address,
            event_type="data_access"
        )


# Initialize loggers
security_logger = SecurityLogger()
audit_logger = AuditLogger()

# Configure structlog
configure_structlog()