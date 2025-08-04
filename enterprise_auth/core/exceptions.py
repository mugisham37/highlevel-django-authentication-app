"""
Custom exception classes for the enterprise authentication system.

This module defines a comprehensive hierarchy of exceptions that can occur
throughout the authentication system, providing clear error categorization
and consistent error handling.
"""

from typing import Any, Dict, Optional


class EnterpriseAuthError(Exception):
    """
    Base exception for all enterprise authentication errors.
    
    All custom exceptions in the system should inherit from this class
    to provide consistent error handling and logging.
    """
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ):
        """
        Initialize the exception.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
            details: Additional error details
            correlation_id: Request correlation ID for tracking
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__.upper()
        self.details = details or {}
        self.correlation_id = correlation_id
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for API responses.
        
        Returns:
            Dictionary representation of the exception
        """
        result = {
            'error': {
                'code': self.error_code,
                'message': self.message,
            }
        }
        
        if self.details:
            result['error']['details'] = self.details
        
        if self.correlation_id:
            result['error']['correlation_id'] = self.correlation_id
        
        return result


# Authentication Exceptions
class AuthenticationError(EnterpriseAuthError):
    """Base exception for authentication-related errors."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Exception raised when user provides invalid credentials."""
    
    def __init__(self, message: str = "Invalid credentials provided", **kwargs):
        super().__init__(message, error_code="INVALID_CREDENTIALS", **kwargs)


class AccountLockedError(AuthenticationError):
    """Exception raised when user account is locked."""
    
    def __init__(
        self,
        message: str = "Account is temporarily locked",
        locked_until: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if locked_until:
            details['locked_until'] = locked_until
        kwargs['details'] = details
        super().__init__(message, error_code="ACCOUNT_LOCKED", **kwargs)


class AccountDisabledError(AuthenticationError):
    """Exception raised when user account is disabled."""
    
    def __init__(self, message: str = "Account is disabled", **kwargs):
        super().__init__(message, error_code="ACCOUNT_DISABLED", **kwargs)


class EmailNotVerifiedError(AuthenticationError):
    """Exception raised when user email is not verified."""
    
    def __init__(self, message: str = "Email address not verified", **kwargs):
        super().__init__(message, error_code="EMAIL_NOT_VERIFIED", **kwargs)


class MFARequiredError(AuthenticationError):
    """Exception raised when multi-factor authentication is required."""
    
    def __init__(
        self,
        message: str = "Multi-factor authentication required",
        available_methods: Optional[list] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if available_methods:
            details['available_methods'] = available_methods
        kwargs['details'] = details
        super().__init__(message, error_code="MFA_REQUIRED", **kwargs)


class MFAInvalidError(AuthenticationError):
    """Exception raised when MFA verification fails."""
    
    def __init__(self, message: str = "Invalid MFA code", **kwargs):
        super().__init__(message, error_code="MFA_INVALID", **kwargs)


# Token Exceptions
class TokenError(EnterpriseAuthError):
    """Base exception for token-related errors."""
    pass


class TokenExpiredError(TokenError):
    """Exception raised when JWT token has expired."""
    
    def __init__(self, message: str = "Token has expired", **kwargs):
        super().__init__(message, error_code="TOKEN_EXPIRED", **kwargs)


class TokenInvalidError(TokenError):
    """Exception raised when JWT token is invalid or malformed."""
    
    def __init__(self, message: str = "Invalid token", **kwargs):
        super().__init__(message, error_code="TOKEN_INVALID", **kwargs)


class TokenBlacklistedError(TokenError):
    """Exception raised when JWT token is blacklisted."""
    
    def __init__(self, message: str = "Token has been revoked", **kwargs):
        super().__init__(message, error_code="TOKEN_BLACKLISTED", **kwargs)


class RefreshTokenInvalidError(TokenError):
    """Exception raised when refresh token is invalid."""
    
    def __init__(self, message: str = "Invalid refresh token", **kwargs):
        super().__init__(message, error_code="REFRESH_TOKEN_INVALID", **kwargs)


# Authorization Exceptions
class AuthorizationError(EnterpriseAuthError):
    """Base exception for authorization-related errors."""
    pass


class InsufficientPermissionsError(AuthorizationError):
    """Exception raised when user lacks required permissions."""
    
    def __init__(
        self,
        message: str = "Insufficient permissions",
        required_permissions: Optional[list] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if required_permissions:
            details['required_permissions'] = required_permissions
        kwargs['details'] = details
        super().__init__(message, error_code="INSUFFICIENT_PERMISSIONS", **kwargs)


class ResourceNotFoundError(AuthorizationError):
    """Exception raised when requested resource is not found."""
    
    def __init__(self, message: str = "Resource not found", **kwargs):
        super().__init__(message, error_code="RESOURCE_NOT_FOUND", **kwargs)


class ResourceAccessDeniedError(AuthorizationError):
    """Exception raised when access to resource is denied."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(message, error_code="ACCESS_DENIED", **kwargs)


# Rate Limiting Exceptions
class RateLimitError(EnterpriseAuthError):
    """Base exception for rate limiting errors."""
    pass


class RateLimitExceededError(RateLimitError):
    """Exception raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        limit_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if retry_after:
            details['retry_after'] = retry_after
        if limit_type:
            details['limit_type'] = limit_type
        kwargs['details'] = details
        super().__init__(message, error_code="RATE_LIMIT_EXCEEDED", **kwargs)


# Session Exceptions
class SessionError(EnterpriseAuthError):
    """Base exception for session-related errors."""
    pass


class SessionExpiredError(SessionError):
    """Exception raised when session has expired."""
    
    def __init__(self, message: str = "Session has expired", **kwargs):
        super().__init__(message, error_code="SESSION_EXPIRED", **kwargs)


class SessionInvalidError(SessionError):
    """Exception raised when session is invalid."""
    
    def __init__(self, message: str = "Invalid session", **kwargs):
        super().__init__(message, error_code="SESSION_INVALID", **kwargs)


class ConcurrentSessionLimitError(SessionError):
    """Exception raised when concurrent session limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Concurrent session limit exceeded",
        max_sessions: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if max_sessions:
            details['max_sessions'] = max_sessions
        kwargs['details'] = details
        super().__init__(message, error_code="CONCURRENT_SESSION_LIMIT", **kwargs)


# OAuth Exceptions
class OAuthError(EnterpriseAuthError):
    """Base exception for OAuth-related errors."""
    pass


class OAuthProviderError(OAuthError):
    """Exception raised when OAuth provider returns an error."""
    
    def __init__(
        self,
        message: str = "OAuth provider error",
        provider: Optional[str] = None,
        provider_error: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        if provider_error:
            details['provider_error'] = provider_error
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_PROVIDER_ERROR", **kwargs)


class OAuthStateInvalidError(OAuthError):
    """Exception raised when OAuth state parameter is invalid."""
    
    def __init__(self, message: str = "Invalid OAuth state", **kwargs):
        super().__init__(message, error_code="OAUTH_STATE_INVALID", **kwargs)


class OAuthCodeInvalidError(OAuthError):
    """Exception raised when OAuth authorization code is invalid."""
    
    def __init__(self, message: str = "Invalid OAuth authorization code", **kwargs):
        super().__init__(message, error_code="OAUTH_CODE_INVALID", **kwargs)


# Security Exceptions
class SecurityError(EnterpriseAuthError):
    """Base exception for security-related errors."""
    pass


class SuspiciousActivityError(SecurityError):
    """Exception raised when suspicious activity is detected."""
    
    def __init__(
        self,
        message: str = "Suspicious activity detected",
        risk_score: Optional[float] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if risk_score is not None:
            details['risk_score'] = risk_score
        kwargs['details'] = details
        super().__init__(message, error_code="SUSPICIOUS_ACTIVITY", **kwargs)


class ThreatDetectedError(SecurityError):
    """Exception raised when a security threat is detected."""
    
    def __init__(
        self,
        message: str = "Security threat detected",
        threat_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if threat_type:
            details['threat_type'] = threat_type
        kwargs['details'] = details
        super().__init__(message, error_code="THREAT_DETECTED", **kwargs)


# Validation Exceptions
class ValidationError(EnterpriseAuthError):
    """Base exception for validation errors."""
    pass


class PasswordValidationError(ValidationError):
    """Exception raised when password validation fails."""
    
    def __init__(
        self,
        message: str = "Password validation failed",
        validation_errors: Optional[list] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if validation_errors:
            details['validation_errors'] = validation_errors
        kwargs['details'] = details
        super().__init__(message, error_code="PASSWORD_VALIDATION_ERROR", **kwargs)


class EmailValidationError(ValidationError):
    """Exception raised when email validation fails."""
    
    def __init__(self, message: str = "Invalid email address", **kwargs):
        super().__init__(message, error_code="EMAIL_VALIDATION_ERROR", **kwargs)


# Integration Exceptions
class IntegrationError(EnterpriseAuthError):
    """Base exception for integration-related errors."""
    pass


class WebhookDeliveryError(IntegrationError):
    """Exception raised when webhook delivery fails."""
    
    def __init__(
        self,
        message: str = "Webhook delivery failed",
        webhook_url: Optional[str] = None,
        status_code: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if webhook_url:
            details['webhook_url'] = webhook_url
        if status_code:
            details['status_code'] = status_code
        kwargs['details'] = details
        super().__init__(message, error_code="WEBHOOK_DELIVERY_ERROR", **kwargs)


class ExternalServiceError(IntegrationError):
    """Exception raised when external service call fails."""
    
    def __init__(
        self,
        message: str = "External service error",
        service_name: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if service_name:
            details['service_name'] = service_name
        kwargs['details'] = details
        super().__init__(message, error_code="EXTERNAL_SERVICE_ERROR", **kwargs)


# Configuration Exceptions
class ConfigurationError(EnterpriseAuthError):
    """Exception raised when configuration is invalid or missing."""
    
    def __init__(
        self,
        message: str = "Configuration error",
        config_key: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if config_key:
            details['config_key'] = config_key
        kwargs['details'] = details
        super().__init__(message, error_code="CONFIGURATION_ERROR", **kwargs)