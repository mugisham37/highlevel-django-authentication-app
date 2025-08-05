"""
Custom exception classes for the enterprise authentication system.

This module defines a comprehensive hierarchy of exceptions that can occur
throughout the authentication system, providing clear error categorization
and consistent error handling.
"""

from typing import Any, Dict, List, Optional


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


# MFA Exceptions
class MFAError(EnterpriseAuthError):
    """Base exception for MFA-related errors."""
    pass


class MFADeviceNotFoundError(MFAError):
    """Exception raised when MFA device is not found."""
    
    def __init__(
        self,
        message: str = "MFA device not found",
        device_id: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if device_id:
            details['device_id'] = device_id
        kwargs['details'] = details
        super().__init__(message, error_code="MFA_DEVICE_NOT_FOUND", **kwargs)


class MFAVerificationError(MFAError):
    """Exception raised when MFA verification fails."""
    
    def __init__(
        self,
        message: str = "MFA verification failed",
        device_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if device_type:
            details['device_type'] = device_type
        kwargs['details'] = details
        super().__init__(message, error_code="MFA_VERIFICATION_ERROR", **kwargs)


class MFARateLimitError(MFAError):
    """Exception raised when MFA rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "MFA rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if retry_after:
            details['retry_after'] = retry_after
        kwargs['details'] = details
        super().__init__(message, error_code="MFA_RATE_LIMIT_ERROR", **kwargs)


class MFADeviceDisabledError(MFAError):
    """Exception raised when MFA device is disabled."""
    
    def __init__(
        self,
        message: str = "MFA device is disabled",
        device_id: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if device_id:
            details['device_id'] = device_id
        kwargs['details'] = details
        super().__init__(message, error_code="MFA_DEVICE_DISABLED", **kwargs)


class MFASetupError(MFAError):
    """Exception raised when MFA setup fails."""
    
    def __init__(
        self,
        message: str = "MFA setup failed",
        device_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if device_type:
            details['device_type'] = device_type
        kwargs['details'] = details
        super().__init__(message, error_code="MFA_SETUP_ERROR", **kwargs)


class MFABackupCodeError(MFAError):
    """Exception raised when backup code operation fails."""
    
    def __init__(
        self,
        message: str = "Backup code operation failed",
        **kwargs
    ):
        super().__init__(message, error_code="MFA_BACKUP_CODE_ERROR", **kwargs)


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


class OAuthProviderNotFoundError(OAuthError):
    """Exception raised when OAuth provider is not found."""
    
    def __init__(
        self,
        message: str = "OAuth provider not found",
        provider: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_PROVIDER_NOT_FOUND", **kwargs)


class OAuthProviderNotConfiguredError(OAuthError):
    """Exception raised when OAuth provider is not configured."""
    
    def __init__(
        self,
        message: str = "OAuth provider not configured",
        provider: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_PROVIDER_NOT_CONFIGURED", **kwargs)


class OAuthProviderDisabledError(OAuthError):
    """Exception raised when OAuth provider is disabled."""
    
    def __init__(
        self,
        message: str = "OAuth provider is disabled",
        provider: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_PROVIDER_DISABLED", **kwargs)


class OAuthScopeError(OAuthError):
    """Exception raised when OAuth scope is invalid or insufficient."""
    
    def __init__(
        self,
        message: str = "Invalid OAuth scope",
        requested_scopes: Optional[List[str]] = None,
        supported_scopes: Optional[List[str]] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if requested_scopes:
            details['requested_scopes'] = requested_scopes
        if supported_scopes:
            details['supported_scopes'] = supported_scopes
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_SCOPE_ERROR", **kwargs)


class OAuthTokenRefreshError(OAuthError):
    """Exception raised when OAuth token refresh fails."""
    
    def __init__(
        self,
        message: str = "OAuth token refresh failed",
        provider: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_TOKEN_REFRESH_ERROR", **kwargs)


class OAuthUserInfoError(OAuthError):
    """Exception raised when OAuth user info retrieval fails."""
    
    def __init__(
        self,
        message: str = "OAuth user info retrieval failed",
        provider: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_USER_INFO_ERROR", **kwargs)


class OAuthTokenExpiredError(OAuthError):
    """Exception raised when OAuth access token has expired."""
    
    def __init__(
        self,
        message: str = "OAuth access token has expired",
        provider: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_TOKEN_EXPIRED", **kwargs)


class OAuthAccountAlreadyLinkedError(OAuthError):
    """Exception raised when OAuth account is already linked to another user."""
    
    def __init__(
        self,
        message: str = "OAuth account is already linked to another user",
        provider: Optional[str] = None,
        provider_user_id: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        if provider_user_id:
            details['provider_user_id'] = provider_user_id
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_ACCOUNT_ALREADY_LINKED", **kwargs)


class OAuthAccountTakeoverAttemptError(OAuthError):
    """Exception raised when a potential account takeover attempt is detected."""
    
    def __init__(
        self,
        message: str = "Potential account takeover attempt detected",
        provider: Optional[str] = None,
        risk_indicators: Optional[List[str]] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        if risk_indicators:
            details['risk_indicators'] = risk_indicators
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_ACCOUNT_TAKEOVER_ATTEMPT", **kwargs)


class OAuthLinkingTokenInvalidError(OAuthError):
    """Exception raised when OAuth linking token is invalid."""
    
    def __init__(
        self,
        message: str = "Invalid OAuth linking token",
        **kwargs
    ):
        super().__init__(message, error_code="OAUTH_LINKING_TOKEN_INVALID", **kwargs)


class OAuthCallbackError(OAuthError):
    """Exception raised during OAuth callback processing."""
    
    def __init__(
        self,
        message: str = "OAuth callback processing failed",
        provider: Optional[str] = None,
        callback_error: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        if callback_error:
            details['callback_error'] = callback_error
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_CALLBACK_ERROR", **kwargs)


class OAuthProviderTimeoutError(OAuthError):
    """Exception raised when OAuth provider request times out."""
    
    def __init__(
        self,
        message: str = "OAuth provider request timed out",
        provider: Optional[str] = None,
        timeout_duration: Optional[float] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        if timeout_duration:
            details['timeout_duration'] = timeout_duration
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_PROVIDER_TIMEOUT", **kwargs)


class OAuthRateLimitError(OAuthError):
    """Exception raised when OAuth provider rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "OAuth provider rate limit exceeded",
        provider: Optional[str] = None,
        retry_after: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if provider:
            details['provider'] = provider
        if retry_after:
            details['retry_after'] = retry_after
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_RATE_LIMIT_ERROR", **kwargs)


class OAuthMaxIdentitiesExceededError(OAuthError):
    """Exception raised when maximum number of linked identities is exceeded."""
    
    def __init__(
        self,
        message: str = "Maximum number of linked accounts exceeded",
        max_allowed: Optional[int] = None,
        current_count: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if max_allowed is not None:
            details['max_allowed'] = max_allowed
        if current_count is not None:
            details['current_count'] = current_count
        kwargs['details'] = details
        super().__init__(message, error_code="OAUTH_MAX_IDENTITIES_EXCEEDED", **kwargs)


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


class PasswordPolicyError(ValidationError):
    """Exception raised when password policy is violated."""
    
    def __init__(
        self,
        message: str = "Password policy violation",
        validation_errors: Optional[list] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if validation_errors:
            details['validation_errors'] = validation_errors
        kwargs['details'] = details
        super().__init__(message, error_code="PASSWORD_POLICY_ERROR", **kwargs)


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
# Session Management Exceptions

class SessionError(EnterpriseAuthError):
    """Base exception for session-related errors."""
    pass


class SessionNotFoundError(SessionError):
    """Exception raised when a session is not found."""
    
    def __init__(self, session_id: str, correlation_id: Optional[str] = None):
        super().__init__(
            message=f"Session not found: {session_id}",
            error_code="SESSION_NOT_FOUND",
            details={"session_id": session_id},
            correlation_id=correlation_id
        )


class SessionInvalidError(SessionError):
    """Exception raised when a session is invalid."""
    
    def __init__(self, session_id: str, reason: str, correlation_id: Optional[str] = None):
        super().__init__(
            message=f"Session invalid: {reason}",
            error_code="SESSION_INVALID",
            details={"session_id": session_id, "reason": reason},
            correlation_id=correlation_id
        )


class SessionExpiredError(SessionError):
    """Exception raised when a session has expired."""
    
    def __init__(self, session_id: str, expired_at: str, correlation_id: Optional[str] = None):
        super().__init__(
            message="Session has expired",
            error_code="SESSION_EXPIRED",
            details={"session_id": session_id, "expired_at": expired_at},
            correlation_id=correlation_id
        )


class SessionTerminatedError(SessionError):
    """Exception raised when a session has been terminated."""
    
    def __init__(self, session_id: str, reason: str, correlation_id: Optional[str] = None):
        super().__init__(
            message="Session has been terminated",
            error_code="SESSION_TERMINATED",
            details={"session_id": session_id, "reason": reason},
            correlation_id=correlation_id
        )


class SessionLimitExceededError(SessionError):
    """Exception raised when session limits are exceeded."""
    
    def __init__(self, user_id: str, limit: int, correlation_id: Optional[str] = None):
        super().__init__(
            message=f"Session limit exceeded: maximum {limit} concurrent sessions allowed",
            error_code="SESSION_LIMIT_EXCEEDED",
            details={"user_id": user_id, "limit": limit},
            correlation_id=correlation_id
        )


class DeviceFingerprintError(SessionError):
    """Exception raised when device fingerprinting fails."""
    
    def __init__(self, reason: str, correlation_id: Optional[str] = None):
        super().__init__(
            message=f"Device fingerprinting failed: {reason}",
            error_code="DEVICE_FINGERPRINT_ERROR",
            details={"reason": reason},
            correlation_id=correlation_id
        )


class SessionSecurityError(SessionError):
    """Exception raised for session security violations."""
    
    def __init__(self, session_id: str, violation_type: str, 
                 risk_score: float, correlation_id: Optional[str] = None):
        super().__init__(
            message=f"Session security violation: {violation_type}",
            error_code="SESSION_SECURITY_VIOLATION",
            details={
                "session_id": session_id,
                "violation_type": violation_type,
                "risk_score": risk_score
            },
            correlation_id=correlation_id
        )