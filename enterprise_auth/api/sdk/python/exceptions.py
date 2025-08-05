"""
EnterpriseAuth Python SDK Exceptions

Custom exception classes for the EnterpriseAuth SDK.
"""
from typing import Dict, Any, Optional


class EnterpriseAuthError(Exception):
    """Base exception for EnterpriseAuth SDK errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class AuthenticationError(EnterpriseAuthError):
    """Raised when authentication fails."""
    pass


class AuthorizationError(EnterpriseAuthError):
    """Raised when authorization fails (insufficient permissions)."""
    pass


class RateLimitError(EnterpriseAuthError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str, retry_after: int = 60, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.retry_after = retry_after


class ValidationError(EnterpriseAuthError):
    """Raised when request validation fails."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.validation_errors = details or {}


class WebhookError(EnterpriseAuthError):
    """Raised when webhook operations fail."""
    pass


class NetworkError(EnterpriseAuthError):
    """Raised when network operations fail."""
    pass


class TimeoutError(EnterpriseAuthError):
    """Raised when requests timeout."""
    pass