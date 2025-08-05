"""
EnterpriseAuth Python SDK

A comprehensive Python SDK for integrating with the EnterpriseAuth API.
"""

__version__ = "1.0.0"
__author__ = "EnterpriseAuth Team"

from .client import EnterpriseAuthClient
from .exceptions import (
    EnterpriseAuthError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ValidationError,
    WebhookError
)
from .models import (
    User,
    APIKey,
    WebhookEndpoint,
    WebhookDelivery,
    Session
)

__all__ = [
    'EnterpriseAuthClient',
    'EnterpriseAuthError',
    'AuthenticationError', 
    'AuthorizationError',
    'RateLimitError',
    'ValidationError',
    'WebhookError',
    'User',
    'APIKey',
    'WebhookEndpoint',
    'WebhookDelivery',
    'Session'
]