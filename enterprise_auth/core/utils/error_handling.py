"""
Error handling middleware and utilities.

This module provides comprehensive error handling middleware that catches
exceptions, logs them appropriately, and returns consistent error responses
to clients.
"""

import json
import logging
import traceback
from typing import Any, Dict, Optional

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError as DjangoValidationError
from django.http import Http404, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from rest_framework import status
from rest_framework.exceptions import (
    APIException,
    AuthenticationFailed,
    NotAuthenticated,
    PermissionDenied as DRFPermissionDenied,
    ValidationError as DRFValidationError,
)

from enterprise_auth.core.exceptions import (
    EnterpriseAuthError,
    AuthenticationError,
    AuthorizationError,
    RateLimitExceededError,
    TokenError,
    SessionError,
    SecurityError,
    ValidationError,
    ConfigurationError,
)
from enterprise_auth.core.utils.correlation import get_correlation_id


logger = logging.getLogger(__name__)


class ErrorHandlingMiddleware(MiddlewareMixin):
    """
    Comprehensive error handling middleware.
    
    This middleware catches all exceptions, logs them appropriately,
    and returns consistent JSON error responses to clients.
    """
    
    def process_exception(self, request, exception):
        """
        Process exceptions and return appropriate error responses.
        
        Args:
            request: Django HttpRequest object
            exception: Exception that occurred
            
        Returns:
            JsonResponse with error details or None to continue processing
        """
        correlation_id = get_correlation_id()
        
        # Add correlation ID to exception if not already present
        if not hasattr(exception, 'correlation_id') and correlation_id:
            exception.correlation_id = correlation_id
        
        # Handle different types of exceptions
        if isinstance(exception, EnterpriseAuthError):
            return self._handle_enterprise_auth_error(request, exception)
        elif isinstance(exception, (NotAuthenticated, AuthenticationFailed)):
            return self._handle_authentication_error(request, exception)
        elif isinstance(exception, (PermissionDenied, DRFPermissionDenied)):
            return self._handle_authorization_error(request, exception)
        elif isinstance(exception, (DjangoValidationError, DRFValidationError)):
            return self._handle_validation_error(request, exception)
        elif isinstance(exception, Http404):
            return self._handle_not_found_error(request, exception)
        elif isinstance(exception, APIException):
            return self._handle_api_exception(request, exception)
        else:
            return self._handle_unexpected_error(request, exception)
    
    def _handle_enterprise_auth_error(self, request, exception: EnterpriseAuthError) -> JsonResponse:
        """
        Handle custom enterprise authentication errors.
        
        Args:
            request: Django HttpRequest object
            exception: EnterpriseAuthError instance
            
        Returns:
            JsonResponse with error details
        """
        # Log the error with appropriate level
        if isinstance(exception, (SecurityError, ConfigurationError)):
            log_level = logging.ERROR
        elif isinstance(exception, (AuthenticationError, AuthorizationError)):
            log_level = logging.WARNING
        else:
            log_level = logging.INFO
        
        logger.log(
            log_level,
            f"Enterprise auth error: {exception.error_code} - {exception.message}",
            extra={
                'error_code': exception.error_code,
                'correlation_id': exception.correlation_id,
                'details': exception.details,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'path': request.path,
                'method': request.method,
            }
        )
        
        # Determine HTTP status code
        status_code = self._get_status_code_for_exception(exception)
        
        # Build error response
        error_data = exception.to_dict()
        if exception.correlation_id:
            error_data['error']['correlation_id'] = exception.correlation_id
        
        return JsonResponse(error_data, status=status_code)
    
    def _handle_authentication_error(self, request, exception) -> JsonResponse:
        """
        Handle Django/DRF authentication errors.
        
        Args:
            request: Django HttpRequest object
            exception: Authentication exception
            
        Returns:
            JsonResponse with error details
        """
        correlation_id = get_correlation_id()
        
        logger.warning(
            f"Authentication error: {str(exception)}",
            extra={
                'correlation_id': correlation_id,
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'path': request.path,
                'method': request.method,
            }
        )
        
        error_data = {
            'error': {
                'code': 'AUTHENTICATION_FAILED',
                'message': 'Authentication credentials were not provided or are invalid.',
            }
        }
        
        if correlation_id:
            error_data['error']['correlation_id'] = correlation_id
        
        return JsonResponse(error_data, status=status.HTTP_401_UNAUTHORIZED)
    
    def _handle_authorization_error(self, request, exception) -> JsonResponse:
        """
        Handle Django/DRF authorization errors.
        
        Args:
            request: Django HttpRequest object
            exception: Authorization exception
            
        Returns:
            JsonResponse with error details
        """
        correlation_id = get_correlation_id()
        
        logger.warning(
            f"Authorization error: {str(exception)}",
            extra={
                'correlation_id': correlation_id,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'ip_address': self._get_client_ip(request),
                'path': request.path,
                'method': request.method,
            }
        )
        
        error_data = {
            'error': {
                'code': 'PERMISSION_DENIED',
                'message': 'You do not have permission to perform this action.',
            }
        }
        
        if correlation_id:
            error_data['error']['correlation_id'] = correlation_id
        
        return JsonResponse(error_data, status=status.HTTP_403_FORBIDDEN)
    
    def _handle_validation_error(self, request, exception) -> JsonResponse:
        """
        Handle Django/DRF validation errors.
        
        Args:
            request: Django HttpRequest object
            exception: Validation exception
            
        Returns:
            JsonResponse with error details
        """
        correlation_id = get_correlation_id()
        
        logger.info(
            f"Validation error: {str(exception)}",
            extra={
                'correlation_id': correlation_id,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'path': request.path,
                'method': request.method,
            }
        )
        
        # Extract validation details
        details = {}
        if isinstance(exception, DRFValidationError):
            details = exception.detail if hasattr(exception, 'detail') else {}
        elif isinstance(exception, DjangoValidationError):
            if hasattr(exception, 'message_dict'):
                details = exception.message_dict
            elif hasattr(exception, 'messages'):
                details = {'non_field_errors': exception.messages}
        
        error_data = {
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'The provided data is invalid.',
                'details': details,
            }
        }
        
        if correlation_id:
            error_data['error']['correlation_id'] = correlation_id
        
        return JsonResponse(error_data, status=status.HTTP_400_BAD_REQUEST)
    
    def _handle_not_found_error(self, request, exception) -> JsonResponse:
        """
        Handle HTTP 404 errors.
        
        Args:
            request: Django HttpRequest object
            exception: Http404 exception
            
        Returns:
            JsonResponse with error details
        """
        correlation_id = get_correlation_id()
        
        logger.info(
            f"Not found error: {request.path}",
            extra={
                'correlation_id': correlation_id,
                'path': request.path,
                'method': request.method,
                'ip_address': self._get_client_ip(request),
            }
        )
        
        error_data = {
            'error': {
                'code': 'NOT_FOUND',
                'message': 'The requested resource was not found.',
            }
        }
        
        if correlation_id:
            error_data['error']['correlation_id'] = correlation_id
        
        return JsonResponse(error_data, status=status.HTTP_404_NOT_FOUND)
    
    def _handle_api_exception(self, request, exception: APIException) -> JsonResponse:
        """
        Handle DRF API exceptions.
        
        Args:
            request: Django HttpRequest object
            exception: APIException instance
            
        Returns:
            JsonResponse with error details
        """
        correlation_id = get_correlation_id()
        
        logger.warning(
            f"API exception: {exception.__class__.__name__} - {str(exception)}",
            extra={
                'correlation_id': correlation_id,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'path': request.path,
                'method': request.method,
            }
        )
        
        error_data = {
            'error': {
                'code': exception.__class__.__name__.upper(),
                'message': str(exception),
            }
        }
        
        if hasattr(exception, 'detail') and exception.detail:
            error_data['error']['details'] = exception.detail
        
        if correlation_id:
            error_data['error']['correlation_id'] = correlation_id
        
        return JsonResponse(error_data, status=exception.status_code)
    
    def _handle_unexpected_error(self, request, exception) -> JsonResponse:
        """
        Handle unexpected errors (500 errors).
        
        Args:
            request: Django HttpRequest object
            exception: Unexpected exception
            
        Returns:
            JsonResponse with error details
        """
        correlation_id = get_correlation_id()
        
        # Log the full traceback for debugging
        logger.error(
            f"Unexpected error: {exception.__class__.__name__} - {str(exception)}",
            extra={
                'correlation_id': correlation_id,
                'user_id': getattr(request.user, 'id', None) if hasattr(request, 'user') else None,
                'ip_address': self._get_client_ip(request),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'path': request.path,
                'method': request.method,
                'traceback': traceback.format_exc(),
            }
        )
        
        # Don't expose internal error details in production
        if settings.DEBUG:
            message = str(exception)
            details = {'traceback': traceback.format_exc()}
        else:
            message = 'An internal server error occurred.'
            details = {}
        
        error_data = {
            'error': {
                'code': 'INTERNAL_SERVER_ERROR',
                'message': message,
            }
        }
        
        if details:
            error_data['error']['details'] = details
        
        if correlation_id:
            error_data['error']['correlation_id'] = correlation_id
        
        return JsonResponse(error_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _get_status_code_for_exception(self, exception: EnterpriseAuthError) -> int:
        """
        Get appropriate HTTP status code for enterprise auth exception.
        
        Args:
            exception: EnterpriseAuthError instance
            
        Returns:
            HTTP status code
        """
        if isinstance(exception, AuthenticationError):
            return status.HTTP_401_UNAUTHORIZED
        elif isinstance(exception, AuthorizationError):
            return status.HTTP_403_FORBIDDEN
        elif isinstance(exception, ValidationError):
            return status.HTTP_400_BAD_REQUEST
        elif isinstance(exception, RateLimitExceededError):
            return status.HTTP_429_TOO_MANY_REQUESTS
        elif isinstance(exception, (TokenError, SessionError)):
            return status.HTTP_401_UNAUTHORIZED
        elif isinstance(exception, SecurityError):
            return status.HTTP_403_FORBIDDEN
        elif isinstance(exception, ConfigurationError):
            return status.HTTP_500_INTERNAL_SERVER_ERROR
        else:
            return status.HTTP_400_BAD_REQUEST
    
    def _get_client_ip(self, request) -> str:
        """
        Get client IP address from request.
        
        Args:
            request: Django HttpRequest object
            
        Returns:
            Client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip


def handle_error_response(
    error_code: str,
    message: str,
    status_code: int = status.HTTP_400_BAD_REQUEST,
    details: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None
) -> JsonResponse:
    """
    Create a standardized error response.
    
    Args:
        error_code: Machine-readable error code
        message: Human-readable error message
        status_code: HTTP status code
        details: Additional error details
        correlation_id: Request correlation ID
        
    Returns:
        JsonResponse with standardized error format
    """
    error_data = {
        'error': {
            'code': error_code,
            'message': message,
        }
    }
    
    if details:
        error_data['error']['details'] = details
    
    if correlation_id:
        error_data['error']['correlation_id'] = correlation_id
    
    return JsonResponse(error_data, status=status_code)


def log_security_event(
    event_type: str,
    message: str,
    request=None,
    user=None,
    additional_data: Optional[Dict[str, Any]] = None
):
    """
    Log security-related events with standardized format.
    
    Args:
        event_type: Type of security event
        message: Event description
        request: Django HttpRequest object (optional)
        user: User object (optional)
        additional_data: Additional event data
    """
    correlation_id = get_correlation_id()
    
    log_data = {
        'event_type': event_type,
        'correlation_id': correlation_id,
        'additional_data': additional_data or {},
    }
    
    if request:
        log_data.update({
            'ip_address': ErrorHandlingMiddleware()._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'path': request.path,
            'method': request.method,
        })
    
    if user:
        log_data['user_id'] = getattr(user, 'id', None)
        log_data['username'] = getattr(user, 'username', None)
    
    logger.warning(f"Security event: {message}", extra=log_data)