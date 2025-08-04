"""
Response utilities for enterprise authentication system.

This module provides utilities for creating consistent API responses
with proper error handling and success formatting.
"""

from typing import Any, Dict, Optional
from rest_framework import status
from rest_framework.response import Response
from django.utils import timezone


def success_response(
    data: Any = None,
    message: str = "Success",
    status_code: int = status.HTTP_200_OK,
    extra_data: Optional[Dict[str, Any]] = None
) -> Response:
    """
    Create a standardized success response.
    
    Args:
        data: Response data
        message: Success message
        status_code: HTTP status code
        extra_data: Additional data to include in response
        
    Returns:
        DRF Response object
    """
    response_data = {
        'success': True,
        'message': message,
        'timestamp': timezone.now().isoformat(),
    }
    
    if data is not None:
        response_data['data'] = data
    
    if extra_data:
        response_data.update(extra_data)
    
    return Response(response_data, status=status_code)


def error_response(
    message: str = "An error occurred",
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    status_code: int = status.HTTP_400_BAD_REQUEST,
    correlation_id: Optional[str] = None
) -> Response:
    """
    Create a standardized error response.
    
    Args:
        message: Error message
        error_code: Machine-readable error code
        details: Additional error details
        status_code: HTTP status code
        correlation_id: Request correlation ID
        
    Returns:
        DRF Response object
    """
    response_data = {
        'success': False,
        'error': {
            'message': message,
            'code': error_code or 'UNKNOWN_ERROR',
        },
        'timestamp': timezone.now().isoformat(),
    }
    
    if details:
        response_data['error']['details'] = details
    
    if correlation_id:
        response_data['error']['correlation_id'] = correlation_id
    
    return Response(response_data, status=status_code)


def validation_error_response(
    validation_errors: Dict[str, Any],
    message: str = "Validation failed",
    status_code: int = status.HTTP_400_BAD_REQUEST
) -> Response:
    """
    Create a standardized validation error response.
    
    Args:
        validation_errors: Dictionary of field validation errors
        message: Error message
        status_code: HTTP status code
        
    Returns:
        DRF Response object
    """
    return error_response(
        message=message,
        error_code="VALIDATION_ERROR",
        details={'validation_errors': validation_errors},
        status_code=status_code
    )


def paginated_response(
    data: Any,
    page: int,
    page_size: int,
    total_count: int,
    message: str = "Success"
) -> Response:
    """
    Create a standardized paginated response.
    
    Args:
        data: Response data
        page: Current page number
        page_size: Number of items per page
        total_count: Total number of items
        message: Success message
        
    Returns:
        DRF Response object
    """
    total_pages = (total_count + page_size - 1) // page_size
    has_next = page < total_pages
    has_previous = page > 1
    
    pagination_data = {
        'page': page,
        'page_size': page_size,
        'total_count': total_count,
        'total_pages': total_pages,
        'has_next': has_next,
        'has_previous': has_previous,
    }
    
    return success_response(
        data=data,
        message=message,
        extra_data={'pagination': pagination_data}
    )


def created_response(
    data: Any = None,
    message: str = "Resource created successfully",
    location: Optional[str] = None
) -> Response:
    """
    Create a standardized created response.
    
    Args:
        data: Response data
        message: Success message
        location: Location header value
        
    Returns:
        DRF Response object
    """
    response = success_response(
        data=data,
        message=message,
        status_code=status.HTTP_201_CREATED
    )
    
    if location:
        response['Location'] = location
    
    return response


def no_content_response(message: str = "Operation completed successfully") -> Response:
    """
    Create a standardized no content response.
    
    Args:
        message: Success message
        
    Returns:
        DRF Response object
    """
    return success_response(
        message=message,
        status_code=status.HTTP_204_NO_CONTENT
    )


def unauthorized_response(
    message: str = "Authentication required",
    error_code: str = "AUTHENTICATION_REQUIRED"
) -> Response:
    """
    Create a standardized unauthorized response.
    
    Args:
        message: Error message
        error_code: Machine-readable error code
        
    Returns:
        DRF Response object
    """
    return error_response(
        message=message,
        error_code=error_code,
        status_code=status.HTTP_401_UNAUTHORIZED
    )


def forbidden_response(
    message: str = "Access denied",
    error_code: str = "ACCESS_DENIED"
) -> Response:
    """
    Create a standardized forbidden response.
    
    Args:
        message: Error message
        error_code: Machine-readable error code
        
    Returns:
        DRF Response object
    """
    return error_response(
        message=message,
        error_code=error_code,
        status_code=status.HTTP_403_FORBIDDEN
    )


def not_found_response(
    message: str = "Resource not found",
    error_code: str = "RESOURCE_NOT_FOUND"
) -> Response:
    """
    Create a standardized not found response.
    
    Args:
        message: Error message
        error_code: Machine-readable error code
        
    Returns:
        DRF Response object
    """
    return error_response(
        message=message,
        error_code=error_code,
        status_code=status.HTTP_404_NOT_FOUND
    )


def rate_limit_response(
    message: str = "Rate limit exceeded",
    retry_after: Optional[int] = None
) -> Response:
    """
    Create a standardized rate limit response.
    
    Args:
        message: Error message
        retry_after: Seconds to wait before retrying
        
    Returns:
        DRF Response object
    """
    details = {}
    if retry_after:
        details['retry_after'] = retry_after
    
    response = error_response(
        message=message,
        error_code="RATE_LIMIT_EXCEEDED",
        details=details,
        status_code=status.HTTP_429_TOO_MANY_REQUESTS
    )
    
    if retry_after:
        response['Retry-After'] = str(retry_after)
    
    return response


def server_error_response(
    message: str = "Internal server error",
    error_code: str = "INTERNAL_SERVER_ERROR",
    correlation_id: Optional[str] = None
) -> Response:
    """
    Create a standardized server error response.
    
    Args:
        message: Error message
        error_code: Machine-readable error code
        correlation_id: Request correlation ID
        
    Returns:
        DRF Response object
    """
    return error_response(
        message=message,
        error_code=error_code,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        correlation_id=correlation_id
    )