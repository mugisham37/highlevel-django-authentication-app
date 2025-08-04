"""
Correlation ID utilities for request tracking.

This module provides utilities for generating and managing correlation IDs
that can be used to track requests across the entire system for debugging
and monitoring purposes.
"""

import uuid
import threading
from typing import Optional

from django.utils.deprecation import MiddlewareMixin


# Thread-local storage for correlation ID
_correlation_context = threading.local()


class CorrelationIDMiddleware(MiddlewareMixin):
    """
    Middleware to generate and manage correlation IDs for each request.
    
    This middleware:
    1. Generates a unique correlation ID for each request
    2. Stores it in thread-local storage for easy access
    3. Adds it to the response headers
    4. Makes it available to logging and other components
    """
    
    CORRELATION_ID_HEADER = 'X-Correlation-ID'
    REQUEST_ID_HEADER = 'X-Request-ID'
    
    def process_request(self, request):
        """
        Process incoming request and set up correlation ID.
        
        Args:
            request: Django HttpRequest object
        """
        # Check if correlation ID is provided in headers (for distributed tracing)
        correlation_id = (
            request.META.get(f'HTTP_{self.CORRELATION_ID_HEADER.upper().replace("-", "_")}') or
            request.META.get(f'HTTP_{self.REQUEST_ID_HEADER.upper().replace("-", "_")}') or
            self._generate_correlation_id()
        )
        
        # Store correlation ID in request and thread-local storage
        request.correlation_id = correlation_id
        set_correlation_id(correlation_id)
        
        # Add correlation ID to request META for logging
        request.META['CORRELATION_ID'] = correlation_id
    
    def process_response(self, request, response):
        """
        Process response and add correlation ID to headers.
        
        Args:
            request: Django HttpRequest object
            response: Django HttpResponse object
            
        Returns:
            Modified response with correlation ID header
        """
        correlation_id = getattr(request, 'correlation_id', None)
        if correlation_id:
            response[self.CORRELATION_ID_HEADER] = correlation_id
            response[self.REQUEST_ID_HEADER] = correlation_id
        
        # Clean up thread-local storage
        clear_correlation_id()
        
        return response
    
    def process_exception(self, request, exception):
        """
        Process exceptions and ensure correlation ID is available for error tracking.
        
        Args:
            request: Django HttpRequest object
            exception: Exception that occurred
        """
        # Ensure correlation ID is available for exception handling
        correlation_id = getattr(request, 'correlation_id', None)
        if correlation_id:
            # Add correlation ID to exception for error tracking
            if hasattr(exception, '__dict__'):
                exception.correlation_id = correlation_id
    
    @staticmethod
    def _generate_correlation_id() -> str:
        """
        Generate a new correlation ID.
        
        Returns:
            UUID-based correlation ID as string
        """
        return str(uuid.uuid4())


def get_correlation_id() -> Optional[str]:
    """
    Get the current correlation ID from thread-local storage.
    
    Returns:
        Current correlation ID or None if not set
    """
    return getattr(_correlation_context, 'correlation_id', None)


def set_correlation_id(correlation_id: str) -> None:
    """
    Set the correlation ID in thread-local storage.
    
    Args:
        correlation_id: Correlation ID to set
    """
    _correlation_context.correlation_id = correlation_id


def clear_correlation_id() -> None:
    """
    Clear the correlation ID from thread-local storage.
    """
    if hasattr(_correlation_context, 'correlation_id'):
        delattr(_correlation_context, 'correlation_id')


def generate_correlation_id() -> str:
    """
    Generate a new correlation ID.
    
    Returns:
        New UUID-based correlation ID
    """
    return str(uuid.uuid4())


class CorrelationIDFilter:
    """
    Logging filter to add correlation ID to log records.
    
    This filter adds the current correlation ID to all log records,
    making it easy to trace requests across log entries.
    """
    
    def filter(self, record):
        """
        Add correlation ID to log record.
        
        Args:
            record: LogRecord to modify
            
        Returns:
            True to allow the record to be processed
        """
        correlation_id = get_correlation_id()
        record.correlation_id = correlation_id or 'no-correlation-id'
        return True


def with_correlation_id(func):
    """
    Decorator to ensure a function has a correlation ID.
    
    If no correlation ID is set, generates a new one for the duration
    of the function call.
    
    Args:
        func: Function to decorate
        
    Returns:
        Decorated function
    """
    def wrapper(*args, **kwargs):
        existing_id = get_correlation_id()
        if not existing_id:
            # Generate temporary correlation ID
            temp_id = generate_correlation_id()
            set_correlation_id(temp_id)
            try:
                return func(*args, **kwargs)
            finally:
                clear_correlation_id()
        else:
            return func(*args, **kwargs)
    
    return wrapper


class CorrelationContext:
    """
    Context manager for setting correlation ID within a specific scope.
    
    Usage:
        with CorrelationContext('my-correlation-id'):
            # Code here will have access to the correlation ID
            pass
    """
    
    def __init__(self, correlation_id: Optional[str] = None):
        """
        Initialize correlation context.
        
        Args:
            correlation_id: Correlation ID to use. If None, generates new one.
        """
        self.correlation_id = correlation_id or generate_correlation_id()
        self.previous_id = None
    
    def __enter__(self):
        """
        Enter the context and set correlation ID.
        
        Returns:
            The correlation ID being used
        """
        self.previous_id = get_correlation_id()
        set_correlation_id(self.correlation_id)
        return self.correlation_id
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit the context and restore previous correlation ID.
        """
        if self.previous_id:
            set_correlation_id(self.previous_id)
        else:
            clear_correlation_id()