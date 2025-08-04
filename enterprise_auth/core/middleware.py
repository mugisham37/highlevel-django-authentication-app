"""
Custom middleware for the enterprise authentication system.
"""

import time
import uuid
from typing import Callable
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from .logging import set_correlation_id, clear_correlation_id, get_correlation_id


class CorrelationIdMiddleware(MiddlewareMixin):
    """
    Middleware to add correlation ID to each request for distributed tracing.
    """
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Add correlation ID to the request and set it in thread local storage.
        """
        # Check if correlation ID is provided in headers
        correlation_id = request.META.get('HTTP_X_CORRELATION_ID')
        
        if not correlation_id:
            # Generate new correlation ID if not provided
            correlation_id = str(uuid.uuid4())
        
        # Set correlation ID in thread local storage
        set_correlation_id(correlation_id)
        
        # Add correlation ID to request for easy access
        request.correlation_id = correlation_id
        
        # Add request start time for performance monitoring
        request.start_time = time.time()
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add correlation ID to response headers and clean up thread local storage.
        """
        # Add correlation ID to response headers
        if hasattr(request, 'correlation_id'):
            response['X-Correlation-ID'] = request.correlation_id
        
        # Add response time header for monitoring
        if hasattr(request, 'start_time'):
            response_time = time.time() - request.start_time
            response['X-Response-Time'] = f"{response_time:.3f}s"
        
        # Clear correlation ID from thread local storage
        clear_correlation_id()
        
        return response


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to responses.
    """
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Add security headers to the response.
        """
        # Content Security Policy
        if not response.get('Content-Security-Policy'):
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' https:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
            response['Content-Security-Policy'] = csp
        
        # Additional security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=(), '
            'payment=(), usb=(), magnetometer=(), gyroscope=()'
        )
        
        return response


class RateLimitMiddleware(MiddlewareMixin):
    """
    Basic rate limiting middleware (will be enhanced in later tasks).
    """
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Check rate limits for the request.
        """
        # Skip rate limiting if disabled
        if not getattr(settings, 'RATE_LIMIT_ENABLE', True):
            return None
        
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Add IP address to request for use by other components
        request.client_ip = ip_address
        
        # Rate limiting logic will be implemented in later tasks
        # For now, just add the IP to the request
        return None
    
    def get_client_ip(self, request: HttpRequest) -> str:
        """
        Get the client IP address from the request.
        """
        # Check for IP in forwarded headers (for load balancers/proxies)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Take the first IP in the chain
            ip = x_forwarded_for.split(',')[0].strip()
            return ip
        
        # Check for real IP header
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            return x_real_ip
        
        # Fall back to remote address
        return request.META.get('REMOTE_ADDR', '127.0.0.1')


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log HTTP requests for monitoring and debugging.
    """
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Log incoming request details.
        """
        import structlog
        
        logger = structlog.get_logger('enterprise_auth.requests')
        
        # Skip logging for health checks and static files
        if self.should_skip_logging(request):
            return None
        
        logger.info(
            "request_started",
            method=request.method,
            path=request.path,
            query_params=dict(request.GET),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            ip_address=getattr(request, 'client_ip', request.META.get('REMOTE_ADDR')),
            user_id=str(request.user.id) if request.user.is_authenticated else None,
            correlation_id=get_correlation_id()
        )
        
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """
        Log response details.
        """
        import structlog
        
        logger = structlog.get_logger('enterprise_auth.requests')
        
        # Skip logging for health checks and static files
        if self.should_skip_logging(request):
            return response
        
        # Calculate response time
        response_time = None
        if hasattr(request, 'start_time'):
            response_time = time.time() - request.start_time
        
        logger.info(
            "request_completed",
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            response_time=response_time,
            user_id=str(request.user.id) if request.user.is_authenticated else None,
            correlation_id=get_correlation_id()
        )
        
        return response
    
    def should_skip_logging(self, request: HttpRequest) -> bool:
        """
        Determine if request logging should be skipped.
        """
        skip_paths = [
            '/health/',
            '/metrics/',
            '/static/',
            '/media/',
            '/favicon.ico',
        ]
        
        return any(request.path.startswith(path) for path in skip_paths)


class ExceptionHandlingMiddleware(MiddlewareMixin):
    """
    Middleware to handle exceptions and provide structured error responses.
    """
    
    def process_exception(self, request: HttpRequest, exception: Exception) -> None:
        """
        Log exceptions and provide structured error information.
        """
        import structlog
        from django.http import JsonResponse
        
        logger = structlog.get_logger('enterprise_auth.exceptions')
        
        # Log the exception with context
        logger.error(
            "unhandled_exception",
            exception_type=type(exception).__name__,
            exception_message=str(exception),
            path=request.path,
            method=request.method,
            user_id=str(request.user.id) if request.user.is_authenticated else None,
            ip_address=getattr(request, 'client_ip', request.META.get('REMOTE_ADDR')),
            correlation_id=get_correlation_id(),
            exc_info=True
        )
        
        # In production, don't expose internal error details
        if not settings.DEBUG:
            return JsonResponse({
                'error': {
                    'code': 'INTERNAL_SERVER_ERROR',
                    'message': 'An internal server error occurred',
                    'correlation_id': get_correlation_id(),
                }
            }, status=500)
        
        # In development, let Django handle the exception normally
        return None