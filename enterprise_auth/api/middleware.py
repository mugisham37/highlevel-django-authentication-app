"""
API Middleware

Security and monitoring middleware for API requests.
"""
import time
import uuid
import json
import logging
from typing import Callable, Optional
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

from .models import APIRequestLog
from enterprise_auth.core.services.rate_limiting import RateLimitingService
from enterprise_auth.core.exceptions import RateLimitExceededError

logger = logging.getLogger(__name__)


class APISecurityMiddleware(MiddlewareMixin):
    """
    Security middleware for API requests.
    
    Handles CORS, security headers, and request validation.
    """
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process incoming API requests."""
        # Skip non-API requests
        if not request.path.startswith('/api/'):
            return None
        
        # Add security headers
        self.add_security_headers(request)
        
        # Validate request size
        if self.is_request_too_large(request):
            return JsonResponse({
                'error': {
                    'code': 'REQUEST_TOO_LARGE',
                    'message': 'Request payload too large',
                    'max_size': settings.DATA_UPLOAD_MAX_MEMORY_SIZE
                }
            }, status=413)
        
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Process API responses."""
        # Skip non-API requests
        if not request.path.startswith('/api/'):
            return response
        
        # Add CORS headers
        self.add_cors_headers(request, response)
        
        # Add security headers to response
        self.add_response_security_headers(response)
        
        return response

    def add_security_headers(self, request: HttpRequest):
        """Add security headers to request context."""
        # Generate request ID if not present
        if not hasattr(request, 'request_id'):
            request.request_id = str(uuid.uuid4())
        
        # Add to request META for logging
        request.META['HTTP_X_REQUEST_ID'] = request.request_id

    def add_cors_headers(self, request: HttpRequest, response: HttpResponse):
        """Add CORS headers to response."""
        # Allow specific origins in production
        allowed_origins = getattr(settings, 'CORS_ALLOWED_ORIGINS', ['*'])
        origin = request.META.get('HTTP_ORIGIN')
        
        if origin and (origin in allowed_origins or '*' in allowed_origins):
            response['Access-Control-Allow-Origin'] = origin
        
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = (
            'Accept, Accept-Language, Authorization, Content-Type, '
            'X-API-Key, X-Request-ID, X-Requested-With'
        )
        response['Access-Control-Expose-Headers'] = 'X-Request-ID, X-Rate-Limit-Remaining'
        response['Access-Control-Max-Age'] = '86400'  # 24 hours

    def add_response_security_headers(self, response: HttpResponse):
        """Add security headers to response."""
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add CSP for API responses
        response['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none';"

    def is_request_too_large(self, request: HttpRequest) -> bool:
        """Check if request payload is too large."""
        content_length = request.META.get('CONTENT_LENGTH')
        if content_length:
            try:
                size = int(content_length)
                max_size = getattr(settings, 'DATA_UPLOAD_MAX_MEMORY_SIZE', 2621440)  # 2.5MB
                return size > max_size
            except (ValueError, TypeError):
                pass
        return False


class APILoggingMiddleware(MiddlewareMixin):
    """
    Middleware for logging API requests and responses.
    
    Tracks performance, errors, and usage analytics.
    """
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Start request timing and logging."""
        # Skip non-API requests
        if not request.path.startswith('/api/'):
            return None
        
        # Record request start time
        request._api_start_time = time.time()
        
        # Extract request information
        request._api_log_data = {
            'request_id': getattr(request, 'request_id', str(uuid.uuid4())),
            'method': request.method,
            'path': request.path,
            'query_params': dict(request.GET),
            'headers': self.extract_safe_headers(request),
            'body_size': len(request.body) if hasattr(request, 'body') else 0,
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }
        
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Log completed API request."""
        # Skip non-API requests
        if not request.path.startswith('/api/') or not hasattr(request, '_api_start_time'):
            return response
        
        # Calculate response time
        response_time_ms = int((time.time() - request._api_start_time) * 1000)
        
        # Add rate limit headers
        self.add_rate_limit_headers(request, response)
        
        # Log the request asynchronously
        self.log_api_request(request, response, response_time_ms)
        
        return response

    def process_exception(self, request: HttpRequest, exception: Exception) -> Optional[HttpResponse]:
        """Log API request exceptions."""
        if not request.path.startswith('/api/') or not hasattr(request, '_api_start_time'):
            return None
        
        # Calculate response time
        response_time_ms = int((time.time() - request._api_start_time) * 1000)
        
        # Log the exception
        self.log_api_exception(request, exception, response_time_ms)
        
        return None

    def extract_safe_headers(self, request: HttpRequest) -> dict:
        """Extract safe headers for logging (excluding sensitive data)."""
        safe_headers = {}
        sensitive_headers = {
            'HTTP_AUTHORIZATION', 'HTTP_X_API_KEY', 'HTTP_COOKIE',
            'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP'
        }
        
        for key, value in request.META.items():
            if key.startswith('HTTP_') and key not in sensitive_headers:
                header_name = key[5:].replace('_', '-').title()
                safe_headers[header_name] = value
        
        return safe_headers

    def get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address."""
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.META.get('HTTP_X_REAL_IP')
        if real_ip:
            return real_ip
        
        return request.META.get('REMOTE_ADDR', '127.0.0.1')

    def add_rate_limit_headers(self, request: HttpRequest, response: HttpResponse):
        """Add rate limiting headers to response."""
        # Add request ID header
        if hasattr(request, 'request_id'):
            response['X-Request-ID'] = request.request_id
        
        # Add rate limit information if available
        if hasattr(request, 'api_key'):
            api_key = request.api_key
            rate_limiter = RateLimitingService()
            
            # Get remaining requests for minute limit
            minute_key = f"api_key_rate_limit:minute:{api_key.key_id}"
            remaining = rate_limiter.get_remaining_attempts(
                minute_key, api_key.rate_limit_per_minute, 60
            )
            response['X-Rate-Limit-Remaining'] = str(remaining)
            response['X-Rate-Limit-Limit'] = str(api_key.rate_limit_per_minute)

    def log_api_request(self, request: HttpRequest, response: HttpResponse, response_time_ms: int):
        """Log API request asynchronously."""
        try:
            from enterprise_auth.api.tasks import log_api_request_async
            
            log_data = request._api_log_data.copy()
            log_data.update({
                'status_code': response.status_code,
                'response_size': len(response.content) if hasattr(response, 'content') else 0,
                'response_time_ms': response_time_ms,
                'api_key_id': getattr(request, 'api_key', None) and request.api_key.id,
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
            })
            
            # Queue for async logging
            log_api_request_async.delay(log_data)
            
        except Exception as e:
            logger.error(f"Failed to queue API request log: {str(e)}")

    def log_api_exception(self, request: HttpRequest, exception: Exception, response_time_ms: int):
        """Log API request exception."""
        try:
            from enterprise_auth.api.tasks import log_api_request_async
            
            log_data = request._api_log_data.copy()
            log_data.update({
                'status_code': 500,
                'response_size': 0,
                'response_time_ms': response_time_ms,
                'error_type': exception.__class__.__name__,
                'error_message': str(exception),
                'api_key_id': getattr(request, 'api_key', None) and request.api_key.id,
                'user_id': request.user.id if hasattr(request, 'user') and request.user.is_authenticated else None,
            })
            
            # Queue for async logging
            log_api_request_async.delay(log_data)
            
        except Exception as e:
            logger.error(f"Failed to queue API exception log: {str(e)}")


class APIRateLimitMiddleware(MiddlewareMixin):
    """
    Rate limiting middleware for API endpoints.
    
    Implements global rate limiting in addition to API key specific limits.
    """
    
    def __init__(self, get_response: Callable):
        super().__init__(get_response)
        self.rate_limiter = RateLimitingService()

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Apply rate limiting to API requests."""
        # Skip non-API requests
        if not request.path.startswith('/api/'):
            return None
        
        # Skip rate limiting for health checks
        if request.path in ['/api/health/', '/api/ready/']:
            return None
        
        try:
            # Apply global IP-based rate limiting
            self.apply_global_rate_limiting(request)
            
            # Apply endpoint-specific rate limiting
            self.apply_endpoint_rate_limiting(request)
            
        except RateLimitExceededError as e:
            return JsonResponse({
                'error': {
                    'code': 'RATE_LIMIT_EXCEEDED',
                    'message': str(e),
                    'retry_after': getattr(e, 'retry_after', 60)
                }
            }, status=429)
        
        return None

    def apply_global_rate_limiting(self, request: HttpRequest):
        """Apply global rate limiting based on IP address."""
        client_ip = self.get_client_ip(request)
        
        # Global limits per IP
        minute_key = f"global_rate_limit:minute:{client_ip}"
        if not self.rate_limiter.check_rate_limit(minute_key, 100, 60):
            raise RateLimitExceededError("Global rate limit exceeded (100 requests per minute)")
        
        hour_key = f"global_rate_limit:hour:{client_ip}"
        if not self.rate_limiter.check_rate_limit(hour_key, 1000, 3600):
            raise RateLimitExceededError("Global rate limit exceeded (1000 requests per hour)")

    def apply_endpoint_rate_limiting(self, request: HttpRequest):
        """Apply endpoint-specific rate limiting."""
        client_ip = self.get_client_ip(request)
        endpoint = self.get_endpoint_key(request)
        
        # Endpoint-specific limits
        endpoint_key = f"endpoint_rate_limit:{endpoint}:{client_ip}"
        
        # Different limits for different endpoint types
        if endpoint.startswith('auth'):
            # Stricter limits for authentication endpoints
            if not self.rate_limiter.check_rate_limit(endpoint_key, 10, 60):
                raise RateLimitExceededError("Authentication endpoint rate limit exceeded")
        elif endpoint.startswith('admin'):
            # Moderate limits for admin endpoints
            if not self.rate_limiter.check_rate_limit(endpoint_key, 30, 60):
                raise RateLimitExceededError("Admin endpoint rate limit exceeded")
        else:
            # Standard limits for other endpoints
            if not self.rate_limiter.check_rate_limit(endpoint_key, 60, 60):
                raise RateLimitExceededError("Endpoint rate limit exceeded")

    def get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address."""
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.META.get('HTTP_X_REAL_IP')
        if real_ip:
            return real_ip
        
        return request.META.get('REMOTE_ADDR', '127.0.0.1')

    def get_endpoint_key(self, request: HttpRequest) -> str:
        """Generate endpoint key for rate limiting."""
        # Remove /api/v1/ prefix and extract base endpoint
        path = request.path.replace('/api/v1/', '').strip('/')
        parts = path.split('/')
        
        if len(parts) > 0:
            return parts[0]
        
        return 'unknown'


class APIVersioningMiddleware(MiddlewareMixin):
    """
    API versioning middleware.
    
    Handles API version detection and routing.
    """
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """Process API version from request."""
        # Skip non-API requests
        if not request.path.startswith('/api/'):
            return None
        
        # Extract version from URL
        version = self.extract_version_from_path(request.path)
        if not version:
            # Check Accept header for version
            version = self.extract_version_from_header(request)
        
        # Set default version if none specified
        if not version:
            version = 'v1'
        
        # Validate version
        if not self.is_version_supported(version):
            return JsonResponse({
                'error': {
                    'code': 'UNSUPPORTED_API_VERSION',
                    'message': f'API version {version} is not supported',
                    'supported_versions': self.get_supported_versions()
                }
            }, status=400)
        
        # Check if version is deprecated
        if self.is_version_deprecated(version):
            # Add deprecation warning header
            request._api_version_deprecated = True
        
        # Store version in request
        request.api_version = version
        
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Add version headers to response."""
        if not request.path.startswith('/api/'):
            return response
        
        # Add API version header
        if hasattr(request, 'api_version'):
            response['X-API-Version'] = request.api_version
        
        # Add deprecation warning if applicable
        if getattr(request, '_api_version_deprecated', False):
            response['X-API-Deprecated'] = 'true'
            response['X-API-Sunset'] = '2024-12-31'  # Example sunset date
        
        return response

    def extract_version_from_path(self, path: str) -> Optional[str]:
        """Extract API version from URL path."""
        parts = path.strip('/').split('/')
        if len(parts) >= 2 and parts[0] == 'api' and parts[1].startswith('v'):
            return parts[1]
        return None

    def extract_version_from_header(self, request: HttpRequest) -> Optional[str]:
        """Extract API version from Accept header."""
        accept_header = request.META.get('HTTP_ACCEPT', '')
        if 'application/vnd.enterpriseauth.v' in accept_header:
            # Extract version from custom media type
            import re
            match = re.search(r'application/vnd\.enterpriseauth\.v(\d+)', accept_header)
            if match:
                return f"v{match.group(1)}"
        return None

    def get_supported_versions(self) -> list:
        """Get list of supported API versions."""
        return ['v1']

    def is_version_supported(self, version: str) -> bool:
        """Check if API version is supported."""
        return version in self.get_supported_versions()

    def is_version_deprecated(self, version: str) -> bool:
        """Check if API version is deprecated."""
        deprecated_versions = []  # Add deprecated versions here
        return version in deprecated_versions