"""
JWT Token Validation Middleware for Enterprise Authentication System.

This middleware provides performance-optimized JWT token validation
for all incoming requests, with caching and efficient token processing.
"""

import time
import logging
from typing import Optional, Callable
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import caches
from django.contrib.auth import get_user_model

from ..services.jwt_service import jwt_service, TokenStatus
from ..utils.request_utils import create_device_fingerprint
from ..logging import get_correlation_id

logger = logging.getLogger(__name__)
User = get_user_model()


class JWTTokenValidationMiddleware(MiddlewareMixin):
    """
    Performance-optimized JWT token validation middleware.
    
    This middleware validates JWT tokens for all incoming requests,
    with intelligent caching and performance optimizations to maintain
    sub-100ms response times.
    
    Features:
    - Cached token validation results
    - Device fingerprint validation
    - Automatic token blacklist checking
    - Performance monitoring and metrics
    - Configurable path exclusions
    """
    
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        """Initialize the middleware with configuration."""
        super().__init__(get_response)
        self.cache = caches['default']
        self.cache_timeout = getattr(settings, 'JWT_VALIDATION_CACHE_TIMEOUT', 300)  # 5 minutes
        
        # Paths that should skip JWT validation
        self.excluded_paths = getattr(settings, 'JWT_VALIDATION_EXCLUDED_PATHS', [
            '/health/',
            '/metrics/',
            '/static/',
            '/media/',
            '/admin/',
            '/api/v1/core/auth/login/',
            '/api/v1/core/auth/register/',
            '/api/v1/core/auth/introspect/',
            '/api/v1/core/auth/password/reset/',
            '/api/v1/core/health/',
        ])
        
        # Enable/disable middleware
        self.enabled = getattr(settings, 'JWT_VALIDATION_MIDDLEWARE_ENABLED', True)
        
        # Performance monitoring
        self.enable_metrics = getattr(settings, 'JWT_VALIDATION_METRICS_ENABLED', True)
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request and validate JWT token if present.
        
        Args:
            request: Django HTTP request
            
        Returns:
            None if validation passes, HttpResponse with error if validation fails
        """
        # Skip if middleware is disabled
        if not self.enabled:
            return None
        
        # Skip validation for excluded paths
        if self.should_skip_validation(request):
            return None
        
        # Start performance timing
        start_time = time.time()
        
        try:
            # Extract JWT token from request
            token = self.extract_token_from_request(request)
            
            if not token:
                # No token present - let other authentication methods handle it
                return None
            
            # Validate token with caching
            validation_result = self.validate_token_with_cache(request, token)
            
            if not validation_result:
                return self.create_error_response(
                    'INVALID_TOKEN',
                    'Invalid or expired token',
                    401
                )
            
            user, claims = validation_result
            
            # Attach user and token claims to request
            request.user = user
            request.jwt_claims = claims
            request.jwt_validated = True
            
            # Log successful validation
            self.log_validation_success(request, user, claims, start_time)
            
            return None
            
        except Exception as e:
            # Log validation error
            self.log_validation_error(request, str(e), start_time)
            
            return self.create_error_response(
                'TOKEN_VALIDATION_ERROR',
                'Token validation failed',
                401
            )
    
    def should_skip_validation(self, request: HttpRequest) -> bool:
        """
        Determine if JWT validation should be skipped for this request.
        
        Args:
            request: Django HTTP request
            
        Returns:
            True if validation should be skipped
        """
        # Check excluded paths
        for excluded_path in self.excluded_paths:
            if request.path.startswith(excluded_path):
                return True
        
        # Skip for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return True
        
        return False
    
    def extract_token_from_request(self, request: HttpRequest) -> Optional[str]:
        """
        Extract JWT token from request headers.
        
        Args:
            request: Django HTTP request
            
        Returns:
            JWT token string or None if not found
        """
        # Check Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                return parts[1]
        
        # Check for token in query parameters (for WebSocket or special cases)
        token = request.GET.get('token')
        if token:
            return token
        
        # Check for token in custom header
        token = request.META.get('HTTP_X_AUTH_TOKEN')
        if token:
            return token
        
        return None
    
    def validate_token_with_cache(self, request: HttpRequest, token: str) -> Optional[tuple]:
        """
        Validate JWT token with intelligent caching.
        
        Args:
            request: Django HTTP request
            token: JWT token string
            
        Returns:
            Tuple of (user, claims) if valid, None otherwise
        """
        # Create cache key based on token and device fingerprint
        device_fingerprint = create_device_fingerprint(request)
        cache_key = f"jwt_validation:{hash(token)}:{hash(device_fingerprint)}"
        
        # Try to get cached validation result
        cached_result = self.cache.get(cache_key)
        if cached_result:
            user_id, claims_dict = cached_result
            
            # Get user from cache or database
            user = self.get_user_from_cache(user_id)
            if user:
                # Reconstruct claims object
                from ..services.jwt_service import TokenClaims
                claims = TokenClaims.from_dict(claims_dict)
                
                # Log cache hit
                logger.debug(f"JWT validation cache hit for token {token[:8]}...")
                
                return (user, claims)
        
        # Cache miss - validate token using JWT service
        validation_result = jwt_service.validate_access_token(token, device_fingerprint)
        
        if not validation_result.is_valid:
            # Cache negative result for a short time to prevent repeated validation
            self.cache.set(f"jwt_invalid:{hash(token)}", True, 60)  # 1 minute
            return None
        
        # Get user from database
        try:
            user = User.objects.get(id=validation_result.claims.user_id)
        except User.DoesNotExist:
            return None
        
        # Check if user is active and not locked
        if not user.is_active:
            return None
        
        if hasattr(user, 'is_account_locked') and user.is_account_locked:
            return None
        
        # Cache successful validation result
        cache_data = (str(user.id), validation_result.claims.to_dict())
        self.cache.set(cache_key, cache_data, self.cache_timeout)
        
        # Cache user data separately for faster lookups
        self.cache_user_data(user)
        
        logger.debug(f"JWT validation cache miss for token {token[:8]}...")
        
        return (user, validation_result.claims)
    
    def get_user_from_cache(self, user_id: str) -> Optional[User]:
        """
        Get user from cache or database with caching.
        
        Args:
            user_id: User ID string
            
        Returns:
            User instance or None
        """
        cache_key = f"user_data:{user_id}"
        cached_user_data = self.cache.get(cache_key)
        
        if cached_user_data:
            # Reconstruct user object from cached data
            try:
                user = User(**cached_user_data)
                user.id = user_id  # Ensure ID is set correctly
                return user
            except Exception:
                # If reconstruction fails, fall back to database
                pass
        
        # Get from database and cache
        try:
            user = User.objects.get(id=user_id)
            self.cache_user_data(user)
            return user
        except User.DoesNotExist:
            return None
    
    def cache_user_data(self, user: User) -> None:
        """
        Cache user data for faster lookups.
        
        Args:
            user: User instance to cache
        """
        cache_key = f"user_data:{user.id}"
        user_data = {
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_active': user.is_active,
            'is_email_verified': getattr(user, 'is_email_verified', False),
            'date_joined': user.date_joined.isoformat() if user.date_joined else None,
        }
        
        # Cache user data for 10 minutes
        self.cache.set(cache_key, user_data, 600)
    
    def create_error_response(self, error_code: str, message: str, status_code: int) -> JsonResponse:
        """
        Create standardized error response.
        
        Args:
            error_code: Error code string
            message: Error message
            status_code: HTTP status code
            
        Returns:
            JsonResponse with error details
        """
        return JsonResponse({
            'error': {
                'code': error_code,
                'message': message,
                'correlation_id': get_correlation_id(),
                'timestamp': time.time(),
            }
        }, status=status_code)
    
    def log_validation_success(self, request: HttpRequest, user: User, claims, start_time: float) -> None:
        """
        Log successful token validation.
        
        Args:
            request: Django HTTP request
            user: Authenticated user
            claims: JWT token claims
            start_time: Validation start time
        """
        if not self.enable_metrics:
            return
        
        validation_time = time.time() - start_time
        
        logger.info(
            "jwt_validation_success",
            user_id=str(user.id),
            user_email=user.email,
            token_id=claims.token_id[:8],
            device_id=claims.device_id[:8],
            validation_time_ms=round(validation_time * 1000, 2),
            path=request.path,
            method=request.method,
            correlation_id=get_correlation_id()
        )
        
        # Update performance metrics
        self.update_performance_metrics('success', validation_time)
    
    def log_validation_error(self, request: HttpRequest, error: str, start_time: float) -> None:
        """
        Log token validation error.
        
        Args:
            request: Django HTTP request
            error: Error message
            start_time: Validation start time
        """
        validation_time = time.time() - start_time
        
        logger.warning(
            "jwt_validation_error",
            error=error,
            validation_time_ms=round(validation_time * 1000, 2),
            path=request.path,
            method=request.method,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            correlation_id=get_correlation_id()
        )
        
        # Update performance metrics
        self.update_performance_metrics('error', validation_time)
    
    def update_performance_metrics(self, result_type: str, validation_time: float) -> None:
        """
        Update performance metrics for monitoring.
        
        Args:
            result_type: 'success' or 'error'
            validation_time: Time taken for validation in seconds
        """
        if not self.enable_metrics:
            return
        
        try:
            # Update counters
            counter_key = f"jwt_validation_count_{result_type}"
            self.cache.set(
                counter_key,
                self.cache.get(counter_key, 0) + 1,
                86400  # 24 hours
            )
            
            # Update timing metrics
            timing_key = f"jwt_validation_timing_{result_type}"
            current_times = self.cache.get(timing_key, [])
            current_times.append(validation_time)
            
            # Keep only last 1000 measurements
            if len(current_times) > 1000:
                current_times = current_times[-1000:]
            
            self.cache.set(timing_key, current_times, 3600)  # 1 hour
            
        except Exception as e:
            logger.error(f"Error updating JWT validation metrics: {str(e)}")


class JWTTokenIntrospectionMiddleware(MiddlewareMixin):
    """
    Lightweight middleware for token introspection without full authentication.
    
    This middleware adds token metadata to requests without enforcing authentication,
    useful for logging and monitoring purposes.
    """
    
    def process_request(self, request: HttpRequest) -> None:
        """
        Add token metadata to request if JWT token is present.
        
        Args:
            request: Django HTTP request
        """
        # Extract token
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return
        
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return
        
        token = parts[1]
        
        try:
            # Get token metadata without full validation
            introspection_data = jwt_service.introspect_token(token)
            
            # Add metadata to request
            request.jwt_introspection = introspection_data
            request.jwt_token_present = True
            
            if introspection_data.get('active'):
                request.jwt_user_id = introspection_data.get('user_id')
                request.jwt_scopes = introspection_data.get('scopes', [])
                request.jwt_device_id = introspection_data.get('device_id')
            
        except Exception as e:
            logger.debug(f"JWT introspection error: {str(e)}")
            request.jwt_token_present = False