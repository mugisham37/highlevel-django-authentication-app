"""
API Authentication

Custom authentication classes for API key and JWT token authentication.
"""
import logging
from typing import Optional, Tuple, Any
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from rest_framework import authentication, exceptions
from rest_framework.request import Request

from .models import APIKey
from enterprise_auth.core.services.jwt_service import JWTService
from enterprise_auth.core.exceptions import (
    TokenExpiredError, TokenInvalidError, RateLimitExceededError
)

User = get_user_model()
logger = logging.getLogger(__name__)


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    API Key authentication for external systems.
    
    Supports rate limiting, IP restrictions, and scope validation.
    """
    
    def authenticate(self, request: Request) -> Optional[Tuple[User, APIKey]]:
        """Authenticate request using API key."""
        api_key = self.get_api_key_from_request(request)
        if not api_key:
            return None
        
        # Validate API key format
        if not api_key.startswith('ea_'):
            return None
        
        try:
            # Extract key ID from API key
            parts = api_key.split('_')
            if len(parts) != 3:
                return None
            
            key_id = parts[1]
            
            # Try to get from cache first
            cache_key = f"api_key:{key_id}"
            api_key_obj = cache.get(cache_key)
            
            if not api_key_obj:
                # Fetch from database
                api_key_obj = APIKey.objects.select_related('created_by').get(
                    key_id=key_id,
                    is_active=True
                )
                # Cache for 5 minutes
                cache.set(cache_key, api_key_obj, 300)
            
            # Verify the key
            if not api_key_obj.verify_key(api_key):
                logger.warning(f"Invalid API key verification for key_id: {key_id}")
                raise exceptions.AuthenticationFailed('Invalid API key')
            
            # Check if key is expired
            if api_key_obj.is_expired():
                logger.warning(f"Expired API key used: {key_id}")
                raise exceptions.AuthenticationFailed('API key has expired')
            
            # Check IP restrictions
            client_ip = self.get_client_ip(request)
            if not api_key_obj.is_ip_allowed(client_ip):
                logger.warning(f"API key {key_id} used from unauthorized IP: {client_ip}")
                raise exceptions.AuthenticationFailed('IP address not authorized for this API key')
            
            # Check rate limits
            self.check_rate_limits(api_key_obj, client_ip)
            
            # Record usage
            api_key_obj.record_usage()
            
            # Set API key in request for later use
            request.api_key = api_key_obj
            
            return (api_key_obj.created_by, api_key_obj)
            
        except APIKey.DoesNotExist:
            logger.warning(f"API key not found: {key_id}")
            raise exceptions.AuthenticationFailed('Invalid API key')
        except RateLimitExceededError as e:
            logger.warning(f"Rate limit exceeded for API key {key_id}: {str(e)}")
            raise exceptions.Throttled(detail=str(e))
        except Exception as e:
            logger.error(f"API key authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed('Authentication failed')

    def get_api_key_from_request(self, request: Request) -> Optional[str]:
        """Extract API key from request headers."""
        # Check Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Check X-API-Key header
        api_key = request.META.get('HTTP_X_API_KEY')
        if api_key:
            return api_key
        
        # Check query parameter (less secure, for development only)
        if hasattr(request, 'query_params'):
            return request.query_params.get('api_key')
        
        return None

    def get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded IP (behind proxy/load balancer)
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        # Check for real IP (some proxies use this)
        real_ip = request.META.get('HTTP_X_REAL_IP')
        if real_ip:
            return real_ip
        
        # Fall back to remote address
        return request.META.get('REMOTE_ADDR', '127.0.0.1')

    def check_rate_limits(self, api_key: APIKey, client_ip: str):
        """Check rate limits for API key."""
        from enterprise_auth.core.services.rate_limiting import RateLimitingService
        
        rate_limiter = RateLimitingService()
        
        # Check per-minute limit
        minute_key = f"api_key_rate_limit:minute:{api_key.key_id}"
        if not rate_limiter.check_rate_limit(minute_key, api_key.rate_limit_per_minute, 60):
            raise RateLimitExceededError("API key minute rate limit exceeded")
        
        # Check per-hour limit
        hour_key = f"api_key_rate_limit:hour:{api_key.key_id}"
        if not rate_limiter.check_rate_limit(hour_key, api_key.rate_limit_per_hour, 3600):
            raise RateLimitExceededError("API key hour rate limit exceeded")
        
        # Check per-day limit
        day_key = f"api_key_rate_limit:day:{api_key.key_id}"
        if not rate_limiter.check_rate_limit(day_key, api_key.rate_limit_per_day, 86400):
            raise RateLimitExceededError("API key day rate limit exceeded")

    def authenticate_header(self, request: Request) -> str:
        """Return authentication header for 401 responses."""
        return 'Bearer'


class JWTAuthentication(authentication.BaseAuthentication):
    """
    JWT token authentication for user sessions.
    
    Supports access token validation and automatic refresh.
    """
    
    def __init__(self):
        self.jwt_service = JWTService()

    def authenticate(self, request: Request) -> Optional[Tuple[User, dict]]:
        """Authenticate request using JWT token."""
        token = self.get_jwt_token_from_request(request)
        if not token:
            return None
        
        try:
            # Validate and decode token
            token_claims = self.jwt_service.validate_access_token(token)
            
            # Get user from token claims
            user_id = token_claims.get('user_id')
            if not user_id:
                raise exceptions.AuthenticationFailed('Invalid token claims')
            
            # Try to get user from cache first
            cache_key = f"user:{user_id}"
            user = cache.get(cache_key)
            
            if not user:
                user = User.objects.get(id=user_id, is_active=True)
                # Cache user for 5 minutes
                cache.set(cache_key, user, 300)
            
            # Set token claims in request for later use
            request.token_claims = token_claims
            
            return (user, token_claims)
            
        except TokenExpiredError:
            logger.info(f"Expired JWT token used")
            raise exceptions.AuthenticationFailed('Token has expired')
        except TokenInvalidError:
            logger.warning(f"Invalid JWT token used")
            raise exceptions.AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            logger.warning(f"JWT token for non-existent user: {user_id}")
            raise exceptions.AuthenticationFailed('User not found')
        except Exception as e:
            logger.error(f"JWT authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed('Authentication failed')

    def get_jwt_token_from_request(self, request: Request) -> Optional[str]:
        """Extract JWT token from request headers."""
        # Check Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            # Make sure it's not an API key
            if not token.startswith('ea_'):
                return token
        
        return None

    def authenticate_header(self, request: Request) -> str:
        """Return authentication header for 401 responses."""
        return 'Bearer'


class CombinedAuthentication(authentication.BaseAuthentication):
    """
    Combined authentication supporting both API keys and JWT tokens.
    
    Tries JWT first, then falls back to API key authentication.
    """
    
    def __init__(self):
        self.jwt_auth = JWTAuthentication()
        self.api_key_auth = APIKeyAuthentication()

    def authenticate(self, request: Request) -> Optional[Tuple[User, Any]]:
        """Authenticate using JWT or API key."""
        # Try JWT authentication first
        jwt_result = self.jwt_auth.authenticate(request)
        if jwt_result:
            return jwt_result
        
        # Fall back to API key authentication
        api_key_result = self.api_key_auth.authenticate(request)
        if api_key_result:
            return api_key_result
        
        return None

    def authenticate_header(self, request: Request) -> str:
        """Return authentication header for 401 responses."""
        return 'Bearer'


class ScopePermission:
    """
    Permission class for API scope validation.
    """
    
    def __init__(self, required_scope: str):
        self.required_scope = required_scope

    def has_permission(self, request: Request, view) -> bool:
        """Check if request has required scope."""
        # For JWT authentication, check token claims
        if hasattr(request, 'token_claims'):
            token_scopes = request.token_claims.get('scopes', [])
            return self.required_scope in token_scopes
        
        # For API key authentication, check API key scopes
        if hasattr(request, 'api_key'):
            return request.api_key.can_access_scope(self.required_scope)
        
        return False


def require_scope(scope: str):
    """Decorator for requiring specific API scope."""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            permission = ScopePermission(scope)
            if not permission.has_permission(request, None):
                raise exceptions.PermissionDenied(f"Required scope: {scope}")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator