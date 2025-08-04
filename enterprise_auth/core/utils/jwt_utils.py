"""
JWT Token Utilities for Enterprise Authentication System.

This module provides utility functions for JWT token claims extraction,
validation, and manipulation throughout the application.
"""

import time
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from django.http import HttpRequest
from django.contrib.auth import get_user_model
from django.core.cache import caches

from ..services.jwt_service import jwt_service, TokenClaims, TokenStatus, TokenValidationResult

logger = logging.getLogger(__name__)
User = get_user_model()


def extract_token_from_request(request: HttpRequest) -> Optional[str]:
    """
    Extract JWT token from various request sources.
    
    Args:
        request: Django HTTP request
        
    Returns:
        JWT token string or None if not found
    """
    # Check Authorization header (most common)
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            return parts[1]
    
    # Check custom header
    token = request.META.get('HTTP_X_AUTH_TOKEN')
    if token:
        return token
    
    # Check query parameters (for WebSocket or special cases)
    token = request.GET.get('token')
    if token:
        return token
    
    # Check POST data (for form submissions)
    if hasattr(request, 'data') and isinstance(request.data, dict):
        token = request.data.get('token')
        if token:
            return token
    
    return None


def get_token_claims_from_request(request: HttpRequest) -> Optional[TokenClaims]:
    """
    Extract and validate JWT token claims from request.
    
    Args:
        request: Django HTTP request
        
    Returns:
        TokenClaims object or None if token is invalid
    """
    # Check if claims are already attached to request (from middleware)
    if hasattr(request, 'jwt_claims'):
        return request.jwt_claims
    
    # Extract token from request
    token = extract_token_from_request(request)
    if not token:
        return None
    
    # Validate token and extract claims
    validation_result = validate_token_with_claims(token, request)
    
    if validation_result.is_valid:
        return validation_result.claims
    
    return None


def validate_token_with_claims(token: str, request: Optional[HttpRequest] = None) -> TokenValidationResult:
    """
    Validate JWT token and return detailed validation result.
    
    Args:
        token: JWT token string
        request: Optional Django HTTP request for device binding
        
    Returns:
        TokenValidationResult with status and claims
    """
    try:
        # Create device fingerprint if request is provided
        device_fingerprint = None
        if request:
            from ..utils.request_utils import create_device_fingerprint
            device_fingerprint = create_device_fingerprint(request)
        
        # Validate token using JWT service
        return jwt_service.validate_access_token(token, device_fingerprint)
        
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return TokenValidationResult(
            status=TokenStatus.INVALID,
            error_message=f"Validation error: {str(e)}"
        )


def extract_user_from_token(token: str, request: Optional[HttpRequest] = None) -> Optional[User]:
    """
    Extract user from JWT token.
    
    Args:
        token: JWT token string
        request: Optional Django HTTP request for device binding
        
    Returns:
        User instance or None if token is invalid
    """
    validation_result = validate_token_with_claims(token, request)
    
    if not validation_result.is_valid:
        return None
    
    try:
        user = User.objects.get(id=validation_result.claims.user_id)
        
        # Check if user is active
        if not user.is_active:
            return None
        
        # Check if user account is locked
        if hasattr(user, 'is_account_locked') and user.is_account_locked:
            return None
        
        return user
        
    except User.DoesNotExist:
        return None
    except Exception as e:
        logger.error(f"Error extracting user from token: {str(e)}")
        return None


def get_token_expiration_info(claims: TokenClaims) -> Dict[str, Any]:
    """
    Get token expiration information.
    
    Args:
        claims: JWT token claims
        
    Returns:
        Dictionary with expiration information
    """
    now = datetime.now(timezone.utc)
    expires_at = datetime.fromtimestamp(claims.expires_at, tz=timezone.utc)
    issued_at = datetime.fromtimestamp(claims.issued_at, tz=timezone.utc)
    
    time_to_expiry = expires_at - now
    token_age = now - issued_at
    
    return {
        'expires_at': expires_at.isoformat(),
        'issued_at': issued_at.isoformat(),
        'time_to_expiry_seconds': int(time_to_expiry.total_seconds()),
        'token_age_seconds': int(token_age.total_seconds()),
        'is_expired': time_to_expiry.total_seconds() <= 0,
        'expires_soon': time_to_expiry.total_seconds() <= 300,  # 5 minutes
    }


def check_token_scopes(claims: TokenClaims, required_scopes: List[str]) -> bool:
    """
    Check if token has required scopes.
    
    Args:
        claims: JWT token claims
        required_scopes: List of required scopes
        
    Returns:
        True if token has all required scopes
    """
    if not required_scopes:
        return True
    
    token_scopes = set(claims.scopes)
    required_scopes_set = set(required_scopes)
    
    return required_scopes_set.issubset(token_scopes)


def get_token_device_info(claims: TokenClaims) -> Dict[str, Any]:
    """
    Extract device information from token claims.
    
    Args:
        claims: JWT token claims
        
    Returns:
        Dictionary with device information
    """
    return {
        'device_id': claims.device_id,
        'device_fingerprint': claims.device_fingerprint,
        'ip_address': claims.ip_address,
        'user_agent': claims.user_agent,
        'session_id': claims.session_id,
    }


def create_token_introspection_response(token: str) -> Dict[str, Any]:
    """
    Create comprehensive token introspection response.
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary with token introspection data
    """
    try:
        # Use JWT service introspection
        introspection_data = jwt_service.introspect_token(token)
        
        # Add additional metadata if token is active
        if introspection_data.get('active'):
            claims = TokenClaims.from_dict(introspection_data)
            
            # Add expiration info
            expiration_info = get_token_expiration_info(claims)
            introspection_data.update(expiration_info)
            
            # Add device info
            device_info = get_token_device_info(claims)
            introspection_data['device_info'] = device_info
        
        return introspection_data
        
    except Exception as e:
        logger.error(f"Token introspection error: {str(e)}")
        return {
            'active': False,
            'error': f'Introspection error: {str(e)}',
            'token_type': 'Bearer',
        }


def validate_token_signature(token: str) -> bool:
    """
    Validate JWT token signature without full validation.
    
    Args:
        token: JWT token string
        
    Returns:
        True if signature is valid
    """
    try:
        # Decode token to check signature
        claims = jwt_service._decode_jwt_token(token)
        return claims is not None
        
    except Exception:
        return False


def get_token_header_info(token: str) -> Optional[Dict[str, Any]]:
    """
    Extract JWT token header information.
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary with header information or None if invalid
    """
    try:
        import jwt
        
        # Get unverified header
        header = jwt.get_unverified_header(token)
        
        return {
            'algorithm': header.get('alg'),
            'key_id': header.get('kid'),
            'token_type': header.get('typ'),
        }
        
    except Exception as e:
        logger.error(f"Error extracting token header: {str(e)}")
        return None


def is_token_blacklisted(token: str) -> bool:
    """
    Check if token is blacklisted.
    
    Args:
        token: JWT token string
        
    Returns:
        True if token is blacklisted
    """
    try:
        # Extract token ID from claims
        claims = jwt_service._decode_jwt_token(token)
        if not claims:
            return True  # Invalid tokens are considered blacklisted
        
        # Check blacklist
        return jwt_service.blacklist_service.is_token_blacklisted(claims.token_id)
        
    except Exception:
        return True  # Assume blacklisted on error


def get_cached_token_validation(token: str, device_fingerprint: Optional[str] = None) -> Optional[TokenValidationResult]:
    """
    Get cached token validation result.
    
    Args:
        token: JWT token string
        device_fingerprint: Optional device fingerprint
        
    Returns:
        Cached TokenValidationResult or None if not cached
    """
    try:
        cache = caches['default']
        
        # Create cache key
        cache_key = f"jwt_validation:{hash(token)}"
        if device_fingerprint:
            cache_key += f":{hash(device_fingerprint)}"
        
        # Get cached result
        cached_data = cache.get(cache_key)
        if not cached_data:
            return None
        
        # Reconstruct validation result
        status_str, claims_dict, error_message = cached_data
        
        status = TokenStatus(status_str)
        claims = TokenClaims.from_dict(claims_dict) if claims_dict else None
        
        return TokenValidationResult(
            status=status,
            claims=claims,
            error_message=error_message
        )
        
    except Exception as e:
        logger.error(f"Error getting cached token validation: {str(e)}")
        return None


def cache_token_validation(
    token: str,
    validation_result: TokenValidationResult,
    device_fingerprint: Optional[str] = None,
    timeout: int = 300
) -> None:
    """
    Cache token validation result.
    
    Args:
        token: JWT token string
        validation_result: TokenValidationResult to cache
        device_fingerprint: Optional device fingerprint
        timeout: Cache timeout in seconds
    """
    try:
        cache = caches['default']
        
        # Create cache key
        cache_key = f"jwt_validation:{hash(token)}"
        if device_fingerprint:
            cache_key += f":{hash(device_fingerprint)}"
        
        # Prepare cache data
        cache_data = (
            validation_result.status.value,
            validation_result.claims.to_dict() if validation_result.claims else None,
            validation_result.error_message
        )
        
        # Cache the result
        cache.set(cache_key, cache_data, timeout)
        
    except Exception as e:
        logger.error(f"Error caching token validation: {str(e)}")


def require_token_scopes(required_scopes: List[str]):
    """
    Decorator to require specific token scopes.
    
    Args:
        required_scopes: List of required scopes
        
    Returns:
        Decorator function
    """
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            # Get token claims
            claims = get_token_claims_from_request(request)
            
            if not claims:
                from django.http import JsonResponse
                return JsonResponse({
                    'error': {
                        'code': 'TOKEN_REQUIRED',
                        'message': 'Valid JWT token required'
                    }
                }, status=401)
            
            # Check scopes
            if not check_token_scopes(claims, required_scopes):
                from django.http import JsonResponse
                return JsonResponse({
                    'error': {
                        'code': 'INSUFFICIENT_SCOPE',
                        'message': f'Required scopes: {", ".join(required_scopes)}'
                    }
                }, status=403)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def get_token_metrics() -> Dict[str, Any]:
    """
    Get JWT token validation metrics.
    
    Returns:
        Dictionary with token validation metrics
    """
    try:
        cache = caches['default']
        
        # Get counters
        success_count = cache.get('jwt_validation_count_success', 0)
        error_count = cache.get('jwt_validation_count_error', 0)
        
        # Get timing data
        success_times = cache.get('jwt_validation_timing_success', [])
        error_times = cache.get('jwt_validation_timing_error', [])
        
        # Calculate averages
        avg_success_time = sum(success_times) / len(success_times) if success_times else 0
        avg_error_time = sum(error_times) / len(error_times) if error_times else 0
        
        return {
            'validation_counts': {
                'success': success_count,
                'error': error_count,
                'total': success_count + error_count,
            },
            'average_times': {
                'success_ms': round(avg_success_time * 1000, 2),
                'error_ms': round(avg_error_time * 1000, 2),
            },
            'recent_validations': {
                'success_samples': len(success_times),
                'error_samples': len(error_times),
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting token metrics: {str(e)}")
        return {
            'validation_counts': {'success': 0, 'error': 0, 'total': 0},
            'average_times': {'success_ms': 0, 'error_ms': 0},
            'recent_validations': {'success_samples': 0, 'error_samples': 0},
        }