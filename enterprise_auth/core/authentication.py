"""
Custom authentication classes for Django REST Framework.

This module provides JWT-based authentication using our custom
JWT service with device binding and comprehensive validation.
"""

from typing import Optional, Tuple, Any
import logging

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request

from .services.jwt_service import jwt_service, TokenStatus, DeviceInfo
from .utils.request_utils import create_device_fingerprint

logger = logging.getLogger(__name__)

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """
    JWT authentication class for Django REST Framework.
    
    This authentication class validates JWT access tokens using our
    custom JWT service with device binding and comprehensive security checks.
    """
    
    # Authentication header configuration
    auth_header_prefix = 'Bearer'
    auth_header_name = 'Authorization'
    
    def authenticate(self, request: Request) -> Optional[Tuple[Any, Any]]:
        """
        Authenticate the request using JWT token.
        
        Args:
            request: Django REST Framework request
            
        Returns:
            Tuple of (user, token_claims) if authenticated, None otherwise
        """
        # Get authorization header
        auth_header = self.get_authorization_header(request)
        if not auth_header:
            return None
        
        # Extract token from header
        token = self.extract_token_from_header(auth_header)
        if not token:
            return None
        
        # Validate token
        return self.authenticate_token(request, token)
    
    def authenticate_token(self, request: Request, token: str) -> Optional[Tuple[Any, Any]]:
        """
        Authenticate a JWT token.
        
        Args:
            request: Django REST Framework request
            token: JWT token string
            
        Returns:
            Tuple of (user, token_claims) if valid, None otherwise
        """
        try:
            # Create device fingerprint for binding validation
            device_fingerprint = create_device_fingerprint(request)
            
            # Validate token using JWT service
            validation_result = jwt_service.validate_access_token(token, device_fingerprint)
            
            if not validation_result.is_valid:
                self.handle_invalid_token(validation_result)
                return None
            
            # Get user from token claims
            user = self.get_user_from_claims(validation_result.claims)
            if not user:
                raise exceptions.AuthenticationFailed(_('User not found'))
            
            # Check if user is active
            if not user.is_active:
                raise exceptions.AuthenticationFailed(_('User account is disabled'))
            
            # Check if user account is locked
            if hasattr(user, 'is_account_locked') and user.is_account_locked:
                raise exceptions.AuthenticationFailed(_('User account is locked'))
            
            # Log successful authentication
            logger.info(
                f"JWT authentication successful for user {user.email} "
                f"with token {validation_result.claims.token_id[:8]}..."
            )
            
            return (user, validation_result.claims)
            
        except exceptions.AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(f"JWT authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed(_('Invalid token'))
    
    def get_authorization_header(self, request: Request) -> Optional[str]:
        """
        Get the authorization header from the request.
        
        Args:
            request: Django REST Framework request
            
        Returns:
            Authorization header value or None
        """
        auth_header = request.META.get(f'HTTP_{self.auth_header_name.upper()}')
        if not auth_header:
            return None
        
        return auth_header.strip()
    
    def extract_token_from_header(self, auth_header: str) -> Optional[str]:
        """
        Extract JWT token from authorization header.
        
        Args:
            auth_header: Authorization header value
            
        Returns:
            JWT token string or None
        """
        parts = auth_header.split()
        
        if len(parts) != 2:
            return None
        
        prefix, token = parts
        
        if prefix.lower() != self.auth_header_prefix.lower():
            return None
        
        return token
    
    def get_user_from_claims(self, claims) -> Optional[Any]:
        """
        Get user instance from JWT claims.
        
        Args:
            claims: TokenClaims instance
            
        Returns:
            User instance or None
        """
        try:
            user = User.objects.get(id=claims.user_id)
            return user
        except User.DoesNotExist:
            return None
        except Exception as e:
            logger.error(f"Error getting user from claims: {str(e)}")
            return None
    
    def handle_invalid_token(self, validation_result) -> None:
        """
        Handle invalid token validation results.
        
        Args:
            validation_result: TokenValidationResult instance
        """
        if validation_result.status == TokenStatus.EXPIRED:
            raise exceptions.AuthenticationFailed(_('Token has expired'))
        elif validation_result.status == TokenStatus.BLACKLISTED:
            raise exceptions.AuthenticationFailed(_('Token has been revoked'))
        elif validation_result.status == TokenStatus.REVOKED:
            raise exceptions.AuthenticationFailed(_('Token has been revoked'))
        else:
            raise exceptions.AuthenticationFailed(_('Invalid token'))
    
    def authenticate_header(self, request: Request) -> str:
        """
        Return the WWW-Authenticate header for 401 responses.
        
        Args:
            request: Django REST Framework request
            
        Returns:
            WWW-Authenticate header value
        """
        return f'{self.auth_header_prefix} realm="api"'


class JWTAuthenticationWithoutDeviceBinding(JWTAuthentication):
    """
    JWT authentication class without device binding.
    
    This is useful for API clients that can't maintain consistent
    device fingerprints or for testing purposes.
    """
    
    def authenticate_token(self, request: Request, token: str) -> Optional[Tuple[Any, Any]]:
        """
        Authenticate a JWT token without device binding.
        
        Args:
            request: Django REST Framework request
            token: JWT token string
            
        Returns:
            Tuple of (user, token_claims) if valid, None otherwise
        """
        try:
            # Validate token without device fingerprint
            validation_result = jwt_service.validate_access_token(token)
            
            if not validation_result.is_valid:
                self.handle_invalid_token(validation_result)
                return None
            
            # Get user from token claims
            user = self.get_user_from_claims(validation_result.claims)
            if not user:
                raise exceptions.AuthenticationFailed(_('User not found'))
            
            # Check if user is active
            if not user.is_active:
                raise exceptions.AuthenticationFailed(_('User account is disabled'))
            
            # Check if user account is locked
            if hasattr(user, 'is_account_locked') and user.is_account_locked:
                raise exceptions.AuthenticationFailed(_('User account is locked'))
            
            # Log successful authentication
            logger.info(
                f"JWT authentication (no device binding) successful for user {user.email} "
                f"with token {validation_result.claims.token_id[:8]}..."
            )
            
            return (user, validation_result.claims)
            
        except exceptions.AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(f"JWT authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed(_('Invalid token'))


class JWTRefreshAuthentication(BaseAuthentication):
    """
    JWT refresh token authentication class.
    
    This authentication class is specifically for refresh token endpoints
    and validates refresh tokens instead of access tokens.
    """
    
    # Authentication header configuration
    auth_header_prefix = 'Bearer'
    auth_header_name = 'Authorization'
    
    def authenticate(self, request: Request) -> Optional[Tuple[Any, Any]]:
        """
        Authenticate the request using JWT refresh token.
        
        Args:
            request: Django REST Framework request
            
        Returns:
            Tuple of (user, token_claims) if authenticated, None otherwise
        """
        # Get authorization header
        auth_header = self.get_authorization_header(request)
        if not auth_header:
            return None
        
        # Extract token from header
        token = self.extract_token_from_header(auth_header)
        if not token:
            return None
        
        # Validate refresh token
        return self.authenticate_refresh_token(request, token)
    
    def authenticate_refresh_token(self, request: Request, token: str) -> Optional[Tuple[Any, Any]]:
        """
        Authenticate a JWT refresh token.
        
        Args:
            request: Django REST Framework request
            token: JWT refresh token string
            
        Returns:
            Tuple of (user, token_claims) if valid, None otherwise
        """
        try:
            # Create device fingerprint for binding validation
            device_fingerprint = create_device_fingerprint(request)
            
            # Validate refresh token using JWT service
            validation_result = jwt_service._validate_refresh_token(token, device_fingerprint)
            
            if not validation_result.is_valid:
                self.handle_invalid_token(validation_result)
                return None
            
            # Get user from token claims
            user = self.get_user_from_claims(validation_result.claims)
            if not user:
                raise exceptions.AuthenticationFailed(_('User not found'))
            
            # Check if user is active
            if not user.is_active:
                raise exceptions.AuthenticationFailed(_('User account is disabled'))
            
            # Check if user account is locked
            if hasattr(user, 'is_account_locked') and user.is_account_locked:
                raise exceptions.AuthenticationFailed(_('User account is locked'))
            
            # Log successful refresh token authentication
            logger.info(
                f"JWT refresh token authentication successful for user {user.email} "
                f"with token {validation_result.claims.token_id[:8]}..."
            )
            
            return (user, validation_result.claims)
            
        except exceptions.AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(f"JWT refresh token authentication error: {str(e)}")
            raise exceptions.AuthenticationFailed(_('Invalid refresh token'))
    
    def get_authorization_header(self, request: Request) -> Optional[str]:
        """Get the authorization header from the request."""
        auth_header = request.META.get(f'HTTP_{self.auth_header_name.upper()}')
        if not auth_header:
            return None
        return auth_header.strip()
    
    def extract_token_from_header(self, auth_header: str) -> Optional[str]:
        """Extract JWT token from authorization header."""
        parts = auth_header.split()
        
        if len(parts) != 2:
            return None
        
        prefix, token = parts
        
        if prefix.lower() != self.auth_header_prefix.lower():
            return None
        
        return token
    
    def get_user_from_claims(self, claims) -> Optional[Any]:
        """Get user instance from JWT claims."""
        try:
            user = User.objects.get(id=claims.user_id)
            return user
        except User.DoesNotExist:
            return None
        except Exception as e:
            logger.error(f"Error getting user from claims: {str(e)}")
            return None
    
    def handle_invalid_token(self, validation_result) -> None:
        """Handle invalid token validation results."""
        if validation_result.status == TokenStatus.EXPIRED:
            raise exceptions.AuthenticationFailed(_('Refresh token has expired'))
        elif validation_result.status == TokenStatus.BLACKLISTED:
            raise exceptions.AuthenticationFailed(_('Refresh token has been revoked'))
        elif validation_result.status == TokenStatus.REVOKED:
            raise exceptions.AuthenticationFailed(_('Refresh token has been revoked'))
        else:
            raise exceptions.AuthenticationFailed(_('Invalid refresh token'))
    
    def authenticate_header(self, request: Request) -> str:
        """Return the WWW-Authenticate header for 401 responses."""
        return f'{self.auth_header_prefix} realm="api"'