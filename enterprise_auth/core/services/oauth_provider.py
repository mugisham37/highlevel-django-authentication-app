"""
OAuth provider abstraction layer for enterprise authentication system.

This module provides a unified interface for integrating with various OAuth2/OpenID Connect
providers, enabling dynamic provider management and consistent user data normalization.
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from ..exceptions import (
    ConfigurationError,
    OAuthCodeInvalidError,
    OAuthError,
    OAuthProviderError,
    OAuthStateInvalidError,
)

logger = logging.getLogger(__name__)


@dataclass
class TokenData:
    """Data structure for OAuth token information."""
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: str = "Bearer"
    scope: Optional[str] = None
    id_token: Optional[str] = None


@dataclass
class NormalizedUserData:
    """Normalized user data structure across all OAuth providers."""
    provider_user_id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    profile_picture_url: Optional[str] = None
    locale: Optional[str] = None
    timezone: Optional[str] = None
    verified_email: bool = False
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class ProviderConfig:
    """Configuration data structure for OAuth providers."""
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: List[str]
    authorization_url: str
    token_url: str
    user_info_url: str
    revoke_url: Optional[str] = None
    extra_params: Optional[Dict[str, Any]] = None
    timeout: int = 30
    use_pkce: bool = True


@dataclass
class AuthorizationRequest:
    """Data structure for OAuth authorization request."""
    authorization_url: str
    state: str
    code_verifier: Optional[str] = None
    code_challenge: Optional[str] = None


class IOAuthProvider(ABC):
    """
    Abstract interface for OAuth2/OpenID Connect providers.
    
    This interface defines the contract that all OAuth providers must implement
    to ensure consistent behavior across different providers.
    """
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the unique name of this OAuth provider."""
        pass
    
    @property
    @abstractmethod
    def display_name(self) -> str:
        """Return the human-readable display name of this provider."""
        pass
    
    @property
    @abstractmethod
    def supported_scopes(self) -> Set[str]:
        """Return the set of scopes supported by this provider."""
        pass
    
    @abstractmethod
    def configure(self, config: ProviderConfig) -> None:
        """
        Configure the OAuth provider with the given configuration.
        
        Args:
            config: Provider configuration data
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        pass
    
    @abstractmethod
    def get_authorization_url(
        self,
        state: str,
        scopes: Optional[List[str]] = None,
        extra_params: Optional[Dict[str, str]] = None
    ) -> AuthorizationRequest:
        """
        Generate OAuth authorization URL with PKCE support.
        
        Args:
            state: State parameter for CSRF protection
            scopes: List of OAuth scopes to request
            extra_params: Additional parameters for the authorization URL
            
        Returns:
            Authorization request data including URL and PKCE parameters
            
        Raises:
            ConfigurationError: If provider is not properly configured
            OAuthError: If authorization URL generation fails
        """
        pass
    
    @abstractmethod
    def exchange_code_for_token(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None
    ) -> TokenData:
        """
        Exchange authorization code for access token.
        
        Args:
            code: Authorization code from OAuth callback
            state: State parameter for verification
            code_verifier: PKCE code verifier if used
            
        Returns:
            Token data including access and refresh tokens
            
        Raises:
            OAuthCodeInvalidError: If authorization code is invalid
            OAuthStateInvalidError: If state parameter is invalid
            OAuthProviderError: If token exchange fails
        """
        pass
    
    @abstractmethod
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        """
        Retrieve user information using access token.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Normalized user data
            
        Raises:
            OAuthProviderError: If user info retrieval fails
        """
        pass
    
    @abstractmethod
    def refresh_access_token(self, refresh_token: str) -> TokenData:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: OAuth refresh token
            
        Returns:
            New token data
            
        Raises:
            OAuthProviderError: If token refresh fails
        """
        pass
    
    @abstractmethod
    def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """
        Revoke an OAuth token.
        
        Args:
            token: Token to revoke
            token_type: Type of token (access_token or refresh_token)
            
        Returns:
            True if revocation was successful
            
        Raises:
            OAuthProviderError: If token revocation fails
        """
        pass
    
    @abstractmethod
    def validate_configuration(self) -> bool:
        """
        Validate the current provider configuration.
        
        Returns:
            True if configuration is valid
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        pass


class BaseOAuthProvider(IOAuthProvider):
    """
    Base implementation of OAuth provider with common functionality.
    
    This class provides common OAuth functionality that can be shared
    across different provider implementations.
    """
    
    def __init__(self):
        """Initialize the base OAuth provider."""
        self.config: Optional[ProviderConfig] = None
    
    def _make_http_request(self, url: str, data: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Make HTTP request using urllib."""
        timeout = self.config.timeout if self.config else 30
        
        default_headers = {
            'User-Agent': f'EnterpriseAuth/{self.provider_name}',
            'Accept': 'application/json',
        }
        
        if headers:
            default_headers.update(headers)
        
        if data:
            # POST request
            post_data = urlencode(data).encode('utf-8')
            request = Request(url, data=post_data, headers=default_headers)
        else:
            # GET request
            request = Request(url, headers=default_headers)
        
        try:
            with urlopen(request, timeout=timeout) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data)
        except HTTPError as e:
            error_data = {}
            try:
                error_response = e.read().decode('utf-8')
                error_data = json.loads(error_response)
            except Exception:
                pass
            
            # Re-raise with additional context
            raise HTTPError(e.url, e.code, e.msg, e.hdrs, e.fp) from e
        except URLError as e:
            raise URLError(e.reason) from e
    
    def configure(self, config: ProviderConfig) -> None:
        """Configure the OAuth provider."""
        self.config = config
        self.validate_configuration()
    
    def validate_configuration(self) -> bool:
        """Validate the provider configuration."""
        if not self.config:
            raise ConfigurationError(
                f"Provider {self.provider_name} is not configured",
                config_key=f"oauth.{self.provider_name}"
            )
        
        required_fields = [
            'client_id', 'client_secret', 'redirect_uri',
            'authorization_url', 'token_url', 'user_info_url'
        ]
        
        for field in required_fields:
            if not getattr(self.config, field):
                raise ConfigurationError(
                    f"Missing required configuration field: {field}",
                    config_key=f"oauth.{self.provider_name}.{field}"
                )
        
        # Validate URLs
        for url_field in ['authorization_url', 'token_url', 'user_info_url']:
            url = getattr(self.config, url_field)
            if url and not self._is_valid_url(url):
                raise ConfigurationError(
                    f"Invalid URL in configuration field: {url_field}",
                    config_key=f"oauth.{self.provider_name}.{url_field}"
                )
        
        return True
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate if a string is a valid URL."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _generate_pkce_challenge(self) -> tuple[str, str]:
        """
        Generate PKCE code verifier and challenge.
        
        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        import base64
        import hashlib
        import secrets
        
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate code challenge
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def get_authorization_url(
        self,
        state: str,
        scopes: Optional[List[str]] = None,
        extra_params: Optional[Dict[str, str]] = None
    ) -> AuthorizationRequest:
        """Generate OAuth authorization URL with PKCE support."""
        if not self.config:
            raise ConfigurationError(f"Provider {self.provider_name} is not configured")
        
        # Use default scopes if none provided
        if scopes is None:
            scopes = self.config.scopes
        
        # Validate requested scopes
        requested_scopes = set(scopes)
        if not requested_scopes.issubset(self.supported_scopes):
            unsupported = requested_scopes - self.supported_scopes
            raise OAuthError(
                f"Unsupported scopes for {self.provider_name}: {unsupported}",
                details={'unsupported_scopes': list(unsupported)}
            )
        
        # Build authorization parameters
        params = {
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'response_type': 'code',
            'state': state,
            'scope': ' '.join(scopes),
        }
        
        # Add PKCE parameters if enabled
        code_verifier = None
        code_challenge = None
        if self.config.use_pkce:
            code_verifier, code_challenge = self._generate_pkce_challenge()
            params.update({
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256',
            })
        
        # Add extra parameters
        if extra_params:
            params.update(extra_params)
        
        if self.config.extra_params:
            params.update(self.config.extra_params)
        
        # Build authorization URL
        authorization_url = f"{self.config.authorization_url}?{urlencode(params)}"
        
        logger.info(
            f"Generated authorization URL for {self.provider_name}",
            extra={
                'provider': self.provider_name,
                'scopes': scopes,
                'state': state,
                'use_pkce': self.config.use_pkce,
            }
        )
        
        return AuthorizationRequest(
            authorization_url=authorization_url,
            state=state,
            code_verifier=code_verifier,
            code_challenge=code_challenge
        )
    
    def exchange_code_for_token(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None
    ) -> TokenData:
        """Exchange authorization code for access token."""
        if not self.config:
            raise ConfigurationError(f"Provider {self.provider_name} is not configured")
        
        # Build token request parameters
        data = {
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.config.redirect_uri,
        }
        
        # Add PKCE code verifier if provided
        if code_verifier:
            data['code_verifier'] = code_verifier
        
        try:
            token_data = self._make_http_request(
                self.config.token_url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            logger.info(
                f"Successfully exchanged code for token with {self.provider_name}",
                extra={
                    'provider': self.provider_name,
                    'state': state,
                }
            )
            
            return TokenData(
                access_token=token_data['access_token'],
                refresh_token=token_data.get('refresh_token'),
                expires_in=token_data.get('expires_in'),
                token_type=token_data.get('token_type', 'Bearer'),
                scope=token_data.get('scope'),
                id_token=token_data.get('id_token'),
            )
            
        except HTTPError as e:
            error_data = {}
            try:
                error_response = e.read().decode('utf-8')
                error_data = json.loads(error_response)
            except Exception:
                pass
            
            logger.error(
                f"Token exchange failed for {self.provider_name}",
                extra={
                    'provider': self.provider_name,
                    'status_code': e.code,
                    'error_data': error_data,
                }
            )
            
            if e.code == 400:
                raise OAuthCodeInvalidError(
                    f"Invalid authorization code for {self.provider_name}",
                    provider=self.provider_name,
                    provider_error=error_data.get('error', 'invalid_grant')
                )
            else:
                raise OAuthProviderError(
                    f"Token exchange failed for {self.provider_name}",
                    provider=self.provider_name,
                    provider_error=str(e)
                )
        
        except Exception as e:
            logger.error(
                f"Unexpected error during token exchange for {self.provider_name}",
                extra={'provider': self.provider_name, 'error': str(e)}
            )
            raise OAuthProviderError(
                f"Token exchange failed for {self.provider_name}",
                provider=self.provider_name,
                provider_error=str(e)
            )
    
    def refresh_access_token(self, refresh_token: str) -> TokenData:
        """Refresh access token using refresh token."""
        if not self.config:
            raise ConfigurationError(f"Provider {self.provider_name} is not configured")
        
        data = {
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
        }
        
        try:
            token_data = self._make_http_request(
                self.config.token_url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            logger.info(
                f"Successfully refreshed token for {self.provider_name}",
                extra={'provider': self.provider_name}
            )
            
            return TokenData(
                access_token=token_data['access_token'],
                refresh_token=token_data.get('refresh_token', refresh_token),
                expires_in=token_data.get('expires_in'),
                token_type=token_data.get('token_type', 'Bearer'),
                scope=token_data.get('scope'),
                id_token=token_data.get('id_token'),
            )
            
        except HTTPError as e:
            error_data = {}
            try:
                error_response = e.read().decode('utf-8')
                error_data = json.loads(error_response)
            except Exception:
                pass
            
            logger.error(
                f"Token refresh failed for {self.provider_name}",
                extra={
                    'provider': self.provider_name,
                    'status_code': e.code,
                    'error_data': error_data,
                }
            )
            
            raise OAuthProviderError(
                f"Token refresh failed for {self.provider_name}",
                provider=self.provider_name,
                provider_error=error_data.get('error', str(e))
            )
        
        except Exception as e:
            logger.error(
                f"Unexpected error during token refresh for {self.provider_name}",
                extra={'provider': self.provider_name, 'error': str(e)}
            )
            raise OAuthProviderError(
                f"Token refresh failed for {self.provider_name}",
                provider=self.provider_name,
                provider_error=str(e)
            )
    
    def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """Revoke an OAuth token."""
        if not self.config or not self.config.revoke_url:
            logger.warning(
                f"Token revocation not supported for {self.provider_name}",
                extra={'provider': self.provider_name}
            )
            return False
        
        data = {
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'token': token,
            'token_type_hint': token_type,
        }
        
        try:
            # For revocation, we don't need the response data, just success/failure
            self._make_http_request(
                self.config.revoke_url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            logger.info(
                f"Successfully revoked token for {self.provider_name}",
                extra={'provider': self.provider_name, 'token_type': token_type}
            )
            
            return True
            
        except HTTPError as e:
            # Some providers return 200, others return 204 for success
            if e.code in [200, 204]:
                logger.info(
                    f"Successfully revoked token for {self.provider_name}",
                    extra={'provider': self.provider_name, 'token_type': token_type}
                )
                return True
            else:
                logger.warning(
                    f"Token revocation failed for {self.provider_name}",
                    extra={
                        'provider': self.provider_name,
                        'status_code': e.code,
                        'token_type': token_type,
                    }
                )
                return False
            
        except Exception as e:
            logger.error(
                f"Error during token revocation for {self.provider_name}",
                extra={'provider': self.provider_name, 'error': str(e)}
            )
            return False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        # No cleanup needed for urllib
        pass


class OAuthProviderError(Exception):
    """Exception raised by OAuth provider implementations."""
    
    def __init__(self, message: str, provider: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.provider = provider
        self.original_error = original_error