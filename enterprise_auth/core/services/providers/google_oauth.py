"""
Google OAuth2/OpenID Connect provider implementation.

This module provides a complete implementation of Google OAuth2 and OpenID Connect
integration with support for PKCE, token refresh, and comprehensive user data normalization.
"""

import json
import logging
from typing import Any, Dict, Optional, Set
from urllib.error import HTTPError
from urllib.parse import urlencode

from django.conf import settings

from ...exceptions import (
    ConfigurationError,
    OAuthError,
    OAuthProviderError,
    OAuthTokenExpiredError,
)
from ..oauth_provider import BaseOAuthProvider, NormalizedUserData, TokenData

logger = logging.getLogger(__name__)


class GoogleOAuthProvider(BaseOAuthProvider):
    """
    Google OAuth2/OpenID Connect provider implementation.
    
    This provider supports:
    - OAuth2 authorization code flow with PKCE
    - OpenID Connect for identity verification
    - Automatic token refresh
    - Comprehensive user data normalization
    - Google-specific scope handling
    """
    
    # Google OAuth2 endpoints
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    OPENID_USER_INFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
    REVOKE_URL = "https://oauth2.googleapis.com/revoke"
    JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
    
    # Google-specific configuration
    DEFAULT_SCOPES = ["openid", "email", "profile"]
    REQUIRED_SCOPES = ["openid", "email"]
    
    @property
    def provider_name(self) -> str:
        """Return the unique name of this OAuth provider."""
        return "google"
    
    @property
    def display_name(self) -> str:
        """Return the human-readable display name of this provider."""
        return "Google"
    
    @property
    def supported_scopes(self) -> Set[str]:
        """Return the set of scopes supported by this provider."""
        return {
            # OpenID Connect scopes
            "openid",
            "email",
            "profile",
            
            # Google API scopes (commonly used)
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/user.birthday.read",
            "https://www.googleapis.com/auth/user.gender.read",
            "https://www.googleapis.com/auth/user.phonenumbers.read",
            "https://www.googleapis.com/auth/user.addresses.read",
            
            # Google Workspace scopes (for enterprise integration)
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
            "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
            
            # Google Drive scopes (if needed for file access)
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/drive.metadata.readonly",
            
            # Calendar scopes (if needed for calendar integration)
            "https://www.googleapis.com/auth/calendar.readonly",
            "https://www.googleapis.com/auth/calendar.events.readonly",
        }
    
    def validate_configuration(self) -> bool:
        """Validate the Google OAuth provider configuration."""
        if not super().validate_configuration():
            return False
        
        # Validate Google-specific requirements
        if not self.config:
            return False
        
        # Ensure required scopes are included
        config_scopes = set(self.config.scopes)
        required_scopes = set(self.REQUIRED_SCOPES)
        
        if not required_scopes.issubset(config_scopes):
            missing_scopes = required_scopes - config_scopes
            raise ConfigurationError(
                f"Google OAuth requires scopes: {missing_scopes}",
                config_key=f"oauth.{self.provider_name}.scopes"
            )
        
        # Validate Google-specific URLs if overridden
        expected_urls = {
            'authorization_url': self.AUTHORIZATION_URL,
            'token_url': self.TOKEN_URL,
            'user_info_url': self.USER_INFO_URL,
        }
        
        for url_field, expected_url in expected_urls.items():
            config_url = getattr(self.config, url_field)
            if config_url and not config_url.startswith('https://'):
                raise ConfigurationError(
                    f"Google OAuth URLs must use HTTPS: {url_field}",
                    config_key=f"oauth.{self.provider_name}.{url_field}"
                )
        
        return True
    
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        """
        Retrieve user information from Google's userinfo endpoint.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Normalized user data
            
        Raises:
            OAuthProviderError: If user info retrieval fails
            OAuthTokenExpiredError: If access token is expired
        """
        if not self.config:
            raise ConfigurationError(f"Provider {self.provider_name} is not configured")
        
        # Try OpenID Connect userinfo endpoint first (more comprehensive)
        user_data = None
        endpoints_to_try = [
            (self.OPENID_USER_INFO_URL, "OpenID Connect"),
            (self.USER_INFO_URL, "OAuth2"),
        ]
        
        for endpoint_url, endpoint_type in endpoints_to_try:
            try:
                logger.debug(
                    f"Fetching user info from Google {endpoint_type} endpoint",
                    extra={'provider': self.provider_name, 'endpoint': endpoint_url}
                )
                
                user_data = self._make_http_request(
                    endpoint_url,
                    headers={
                        'Authorization': f'Bearer {access_token}',
                        'Accept': 'application/json',
                    }
                )
                
                logger.info(
                    f"Successfully retrieved user info from Google {endpoint_type} endpoint",
                    extra={
                        'provider': self.provider_name,
                        'endpoint': endpoint_url,
                        'user_id': user_data.get('sub') or user_data.get('id'),
                    }
                )
                break
                
            except HTTPError as e:
                if e.code == 401:
                    # Token expired or invalid
                    logger.warning(
                        f"Access token expired for Google {endpoint_type} endpoint",
                        extra={'provider': self.provider_name, 'status_code': e.code}
                    )
                    if endpoint_type == "OAuth2":  # Last endpoint to try
                        raise OAuthTokenExpiredError(
                            f"Access token expired for {self.provider_name}",
                            provider=self.provider_name
                        )
                    continue
                else:
                    logger.warning(
                        f"Failed to get user info from Google {endpoint_type} endpoint",
                        extra={
                            'provider': self.provider_name,
                            'status_code': e.code,
                            'endpoint': endpoint_url,
                        }
                    )
                    if endpoint_type == "OAuth2":  # Last endpoint to try
                        raise OAuthProviderError(
                            f"Failed to get user info from {self.provider_name}",
                            provider=self.provider_name,
                            provider_error=f"HTTP {e.code}"
                        )
                    continue
            
            except Exception as e:
                logger.error(
                    f"Unexpected error getting user info from Google {endpoint_type} endpoint",
                    extra={
                        'provider': self.provider_name,
                        'error': str(e),
                        'endpoint': endpoint_url,
                    }
                )
                if endpoint_type == "OAuth2":  # Last endpoint to try
                    raise OAuthProviderError(
                        f"Failed to get user info from {self.provider_name}: {e}",
                        provider=self.provider_name,
                        provider_error=str(e)
                    )
                continue
        
        if not user_data:
            raise OAuthProviderError(
                f"Failed to retrieve user info from any Google endpoint",
                provider=self.provider_name
            )
        
        # Normalize Google user data
        return self._normalize_google_user_data(user_data)
    
    def _normalize_google_user_data(self, user_data: Dict[str, Any]) -> NormalizedUserData:
        """
        Normalize Google user data to standard format.
        
        Args:
            user_data: Raw user data from Google API
            
        Returns:
            Normalized user data
        """
        # Google can return data in different formats depending on the endpoint
        # OpenID Connect format uses 'sub', OAuth2 format uses 'id'
        provider_user_id = user_data.get('sub') or user_data.get('id')
        if not provider_user_id:
            raise OAuthProviderError(
                "Google user data missing required 'sub' or 'id' field",
                provider=self.provider_name
            )
        
        # Extract name information
        first_name = user_data.get('given_name') or user_data.get('first_name', '')
        last_name = user_data.get('family_name') or user_data.get('last_name', '')
        
        # If we don't have given_name/family_name, try to parse 'name'
        if not first_name and not last_name and user_data.get('name'):
            name_parts = user_data['name'].split(' ', 1)
            first_name = name_parts[0] if len(name_parts) > 0 else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''
        
        # Extract email information
        email = user_data.get('email')
        # Google uses different field names: 'email_verified' (OpenID Connect) or 'verified_email' (OAuth2)
        verified_email = user_data.get('email_verified') or user_data.get('verified_email', False)
        
        # Convert string boolean to actual boolean if needed
        if isinstance(verified_email, str):
            verified_email = verified_email.lower() in ('true', '1', 'yes')
        
        # Extract profile information
        profile_picture_url = user_data.get('picture')
        locale = user_data.get('locale')
        
        # Extract additional Google-specific data
        google_data = {
            'hd': user_data.get('hd'),  # Hosted domain (for Google Workspace)
            'at_hash': user_data.get('at_hash'),  # Access token hash
            'aud': user_data.get('aud'),  # Audience
            'azp': user_data.get('azp'),  # Authorized party
            'iss': user_data.get('iss'),  # Issuer
            'iat': user_data.get('iat'),  # Issued at
            'exp': user_data.get('exp'),  # Expires at
            'nonce': user_data.get('nonce'),  # Nonce
        }
        
        # Remove None values from google_data
        google_data = {k: v for k, v in google_data.items() if v is not None}
        
        # Determine timezone from locale if available
        timezone = None
        if locale:
            # Basic timezone mapping from locale
            timezone_mapping = {
                'en-US': 'America/New_York',
                'en-GB': 'Europe/London',
                'en-CA': 'America/Toronto',
                'en-AU': 'Australia/Sydney',
                'de-DE': 'Europe/Berlin',
                'fr-FR': 'Europe/Paris',
                'es-ES': 'Europe/Madrid',
                'it-IT': 'Europe/Rome',
                'ja-JP': 'Asia/Tokyo',
                'ko-KR': 'Asia/Seoul',
                'zh-CN': 'Asia/Shanghai',
                'zh-TW': 'Asia/Taipei',
                'pt-BR': 'America/Sao_Paulo',
                'ru-RU': 'Europe/Moscow',
                'ar-SA': 'Asia/Riyadh',
                'hi-IN': 'Asia/Kolkata',
            }
            timezone = timezone_mapping.get(locale)
        
        logger.debug(
            f"Normalized Google user data",
            extra={
                'provider': self.provider_name,
                'user_id': provider_user_id,
                'email': email,
                'verified_email': verified_email,
                'has_profile_picture': bool(profile_picture_url),
                'locale': locale,
                'hosted_domain': google_data.get('hd'),
            }
        )
        
        return NormalizedUserData(
            provider_user_id=str(provider_user_id),
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=email,  # Google uses email as the primary identifier
            profile_picture_url=profile_picture_url,
            locale=locale,
            timezone=timezone,
            verified_email=verified_email,
            raw_data={
                **user_data,
                'google_specific': google_data,
            }
        )
    
    def get_authorization_url(
        self,
        state: str,
        scopes: Optional[list[str]] = None,
        extra_params: Optional[Dict[str, str]] = None
    ) -> "AuthorizationRequest":
        """
        Generate Google OAuth authorization URL with PKCE and OpenID Connect support.
        
        Args:
            state: State parameter for CSRF protection
            scopes: List of OAuth scopes to request
            extra_params: Additional parameters for the authorization URL
            
        Returns:
            Authorization request data including URL and PKCE parameters
        """
        # Use default scopes if none provided
        if scopes is None:
            scopes = self.DEFAULT_SCOPES.copy()
        
        # Ensure required scopes are included
        scopes_set = set(scopes)
        for required_scope in self.REQUIRED_SCOPES:
            if required_scope not in scopes_set:
                scopes.append(required_scope)
        
        # Google-specific extra parameters
        google_extra_params = {
            'access_type': 'offline',  # Request refresh token
            'prompt': 'consent',       # Force consent screen to get refresh token
            'include_granted_scopes': 'true',  # Incremental authorization
        }
        
        # Merge with provided extra parameters
        if extra_params:
            google_extra_params.update(extra_params)
        
        # Call parent implementation with Google-specific parameters
        return super().get_authorization_url(
            state=state,
            scopes=scopes,
            extra_params=google_extra_params
        )
    
    def exchange_code_for_token(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None
    ) -> TokenData:
        """
        Exchange authorization code for Google OAuth tokens.
        
        This method handles Google-specific token exchange requirements
        and validates the returned tokens.
        
        Args:
            code: Authorization code from OAuth callback
            state: State parameter for verification
            code_verifier: PKCE code verifier if used
            
        Returns:
            Token data including access and refresh tokens
        """
        # Call parent implementation
        token_data = super().exchange_code_for_token(code, state, code_verifier)
        
        # Google-specific token validation
        if token_data.id_token:
            try:
                # Basic ID token validation (in production, you'd want to verify signature)
                id_token_payload = self._decode_id_token(token_data.id_token)
                
                logger.debug(
                    f"Received Google ID token",
                    extra={
                        'provider': self.provider_name,
                        'aud': id_token_payload.get('aud'),
                        'iss': id_token_payload.get('iss'),
                        'sub': id_token_payload.get('sub'),
                    }
                )
                
                # Validate issuer
                if id_token_payload.get('iss') not in ['https://accounts.google.com', 'accounts.google.com']:
                    logger.warning(
                        f"Invalid ID token issuer from Google",
                        extra={
                            'provider': self.provider_name,
                            'issuer': id_token_payload.get('iss'),
                        }
                    )
                
                # Validate audience (should match client_id)
                if self.config and id_token_payload.get('aud') != self.config.client_id:
                    logger.warning(
                        f"ID token audience mismatch",
                        extra={
                            'provider': self.provider_name,
                            'expected_aud': self.config.client_id,
                            'actual_aud': id_token_payload.get('aud'),
                        }
                    )
                
            except Exception as e:
                logger.warning(
                    f"Failed to validate Google ID token: {e}",
                    extra={'provider': self.provider_name}
                )
        
        return token_data
    
    def _decode_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Decode Google ID token payload (without signature verification).
        
        Note: In production, you should verify the signature using Google's public keys.
        
        Args:
            id_token: JWT ID token from Google
            
        Returns:
            Decoded token payload
        """
        import base64
        
        try:
            # Split the JWT into parts
            parts = id_token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            # Decode the payload (second part)
            payload = parts[1]
            
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            # Decode base64
            decoded_bytes = base64.urlsafe_b64decode(payload)
            payload_data = json.loads(decoded_bytes.decode('utf-8'))
            
            return payload_data
            
        except Exception as e:
            logger.error(
                f"Failed to decode Google ID token: {e}",
                extra={'provider': self.provider_name}
            )
            return {}
    
    def refresh_access_token(self, refresh_token: str) -> TokenData:
        """
        Refresh Google OAuth access token.
        
        Args:
            refresh_token: OAuth refresh token
            
        Returns:
            New token data
        """
        token_data = super().refresh_access_token(refresh_token)
        
        # Google may not always return a new refresh token
        # If no new refresh token is provided, keep the old one
        if not token_data.refresh_token:
            token_data.refresh_token = refresh_token
            
            logger.debug(
                f"Google did not provide new refresh token, keeping existing one",
                extra={'provider': self.provider_name}
            )
        
        return token_data
    
    def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """
        Revoke a Google OAuth token.
        
        Args:
            token: Token to revoke
            token_type: Type of token (access_token or refresh_token)
            
        Returns:
            True if revocation was successful
        """
        if not self.config:
            logger.warning(
                f"Cannot revoke token - provider not configured",
                extra={'provider': self.provider_name}
            )
            return False
        
        try:
            # Google's revoke endpoint accepts both access and refresh tokens
            # and will revoke all associated tokens
            self._make_http_request(
                self.REVOKE_URL,
                data={'token': token},
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            logger.info(
                f"Successfully revoked Google token",
                extra={
                    'provider': self.provider_name,
                    'token_type': token_type,
                }
            )
            
            return True
            
        except HTTPError as e:
            # Google returns 200 for successful revocation
            if e.code == 200:
                logger.info(
                    f"Successfully revoked Google token",
                    extra={
                        'provider': self.provider_name,
                        'token_type': token_type,
                    }
                )
                return True
            else:
                logger.warning(
                    f"Failed to revoke Google token",
                    extra={
                        'provider': self.provider_name,
                        'status_code': e.code,
                        'token_type': token_type,
                    }
                )
                return False
        
        except Exception as e:
            logger.error(
                f"Error revoking Google token: {e}",
                extra={
                    'provider': self.provider_name,
                    'token_type': token_type,
                }
            )
            return False
    
    def get_provider_metadata(self) -> Dict[str, Any]:
        """
        Get Google OAuth provider metadata.
        
        Returns:
            Provider metadata including endpoints and capabilities
        """
        return {
            'provider_name': self.provider_name,
            'display_name': self.display_name,
            'authorization_endpoint': self.AUTHORIZATION_URL,
            'token_endpoint': self.TOKEN_URL,
            'userinfo_endpoint': self.USER_INFO_URL,
            'revocation_endpoint': self.REVOKE_URL,
            'jwks_uri': self.JWKS_URL,
            'supported_scopes': list(self.supported_scopes),
            'default_scopes': self.DEFAULT_SCOPES,
            'required_scopes': self.REQUIRED_SCOPES,
            'supports_pkce': True,
            'supports_refresh_token': True,
            'supports_id_token': True,
            'supports_openid_connect': True,
            'issuer': 'https://accounts.google.com',
            'documentation_url': 'https://developers.google.com/identity/protocols/oauth2',
            'privacy_policy_url': 'https://policies.google.com/privacy',
            'terms_of_service_url': 'https://policies.google.com/terms',
        }