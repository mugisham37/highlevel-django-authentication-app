"""
OAuth service for managing OAuth provider integrations.

This module provides a high-level service for managing OAuth providers,
handling authentication flows, and managing user identity linking.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from ..exceptions import (
    ConfigurationError,
    OAuthError,
    OAuthProviderDisabledError,
    OAuthProviderNotConfiguredError,
    OAuthProviderNotFoundError,
    OAuthScopeError,
)
from ..models.user import UserIdentity
from .oauth_config import oauth_config_manager
from .oauth_provider import AuthorizationRequest, IOAuthProvider, NormalizedUserData, TokenData
from .oauth_registry import oauth_registry

User = get_user_model()
logger = logging.getLogger(__name__)


class OAuthService:
    """
    High-level service for OAuth provider management and authentication flows.
    
    This service provides a unified interface for working with OAuth providers,
    managing user identities, and handling authentication workflows.
    """
    
    def __init__(self):
        """Initialize the OAuth service."""
        self.registry = oauth_registry
        self.config_manager = oauth_config_manager
    
    def initialize(self) -> None:
        """Initialize OAuth providers from settings."""
        try:
            self.registry.initialize_from_settings()
            logger.info("OAuth service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OAuth service: {e}")
            raise ConfigurationError(f"OAuth service initialization failed: {e}")
    
    def get_available_providers(self) -> List[Dict[str, Any]]:
        """
        Get list of available OAuth providers for client applications.
        
        Returns:
            List of provider information dictionaries
        """
        return self.registry.get_available_providers()
    
    def get_provider(self, provider_name: str) -> IOAuthProvider:
        """
        Get a configured OAuth provider instance.
        
        Args:
            provider_name: Name of the OAuth provider
            
        Returns:
            Configured provider instance
            
        Raises:
            OAuthProviderNotFoundError: If provider is not registered
            OAuthProviderNotConfiguredError: If provider is not configured
            OAuthProviderDisabledError: If provider is disabled
        """
        try:
            return self.registry.get_provider(provider_name)
        except KeyError:
            raise OAuthProviderNotFoundError(
                f"OAuth provider '{provider_name}' not found",
                provider=provider_name
            )
        except ConfigurationError as e:
            if "not configured" in str(e):
                raise OAuthProviderNotConfiguredError(
                    f"OAuth provider '{provider_name}' is not configured",
                    provider=provider_name
                )
            raise
        except OAuthError as e:
            if "disabled" in str(e):
                raise OAuthProviderDisabledError(
                    f"OAuth provider '{provider_name}' is disabled",
                    provider=provider_name
                )
            raise
    
    def initiate_authorization(
        self,
        provider_name: str,
        state: str,
        scopes: Optional[List[str]] = None,
        extra_params: Optional[Dict[str, str]] = None
    ) -> AuthorizationRequest:
        """
        Initiate OAuth authorization flow.
        
        Args:
            provider_name: Name of the OAuth provider
            state: State parameter for CSRF protection
            scopes: List of OAuth scopes to request
            extra_params: Additional parameters for authorization URL
            
        Returns:
            Authorization request data including URL and PKCE parameters
            
        Raises:
            OAuthProviderNotFoundError: If provider is not found
            OAuthScopeError: If requested scopes are not supported
        """
        provider = self.get_provider(provider_name)
        
        # Validate scopes if provided
        if scopes:
            supported_scopes = provider.supported_scopes
            requested_scopes = set(scopes)
            if not requested_scopes.issubset(supported_scopes):
                unsupported = requested_scopes - supported_scopes
                raise OAuthScopeError(
                    f"Unsupported scopes for {provider_name}: {unsupported}",
                    requested_scopes=scopes,
                    supported_scopes=list(supported_scopes)
                )
        
        try:
            auth_request = provider.get_authorization_url(
                state=state,
                scopes=scopes,
                extra_params=extra_params
            )
            
            logger.info(
                f"Initiated OAuth authorization for {provider_name}",
                extra={
                    'provider': provider_name,
                    'state': state,
                    'scopes': scopes,
                }
            )
            
            return auth_request
            
        except Exception as e:
            logger.error(
                f"Failed to initiate OAuth authorization for {provider_name}",
                extra={'provider': provider_name, 'error': str(e)}
            )
            raise OAuthError(
                f"Failed to initiate authorization for {provider_name}: {e}",
                provider=provider_name
            )
    
    def handle_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        code_verifier: Optional[str] = None
    ) -> Tuple[TokenData, NormalizedUserData]:
        """
        Handle OAuth callback and exchange code for tokens and user data.
        
        Args:
            provider_name: Name of the OAuth provider
            code: Authorization code from callback
            state: State parameter for verification
            code_verifier: PKCE code verifier if used
            
        Returns:
            Tuple of (token_data, user_data)
            
        Raises:
            OAuthProviderNotFoundError: If provider is not found
            OAuthError: If callback handling fails
        """
        provider = self.get_provider(provider_name)
        
        try:
            # Exchange code for tokens
            token_data = provider.exchange_code_for_token(
                code=code,
                state=state,
                code_verifier=code_verifier
            )
            
            # Get user information
            user_data = provider.get_user_info(token_data.access_token)
            
            logger.info(
                f"Successfully handled OAuth callback for {provider_name}",
                extra={
                    'provider': provider_name,
                    'state': state,
                    'user_id': user_data.provider_user_id,
                }
            )
            
            return token_data, user_data
            
        except Exception as e:
            logger.error(
                f"Failed to handle OAuth callback for {provider_name}",
                extra={'provider': provider_name, 'error': str(e)}
            )
            raise
    
    @transaction.atomic
    def link_user_identity(
        self,
        user: User,
        provider_name: str,
        token_data: TokenData,
        user_data: NormalizedUserData,
        is_primary: bool = False
    ) -> UserIdentity:
        """
        Link OAuth provider identity to user account.
        
        Args:
            user: User to link identity to
            provider_name: Name of the OAuth provider
            token_data: OAuth token data
            user_data: Normalized user data from provider
            is_primary: Whether this should be the primary identity for the provider
            
        Returns:
            Created or updated UserIdentity instance
            
        Raises:
            OAuthError: If identity linking fails
        """
        try:
            # Check if identity already exists
            identity, created = UserIdentity.objects.get_or_create(
                provider=provider_name,
                provider_user_id=user_data.provider_user_id,
                defaults={
                    'user': user,
                    'provider_username': user_data.username,
                    'provider_email': user_data.email,
                    'provider_data': user_data.raw_data or {},
                    'is_verified': user_data.verified_email,
                    'is_primary': is_primary,
                }
            )
            
            if not created:
                # Update existing identity
                if identity.user != user:
                    raise OAuthError(
                        f"Identity {provider_name}:{user_data.provider_user_id} is already linked to another user",
                        provider=provider_name
                    )
                
                # Update identity data
                identity.provider_username = user_data.username
                identity.provider_email = user_data.email
                identity.provider_data = user_data.raw_data or {}
                identity.is_verified = user_data.verified_email
                identity.last_used = timezone.now()
                
                if is_primary:
                    identity.set_as_primary()
                
                identity.save()
            
            # Store tokens
            if token_data.access_token:
                identity.set_access_token(
                    token_data.access_token,
                    token_data.expires_in
                )
            
            if token_data.refresh_token:
                identity.set_refresh_token(token_data.refresh_token)
            
            # Mark as used
            identity.mark_as_used()
            
            logger.info(
                f"{'Created' if created else 'Updated'} identity link for {provider_name}",
                extra={
                    'provider': provider_name,
                    'user_id': user.id,
                    'provider_user_id': user_data.provider_user_id,
                    'created': created,
                }
            )
            
            return identity
            
        except Exception as e:
            logger.error(
                f"Failed to link user identity for {provider_name}",
                extra={
                    'provider': provider_name,
                    'user_id': user.id,
                    'error': str(e)
                }
            )
            raise OAuthError(
                f"Failed to link identity for {provider_name}: {e}",
                provider=provider_name
            )
    
    def get_user_identities(self, user: User, provider_name: Optional[str] = None) -> List[UserIdentity]:
        """
        Get user's OAuth identities.
        
        Args:
            user: User to get identities for
            provider_name: Optional provider name to filter by
            
        Returns:
            List of user identities
        """
        queryset = user.identities.all()
        
        if provider_name:
            queryset = queryset.filter(provider=provider_name)
        
        return list(queryset.order_by('-last_used'))
    
    @transaction.atomic
    def unlink_user_identity(self, user: User, provider_name: str) -> bool:
        """
        Unlink OAuth provider identity from user account.
        
        Args:
            user: User to unlink identity from
            provider_name: Name of the OAuth provider
            
        Returns:
            True if identity was unlinked, False if not found
        """
        try:
            identity = UserIdentity.objects.get(
                user=user,
                provider=provider_name
            )
            
            # Revoke tokens if possible
            try:
                provider = self.get_provider(provider_name)
                access_token = identity.get_access_token()
                if access_token:
                    provider.revoke_token(access_token)
            except Exception as e:
                logger.warning(
                    f"Failed to revoke tokens during identity unlink: {e}",
                    extra={'provider': provider_name, 'user_id': user.id}
                )
            
            identity.delete()
            
            logger.info(
                f"Unlinked identity for {provider_name}",
                extra={'provider': provider_name, 'user_id': user.id}
            )
            
            return True
            
        except UserIdentity.DoesNotExist:
            return False
        except Exception as e:
            logger.error(
                f"Failed to unlink identity for {provider_name}",
                extra={'provider': provider_name, 'user_id': user.id, 'error': str(e)}
            )
            raise OAuthError(
                f"Failed to unlink identity for {provider_name}: {e}",
                provider=provider_name
            )
    
    def refresh_user_tokens(self, user: User, provider_name: str) -> bool:
        """
        Refresh OAuth tokens for a user's identity.
        
        Args:
            user: User whose tokens to refresh
            provider_name: Name of the OAuth provider
            
        Returns:
            True if tokens were refreshed successfully
            
        Raises:
            OAuthError: If token refresh fails
        """
        try:
            identity = UserIdentity.objects.get(
                user=user,
                provider=provider_name
            )
            
            refresh_token = identity.get_refresh_token()
            if not refresh_token:
                raise OAuthError(
                    f"No refresh token available for {provider_name}",
                    provider=provider_name
                )
            
            provider = self.get_provider(provider_name)
            token_data = provider.refresh_access_token(refresh_token)
            
            # Update stored tokens
            identity.set_access_token(
                token_data.access_token,
                token_data.expires_in
            )
            
            if token_data.refresh_token:
                identity.set_refresh_token(token_data.refresh_token)
            
            identity.mark_as_used()
            
            logger.info(
                f"Refreshed tokens for {provider_name}",
                extra={'provider': provider_name, 'user_id': user.id}
            )
            
            return True
            
        except UserIdentity.DoesNotExist:
            raise OAuthError(
                f"No identity found for {provider_name}",
                provider=provider_name
            )
        except Exception as e:
            logger.error(
                f"Failed to refresh tokens for {provider_name}",
                extra={'provider': provider_name, 'user_id': user.id, 'error': str(e)}
            )
            raise OAuthError(
                f"Failed to refresh tokens for {provider_name}: {e}",
                provider=provider_name
            )
    
    def find_user_by_provider_identity(
        self,
        provider_name: str,
        provider_user_id: str
    ) -> Optional[User]:
        """
        Find user by OAuth provider identity.
        
        Args:
            provider_name: Name of the OAuth provider
            provider_user_id: Provider's user ID
            
        Returns:
            User if found, None otherwise
        """
        try:
            identity = UserIdentity.objects.select_related('user').get(
                provider=provider_name,
                provider_user_id=provider_user_id
            )
            return identity.user
        except UserIdentity.DoesNotExist:
            return None
    
    def get_provider_health_status(self) -> Dict[str, Any]:
        """
        Get health status of all OAuth providers.
        
        Returns:
            Health status information
        """
        return self.registry.health_check()
    
    def validate_provider_configuration(self, provider_name: str) -> List[str]:
        """
        Validate OAuth provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            
        Returns:
            List of validation errors (empty if valid)
        """
        try:
            provider = self.get_provider(provider_name)
            provider.validate_configuration()
            return []
        except Exception as e:
            return [str(e)]


# Global OAuth service instance
oauth_service = OAuthService()