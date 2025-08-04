"""
OAuth callback service for comprehensive error handling and fallback authentication.

This service provides centralized error handling for OAuth callback flows,
including monitoring, logging, and fallback authentication methods.
"""

import logging
from typing import Any, Dict, Optional
from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

from ..exceptions import (
    OAuthError,
    OAuthProviderError,
    OAuthStateInvalidError,
    OAuthCodeInvalidError,
    OAuthUserInfoError,
    OAuthTokenExpiredError,
    OAuthAccountAlreadyLinkedError,
    SecurityError,
    ValidationError,
)
from ..models.user import UserIdentity
from ..utils.monitoring import oauth_metrics

User = get_user_model()
logger = logging.getLogger(__name__)


class OAuthCallbackService:
    """
    Service for handling OAuth callback errors and providing fallback authentication.
    
    This service centralizes error handling for OAuth flows and provides
    comprehensive monitoring, logging, and fallback mechanisms.
    """
    
    def __init__(self):
        """Initialize the OAuth callback service."""
        self.fallback_methods = {
            'email_password': self._suggest_email_password_fallback,
            'magic_link': self._suggest_magic_link_fallback,
            'alternative_oauth': self._suggest_alternative_oauth_fallback,
        }
    
    def handle_oauth_provider_error(
        self,
        provider_name: str,
        oauth_error: str,
        error_description: str,
        error_uri: str,
        correlation_id: str
    ) -> Response:
        """
        Handle OAuth provider errors with appropriate fallback suggestions.
        
        Args:
            provider_name: Name of the OAuth provider
            oauth_error: OAuth error code from provider
            error_description: Error description from provider
            error_uri: Error URI from provider
            correlation_id: Request correlation ID
            
        Returns:
            Response with error details and fallback suggestions
        """
        # Record OAuth provider error metrics
        oauth_metrics.record_provider_error(
            provider=provider_name,
            error_code=oauth_error,
            error_description=error_description
        )
        
        # Map OAuth error codes to user-friendly messages and fallbacks
        error_mapping = {
            'access_denied': {
                'message': 'You denied access to your account. Authentication was cancelled.',
                'user_action': 'Try again and grant the necessary permissions.',
                'fallbacks': ['alternative_oauth', 'email_password'],
                'status_code': status.HTTP_400_BAD_REQUEST,
                'retry_available': True,
            },
            'invalid_request': {
                'message': 'The authentication request was invalid.',
                'user_action': 'Please try authenticating again.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_400_BAD_REQUEST,
                'retry_available': True,
            },
            'invalid_client': {
                'message': 'There was a configuration issue with the authentication provider.',
                'user_action': 'Please contact support or try an alternative method.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_422_UNPROCESSABLE_ENTITY,
                'retry_available': False,
            },
            'invalid_grant': {
                'message': 'The authentication code has expired or is invalid.',
                'user_action': 'Please try authenticating again.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_400_BAD_REQUEST,
                'retry_available': True,
            },
            'unauthorized_client': {
                'message': 'This application is not authorized to use this authentication method.',
                'user_action': 'Please contact support or try an alternative method.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_422_UNPROCESSABLE_ENTITY,
                'retry_available': False,
            },
            'unsupported_response_type': {
                'message': 'The authentication method is not supported.',
                'user_action': 'Please try an alternative authentication method.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_422_UNPROCESSABLE_ENTITY,
                'retry_available': False,
            },
            'invalid_scope': {
                'message': 'The requested permissions are not available.',
                'user_action': 'Please try again with different permissions.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_400_BAD_REQUEST,
                'retry_available': True,
            },
            'server_error': {
                'message': 'The authentication provider is experiencing issues.',
                'user_action': 'Please try again later or use an alternative method.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_502_BAD_GATEWAY,
                'retry_available': True,
            },
            'temporarily_unavailable': {
                'message': 'The authentication provider is temporarily unavailable.',
                'user_action': 'Please try again in a few minutes.',
                'fallbacks': ['email_password', 'alternative_oauth'],
                'status_code': status.HTTP_503_SERVICE_UNAVAILABLE,
                'retry_available': True,
            },
        }
        
        error_info = error_mapping.get(oauth_error, {
            'message': f'Authentication failed: {error_description or oauth_error}',
            'user_action': 'Please try an alternative authentication method.',
            'fallbacks': ['email_password', 'alternative_oauth'],
            'status_code': status.HTTP_400_BAD_REQUEST,
            'retry_available': True,
        })
        
        # Generate fallback suggestions
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=error_info['fallbacks']
        )
        
        # Log structured error information
        logger.error(
            f"OAuth provider error handled for {provider_name}",
            extra={
                'provider': provider_name,
                'oauth_error': oauth_error,
                'error_description': error_description,
                'error_uri': error_uri,
                'correlation_id': correlation_id,
                'fallback_count': len(fallback_suggestions),
            }
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_PROVIDER_ERROR',
                'message': error_info['message'],
                'provider': provider_name,
                'oauth_error': oauth_error,
                'oauth_error_description': error_description,
                'oauth_error_uri': error_uri,
                'user_action': error_info['user_action'],
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': error_info.get('retry_available', True),
            'timestamp': timezone.now().isoformat(),
        }, status=error_info['status_code'])
    
    def handle_missing_parameters_error(
        self,
        provider_name: str,
        correlation_id: str
    ) -> Response:
        """Handle missing OAuth callback parameters."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='missing_parameters'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_MISSING_PARAMETERS',
                'message': 'Required OAuth callback parameters are missing.',
                'provider': provider_name,
                'user_action': 'Please try authenticating again.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': True,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_state_mismatch_error(
        self,
        provider_name: str,
        correlation_id: str
    ) -> Response:
        """Handle OAuth state parameter mismatch (potential CSRF attack)."""
        oauth_metrics.record_security_event(
            provider=provider_name,
            event_type='state_mismatch',
            severity='high'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_STATE_MISMATCH',
                'message': 'Invalid OAuth state parameter. This may indicate a security issue.',
                'provider': provider_name,
                'user_action': 'Please clear your browser cache and try authenticating again.',
                'security_warning': 'If this problem persists, please contact support.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': True,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_callback_processing_error(
        self,
        provider_name: str,
        error: Exception,
        correlation_id: str
    ) -> Response:
        """Handle OAuth callback processing errors."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='processing_error'
        )
        
        # Determine error type and appropriate response
        if isinstance(error, OAuthTokenExpiredError):
            message = 'The authentication code has expired. Please try again.'
            retry_available = True
        elif isinstance(error, OAuthCodeInvalidError):
            message = 'The authentication code is invalid. Please try again.'
            retry_available = True
        elif isinstance(error, OAuthUserInfoError):
            message = 'Unable to retrieve user information from the provider.'
            retry_available = True
        else:
            message = 'Authentication processing failed. Please try again.'
            retry_available = True
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_PROCESSING_ERROR',
                'message': message,
                'provider': provider_name,
                'user_action': 'Please try authenticating again.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': retry_available,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_missing_user_data_error(
        self,
        provider_name: str,
        correlation_id: str
    ) -> Response:
        """Handle missing essential user data from OAuth provider."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='missing_user_data'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_MISSING_USER_DATA',
                'message': 'Essential user information is missing from the authentication provider.',
                'provider': provider_name,
                'user_action': 'Please ensure your account has a valid email address and try again.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': True,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_user_creation_error(
        self,
        provider_name: str,
        error: Exception,
        correlation_id: str
    ) -> Response:
        """Handle user account creation or linking errors."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='user_creation_error'
        )
        
        # Determine specific error type
        if isinstance(error, OAuthAccountAlreadyLinkedError):
            message = 'This account is already linked to another user.'
            user_action = 'Please use a different account or contact support.'
        elif isinstance(error, ValidationError):
            message = 'User account validation failed.'
            user_action = 'Please check your account information and try again.'
        else:
            message = 'Unable to create or link user account.'
            user_action = 'Please try again or contact support if the problem persists.'
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_USER_CREATION_ERROR',
                'message': message,
                'provider': provider_name,
                'user_action': user_action,
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': False,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_token_generation_error(
        self,
        provider_name: str,
        error: Exception,
        correlation_id: str
    ) -> Response:
        """Handle JWT token generation errors."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='token_generation_error'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_TOKEN_GENERATION_ERROR',
                'message': 'Unable to generate authentication tokens.',
                'provider': provider_name,
                'user_action': 'Please try again or contact support.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': True,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def handle_provider_not_found_error(
        self,
        provider_name: str,
        correlation_id: str
    ) -> Response:
        """Handle OAuth provider not found errors."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='provider_not_found'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_PROVIDER_NOT_FOUND',
                'message': f'OAuth provider "{provider_name}" is not available.',
                'provider': provider_name,
                'user_action': 'Please try a different authentication method.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': False,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_404_NOT_FOUND)
    
    def handle_provider_unavailable_error(
        self,
        provider_name: str,
        error: Exception,
        correlation_id: str
    ) -> Response:
        """Handle OAuth provider unavailable errors."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='provider_unavailable'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_PROVIDER_UNAVAILABLE',
                'message': f'OAuth provider "{provider_name}" is currently unavailable.',
                'provider': provider_name,
                'user_action': 'Please try a different authentication method.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': False,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
    
    def handle_oauth_error(
        self,
        provider_name: str,
        error: OAuthError,
        correlation_id: str
    ) -> Response:
        """Handle general OAuth errors."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='oauth_error'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_ERROR',
                'message': 'OAuth authentication failed.',
                'provider': provider_name,
                'details': str(error),
                'user_action': 'Please try again or use an alternative method.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': True,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def handle_unexpected_error(
        self,
        provider_name: str,
        error: Exception,
        correlation_id: str
    ) -> Response:
        """Handle unexpected errors during OAuth callback."""
        oauth_metrics.record_callback_error(
            provider=provider_name,
            error_type='unexpected_error'
        )
        
        fallback_suggestions = self._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth']
        )
        
        return Response({
            'error': {
                'code': 'OAUTH_UNEXPECTED_ERROR',
                'message': 'An unexpected error occurred during authentication.',
                'provider': provider_name,
                'user_action': 'Please try again or contact support if the problem persists.',
                'correlation_id': correlation_id,
            },
            'fallback_methods': fallback_suggestions,
            'retry_available': True,
            'timestamp': timezone.now().isoformat(),
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def record_successful_authentication(
        self,
        provider_name: str,
        user: User,
        identity: UserIdentity,
        is_new_user: bool,
        correlation_id: str,
        request_info: Dict[str, Any]
    ) -> None:
        """Record successful OAuth authentication for monitoring."""
        oauth_metrics.record_successful_authentication(
            provider=provider_name,
            user_id=str(user.id),
            is_new_user=is_new_user,
            correlation_id=correlation_id
        )
        
        # Log authentication success with detailed information
        logger.info(
            f"OAuth authentication success recorded for {provider_name}",
            extra={
                'provider': provider_name,
                'user_id': user.id,
                'identity_id': identity.id,
                'is_new_user': is_new_user,
                'correlation_id': correlation_id,
                'ip_address': request_info.get('ip_address'),
                'user_agent': request_info.get('user_agent'),
            }
        )
    
    def _generate_fallback_suggestions(
        self,
        provider_name: str,
        fallback_methods: list
    ) -> list:
        """Generate fallback authentication method suggestions."""
        suggestions = []
        
        for method in fallback_methods:
            if method in self.fallback_methods:
                suggestion = self.fallback_methods[method](provider_name)
                if suggestion:
                    suggestions.append(suggestion)
        
        return suggestions
    
    def _suggest_email_password_fallback(self, provider_name: str) -> Dict[str, Any]:
        """Suggest email/password authentication as fallback."""
        return {
            'method': 'email_password',
            'title': 'Sign in with Email',
            'description': 'Use your email address and password to sign in.',
            'endpoint': '/api/v1/auth/login',
            'requires_registration': False,
            'estimated_time': '30 seconds',
        }
    
    def _suggest_magic_link_fallback(self, provider_name: str) -> Dict[str, Any]:
        """Suggest magic link authentication as fallback."""
        return {
            'method': 'magic_link',
            'title': 'Sign in with Magic Link',
            'description': 'Receive a secure link via email to sign in without a password.',
            'endpoint': '/api/v1/auth/magic-link',
            'requires_registration': False,
            'estimated_time': '2 minutes',
        }
    
    def _suggest_alternative_oauth_fallback(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """Suggest alternative OAuth providers as fallback."""
        # Import here to avoid circular imports
        from .oauth_service import oauth_service
        
        try:
            available_providers = oauth_service.get_available_providers()
            alternative_providers = [
                p for p in available_providers 
                if p['name'] != provider_name and p['enabled']
            ]
            
            if alternative_providers:
                # Suggest the most popular alternative
                popular_providers = ['google', 'github', 'microsoft']
                for popular in popular_providers:
                    for provider in alternative_providers:
                        if provider['name'] == popular:
                            return {
                                'method': 'oauth',
                                'title': f"Sign in with {provider['display_name']}",
                                'description': f"Use your {provider['display_name']} account to sign in.",
                                'endpoint': f"/api/v1/oauth/{provider['name']}/authorize",
                                'provider': provider['name'],
                                'requires_registration': False,
                                'estimated_time': '1 minute',
                            }
                
                # If no popular provider found, suggest the first available
                provider = alternative_providers[0]
                return {
                    'method': 'oauth',
                    'title': f"Sign in with {provider['display_name']}",
                    'description': f"Use your {provider['display_name']} account to sign in.",
                    'endpoint': f"/api/v1/oauth/{provider['name']}/authorize",
                    'provider': provider['name'],
                    'requires_registration': False,
                    'estimated_time': '1 minute',
                }
        except Exception as e:
            logger.warning(f"Failed to suggest alternative OAuth providers: {e}")
        
        return None


# Global OAuth callback service instance
oauth_callback_service = OAuthCallbackService()