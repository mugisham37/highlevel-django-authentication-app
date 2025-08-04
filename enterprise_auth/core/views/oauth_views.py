"""
OAuth authentication API views.

This module provides API endpoints for OAuth provider integration,
including authorization initiation, callback handling, and account linking.
"""

import logging
import secrets
from typing import Dict, Any, Optional

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from ..authentication import JWTAuthentication
from ..exceptions import (
    OAuthError,
    OAuthProviderNotFoundError,
    OAuthProviderNotConfiguredError,
    OAuthProviderDisabledError,
    OAuthScopeError,
)
from ..models.user import UserProfile, UserIdentity
from ..services.oauth_service import oauth_service
from ..services.jwt_service import jwt_service, DeviceInfo
from ..utils.request_utils import extract_request_info

User = get_user_model()
logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
def list_oauth_providers(request: Request) -> Response:
    """
    List available OAuth providers.
    
    Returns a list of configured and enabled OAuth providers
    that can be used for authentication.
    
    Returns:
        200: List of available OAuth providers
        500: Internal server error
    """
    try:
        providers = oauth_service.get_available_providers()
        
        return Response({
            'providers': providers,
            'count': len(providers)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(
            f"Failed to list OAuth providers: {e}",
            extra={'error': str(e)}
        )
        return Response({
            'error': 'Failed to retrieve OAuth providers',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def initiate_oauth_authorization(request: Request, provider_name: str) -> Response:
    """
    Initiate OAuth authorization flow for a specific provider.
    
    This endpoint generates an authorization URL for the specified OAuth provider
    and returns it along with state information for CSRF protection.
    
    Args:
        provider_name: Name of the OAuth provider (e.g., 'google')
        
    Request Body:
        scopes (list, optional): List of OAuth scopes to request
        redirect_uri (str, optional): Custom redirect URI (if different from configured)
        
    Returns:
        200: Authorization URL and state information
        400: Invalid request data
        404: OAuth provider not found
        422: OAuth provider not configured or disabled
        500: Internal server error
    """
    try:
        # Extract request parameters
        scopes = request.data.get('scopes')
        custom_redirect_uri = request.data.get('redirect_uri')
        
        # Generate secure state parameter
        state = secrets.token_urlsafe(32)
        
        # Store state in session for verification
        request.session[f'oauth_state_{provider_name}'] = state
        
        # Prepare extra parameters
        extra_params = {}
        if custom_redirect_uri:
            extra_params['redirect_uri'] = custom_redirect_uri
        
        # Initiate authorization
        auth_request = oauth_service.initiate_authorization(
            provider_name=provider_name,
            state=state,
            scopes=scopes,
            extra_params=extra_params if extra_params else None
        )
        
        # Store PKCE code verifier in session if present
        if auth_request.code_verifier:
            request.session[f'oauth_code_verifier_{provider_name}'] = auth_request.code_verifier
        
        logger.info(
            f"Initiated OAuth authorization for {provider_name}",
            extra={
                'provider': provider_name,
                'state': state,
                'scopes': scopes,
                'has_pkce': bool(auth_request.code_verifier),
            }
        )
        
        return Response({
            'authorization_url': auth_request.authorization_url,
            'state': state,
            'provider': provider_name,
            'uses_pkce': bool(auth_request.code_verifier),
        }, status=status.HTTP_200_OK)
        
    except OAuthProviderNotFoundError as e:
        logger.warning(f"OAuth provider not found: {provider_name}")
        return Response({
            'error': f'OAuth provider "{provider_name}" not found',
            'provider': provider_name
        }, status=status.HTTP_404_NOT_FOUND)
        
    except (OAuthProviderNotConfiguredError, OAuthProviderDisabledError) as e:
        logger.warning(f"OAuth provider not available: {provider_name} - {e}")
        return Response({
            'error': f'OAuth provider "{provider_name}" is not available',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
    except OAuthScopeError as e:
        logger.warning(f"Invalid OAuth scopes for {provider_name}: {e}")
        return Response({
            'error': 'Invalid OAuth scopes requested',
            'provider': provider_name,
            'details': str(e),
            'requested_scopes': getattr(e, 'requested_scopes', []),
            'supported_scopes': getattr(e, 'supported_scopes', [])
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(
            f"Failed to initiate OAuth authorization for {provider_name}: {e}",
            extra={'provider': provider_name, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to initiate OAuth authorization',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def handle_oauth_callback(request: Request, provider_name: str) -> Response:
    """
    Handle OAuth callback and complete authentication flow.
    
    This endpoint processes the OAuth callback, exchanges the authorization code
    for tokens, retrieves user information, and either creates a new user account
    or links the OAuth identity to an existing account.
    
    Args:
        provider_name: Name of the OAuth provider (e.g., 'google')
        
    Request Body:
        code (str): Authorization code from OAuth callback
        state (str): State parameter for CSRF verification
        
    Returns:
        200: JWT token pair and user information
        400: Invalid request data or state mismatch
        404: OAuth provider not found
        422: OAuth provider not configured or disabled
        500: Internal server error
    """
    try:
        # Extract callback parameters
        code = request.data.get('code')
        state = request.data.get('state')
        
        if not code or not state:
            return Response({
                'error': 'Missing required parameters: code and state'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify state parameter
        session_state = request.session.get(f'oauth_state_{provider_name}')
        if not session_state or session_state != state:
            logger.warning(
                f"OAuth state mismatch for {provider_name}",
                extra={
                    'provider': provider_name,
                    'expected_state': session_state,
                    'received_state': state,
                }
            )
            return Response({
                'error': 'Invalid state parameter',
                'provider': provider_name
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get PKCE code verifier from session
        code_verifier = request.session.get(f'oauth_code_verifier_{provider_name}')
        
        # Handle OAuth callback
        token_data, user_data = oauth_service.handle_callback(
            provider_name=provider_name,
            code=code,
            state=state,
            code_verifier=code_verifier
        )
        
        # Clean up session data
        request.session.pop(f'oauth_state_{provider_name}', None)
        request.session.pop(f'oauth_code_verifier_{provider_name}', None)
        
        # Find or create user account
        user = None
        identity = None
        is_new_user = False
        
        with transaction.atomic():
            # Try to find existing user by OAuth identity
            user = oauth_service.find_user_by_provider_identity(
                provider_name=provider_name,
                provider_user_id=user_data.provider_user_id
            )
            
            if not user and user_data.email:
                # Try to find existing user by email
                try:
                    user = User.objects.get(email=user_data.email, is_deleted=False)
                    logger.info(
                        f"Found existing user by email for OAuth {provider_name}",
                        extra={
                            'provider': provider_name,
                            'user_id': user.id,
                            'email': user_data.email,
                        }
                    )
                except User.DoesNotExist:
                    pass
            
            if not user:
                # Create new user account
                user = User.objects.create_user(
                    email=user_data.email,
                    first_name=user_data.first_name or '',
                    last_name=user_data.last_name or '',
                    is_email_verified=user_data.verified_email,
                    profile_picture_url=user_data.profile_picture_url,
                    language=user_data.locale[:2] if user_data.locale else 'en',
                    timezone=user_data.timezone or 'UTC',
                )
                is_new_user = True
                
                logger.info(
                    f"Created new user from OAuth {provider_name}",
                    extra={
                        'provider': provider_name,
                        'user_id': user.id,
                        'email': user_data.email,
                    }
                )
            
            # Link OAuth identity to user account
            identity = oauth_service.link_user_identity(
                user=user,
                provider_name=provider_name,
                token_data=token_data,
                user_data=user_data,
                is_primary=True
            )
        
        # Extract device information
        device_info = DeviceInfo(
            **extract_request_info(request)
        )
        
        # Generate JWT tokens
        jwt_tokens = jwt_service.generate_token_pair(
            user=user,
            device_info=device_info,
            scopes=['read', 'write']  # Default scopes for OAuth users
        )
        
        # Update user login metadata
        user.update_login_metadata(
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent
        )
        
        logger.info(
            f"OAuth authentication successful for {provider_name}",
            extra={
                'provider': provider_name,
                'user_id': user.id,
                'is_new_user': is_new_user,
                'identity_id': identity.id,
            }
        )
        
        return Response({
            'access_token': jwt_tokens.access_token,
            'refresh_token': jwt_tokens.refresh_token,
            'token_type': 'Bearer',
            'expires_in': jwt_tokens.expires_in,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'full_name': user.get_full_name(),
                'is_email_verified': user.is_email_verified,
                'profile_picture_url': user.profile_picture_url,
                'is_new_user': is_new_user,
            },
            'oauth_identity': {
                'provider': provider_name,
                'provider_user_id': user_data.provider_user_id,
                'provider_username': user_data.username,
                'is_primary': identity.is_primary,
                'linked_at': identity.linked_at.isoformat(),
            }
        }, status=status.HTTP_200_OK)
        
    except OAuthProviderNotFoundError as e:
        logger.warning(f"OAuth provider not found: {provider_name}")
        return Response({
            'error': f'OAuth provider "{provider_name}" not found',
            'provider': provider_name
        }, status=status.HTTP_404_NOT_FOUND)
        
    except (OAuthProviderNotConfiguredError, OAuthProviderDisabledError) as e:
        logger.warning(f"OAuth provider not available: {provider_name} - {e}")
        return Response({
            'error': f'OAuth provider "{provider_name}" is not available',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        
    except OAuthError as e:
        logger.error(
            f"OAuth callback failed for {provider_name}: {e}",
            extra={'provider': provider_name, 'error': str(e)}
        )
        return Response({
            'error': 'OAuth authentication failed',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(
            f"Unexpected error in OAuth callback for {provider_name}: {e}",
            extra={'provider': provider_name, 'error': str(e)}
        )
        return Response({
            'error': 'OAuth authentication failed',
            'provider': provider_name,
            'details': 'An unexpected error occurred'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_user_oauth_identities(request: Request) -> Response:
    """
    List OAuth identities linked to the authenticated user.
    
    Returns a list of all OAuth provider identities linked to the user's account.
    
    Returns:
        200: List of linked OAuth identities
        401: User not authenticated
    """
    try:
        identities = oauth_service.get_user_identities(request.user)
        
        identity_data = []
        for identity in identities:
            identity_data.append({
                'id': str(identity.id),
                'provider': identity.provider,
                'provider_user_id': identity.provider_user_id,
                'provider_username': identity.provider_username,
                'provider_email': identity.provider_email,
                'is_primary': identity.is_primary,
                'is_verified': identity.is_verified,
                'linked_at': identity.linked_at.isoformat(),
                'last_used': identity.last_used.isoformat(),
            })
        
        return Response({
            'identities': identity_data,
            'count': len(identity_data)
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(
            f"Failed to list user OAuth identities: {e}",
            extra={'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to retrieve OAuth identities',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def link_oauth_identity(request: Request, provider_name: str) -> Response:
    """
    Link an additional OAuth identity to the authenticated user's account.
    
    This endpoint allows users to link additional OAuth provider accounts
    to their existing user account for multiple authentication options.
    
    Args:
        provider_name: Name of the OAuth provider to link
        
    Request Body:
        code (str): Authorization code from OAuth callback
        state (str): State parameter for CSRF verification
        
    Returns:
        200: Successfully linked OAuth identity
        400: Invalid request data or state mismatch
        404: OAuth provider not found
        409: OAuth identity already linked to another account
        422: OAuth provider not configured or disabled
        500: Internal server error
    """
    try:
        # Extract callback parameters
        code = request.data.get('code')
        state = request.data.get('state')
        
        if not code or not state:
            return Response({
                'error': 'Missing required parameters: code and state'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify state parameter
        session_state = request.session.get(f'oauth_state_{provider_name}')
        if not session_state or session_state != state:
            return Response({
                'error': 'Invalid state parameter',
                'provider': provider_name
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get PKCE code verifier from session
        code_verifier = request.session.get(f'oauth_code_verifier_{provider_name}')
        
        # Handle OAuth callback
        token_data, user_data = oauth_service.handle_callback(
            provider_name=provider_name,
            code=code,
            state=state,
            code_verifier=code_verifier
        )
        
        # Clean up session data
        request.session.pop(f'oauth_state_{provider_name}', None)
        request.session.pop(f'oauth_code_verifier_{provider_name}', None)
        
        # Check if this OAuth identity is already linked to another user
        existing_user = oauth_service.find_user_by_provider_identity(
            provider_name=provider_name,
            provider_user_id=user_data.provider_user_id
        )
        
        if existing_user and existing_user != request.user:
            logger.warning(
                f"OAuth identity already linked to another user",
                extra={
                    'provider': provider_name,
                    'provider_user_id': user_data.provider_user_id,
                    'current_user_id': request.user.id,
                    'existing_user_id': existing_user.id,
                }
            )
            return Response({
                'error': 'This OAuth account is already linked to another user',
                'provider': provider_name
            }, status=status.HTTP_409_CONFLICT)
        
        # Link OAuth identity to current user
        with transaction.atomic():
            identity = oauth_service.link_user_identity(
                user=request.user,
                provider_name=provider_name,
                token_data=token_data,
                user_data=user_data,
                is_primary=False  # Additional identities are not primary by default
            )
        
        logger.info(
            f"Successfully linked OAuth identity for {provider_name}",
            extra={
                'provider': provider_name,
                'user_id': request.user.id,
                'identity_id': identity.id,
            }
        )
        
        return Response({
            'message': f'Successfully linked {provider_name} account',
            'identity': {
                'id': str(identity.id),
                'provider': identity.provider,
                'provider_user_id': identity.provider_user_id,
                'provider_username': identity.provider_username,
                'provider_email': identity.provider_email,
                'is_primary': identity.is_primary,
                'is_verified': identity.is_verified,
                'linked_at': identity.linked_at.isoformat(),
            }
        }, status=status.HTTP_200_OK)
        
    except OAuthError as e:
        logger.error(
            f"Failed to link OAuth identity for {provider_name}: {e}",
            extra={'provider': provider_name, 'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to link OAuth account',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(
            f"Unexpected error linking OAuth identity for {provider_name}: {e}",
            extra={'provider': provider_name, 'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to link OAuth account',
            'provider': provider_name,
            'details': 'An unexpected error occurred'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def unlink_oauth_identity(request: Request, provider_name: str) -> Response:
    """
    Unlink an OAuth identity from the authenticated user's account.
    
    This endpoint allows users to remove OAuth provider accounts
    from their user account.
    
    Args:
        provider_name: Name of the OAuth provider to unlink
        
    Returns:
        200: Successfully unlinked OAuth identity
        404: OAuth identity not found
        500: Internal server error
    """
    try:
        # Unlink the OAuth identity
        success = oauth_service.unlink_user_identity(
            user=request.user,
            provider_name=provider_name
        )
        
        if success:
            logger.info(
                f"Successfully unlinked OAuth identity for {provider_name}",
                extra={'provider': provider_name, 'user_id': request.user.id}
            )
            return Response({
                'message': f'Successfully unlinked {provider_name} account',
                'provider': provider_name
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': f'No {provider_name} account found to unlink',
                'provider': provider_name
            }, status=status.HTTP_404_NOT_FOUND)
        
    except Exception as e:
        logger.error(
            f"Failed to unlink OAuth identity for {provider_name}: {e}",
            extra={'provider': provider_name, 'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to unlink OAuth account',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_provider_health(request: Request) -> Response:
    """
    Get health status of all OAuth providers.
    
    Returns the health status and configuration status of all registered
    OAuth providers for monitoring and debugging purposes.
    
    Returns:
        200: OAuth provider health status
        500: Internal server error
    """
    try:
        health_status = oauth_service.get_provider_health_status()
        
        return Response(health_status, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(
            f"Failed to get OAuth provider health status: {e}",
            extra={'error': str(e)}
        )
        return Response({
            'error': 'Failed to retrieve OAuth provider health status',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)