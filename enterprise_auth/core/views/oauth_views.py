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
from django.utils import timezone
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
    ValidationError,
    TokenInvalidError,
    TokenExpiredError,
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
    or links the OAuth identity to an existing account. Includes comprehensive
    error handling, monitoring, and fallback authentication methods.
    
    Args:
        provider_name: Name of the OAuth provider (e.g., 'google')
        
    Request Body:
        code (str): Authorization code from OAuth callback
        state (str): State parameter for CSRF verification
        error (str, optional): OAuth error code from provider
        error_description (str, optional): OAuth error description from provider
        
    Returns:
        200: JWT token pair and user information
        400: Invalid request data or state mismatch
        404: OAuth provider not found
        422: OAuth provider not configured or disabled
        500: Internal server error
    """
    from ..services.oauth_callback_service import oauth_callback_service
    
    # Extract request information for monitoring
    request_info = extract_request_info(request)
    correlation_id = request.headers.get('X-Correlation-ID', secrets.token_urlsafe(16))
    
    # Log callback initiation
    logger.info(
        f"OAuth callback initiated for {provider_name}",
        extra={
            'provider': provider_name,
            'correlation_id': correlation_id,
            'ip_address': request_info['ip_address'],
            'user_agent': request_info['user_agent'],
        }
    )
    
    try:
        # Check for OAuth provider errors first
        oauth_error = request.data.get('error')
        if oauth_error:
            error_description = request.data.get('error_description', '')
            error_uri = request.data.get('error_uri', '')
            
            # Log OAuth provider error
            logger.warning(
                f"OAuth provider error for {provider_name}: {oauth_error}",
                extra={
                    'provider': provider_name,
                    'oauth_error': oauth_error,
                    'error_description': error_description,
                    'error_uri': error_uri,
                    'correlation_id': correlation_id,
                }
            )
            
            # Handle specific OAuth errors with fallback suggestions
            return oauth_callback_service.handle_oauth_provider_error(
                provider_name=provider_name,
                oauth_error=oauth_error,
                error_description=error_description,
                error_uri=error_uri,
                correlation_id=correlation_id
            )
        
        # Extract callback parameters
        code = request.data.get('code')
        state = request.data.get('state')
        
        if not code or not state:
            logger.warning(
                f"Missing OAuth callback parameters for {provider_name}",
                extra={
                    'provider': provider_name,
                    'has_code': bool(code),
                    'has_state': bool(state),
                    'correlation_id': correlation_id,
                }
            )
            return oauth_callback_service.handle_missing_parameters_error(
                provider_name=provider_name,
                correlation_id=correlation_id
            )
        
        # Verify state parameter with enhanced validation
        session_state = request.session.get(f'oauth_state_{provider_name}')
        if not session_state or session_state != state:
            logger.warning(
                f"OAuth state mismatch for {provider_name}",
                extra={
                    'provider': provider_name,
                    'expected_state': session_state,
                    'received_state': state,
                    'correlation_id': correlation_id,
                    'ip_address': request_info['ip_address'],
                }
            )
            return oauth_callback_service.handle_state_mismatch_error(
                provider_name=provider_name,
                correlation_id=correlation_id
            )
        
        # Get PKCE code verifier from session
        code_verifier = request.session.get(f'oauth_code_verifier_{provider_name}')
        
        # Handle OAuth callback with comprehensive error handling
        try:
            token_data, user_data = oauth_service.handle_callback(
                provider_name=provider_name,
                code=code,
                state=state,
                code_verifier=code_verifier
            )
        except Exception as callback_error:
            logger.error(
                f"OAuth callback processing failed for {provider_name}",
                extra={
                    'provider': provider_name,
                    'error': str(callback_error),
                    'correlation_id': correlation_id,
                }
            )
            return oauth_callback_service.handle_callback_processing_error(
                provider_name=provider_name,
                error=callback_error,
                correlation_id=correlation_id
            )
        
        # Clean up session data
        request.session.pop(f'oauth_state_{provider_name}', None)
        request.session.pop(f'oauth_code_verifier_{provider_name}', None)
        
        # Find or create user account with enhanced error handling
        user = None
        identity = None
        is_new_user = False
        
        try:
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
                                'correlation_id': correlation_id,
                            }
                        )
                    except User.DoesNotExist:
                        pass
                
                if not user:
                    # Validate user data before creating account
                    if not user_data.email:
                        logger.warning(
                            f"OAuth user data missing email for {provider_name}",
                            extra={
                                'provider': provider_name,
                                'provider_user_id': user_data.provider_user_id,
                                'correlation_id': correlation_id,
                            }
                        )
                        return oauth_callback_service.handle_missing_user_data_error(
                            provider_name=provider_name,
                            correlation_id=correlation_id
                        )
                    
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
                            'correlation_id': correlation_id,
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
                
        except Exception as user_creation_error:
            logger.error(
                f"User creation/linking failed for OAuth {provider_name}",
                extra={
                    'provider': provider_name,
                    'error': str(user_creation_error),
                    'correlation_id': correlation_id,
                }
            )
            return oauth_callback_service.handle_user_creation_error(
                provider_name=provider_name,
                error=user_creation_error,
                correlation_id=correlation_id
            )
        
        # Extract device information
        device_info = DeviceInfo.from_request(request)
        
        # Generate JWT tokens with error handling
        try:
            jwt_tokens = jwt_service.generate_token_pair(
                user=user,
                device_info=device_info,
                scopes=['read', 'write']  # Default scopes for OAuth users
            )
        except Exception as token_error:
            logger.error(
                f"JWT token generation failed for OAuth {provider_name}",
                extra={
                    'provider': provider_name,
                    'user_id': user.id,
                    'error': str(token_error),
                    'correlation_id': correlation_id,
                }
            )
            return oauth_callback_service.handle_token_generation_error(
                provider_name=provider_name,
                error=token_error,
                correlation_id=correlation_id
            )
        
        # Update user login metadata
        try:
            user.update_login_metadata(
                ip_address=device_info.ip_address,
                user_agent=device_info.user_agent
            )
        except Exception as metadata_error:
            # Log but don't fail the authentication
            logger.warning(
                f"Failed to update login metadata for OAuth {provider_name}",
                extra={
                    'provider': provider_name,
                    'user_id': user.id,
                    'error': str(metadata_error),
                    'correlation_id': correlation_id,
                }
            )
        
        # Log successful OAuth authentication
        logger.info(
            f"OAuth authentication successful for {provider_name}",
            extra={
                'provider': provider_name,
                'user_id': user.id,
                'is_new_user': is_new_user,
                'identity_id': identity.id,
                'correlation_id': correlation_id,
            }
        )
        
        # Record successful OAuth authentication event
        oauth_callback_service.record_successful_authentication(
            provider_name=provider_name,
            user=user,
            identity=identity,
            is_new_user=is_new_user,
            correlation_id=correlation_id,
            request_info=request_info
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
            },
            'correlation_id': correlation_id,
        }, status=status.HTTP_200_OK)
        
    except OAuthProviderNotFoundError as e:
        logger.warning(
            f"OAuth provider not found: {provider_name}",
            extra={'provider': provider_name, 'correlation_id': correlation_id}
        )
        return oauth_callback_service.handle_provider_not_found_error(
            provider_name=provider_name,
            correlation_id=correlation_id
        )
        
    except (OAuthProviderNotConfiguredError, OAuthProviderDisabledError) as e:
        logger.warning(
            f"OAuth provider not available: {provider_name} - {e}",
            extra={'provider': provider_name, 'error': str(e), 'correlation_id': correlation_id}
        )
        return oauth_callback_service.handle_provider_unavailable_error(
            provider_name=provider_name,
            error=e,
            correlation_id=correlation_id
        )
        
    except OAuthError as e:
        logger.error(
            f"OAuth callback failed for {provider_name}: {e}",
            extra={'provider': provider_name, 'error': str(e), 'correlation_id': correlation_id}
        )
        return oauth_callback_service.handle_oauth_error(
            provider_name=provider_name,
            error=e,
            correlation_id=correlation_id
        )
        
    except Exception as e:
        logger.error(
            f"Unexpected error in OAuth callback for {provider_name}: {e}",
            extra={'provider': provider_name, 'error': str(e), 'correlation_id': correlation_id}
        )
        return oauth_callback_service.handle_unexpected_error(
            provider_name=provider_name,
            error=e,
            correlation_id=correlation_id
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_user_oauth_identities(request: Request) -> Response:
    """
    List OAuth identities linked to the authenticated user.
    
    Returns a list of all OAuth provider identities linked to the user's account
    with additional metadata about unlinking capabilities.
    
    Returns:
        200: List of linked OAuth identities
        401: User not authenticated
    """
    try:
        # Import the social linking service
        from ..services.social_account_linking_service import social_linking_service
        
        # Get linked accounts with enhanced information
        linked_accounts = social_linking_service.get_user_linked_accounts(request.user)
        
        return Response({
            'identities': linked_accounts,
            'count': len(linked_accounts),
            'user_has_password': bool(request.user.password),
            'can_unlink_all': len(linked_accounts) > 1 or bool(request.user.password)
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
    Uses secure account linking with email verification and anti-takeover protection.
    
    Args:
        provider_name: Name of the OAuth provider to link
        
    Request Body:
        code (str): Authorization code from OAuth callback
        state (str): State parameter for CSRF verification
        require_email_verification (bool, optional): Override email verification requirement
        
    Returns:
        200: Successfully linked OAuth identity or verification required
        400: Invalid request data or state mismatch
        404: OAuth provider not found
        409: OAuth identity already linked to another account
        422: OAuth provider not configured or disabled
        500: Internal server error
    """
    try:
        # Import the social linking service
        from ..services.social_account_linking_service import social_linking_service
        
        # Extract callback parameters
        code = request.data.get('code')
        state = request.data.get('state')
        require_email_verification = request.data.get('require_email_verification')
        
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
        
        # Convert user_data to dictionary format
        provider_user_data = {
            'provider_user_id': user_data.provider_user_id,
            'email': user_data.email,
            'username': user_data.username,
            'first_name': user_data.first_name,
            'last_name': user_data.last_name,
            'profile_picture_url': user_data.profile_picture_url,
            'verified_email': user_data.verified_email,
            'locale': user_data.locale,
            'timezone': user_data.timezone,
        }
        
        # Convert token_data to dictionary format
        token_dict = {
            'access_token': token_data.access_token,
            'refresh_token': token_data.refresh_token,
            'expires_in': token_data.expires_in,
            'token_type': token_data.token_type,
            'scope': token_data.scope,
        }
        
        # Initiate secure account linking
        result = social_linking_service.initiate_account_linking(
            user=request.user,
            provider_name=provider_name,
            provider_user_data=provider_user_data,
            token_data=token_dict,
            require_email_verification=require_email_verification
        )
        
        logger.info(
            f"Account linking initiated for {provider_name}",
            extra={
                'provider': provider_name,
                'user_id': request.user.id,
                'status': result['status'],
            }
        )
        
        # Return appropriate response based on status
        if result['status'] == 'verification_required':
            return Response({
                'message': result['message'],
                'status': result['status'],
                'verification_token': result['verification_token'],
                'expires_at': result['expires_at'],
                'provider': result['provider']
            }, status=status.HTTP_200_OK)
        elif result['status'] == 'already_linked':
            return Response({
                'message': result['message'],
                'status': result['status'],
                'identity_id': result['identity_id'],
                'linked_at': result['linked_at']
            }, status=status.HTTP_200_OK)
        else:  # status == 'linked'
            return Response({
                'message': result['message'],
                'status': result['status'],
                'identity': result['identity']
            }, status=status.HTTP_200_OK)
        
    except OAuthError as e:
        logger.error(
            f"Failed to link OAuth identity for {provider_name}: {e}",
            extra={'provider': provider_name, 'user_id': request.user.id, 'error': str(e)}
        )
        
        # Handle specific OAuth errors
        if 'already linked' in str(e):
            return Response({
                'error': 'This OAuth account is already linked to another user',
                'provider': provider_name
            }, status=status.HTTP_409_CONFLICT)
        
        return Response({
            'error': 'Failed to link OAuth account',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except ValidationError as e:
        logger.warning(
            f"Validation error linking OAuth identity for {provider_name}: {e}",
            extra={'provider': provider_name, 'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': str(e),
            'provider': provider_name,
            'details': getattr(e, 'details', {})
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
    from their user account with proper cleanup and validation.
    
    Args:
        provider_name: Name of the OAuth provider to unlink
        
    Query Parameters:
        identity_id (str, optional): Specific identity ID to unlink
        
    Returns:
        200: Successfully unlinked OAuth identity
        400: Cannot unlink (validation error)
        404: OAuth identity not found
        500: Internal server error
    """
    try:
        # Import the social linking service
        from ..services.social_account_linking_service import social_linking_service
        
        # Get optional identity ID from query parameters
        identity_id = request.query_params.get('identity_id')
        
        # Unlink the OAuth identity with proper cleanup
        result = social_linking_service.unlink_social_account(
            user=request.user,
            provider_name=provider_name,
            identity_id=identity_id
        )
        
        if result['status'] == 'unlinked':
            logger.info(
                f"Successfully unlinked OAuth identity for {provider_name}",
                extra={
                    'provider': provider_name, 
                    'user_id': request.user.id,
                    'identity_id': result['unlinked_identity']['id']
                }
            )
            return Response({
                'message': result['message'],
                'status': result['status'],
                'unlinked_identity': result['unlinked_identity']
            }, status=status.HTTP_200_OK)
        else:  # status == 'not_found'
            return Response({
                'error': result['message'],
                'provider': provider_name,
                'status': result['status']
            }, status=status.HTTP_404_NOT_FOUND)
        
    except ValidationError as e:
        logger.warning(
            f"Validation error unlinking OAuth identity for {provider_name}: {e}",
            extra={'provider': provider_name, 'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': str(e),
            'provider': provider_name,
            'details': getattr(e, 'details', {})
        }, status=status.HTTP_400_BAD_REQUEST)
        
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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_social_linking(request: Request) -> Response:
    """
    Verify social account linking using verification token.
    
    This endpoint completes the social account linking process after
    email verification has been completed.
    
    Request Body:
        linking_token (str): Linking verification token from email
        
    Returns:
        200: Successfully completed account linking
        400: Invalid or expired token
        500: Internal server error
    """
    try:
        # Import the social linking service
        from ..services.social_account_linking_service import social_linking_service
        
        # Extract linking token
        linking_token = request.data.get('linking_token')
        
        if not linking_token:
            return Response({
                'error': 'Missing required parameter: linking_token'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Verify and complete linking
        result = social_linking_service.verify_and_complete_linking(
            user_id=str(request.user.id),
            linking_token=linking_token
        )
        
        logger.info(
            f"Social account linking verified and completed",
            extra={
                'user_id': request.user.id,
                'identity_id': result.get('identity', {}).get('id')
            }
        )
        
        return Response({
            'message': result['message'],
            'status': result['status'],
            'identity': result['identity']
        }, status=status.HTTP_200_OK)
        
    except TokenInvalidError as e:
        logger.warning(
            f"Invalid linking token: {e}",
            extra={'user_id': request.user.id}
        )
        return Response({
            'error': str(e),
            'code': 'INVALID_TOKEN'
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except TokenExpiredError as e:
        logger.warning(
            f"Expired linking token: {e}",
            extra={'user_id': request.user.id}
        )
        return Response({
            'error': str(e),
            'code': 'TOKEN_EXPIRED'
        }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(
            f"Failed to verify social linking: {e}",
            extra={'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to verify social account linking',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_social_linking_statistics(request: Request) -> Response:
    """
    Get social account linking statistics for the authenticated user.
    
    Returns statistics about the user's linked accounts and system limits.
    
    Returns:
        200: Social linking statistics
        500: Internal server error
    """
    try:
        # Import the social linking service
        from ..services.social_account_linking_service import social_linking_service
        
        # Get user's linked accounts
        linked_accounts = social_linking_service.get_user_linked_accounts(request.user)
        
        # Calculate statistics
        provider_counts = {}
        for account in linked_accounts:
            provider = account['provider']
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        return Response({
            'user_statistics': {
                'total_linked_accounts': len(linked_accounts),
                'provider_breakdown': provider_counts,
                'has_password': bool(request.user.password),
                'can_link_more': len(linked_accounts) < social_linking_service.max_total_identities
            },
            'system_limits': {
                'max_identities_per_provider': social_linking_service.max_identities_per_provider,
                'max_total_identities': social_linking_service.max_total_identities,
                'require_email_verification': social_linking_service.require_email_verification
            },
            'linked_accounts': linked_accounts
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(
            f"Failed to get social linking statistics: {e}",
            extra={'user_id': request.user.id, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to retrieve social linking statistics',
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


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_error_details(request: Request, provider_name: str) -> Response:
    """
    Get detailed OAuth error information and fallback suggestions.
    
    This endpoint provides comprehensive error details for OAuth failures,
    including suggested fallback authentication methods and troubleshooting steps.
    
    Args:
        provider_name: Name of the OAuth provider
        
    Query Parameters:
        error_code (str, optional): Specific error code to get details for
        correlation_id (str, optional): Correlation ID for error tracking
        
    Returns:
        200: OAuth error details and fallback suggestions
        404: OAuth provider not found
        500: Internal server error
    """
    from ..services.oauth_callback_service import oauth_callback_service
    from ..utils.monitoring import oauth_metrics
    
    try:
        error_code = request.query_params.get('error_code')
        correlation_id = request.query_params.get('correlation_id', secrets.token_urlsafe(16))
        
        # Get provider metrics
        provider_metrics = oauth_metrics.get_provider_metrics(provider_name)
        
        # Generate fallback suggestions
        fallback_suggestions = oauth_callback_service._generate_fallback_suggestions(
            provider_name=provider_name,
            fallback_methods=['email_password', 'alternative_oauth', 'magic_link']
        )
        
        # Get error-specific information
        error_info = {}
        if error_code:
            error_mapping = {
                'access_denied': {
                    'title': 'Access Denied',
                    'description': 'You denied access to your account during authentication.',
                    'common_causes': [
                        'User clicked "Cancel" or "Deny" on the provider\'s authorization page',
                        'User closed the authentication window before completing the process',
                        'Provider account permissions are insufficient'
                    ],
                    'troubleshooting_steps': [
                        'Try authenticating again and click "Allow" or "Authorize"',
                        'Check that your account has the necessary permissions',
                        'Clear your browser cache and cookies for the provider',
                        'Try using an incognito/private browsing window'
                    ],
                    'user_action_required': True,
                },
                'invalid_request': {
                    'title': 'Invalid Request',
                    'description': 'The authentication request was malformed or invalid.',
                    'common_causes': [
                        'Corrupted authentication state or session data',
                        'Browser security settings blocking the request',
                        'Network connectivity issues during authentication'
                    ],
                    'troubleshooting_steps': [
                        'Clear your browser cache and cookies',
                        'Try using a different browser or device',
                        'Check your internet connection',
                        'Disable browser extensions that might interfere'
                    ],
                    'user_action_required': True,
                },
                'server_error': {
                    'title': 'Provider Server Error',
                    'description': 'The authentication provider is experiencing technical difficulties.',
                    'common_causes': [
                        'Provider service outage or maintenance',
                        'High traffic causing provider slowdowns',
                        'Temporary provider configuration issues'
                    ],
                    'troubleshooting_steps': [
                        'Wait a few minutes and try again',
                        'Check the provider\'s status page for known issues',
                        'Try using an alternative authentication method',
                        'Contact support if the issue persists'
                    ],
                    'user_action_required': False,
                },
                'temporarily_unavailable': {
                    'title': 'Service Temporarily Unavailable',
                    'description': 'The authentication provider is temporarily unavailable.',
                    'common_causes': [
                        'Scheduled maintenance by the provider',
                        'Temporary service disruption',
                        'Provider rate limiting or capacity issues'
                    ],
                    'troubleshooting_steps': [
                        'Wait 5-10 minutes and try again',
                        'Use an alternative authentication method',
                        'Check the provider\'s social media for updates',
                        'Try again during off-peak hours'
                    ],
                    'user_action_required': False,
                },
            }
            
            error_info = error_mapping.get(error_code, {
                'title': 'Authentication Error',
                'description': f'An error occurred during {provider_name} authentication.',
                'common_causes': ['Various technical issues may cause authentication failures'],
                'troubleshooting_steps': [
                    'Try authenticating again',
                    'Use an alternative authentication method',
                    'Contact support if the problem persists'
                ],
                'user_action_required': True,
            })
        
        # Get provider-specific troubleshooting
        provider_troubleshooting = {
            'google': {
                'additional_steps': [
                    'Ensure your Google account is not suspended',
                    'Check if two-factor authentication is properly configured',
                    'Verify that third-party app access is enabled in Google settings'
                ],
                'support_url': 'https://support.google.com/accounts',
            },
            'github': {
                'additional_steps': [
                    'Ensure your GitHub account email is verified',
                    'Check if your account has the required OAuth app permissions',
                    'Verify that your account is not flagged for security review'
                ],
                'support_url': 'https://support.github.com',
            },
            'microsoft': {
                'additional_steps': [
                    'Ensure your Microsoft account is active and verified',
                    'Check if your organization allows third-party app access',
                    'Verify that your account type (personal/work) is supported'
                ],
                'support_url': 'https://support.microsoft.com',
            },
        }
        
        provider_specific = provider_troubleshooting.get(provider_name, {
            'additional_steps': [],
            'support_url': None,
        })
        
        response_data = {
            'provider': provider_name,
            'error_code': error_code,
            'correlation_id': correlation_id,
            'error_info': error_info,
            'provider_specific': provider_specific,
            'fallback_methods': fallback_suggestions,
            'provider_metrics': {
                'success_rate': provider_metrics.get('success_rate', 0.0),
                'recent_error_count': len(provider_metrics.get('recent_errors', [])),
                'is_experiencing_issues': provider_metrics.get('success_rate', 1.0) < 0.8,
            },
            'system_status': {
                'provider_available': True,  # This would be determined by health checks
                'estimated_resolution_time': None,
                'known_issues': [],
            },
            'timestamp': timezone.now().isoformat(),
        }
        
        logger.info(
            f"OAuth error details provided for {provider_name}",
            extra={
                'provider': provider_name,
                'error_code': error_code,
                'correlation_id': correlation_id,
                'fallback_count': len(fallback_suggestions),
            }
        )
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(
            f"Failed to get OAuth error details for {provider_name}: {e}",
            extra={'provider': provider_name, 'error': str(e)}
        )
        return Response({
            'error': 'Failed to retrieve OAuth error details',
            'provider': provider_name,
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([AllowAny])
def oauth_metrics_summary(request: Request) -> Response:
    """
    Get OAuth metrics summary for monitoring and debugging.
    
    Returns aggregated OAuth metrics including success rates, error counts,
    and provider-specific statistics for monitoring purposes.
    
    Query Parameters:
        provider (str, optional): Specific provider to get metrics for
        
    Returns:
        200: OAuth metrics summary
        500: Internal server error
    """
    from ..utils.monitoring import oauth_metrics
    
    try:
        provider_name = request.query_params.get('provider')
        
        if provider_name:
            # Get metrics for specific provider
            metrics = oauth_metrics.get_provider_metrics(provider_name)
            response_data = {
                'provider_metrics': metrics,
                'timestamp': timezone.now().isoformat(),
            }
        else:
            # Get overall metrics
            overall_metrics = oauth_metrics.get_overall_metrics()
            
            # Get metrics for all available providers
            available_providers = oauth_service.get_available_providers()
            provider_metrics = {}
            
            for provider in available_providers:
                provider_name = provider['name']
                provider_metrics[provider_name] = oauth_metrics.get_provider_metrics(provider_name)
            
            response_data = {
                'overall_metrics': overall_metrics,
                'provider_metrics': provider_metrics,
                'timestamp': timezone.now().isoformat(),
            }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(
            f"Failed to get OAuth metrics summary: {e}",
            extra={'error': str(e)}
        )
        return Response({
            'error': 'Failed to retrieve OAuth metrics summary',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)