"""
Authentication API views for JWT token management.

This module provides API endpoints for JWT token generation,
refresh, validation, and revocation.
"""

import logging
from typing import Dict, Any

from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from ..authentication import JWTAuthentication, JWTRefreshAuthentication
from ..services.jwt_service import jwt_service, DeviceInfo
from ..utils.request_utils import extract_request_info

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request: Request) -> Response:
    """
    Authenticate user and return JWT token pair.
    
    This endpoint validates user credentials and returns access and refresh tokens
    with device binding for enhanced security.
    
    Request Body:
        email (str): User's email address
        password (str): User's password
        
    Returns:
        200: JWT token pair with user information
        400: Invalid request data
        401: Invalid credentials
    """
    try:
        # Extract credentials
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': 'Email and password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Authenticate user
        user = authenticate(request, username=email, password=password)
        if not user:
            logger.warning(f"Failed login attempt for email: {email}")
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if user is active
        if not user.is_active:
            return Response(
                {'error': 'Account is disabled'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if account is locked
        if hasattr(user, 'is_account_locked') and user.is_account_locked:
            return Response(
                {'error': 'Account is temporarily locked'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create device info from request
        device_info = DeviceInfo.from_request(request)
        
        # Generate JWT token pair
        token_pair = jwt_service.generate_token_pair(
            user=user,
            device_info=device_info,
            scopes=['read', 'write']
        )
        
        # Update user login metadata
        request_info = extract_request_info(request)
        user.update_login_metadata(
            ip_address=request_info['ip_address'],
            user_agent=request_info['user_agent']
        )
        
        # Log successful login
        logger.info(f"Successful login for user: {user.email}")
        
        # Prepare response
        response_data = {
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_email_verified': user.is_email_verified,
            },
            'tokens': token_pair.to_dict(),
            'device_info': {
                'device_id': device_info.device_id,
                'device_type': device_info.device_type,
                'browser': device_info.browser,
                'operating_system': device_info.operating_system,
            }
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request: Request) -> Response:
    """
    Refresh JWT access token using refresh token.
    
    This endpoint validates a refresh token and returns a new token pair
    with token rotation for enhanced security.
    
    Request Body:
        refresh_token (str): Valid refresh token
        
    Returns:
        200: New JWT token pair
        400: Invalid request data
        401: Invalid or expired refresh token
    """
    try:
        # Extract refresh token
        refresh_token_str = request.data.get('refresh_token')
        
        if not refresh_token_str:
            return Response(
                {'error': 'Refresh token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create device info from request
        device_info = DeviceInfo.from_request(request)
        
        # Refresh token pair
        new_token_pair = jwt_service.refresh_token_pair(
            refresh_token=refresh_token_str,
            device_info=device_info
        )
        
        if not new_token_pair:
            return Response(
                {'error': 'Invalid or expired refresh token'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Log successful token refresh
        logger.info(f"Token refresh successful for device: {device_info.device_id}")
        
        # Prepare response
        response_data = {
            'tokens': new_token_pair.to_dict(),
            'device_info': {
                'device_id': device_info.device_id,
                'device_type': device_info.device_type,
                'browser': device_info.browser,
                'operating_system': device_info.operating_system,
            }
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request: Request) -> Response:
    """
    Logout user and revoke current token.
    
    This endpoint revokes the current access token and optionally
    revokes all tokens for the user.
    
    Request Body:
        revoke_all (bool, optional): Whether to revoke all user tokens
        
    Returns:
        200: Logout successful
        401: Invalid token
    """
    try:
        # Get token from request
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return Response(
                {'error': 'Invalid authorization header'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        token = auth_header.split(' ')[1]
        revoke_all = request.data.get('revoke_all', False)
        
        if revoke_all:
            # Revoke all tokens for the user
            success = jwt_service.revoke_all_user_tokens(
                user_id=str(request.user.id),
                reason='user_logout_all'
            )
        else:
            # Revoke only the current token
            success = jwt_service.revoke_token(token, reason='user_logout')
        
        if not success:
            return Response(
                {'error': 'Failed to revoke token'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Log successful logout
        logger.info(f"Logout successful for user: {request.user.email}")
        
        return Response(
            {'message': 'Logout successful'},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([AllowAny])
def introspect_token(request: Request) -> Response:
    """
    Introspect JWT token and return metadata.
    
    This endpoint validates a token and returns its metadata
    without requiring authentication.
    
    Request Body:
        token (str): JWT token to introspect
        
    Returns:
        200: Token metadata
        400: Invalid request data
    """
    try:
        # Extract token
        token = request.data.get('token')
        
        if not token:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Introspect token
        introspection_data = jwt_service.introspect_token(token)
        
        return Response(introspection_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Token introspection error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def validate_token(request: Request) -> Response:
    """
    Validate current JWT token.
    
    This endpoint validates the current token and returns user information.
    It's useful for client applications to verify token validity.
    
    Returns:
        200: Token is valid with user information
        401: Invalid token
    """
    try:
        # Token is already validated by authentication middleware
        # Return user information and token claims
        token_claims = getattr(request, 'auth', None)
        
        response_data = {
            'valid': True,
            'user': {
                'id': str(request.user.id),
                'email': request.user.email,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'is_email_verified': request.user.is_email_verified,
            }
        }
        
        if token_claims:
            response_data['token_info'] = {
                'token_id': token_claims.token_id,
                'device_id': token_claims.device_id,
                'scopes': token_claims.scopes,
                'issued_at': token_claims.issued_at,
                'expires_at': token_claims.expires_at,
            }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request: Request) -> Response:
    """
    Get current user profile information.
    
    This endpoint returns detailed profile information for the
    authenticated user.
    
    Returns:
        200: User profile information
        401: Invalid token
    """
    try:
        user = request.user
        
        response_data = {
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone_number': user.phone_number,
            'is_email_verified': user.is_email_verified,
            'is_phone_verified': user.is_phone_verified,
            'organization': user.organization,
            'department': user.department,
            'employee_id': user.employee_id,
            'job_title': user.job_title,
            'timezone': user.timezone,
            'language': user.language,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'date_joined': user.date_joined.isoformat(),
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"User profile error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_token(request: Request) -> Response:
    """
    Revoke a specific JWT token.
    
    This endpoint allows revoking a specific token by its token string.
    Useful for security incidents or when a token is compromised.
    
    Request Body:
        token (str): JWT token to revoke
        reason (str, optional): Reason for revocation
        
    Returns:
        200: Token revoked successfully
        400: Invalid request data
        401: Invalid token or insufficient permissions
    """
    try:
        # Extract token and reason
        token_to_revoke = request.data.get('token')
        reason = request.data.get('reason', 'manual_revocation')
        
        if not token_to_revoke:
            return Response(
                {'error': 'Token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Revoke the token
        success = jwt_service.revoke_token(token_to_revoke, reason)
        
        if not success:
            return Response(
                {'error': 'Failed to revoke token'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Log the revocation
        logger.info(f"Token revoked by user {request.user.email} with reason: {reason}")
        
        return Response(
            {'message': 'Token revoked successfully'},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Token revocation error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_all_user_tokens(request: Request) -> Response:
    """
    Revoke all tokens for the current user.
    
    This endpoint revokes all tokens for the authenticated user.
    Useful for security incidents or when changing passwords.
    
    Request Body:
        reason (str, optional): Reason for revocation
        
    Returns:
        200: All tokens revoked successfully
        401: Invalid token
    """
    try:
        reason = request.data.get('reason', 'user_requested_revocation')
        
        # Revoke all tokens for the user
        success = jwt_service.revoke_all_user_tokens(
            user_id=str(request.user.id),
            reason=reason
        )
        
        if not success:
            return Response(
                {'error': 'Failed to revoke all tokens'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Log the revocation
        logger.info(f"All tokens revoked for user {request.user.email} with reason: {reason}")
        
        return Response(
            {'message': 'All tokens revoked successfully'},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"All tokens revocation error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_device_tokens(request: Request) -> Response:
    """
    Revoke all tokens for a specific device.
    
    This endpoint revokes all tokens for a specific device.
    Useful when a device is lost or compromised.
    
    Request Body:
        device_id (str): Device identifier to revoke tokens for
        reason (str, optional): Reason for revocation
        
    Returns:
        200: Device tokens revoked successfully
        400: Invalid request data
        401: Invalid token
    """
    try:
        device_id = request.data.get('device_id')
        reason = request.data.get('reason', 'device_compromised')
        
        if not device_id:
            return Response(
                {'error': 'Device ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Revoke all tokens for the device
        success = jwt_service.revoke_device_tokens(device_id, reason)
        
        if not success:
            return Response(
                {'error': 'Failed to revoke device tokens'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Log the revocation
        logger.info(f"Device tokens revoked by user {request.user.email} for device {device_id} with reason: {reason}")
        
        return Response(
            {'message': 'Device tokens revoked successfully'},
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Device tokens revocation error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def bulk_revoke_tokens(request: Request) -> Response:
    """
    Revoke multiple tokens at once.
    
    This endpoint allows bulk revocation of multiple tokens.
    Useful for security incidents affecting multiple tokens.
    
    Request Body:
        token_ids (list): List of token identifiers to revoke
        reason (str, optional): Reason for revocation
        
    Returns:
        200: Tokens revoked successfully with count
        400: Invalid request data
        401: Invalid token
    """
    try:
        token_ids = request.data.get('token_ids', [])
        reason = request.data.get('reason', 'bulk_security_incident')
        
        if not token_ids or not isinstance(token_ids, list):
            return Response(
                {'error': 'Token IDs list is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if len(token_ids) > 1000:  # Limit bulk operations
            return Response(
                {'error': 'Maximum 1000 tokens can be revoked at once'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Bulk revoke tokens
        revoked_count = jwt_service.bulk_revoke_tokens(token_ids, reason)
        
        # Log the bulk revocation
        logger.info(f"Bulk revocation by user {request.user.email}: {revoked_count}/{len(token_ids)} tokens revoked with reason: {reason}")
        
        return Response(
            {
                'message': 'Bulk revocation completed',
                'revoked_count': revoked_count,
                'total_requested': len(token_ids)
            },
            status=status.HTTP_200_OK
        )
        
    except Exception as e:
        logger.error(f"Bulk token revocation error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )