"""
Email Multi-Factor Authentication API views for enterprise authentication system.

This module provides REST API endpoints for Email MFA operations including
setup, verification, code sending, and fallback functionality.
"""

from typing import Dict, Any
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _

from ..services import email_mfa_service
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)
from ..utils.request_helpers import get_client_ip, get_user_agent


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_email_mfa(request: Request) -> Response:
    """
    Set up Email MFA for the authenticated user.
    
    Request body:
    {
        "device_name": "My Email",
        "email_address": "user@example.com"  # Optional, defaults to user's primary email
    }
    
    Returns:
        201: Email MFA setup initiated successfully
        400: Invalid request data
        429: Rate limit exceeded
        500: Internal server error
    """
    try:
        device_name = request.data.get('device_name')
        email_address = request.data.get('email_address')
        
        if not device_name:
            return Response(
                {'error': 'Device name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        result = email_mfa_service.setup_email_mfa(
            user=request.user,
            device_name=device_name,
            email_address=email_address,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response(result, status=status.HTTP_201_CREATED)
        
    except MFARateLimitError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except MFAError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to set up Email MFA'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_email_setup(request: Request) -> Response:
    """
    Confirm Email MFA setup by verifying the code.
    
    Request body:
    {
        "device_id": "uuid",
        "verification_code": "123456"
    }
    
    Returns:
        200: Email MFA setup confirmed successfully
        400: Invalid request data or verification failed
        404: Device not found
        500: Internal server error
    """
    try:
        device_id = request.data.get('device_id')
        verification_code = request.data.get('verification_code')
        
        if not device_id:
            return Response(
                {'error': 'Device ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not verification_code:
            return Response(
                {'error': 'Verification code is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        result = email_mfa_service.confirm_email_setup(
            user=request.user,
            device_id=device_id,
            verification_code=verification_code,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response(result, status=status.HTTP_200_OK)
        
    except MFADeviceNotFoundError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_404_NOT_FOUND
        )
    except MFAVerificationError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to confirm Email MFA setup'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_email_code(request: Request) -> Response:
    """
    Send email verification code to user's device.
    
    Request body:
    {
        "device_id": "uuid"  # Optional, uses first active device if not provided
    }
    
    Returns:
        200: Email code sent successfully
        400: Invalid request data
        404: No active email devices found
        429: Rate limit exceeded
        500: Internal server error
    """
    try:
        device_id = request.data.get('device_id')
        
        result = email_mfa_service.send_email_code(
            user=request.user,
            device_id=device_id,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response(result, status=status.HTTP_200_OK)
        
    except MFARateLimitError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except MFADeviceNotFoundError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_404_NOT_FOUND
        )
    except MFAError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to send email code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_email_code(request: Request) -> Response:
    """
    Verify an email MFA code.
    
    Request body:
    {
        "verification_code": "123456",
        "device_id": "uuid"  # Optional, tries all active devices if not provided
    }
    
    Returns:
        200: Email code verified successfully
        400: Invalid request data or verification failed
        404: No active email devices found
        429: Rate limit exceeded
        500: Internal server error
    """
    try:
        verification_code = request.data.get('verification_code')
        device_id = request.data.get('device_id')
        
        if not verification_code:
            return Response(
                {'error': 'Verification code is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        result = email_mfa_service.verify_email(
            user=request.user,
            verification_code=verification_code,
            device_id=device_id,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response(result, status=status.HTTP_200_OK)
        
    except MFARateLimitError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except MFADeviceNotFoundError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_404_NOT_FOUND
        )
    except MFAVerificationError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to verify email code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resend_email_code(request: Request) -> Response:
    """
    Resend email verification code.
    
    Request body:
    {
        "device_id": "uuid"
    }
    
    Returns:
        200: Email code resent successfully
        400: Invalid request data
        404: Device not found
        429: Rate limit exceeded
        500: Internal server error
    """
    try:
        device_id = request.data.get('device_id')
        
        if not device_id:
            return Response(
                {'error': 'Device ID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        result = email_mfa_service.resend_email_code(
            user=request.user,
            device_id=device_id,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response(result, status=status.HTTP_200_OK)
        
    except MFARateLimitError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except MFADeviceNotFoundError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_404_NOT_FOUND
        )
    except MFADeviceDisabledError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except MFAError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to resend email code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def trigger_sms_fallback(request: Request) -> Response:
    """
    Trigger SMS fallback when email MFA fails repeatedly.
    
    Returns:
        200: SMS fallback triggered successfully
        400: SMS fallback not available or failed
        500: Internal server error
    """
    try:
        result = email_mfa_service.trigger_sms_fallback(
            user=request.user,
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request)
        )
        
        return Response(result, status=status.HTTP_200_OK)
        
    except MFAError as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to trigger SMS fallback'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_email_mfa_status(request: Request) -> Response:
    """
    Get email MFA status for the authenticated user.
    
    Returns:
        200: Email MFA status retrieved successfully
        500: Internal server error
    """
    try:
        from ..models import MFADevice
        
        # Get user's email MFA devices
        email_devices = MFADevice.objects.filter(
            user=request.user,
            device_type='email'
        ).order_by('-created_at')
        
        devices_data = []
        for device in email_devices:
            device_info = device.get_display_info()
            devices_data.append(device_info)
        
        # Check if user has any active email MFA devices
        has_active_email_mfa = email_devices.filter(
            status='active',
            is_confirmed=True
        ).exists()
        
        # Check if SMS fallback is available
        sms_devices = MFADevice.objects.filter(
            user=request.user,
            device_type='sms',
            status='active',
            is_confirmed=True
        )
        has_sms_fallback = sms_devices.exists()
        
        result = {
            'has_email_mfa': has_active_email_mfa,
            'has_sms_fallback': has_sms_fallback,
            'email_devices': devices_data,
            'sms_devices_count': sms_devices.count(),
            'email_mfa_enabled': email_mfa_service.enable_sms_fallback,
            'fallback_threshold': email_mfa_service.fallback_threshold_failures
        }
        
        return Response(result, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': 'Failed to get email MFA status'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_email_device(request: Request, device_id: str) -> Response:
    """
    Remove an email MFA device.
    
    Args:
        device_id: ID of the device to remove
    
    Returns:
        200: Device removed successfully
        404: Device not found
        500: Internal server error
    """
    try:
        from ..models import MFADevice
        
        device = MFADevice.objects.get(
            id=device_id,
            user=request.user,
            device_type='email'
        )
        
        device_name = device.device_name
        device.delete()
        
        # Log the device removal
        from ..services import audit_service
        audit_service.log_authentication_event(
            event_type='mfa_email_device_removed',
            user=request.user,
            description=f'Email MFA device removed: {device_name}',
            request_info={
                'ip_address': get_client_ip(request),
                'user_agent': get_user_agent(request)
            },
            metadata={
                'device_id': device_id,
                'device_name': device_name
            }
        )
        
        return Response(
            {'message': f'Email MFA device "{device_name}" removed successfully'},
            status=status.HTTP_200_OK
        )
        
    except MFADevice.DoesNotExist:
        return Response(
            {'error': 'Email MFA device not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {'error': 'Failed to remove email MFA device'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )