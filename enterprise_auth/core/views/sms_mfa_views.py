"""
SMS Multi-Factor Authentication API views for enterprise authentication system.

This module provides REST API endpoints for SMS MFA operations including
setup, verification, code sending, and delivery status tracking.
"""

from typing import Dict, Any
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _

from ..services import sms_mfa_service
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
def setup_sms_mfa(request: Request) -> Response:
    """
    Set up SMS MFA for the authenticated user.
    
    Request body:
    {
        "device_name": "My Phone",
        "phone_number": "+1234567890"
    }
    
    Returns:
        201: SMS MFA setup initiated successfully
        400: Invalid request data
        429: Rate limit exceeded
        500: Internal server error
    """
    try:
        device_name = request.data.get('device_name')
        phone_number = request.data.get('phone_number')
        
        if not device_name:
            return Response(
                {'error': 'Device name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not phone_number:
            return Response(
                {'error': 'Phone number is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        result = sms_mfa_service.setup_sms(
            user=request.user,
            device_name=device_name,
            phone_number=phone_number,
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
            {'error': 'Failed to set up SMS MFA'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_sms_setup(request: Request) -> Response:
    """
    Confirm SMS MFA setup by verifying the code.
    
    Request body:
    {
        "device_id": "uuid",
        "verification_code": "123456"
    }
    
    Returns:
        200: SMS MFA setup confirmed successfully
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
        
        result = sms_mfa_service.confirm_sms_setup(
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
            {'error': 'Failed to confirm SMS MFA setup'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_sms_code(request: Request) -> Response:
    """
    Send SMS verification code to user's device.
    
    Request body:
    {
        "device_id": "uuid"  // Optional, uses first active device if not provided
    }
    
    Returns:
        200: SMS code sent successfully
        400: Invalid request data
        404: Device not found
        429: Rate limit exceeded
        500: Internal server error
    """
    try:
        device_id = request.data.get('device_id')
        
        result = sms_mfa_service.send_sms_code(
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
            {'error': 'Failed to send SMS code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_sms_code(request: Request) -> Response:
    """
    Verify SMS verification code.
    
    Request body:
    {
        "verification_code": "123456",
        "device_id": "uuid"  // Optional, tries all active devices if not provided
    }
    
    Returns:
        200: SMS code verified successfully
        400: Invalid request data or verification failed
        404: Device not found
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
        
        result = sms_mfa_service.verify_sms(
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
            {'error': 'Failed to verify SMS code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resend_sms_code(request: Request) -> Response:
    """
    Resend SMS verification code.
    
    Request body:
    {
        "device_id": "uuid"
    }
    
    Returns:
        200: SMS code resent successfully
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
        
        result = sms_mfa_service.resend_sms_code(
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
            {'error': 'Failed to resend SMS code'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_sms_delivery_status(request: Request) -> Response:
    """
    Get SMS delivery status from Twilio.
    
    Query parameters:
    - message_sid: Twilio message SID
    
    Returns:
        200: Delivery status retrieved successfully
        400: Invalid request data
        500: Internal server error
    """
    try:
        message_sid = request.query_params.get('message_sid')
        
        if not message_sid:
            return Response(
                {'error': 'Message SID is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        result = sms_mfa_service.get_sms_delivery_status(
            user=request.user,
            message_sid=message_sid,
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
            {'error': 'Failed to get SMS delivery status'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )