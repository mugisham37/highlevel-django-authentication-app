"""
Multi-Factor Authentication views for enterprise authentication system.

This module provides API endpoints for TOTP setup, verification,
backup codes management, and device management.
"""

from typing import Dict, Any
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _

from ..services.mfa_service import MFAService
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)
from ..utils.request_utils import get_client_ip, get_user_agent
from ..utils.response_utils import success_response, error_response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_totp(request: Request) -> Response:
    """
    Set up TOTP for the authenticated user.
    
    Request body:
    {
        "device_name": "My Phone"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "device_id": "uuid",
            "secret_key": "base32_secret",
            "qr_code_uri": "otpauth://...",
            "qr_code_data": "data:image/png;base64,...",
            "manual_entry_key": "XXXX XXXX XXXX XXXX",
            "issuer": "Enterprise Auth",
            "account_name": "user@example.com"
        }
    }
    """
    try:
        device_name = request.data.get('device_name')
        if not device_name:
            return error_response(
                message="Device name is required",
                error_code="MISSING_DEVICE_NAME",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Set up TOTP
        mfa_service = MFAService()
        setup_data = mfa_service.setup_totp(
            user=request.user,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=setup_data,
            message="TOTP setup initiated successfully"
        )
        
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to set up TOTP",
            error_code="TOTP_SETUP_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_totp_setup(request: Request) -> Response:
    """
    Confirm TOTP setup by verifying the first code.
    
    Request body:
    {
        "device_id": "uuid",
        "verification_code": "123456"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "device_id": "uuid",
            "device_name": "My Phone",
            "backup_codes": ["XXXXXXXX", "XXXXXXXX", ...],
            "confirmed_at": "2024-01-15T10:30:00Z",
            "status": "active"
        }
    }
    """
    try:
        device_id = request.data.get('device_id')
        verification_code = request.data.get('verification_code')
        
        if not device_id:
            return error_response(
                message="Device ID is required",
                error_code="MISSING_DEVICE_ID",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        if not verification_code:
            return error_response(
                message="Verification code is required",
                error_code="MISSING_VERIFICATION_CODE",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Confirm TOTP setup
        mfa_service = MFAService()
        confirmation_data = mfa_service.confirm_totp_setup(
            user=request.user,
            device_id=device_id,
            verification_code=verification_code,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=confirmation_data,
            message="TOTP setup confirmed successfully"
        )
        
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAVerificationError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to confirm TOTP setup",
            error_code="TOTP_CONFIRMATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_totp(request: Request) -> Response:
    """
    Verify a TOTP code.
    
    Request body:
    {
        "verification_code": "123456",
        "device_id": "uuid"  // optional
    }
    
    Response:
    {
        "success": true,
        "data": {
            "verified": true,
            "device_id": "uuid",
            "device_name": "My Phone",
            "verified_at": "2024-01-15T10:30:00Z"
        }
    }
    """
    try:
        verification_code = request.data.get('verification_code')
        device_id = request.data.get('device_id')
        
        if not verification_code:
            return error_response(
                message="Verification code is required",
                error_code="MISSING_VERIFICATION_CODE",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Verify TOTP
        mfa_service = MFAService()
        verification_data = mfa_service.verify_totp(
            user=request.user,
            verification_code=verification_code,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=verification_data,
            message="TOTP verified successfully"
        )
        
    except MFARateLimitError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAVerificationError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to verify TOTP",
            error_code="TOTP_VERIFICATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_backup_code(request: Request) -> Response:
    """
    Verify a backup code.
    
    Request body:
    {
        "backup_code": "XXXXXXXX"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "verified": true,
            "device_id": "uuid",
            "remaining_codes": 9,
            "warning": "Only 2 backup codes remaining. Generate new ones soon.",
            "verified_at": "2024-01-15T10:30:00Z"
        }
    }
    """
    try:
        backup_code = request.data.get('backup_code')
        
        if not backup_code:
            return error_response(
                message="Backup code is required",
                error_code="MISSING_BACKUP_CODE",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Verify backup code
        mfa_service = MFAService()
        verification_data = mfa_service.verify_backup_code(
            user=request.user,
            backup_code=backup_code,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=verification_data,
            message="Backup code verified successfully"
        )
        
    except MFARateLimitError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS
        )
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAVerificationError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to verify backup code",
            error_code="BACKUP_CODE_VERIFICATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_backup_codes(request: Request) -> Response:
    """
    Regenerate backup codes for the authenticated user.
    
    Response:
    {
        "success": true,
        "data": {
            "backup_codes": ["XXXXXXXX", "XXXXXXXX", ...]
        }
    }
    """
    try:
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Regenerate backup codes
        mfa_service = MFAService()
        new_codes = mfa_service.regenerate_backup_codes(
            user=request.user,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data={'backup_codes': new_codes},
            message="Backup codes regenerated successfully"
        )
        
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to regenerate backup codes",
            error_code="BACKUP_CODE_REGENERATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_mfa_devices(request: Request) -> Response:
    """
    List all MFA devices for the authenticated user.
    
    Response:
    {
        "success": true,
        "data": {
            "devices": [
                {
                    "id": "uuid",
                    "name": "My Phone",
                    "type": "totp",
                    "type_display": "TOTP (Time-based One-Time Password)",
                    "status": "active",
                    "status_display": "Active",
                    "is_confirmed": true,
                    "is_active": true,
                    "created_at": "2024-01-15T10:30:00Z",
                    "last_used": "2024-01-15T10:30:00Z",
                    "usage_count": 5
                }
            ]
        }
    }
    """
    try:
        mfa_service = MFAService()
        devices = mfa_service.get_user_mfa_devices(request.user)
        
        return success_response(
            data={'devices': devices},
            message="MFA devices retrieved successfully"
        )
        
    except Exception as e:
        return error_response(
            message="Failed to retrieve MFA devices",
            error_code="MFA_DEVICES_RETRIEVAL_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable_mfa_device(request: Request) -> Response:
    """
    Disable an MFA device.
    
    Request body:
    {
        "device_id": "uuid",
        "reason": "user_request"  // optional
    }
    
    Response:
    {
        "success": true,
        "data": {
            "disabled": true
        }
    }
    """
    try:
        device_id = request.data.get('device_id')
        reason = request.data.get('reason', 'user_request')
        
        if not device_id:
            return error_response(
                message="Device ID is required",
                error_code="MISSING_DEVICE_ID",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Disable device
        mfa_service = MFAService()
        success = mfa_service.disable_mfa_device(
            user=request.user,
            device_id=device_id,
            reason=reason,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data={'disabled': success},
            message="MFA device disabled successfully"
        )
        
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=e.error_code,
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to disable MFA device",
            error_code="MFA_DEVICE_DISABLE_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mfa_status(request: Request) -> Response:
    """
    Get MFA status for the authenticated user.
    
    Response:
    {
        "success": true,
        "data": {
            "has_active_mfa": true,
            "device_count": 2,
            "totp_devices": 1,
            "backup_codes_available": true,
            "backup_codes_remaining": 8
        }
    }
    """
    try:
        mfa_service = MFAService()
        
        # Check if user has active MFA
        has_active_mfa = mfa_service.has_active_mfa(request.user)
        
        # Get device counts
        devices = mfa_service.get_user_mfa_devices(request.user)
        device_count = len([d for d in devices if d['is_active']])
        totp_devices = len([d for d in devices if d['type'] == 'totp' and d['is_active']])
        
        # Check backup codes
        backup_codes_device = None
        backup_codes_remaining = 0
        for device in devices:
            if device['type'] == 'backup_codes' and device['is_active']:
                backup_codes_device = device
                backup_codes_remaining = device.get('remaining_codes', 0)
                break
        
        return success_response(
            data={
                'has_active_mfa': has_active_mfa,
                'device_count': device_count,
                'totp_devices': totp_devices,
                'backup_codes_available': backup_codes_device is not None,
                'backup_codes_remaining': backup_codes_remaining
            },
            message="MFA status retrieved successfully"
        )
        
    except Exception as e:
        return error_response(
            message="Failed to retrieve MFA status",
            error_code="MFA_STATUS_RETRIEVAL_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )