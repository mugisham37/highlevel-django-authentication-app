"""
MFA Device Management views for enterprise authentication system.

This module provides API endpoints for MFA device registration, confirmation,
listing, removal with security checks, and organization-level MFA enforcement.
"""

from typing import Dict, Any
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _

from ..services.mfa_device_management_service import mfa_device_management_service
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
def register_mfa_device(request: Request) -> Response:
    """
    Register a new MFA device for the authenticated user.
    
    Request body:
    {
        "device_type": "totp|sms|email|backup_codes",
        "device_name": "My Phone",
        "device_config": {
            "phone_number": "+1234567890",  // for SMS
            "email_address": "user@example.com",  // for email (optional)
            "count": 10  // for backup codes (optional)
        }
    }
    
    Response:
    {
        "success": true,
        "data": {
            "device_id": "uuid",
            "device_type": "totp",
            "device_name": "My Phone",
            "status": "pending",
            "registration_data": {
                // Device-specific registration data (QR code, etc.)
            },
            "confirmation_required": true,
            "confirmation_timeout_seconds": 3600
        }
    }
    """
    try:
        device_type = request.data.get('device_type')
        device_name = request.data.get('device_name')
        device_config = request.data.get('device_config', {})
        
        if not device_type:
            return error_response(
                message="Device type is required",
                error_code="MISSING_DEVICE_TYPE",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        if not device_name:
            return error_response(
                message="Device name is required",
                error_code="MISSING_DEVICE_NAME",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Register the device
        registration_result = mfa_device_management_service.register_device(
            user=request.user,
            device_type=device_type,
            device_name=device_name,
            device_config=device_config,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=registration_result,
            message="MFA device registration initiated successfully"
        )
        
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=getattr(e, 'error_code', 'MFA_REGISTRATION_FAILED'),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to register MFA device",
            error_code="MFA_REGISTRATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def confirm_mfa_device_registration(request: Request) -> Response:
    """
    Confirm MFA device registration.
    
    Request body:
    {
        "device_id": "uuid",
        "confirmation_data": {
            "verification_code": "123456",  // for TOTP, SMS, email
            // Other device-specific confirmation data
        }
    }
    
    Response:
    {
        "success": true,
        "data": {
            "device_id": "uuid",
            "device_name": "My Phone",
            "device_type": "totp",
            "status": "active",
            "confirmed_at": "2024-01-15T10:30:00Z",
            "backup_codes": ["XXXXXXXX", ...],  // if applicable
            "security_score": 0.9
        }
    }
    """
    try:
        device_id = request.data.get('device_id')
        confirmation_data = request.data.get('confirmation_data', {})
        
        if not device_id:
            return error_response(
                message="Device ID is required",
                error_code="MISSING_DEVICE_ID",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Confirm the device registration
        confirmation_result = mfa_device_management_service.confirm_device_registration(
            user=request.user,
            device_id=device_id,
            confirmation_data=confirmation_data,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=confirmation_result,
            message="MFA device registration confirmed successfully"
        )
        
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=getattr(e, 'error_code', 'MFA_DEVICE_NOT_FOUND'),
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAVerificationError as e:
        return error_response(
            message=str(e),
            error_code=getattr(e, 'error_code', 'MFA_VERIFICATION_FAILED'),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=getattr(e, 'error_code', 'MFA_CONFIRMATION_FAILED'),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to confirm MFA device registration",
            error_code="MFA_CONFIRMATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_mfa_devices(request: Request) -> Response:
    """
    List MFA devices for the authenticated user.
    
    Query parameters:
    - include_inactive: boolean (default: false)
    - device_type: string (filter by device type)
    
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
                    "is_primary": true,
                    "can_be_removed": false,
                    "security_score": 0.9,
                    "created_at": "2024-01-15T10:30:00Z",
                    "last_used": "2024-01-15T10:30:00Z",
                    "usage_count": 5,
                    "last_activity": {
                        "timestamp": "2024-01-15T10:30:00Z",
                        "ip_address": "192.168.1.1",
                        "user_agent": "Mozilla/5.0..."
                    },
                    "usage_statistics": {
                        "total_attempts": 10,
                        "successful_attempts": 9,
                        "failed_attempts": 1
                    }
                }
            ],
            "total_devices": 3,
            "active_devices": 2,
            "device_type_counts": {
                "totp": 1,
                "sms": 1,
                "backup_codes": 1
            }
        }
    }
    """
    try:
        # Get query parameters
        include_inactive = request.GET.get('include_inactive', 'false').lower() == 'true'
        device_type_filter = request.GET.get('device_type')
        
        # List devices
        devices = mfa_device_management_service.list_user_devices(
            user=request.user,
            include_inactive=include_inactive,
            device_type_filter=device_type_filter
        )
        
        # Calculate summary statistics
        total_devices = len(devices)
        active_devices = len([d for d in devices if d['is_active']])
        
        device_type_counts = {}
        for device in devices:
            device_type = device['type']
            device_type_counts[device_type] = device_type_counts.get(device_type, 0) + 1
        
        return success_response(
            data={
                'devices': devices,
                'total_devices': total_devices,
                'active_devices': active_devices,
                'device_type_counts': device_type_counts
            },
            message="MFA devices retrieved successfully"
        )
        
    except Exception as e:
        return error_response(
            message="Failed to retrieve MFA devices",
            error_code="MFA_DEVICES_RETRIEVAL_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_mfa_device(request: Request) -> Response:
    """
    Remove an MFA device with proper security checks.
    
    Request body:
    {
        "device_id": "uuid",
        "removal_reason": "user_request",  // optional
        "current_mfa_verification": {  // required for active devices
            "type": "totp|backup_code",
            "code": "123456",
            "device_id": "uuid"  // optional for TOTP
        }
    }
    
    Response:
    {
        "success": true,
        "data": {
            "removed": true,
            "device_info": {
                "device_id": "uuid",
                "device_name": "My Phone",
                "device_type": "totp",
                "status": "active",
                "usage_count": 5
            },
            "removal_reason": "user_request",
            "removed_at": "2024-01-15T10:30:00Z"
        }
    }
    """
    try:
        device_id = request.data.get('device_id')
        removal_reason = request.data.get('removal_reason', 'user_request')
        current_mfa_verification = request.data.get('current_mfa_verification')
        
        if not device_id:
            return error_response(
                message="Device ID is required",
                error_code="MISSING_DEVICE_ID",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Remove the device
        removal_result = mfa_device_management_service.remove_device(
            user=request.user,
            device_id=device_id,
            removal_reason=removal_reason,
            current_mfa_verification=current_mfa_verification,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=removal_result,
            message="MFA device removed successfully"
        )
        
    except MFADeviceNotFoundError as e:
        return error_response(
            message=str(e),
            error_code=getattr(e, 'error_code', 'MFA_DEVICE_NOT_FOUND'),
            status_code=status.HTTP_404_NOT_FOUND
        )
    except MFAError as e:
        return error_response(
            message=str(e),
            error_code=getattr(e, 'error_code', 'MFA_DEVICE_REMOVAL_FAILED'),
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to remove MFA device",
            error_code="MFA_DEVICE_REMOVAL_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_organization_mfa_policy(request: Request) -> Response:
    """
    Get MFA enforcement policy for the user's organization.
    
    Response:
    {
        "success": true,
        "data": {
            "organization": "Acme Corp",
            "enforcement_enabled": true,
            "mfa_required": true,
            "allowed_device_types": ["totp", "sms", "email", "backup_codes"],
            "min_devices_required": 2,
            "max_devices_allowed": 10,
            "require_backup_codes": true,
            "allowed_grace_period_hours": 24,
            "enforce_device_diversity": false
        }
    }
    """
    try:
        if not request.user.organization:
            return error_response(
                message="User is not associated with an organization",
                error_code="NO_ORGANIZATION",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get organization policy
        policy = mfa_device_management_service.get_organization_mfa_policy(
            request.user.organization
        )
        
        policy['organization'] = request.user.organization
        
        return success_response(
            data=policy,
            message="Organization MFA policy retrieved successfully"
        )
        
    except Exception as e:
        return error_response(
            message="Failed to retrieve organization MFA policy",
            error_code="ORG_POLICY_RETRIEVAL_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enforce_organization_mfa_policy(request: Request) -> Response:
    """
    Enforce organization MFA policy for the authenticated user.
    
    Response:
    {
        "success": true,
        "data": {
            "policy_enforced": true,
            "organization": "Acme Corp",
            "compliance_status": "compliant|non_compliant|grace_period",
            "compliance_issues": [
                "MFA is required but no active devices found",
                "Minimum 2 devices required, but only 1 found"
            ],
            "active_devices_count": 1,
            "device_types": ["totp"],
            "enforcement_actions": ["show_warning", "encourage_mfa_setup"],
            "policy": {
                // Full policy details
            }
        }
    }
    """
    try:
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Enforce organization policy
        enforcement_result = mfa_device_management_service.enforce_organization_mfa_policy(
            user=request.user,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return success_response(
            data=enforcement_result,
            message="Organization MFA policy enforcement completed"
        )
        
    except Exception as e:
        return error_response(
            message="Failed to enforce organization MFA policy",
            error_code="ORG_POLICY_ENFORCEMENT_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_device_management_statistics(request: Request) -> Response:
    """
    Get device management statistics for the authenticated user.
    
    Query parameters:
    - days: integer (default: 30) - Number of days to look back
    
    Response:
    {
        "success": true,
        "data": {
            "period_days": 30,
            "total_devices": 3,
            "active_devices": 2,
            "pending_devices": 0,
            "disabled_devices": 1,
            "device_type_statistics": {
                "totp": {
                    "device_count": 1,
                    "total_attempts": 50,
                    "successful_attempts": 48,
                    "failed_attempts": 2,
                    "last_used": "2024-01-15T10:30:00Z"
                },
                "sms": {
                    "device_count": 1,
                    "total_attempts": 10,
                    "successful_attempts": 9,
                    "failed_attempts": 1,
                    "last_used": "2024-01-14T15:20:00Z"
                }
            },
            "organization_compliance": {
                // Organization compliance details if applicable
            }
        }
    }
    """
    try:
        # Get query parameters
        days = int(request.GET.get('days', 30))
        
        # Get device management statistics
        statistics = mfa_device_management_service.get_device_management_statistics(
            user=request.user,
            days=days
        )
        
        return success_response(
            data=statistics,
            message="Device management statistics retrieved successfully"
        )
        
    except ValueError:
        return error_response(
            message="Invalid days parameter. Must be a positive integer.",
            error_code="INVALID_DAYS_PARAMETER",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return error_response(
            message="Failed to retrieve device management statistics",
            error_code="STATISTICS_RETRIEVAL_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def bulk_device_operation(request: Request) -> Response:
    """
    Perform bulk operations on MFA devices.
    
    Request body:
    {
        "operation": "disable|enable|remove",
        "device_ids": ["uuid1", "uuid2", "uuid3"],
        "reason": "security_incident",  // optional
        "current_mfa_verification": {  // required for sensitive operations
            "type": "totp|backup_code",
            "code": "123456",
            "device_id": "uuid"  // optional for TOTP
        }
    }
    
    Response:
    {
        "success": true,
        "data": {
            "operation": "disable",
            "total_devices": 3,
            "successful_operations": 2,
            "failed_operations": 1,
            "results": [
                {
                    "device_id": "uuid1",
                    "success": true,
                    "message": "Device disabled successfully"
                },
                {
                    "device_id": "uuid2",
                    "success": false,
                    "error": "Device not found"
                }
            ]
        }
    }
    """
    try:
        operation = request.data.get('operation')
        device_ids = request.data.get('device_ids', [])
        reason = request.data.get('reason', 'bulk_operation')
        current_mfa_verification = request.data.get('current_mfa_verification')
        
        if not operation:
            return error_response(
                message="Operation is required",
                error_code="MISSING_OPERATION",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        if not device_ids:
            return error_response(
                message="Device IDs are required",
                error_code="MISSING_DEVICE_IDS",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        valid_operations = ['disable', 'enable', 'remove']
        if operation not in valid_operations:
            return error_response(
                message=f"Invalid operation. Must be one of: {', '.join(valid_operations)}",
                error_code="INVALID_OPERATION",
                status_code=status.HTTP_400_BAD_REQUEST
            )
        
        # Get request metadata
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
        
        # Perform bulk operation
        results = []
        successful_operations = 0
        
        for device_id in device_ids:
            try:
                if operation == 'remove':
                    result = mfa_device_management_service.remove_device(
                        user=request.user,
                        device_id=device_id,
                        removal_reason=reason,
                        current_mfa_verification=current_mfa_verification,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    results.append({
                        'device_id': device_id,
                        'success': True,
                        'message': 'Device removed successfully',
                        'result': result
                    })
                    successful_operations += 1
                elif operation == 'disable':
                    # Get device and disable it
                    from ..models import MFADevice
                    device = MFADevice.objects.get(id=device_id, user=request.user)
                    device.disable_device(reason)
                    
                    results.append({
                        'device_id': device_id,
                        'success': True,
                        'message': 'Device disabled successfully'
                    })
                    successful_operations += 1
                elif operation == 'enable':
                    # Get device and enable it
                    from ..models import MFADevice
                    device = MFADevice.objects.get(id=device_id, user=request.user)
                    if device.status == 'disabled':
                        device.status = 'active'
                        device.save(update_fields=['status'])
                    
                    results.append({
                        'device_id': device_id,
                        'success': True,
                        'message': 'Device enabled successfully'
                    })
                    successful_operations += 1
                    
            except Exception as e:
                results.append({
                    'device_id': device_id,
                    'success': False,
                    'error': str(e)
                })
        
        return success_response(
            data={
                'operation': operation,
                'total_devices': len(device_ids),
                'successful_operations': successful_operations,
                'failed_operations': len(device_ids) - successful_operations,
                'results': results
            },
            message=f"Bulk {operation} operation completed"
        )
        
    except Exception as e:
        return error_response(
            message=f"Failed to perform bulk {operation} operation",
            error_code="BULK_OPERATION_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )