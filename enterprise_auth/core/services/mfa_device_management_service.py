"""
MFA Device Management service for enterprise authentication system.

This module provides comprehensive MFA device management functionality including
device registration, confirmation, listing, removal with security checks,
and organization-level MFA enforcement policies.
"""

import secrets
import string
from typing import Optional, Dict, Any, List
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.db import transaction

from django.db import models
from ..models import UserProfile, MFADevice, MFAAttempt
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)
from .audit_service import AuditService
from .sms_mfa_service import SMSMFAService
from .email_mfa_service import EmailMFAService
from .backup_codes_service import BackupCodesService


class MFADeviceManagementService:
    """
    Service for managing MFA device lifecycle and enforcement policies.
    
    Provides device registration, confirmation, listing, removal with security checks,
    and organization-level MFA enforcement policies with comprehensive audit logging.
    """
    
    def __init__(self):
        """Initialize the MFA device management service."""
        self.audit_service = AuditService()
        self.sms_service = SMSMFAService()
        self.email_service = EmailMFAService()
        self.backup_codes_service = BackupCodesService()
        
        # Configuration
        self.max_devices_per_user = getattr(settings, 'MFA_MAX_DEVICES_PER_USER', 10)
        self.max_devices_per_type = getattr(settings, 'MFA_MAX_DEVICES_PER_TYPE', 5)
        self.device_confirmation_timeout = getattr(settings, 'MFA_DEVICE_CONFIRMATION_TIMEOUT', 3600)  # 1 hour
        self.require_current_mfa_for_removal = getattr(settings, 'MFA_REQUIRE_CURRENT_MFA_FOR_REMOVAL', True)
        self.min_active_devices = getattr(settings, 'MFA_MIN_ACTIVE_DEVICES', 1)
        
        # Organization policy settings
        self.org_mfa_enforcement_enabled = getattr(settings, 'MFA_ORG_ENFORCEMENT_ENABLED', True)
        self.default_org_mfa_required = getattr(settings, 'MFA_DEFAULT_ORG_REQUIRED', False)
        self.org_policy_cache_timeout = getattr(settings, 'MFA_ORG_POLICY_CACHE_TIMEOUT', 300)  # 5 minutes
    
    def register_device(
        self,
        user: UserProfile,
        device_type: str,
        device_name: str,
        device_config: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Register a new MFA device for a user.
        
        Args:
            user: User to register device for
            device_type: Type of MFA device (totp, sms, email, backup_codes)
            device_name: User-friendly name for the device
            device_config: Device-specific configuration
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing device registration information
            
        Raises:
            MFAError: If registration fails or limits exceeded
        """
        try:
            # Validate device type
            valid_types = ['totp', 'sms', 'email', 'backup_codes']
            if device_type not in valid_types:
                raise MFAError(f"Invalid device type. Must be one of: {', '.join(valid_types)}")
            
            # Check device limits
            self._check_device_limits(user, device_type)
            
            # Validate device name uniqueness for user
            if MFADevice.objects.filter(user=user, device_name=device_name).exists():
                raise MFAError("Device name already exists. Please choose a different name.")
            
            # Register device based on type
            if device_type == 'totp':
                return self._register_totp_device(user, device_name, device_config, ip_address, user_agent)
            elif device_type == 'sms':
                return self._register_sms_device(user, device_name, device_config, ip_address, user_agent)
            elif device_type == 'email':
                return self._register_email_device(user, device_name, device_config, ip_address, user_agent)
            elif device_type == 'backup_codes':
                return self._register_backup_codes_device(user, device_name, device_config, ip_address, user_agent)
            
        except MFAError:
            raise
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_device_registration_failed',
                user=user,
                description=f'MFA device registration failed: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_type': device_type,
                    'device_name': device_name,
                    'error': str(e)
                }
            )
            raise MFAError(f"Failed to register MFA device: {str(e)}")
    
    def confirm_device_registration(
        self,
        user: UserProfile,
        device_id: str,
        confirmation_data: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Confirm MFA device registration.
        
        Args:
            user: User confirming the device
            device_id: ID of the device to confirm
            confirmation_data: Device-specific confirmation data
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing confirmation result
            
        Raises:
            MFADeviceNotFoundError: If device not found
            MFAVerificationError: If confirmation fails
        """
        try:
            # Get the device
            device = MFADevice.objects.get(
                id=device_id,
                user=user,
                status='pending'
            )
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("MFA device not found or already confirmed")
        
        # Check confirmation timeout
        if device.created_at < timezone.now() - timedelta(seconds=self.device_confirmation_timeout):
            device.mark_compromised('confirmation_timeout')
            raise MFAVerificationError("Device confirmation timeout. Please register a new device.")
        
        try:
            # Confirm device based on type
            if device.device_type == 'totp':
                return self._confirm_totp_device(device, confirmation_data, ip_address, user_agent)
            elif device.device_type == 'sms':
                return self._confirm_sms_device(device, confirmation_data, ip_address, user_agent)
            elif device.device_type == 'email':
                return self._confirm_email_device(device, confirmation_data, ip_address, user_agent)
            elif device.device_type == 'backup_codes':
                return self._confirm_backup_codes_device(device, confirmation_data, ip_address, user_agent)
            else:
                raise MFAError(f"Unsupported device type: {device.device_type}")
                
        except (MFAVerificationError, MFAError):
            raise
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_device_confirmation_failed',
                user=user,
                description=f'MFA device confirmation failed: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': device_id,
                    'device_type': device.device_type,
                    'device_name': device.device_name,
                    'error': str(e)
                }
            )
            raise MFAError(f"Failed to confirm MFA device: {str(e)}")
    
    def list_user_devices(
        self,
        user: UserProfile,
        include_inactive: bool = False,
        device_type_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List MFA devices for a user with detailed information.
        
        Args:
            user: User to list devices for
            include_inactive: Whether to include inactive devices
            device_type_filter: Filter by specific device type
            
        Returns:
            List of device information dictionaries
        """
        # Get devices based on filters
        devices = MFADevice.objects.filter(user=user)
        
        if not include_inactive:
            devices = devices.filter(status='active', is_confirmed=True)
        
        if device_type_filter:
            devices = devices.filter(device_type=device_type_filter)
        
        devices = devices.order_by('device_type', 'device_name')
        
        # Build detailed device information
        device_list = []
        for device in devices:
            device_info = device.get_display_info()
            
            # Add additional management information
            device_info.update({
                'can_be_removed': self._can_device_be_removed(user, device),
                'is_primary': self._is_primary_device(user, device),
                'security_score': self._calculate_device_security_score(device),
                'last_activity': self._get_device_last_activity(device),
                'usage_statistics': self._get_device_usage_statistics(device)
            })
            
            device_list.append(device_info)
        
        return device_list
    
    def remove_device(
        self,
        user: UserProfile,
        device_id: str,
        removal_reason: str = 'user_request',
        current_mfa_verification: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Remove an MFA device with proper security checks.
        
        Args:
            user: User removing the device
            device_id: ID of the device to remove
            removal_reason: Reason for removal
            current_mfa_verification: Current MFA verification data if required
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing removal result
            
        Raises:
            MFADeviceNotFoundError: If device not found
            MFAError: If removal is not allowed or fails
        """
        try:
            # Get the device
            device = MFADevice.objects.get(id=device_id, user=user)
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("MFA device not found")
        
        # Check if device can be removed
        if not self._can_device_be_removed(user, device):
            raise MFAError("Cannot remove device. At least one active MFA device must remain.")
        
        # Verify current MFA if required
        if self.require_current_mfa_for_removal and device.status == 'active':
            if not current_mfa_verification:
                raise MFAError("Current MFA verification required to remove active device")
            
            self._verify_current_mfa(user, current_mfa_verification, ip_address, user_agent)
        
        # Check organization policy
        if not self._check_org_policy_allows_removal(user, device):
            raise MFAError("Organization policy prevents removal of this device type")
        
        try:
            with transaction.atomic():
                # Store device info for logging
                device_info = {
                    'device_id': str(device.id),
                    'device_name': device.device_name,
                    'device_type': device.device_type,
                    'status': device.status,
                    'usage_count': device.usage_count,
                    'last_used': device.last_used.isoformat() if device.last_used else None
                }
                
                # Remove the device
                device.delete()
                
                # Log the removal
                self.audit_service.log_authentication_event(
                    event_type='mfa_device_removed',
                    user=user,
                    description=f'MFA device removed: {device_info["device_name"]} ({removal_reason})',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    },
                    metadata={
                        **device_info,
                        'removal_reason': removal_reason,
                        'required_mfa_verification': self.require_current_mfa_for_removal
                    }
                )
                
                return {
                    'removed': True,
                    'device_info': device_info,
                    'removal_reason': removal_reason,
                    'removed_at': timezone.now().isoformat()
                }
                
        except (MFADeviceNotFoundError, MFAError):
            raise
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_device_removal_failed',
                user=user,
                description=f'MFA device removal failed: {str(e)}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': device_id,
                    'removal_reason': removal_reason,
                    'error': str(e)
                }
            )
            raise MFAError(f"Failed to remove MFA device: {str(e)}")
    
    def get_organization_mfa_policy(self, organization: str) -> Dict[str, Any]:
        """
        Get MFA enforcement policy for an organization.
        
        Args:
            organization: Organization name
            
        Returns:
            Dictionary containing organization MFA policy
        """
        if not self.org_mfa_enforcement_enabled:
            return {
                'enforcement_enabled': False,
                'mfa_required': False,
                'allowed_device_types': ['totp', 'sms', 'email', 'backup_codes'],
                'min_devices_required': 0,
                'max_devices_allowed': self.max_devices_per_user
            }
        
        # Check cache first
        cache_key = f"org_mfa_policy:{organization}"
        cached_policy = cache.get(cache_key)
        if cached_policy:
            return cached_policy
        
        # Get policy from database or use defaults
        # This would typically query an OrganizationMFAPolicy model
        # For now, we'll use default settings
        policy = {
            'enforcement_enabled': True,
            'mfa_required': self.default_org_mfa_required,
            'allowed_device_types': ['totp', 'sms', 'email', 'backup_codes'],
            'min_devices_required': 1 if self.default_org_mfa_required else 0,
            'max_devices_allowed': self.max_devices_per_user,
            'require_backup_codes': True,
            'allowed_grace_period_hours': 24,
            'enforce_device_diversity': False  # Require different device types
        }
        
        # Cache the policy
        cache.set(cache_key, policy, timeout=self.org_policy_cache_timeout)
        
        return policy
    
    def enforce_organization_mfa_policy(
        self,
        user: UserProfile,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enforce organization MFA policy for a user.
        
        Args:
            user: User to enforce policy for
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing policy enforcement result
        """
        if not user.organization:
            return {
                'policy_enforced': False,
                'reason': 'User not associated with an organization',
                'compliance_status': 'not_applicable'
            }
        
        policy = self.get_organization_mfa_policy(user.organization)
        
        if not policy['enforcement_enabled']:
            return {
                'policy_enforced': False,
                'reason': 'MFA enforcement not enabled for organization',
                'compliance_status': 'not_applicable'
            }
        
        # Check current MFA status
        active_devices = MFADevice.objects.get_active_devices(user)
        device_types = set(device.device_type for device in active_devices)
        
        compliance_issues = []
        
        # Check if MFA is required
        if policy['mfa_required'] and not active_devices.exists():
            compliance_issues.append('MFA is required but no active devices found')
        
        # Check minimum devices requirement
        if active_devices.count() < policy['min_devices_required']:
            compliance_issues.append(
                f"Minimum {policy['min_devices_required']} devices required, "
                f"but only {active_devices.count()} found"
            )
        
        # Check device type restrictions
        disallowed_types = device_types - set(policy['allowed_device_types'])
        if disallowed_types:
            compliance_issues.append(
                f"Disallowed device types found: {', '.join(disallowed_types)}"
            )
        
        # Check backup codes requirement
        if policy.get('require_backup_codes', False):
            if not active_devices.filter(device_type='backup_codes').exists():
                compliance_issues.append('Backup codes are required but not configured')
        
        # Check device diversity requirement
        if policy.get('enforce_device_diversity', False):
            if len(device_types) < 2:
                compliance_issues.append('Multiple device types required for diversity')
        
        # Determine compliance status
        if not compliance_issues:
            compliance_status = 'compliant'
        elif policy.get('allowed_grace_period_hours', 0) > 0:
            # Check if user is within grace period
            grace_period = timedelta(hours=policy['allowed_grace_period_hours'])
            if user.created_at > timezone.now() - grace_period:
                compliance_status = 'grace_period'
            else:
                compliance_status = 'non_compliant'
        else:
            compliance_status = 'non_compliant'
        
        # Log policy enforcement
        self.audit_service.log_authentication_event(
            event_type='mfa_policy_enforcement_check',
            user=user,
            description=f'MFA policy enforcement check: {compliance_status}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'organization': user.organization,
                'policy': policy,
                'compliance_status': compliance_status,
                'compliance_issues': compliance_issues,
                'active_devices_count': active_devices.count(),
                'device_types': list(device_types)
            }
        )
        
        return {
            'policy_enforced': True,
            'organization': user.organization,
            'policy': policy,
            'compliance_status': compliance_status,
            'compliance_issues': compliance_issues,
            'active_devices_count': active_devices.count(),
            'device_types': list(device_types),
            'enforcement_actions': self._get_enforcement_actions(compliance_status, compliance_issues)
        }
    
    def get_device_management_statistics(
        self,
        user: UserProfile,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get device management statistics for monitoring.
        
        Args:
            user: User to get statistics for
            days: Number of days to look back
            
        Returns:
            Dictionary containing device management statistics
        """
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Get all devices
        all_devices = MFADevice.objects.filter(user=user)
        active_devices = all_devices.filter(status='active', is_confirmed=True)
        
        # Get device usage statistics
        attempts = MFAAttempt.objects.filter(
            user=user,
            created_at__gte=cutoff_date
        )
        
        # Calculate statistics by device type
        device_type_stats = {}
        for device_type in ['totp', 'sms', 'email', 'backup_codes']:
            type_devices = active_devices.filter(device_type=device_type)
            type_attempts = attempts.filter(device__device_type=device_type)
            
            device_type_stats[device_type] = {
                'device_count': type_devices.count(),
                'total_attempts': type_attempts.count(),
                'successful_attempts': type_attempts.filter(result='success').count(),
                'failed_attempts': type_attempts.filter(result='failure').count(),
                'last_used': type_devices.aggregate(
                    last_used=models.Max('last_used')
                )['last_used']
            }
        
        return {
            'period_days': days,
            'total_devices': all_devices.count(),
            'active_devices': active_devices.count(),
            'pending_devices': all_devices.filter(status='pending').count(),
            'disabled_devices': all_devices.filter(status='disabled').count(),
            'device_type_statistics': device_type_stats,
            'organization_compliance': self.enforce_organization_mfa_policy(user) if user.organization else None
        }
    
    # Private helper methods
    
    def _check_device_limits(self, user: UserProfile, device_type: str) -> None:
        """Check if user can add another device of the specified type."""
        # Check total device limit
        total_devices = MFADevice.objects.filter(user=user).count()
        if total_devices >= self.max_devices_per_user:
            raise MFAError(f"Maximum {self.max_devices_per_user} devices allowed per user")
        
        # Check device type limit
        type_devices = MFADevice.objects.filter(user=user, device_type=device_type).count()
        if type_devices >= self.max_devices_per_type:
            raise MFAError(f"Maximum {self.max_devices_per_type} {device_type} devices allowed")
    
    def _register_totp_device(
        self,
        user: UserProfile,
        device_name: str,
        device_config: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Register a TOTP device."""
        from .mfa_service import MFAService
        mfa_service = MFAService()
        return mfa_service.setup_totp(user, device_name, ip_address, user_agent)
    
    def _register_sms_device(
        self,
        user: UserProfile,
        device_name: str,
        device_config: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Register an SMS device."""
        phone_number = device_config.get('phone_number')
        if not phone_number:
            raise MFAError("Phone number is required for SMS device")
        
        return self.sms_service.setup_sms(user, device_name, phone_number, ip_address, user_agent)
    
    def _register_email_device(
        self,
        user: UserProfile,
        device_name: str,
        device_config: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Register an email device."""
        email_address = device_config.get('email_address')
        return self.email_service.setup_email_mfa(user, device_name, email_address, ip_address, user_agent)
    
    def _register_backup_codes_device(
        self,
        user: UserProfile,
        device_name: str,
        device_config: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Register a backup codes device."""
        count = device_config.get('count', 10)
        return self.backup_codes_service.generate_backup_codes(user, count, ip_address, user_agent)
    
    def _confirm_totp_device(
        self,
        device: MFADevice,
        confirmation_data: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Confirm a TOTP device."""
        from .mfa_service import MFAService
        mfa_service = MFAService()
        verification_code = confirmation_data.get('verification_code')
        if not verification_code:
            raise MFAVerificationError("Verification code is required")
        
        return mfa_service.confirm_totp_setup(
            device.user, str(device.id), verification_code, ip_address, user_agent
        )
    
    def _confirm_sms_device(
        self,
        device: MFADevice,
        confirmation_data: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Confirm an SMS device."""
        verification_code = confirmation_data.get('verification_code')
        if not verification_code:
            raise MFAVerificationError("Verification code is required")
        
        return self.sms_service.confirm_sms_setup(
            device.user, str(device.id), verification_code, ip_address, user_agent
        )
    
    def _confirm_email_device(
        self,
        device: MFADevice,
        confirmation_data: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Confirm an email device."""
        verification_code = confirmation_data.get('verification_code')
        if not verification_code:
            raise MFAVerificationError("Verification code is required")
        
        return self.email_service.confirm_email_setup(
            device.user, str(device.id), verification_code, ip_address, user_agent
        )
    
    def _confirm_backup_codes_device(
        self,
        device: MFADevice,
        confirmation_data: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Dict[str, Any]:
        """Confirm a backup codes device."""
        # Backup codes are automatically confirmed when generated
        device.confirm_device(ip_address)
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'confirmed_at': device.created_at.isoformat(),
            'status': 'active'
        }
    
    def _can_device_be_removed(self, user: UserProfile, device: MFADevice) -> bool:
        """Check if a device can be removed without violating minimum requirements."""
        if device.status != 'active':
            return True  # Inactive devices can always be removed
        
        active_devices = MFADevice.objects.get_active_devices(user)
        
        # Check minimum active devices requirement
        if active_devices.count() <= self.min_active_devices:
            return False
        
        # Check organization policy
        if user.organization:
            policy = self.get_organization_mfa_policy(user.organization)
            if active_devices.count() <= policy.get('min_devices_required', 0):
                return False
        
        return True
    
    def _is_primary_device(self, user: UserProfile, device: MFADevice) -> bool:
        """Check if this is the user's primary device of its type."""
        return not MFADevice.objects.filter(
            user=user,
            device_type=device.device_type,
            status='active',
            is_confirmed=True,
            created_at__lt=device.created_at
        ).exists()
    
    def _calculate_device_security_score(self, device: MFADevice) -> float:
        """Calculate a security score for the device."""
        score = 0.0
        
        # Base score by device type
        type_scores = {
            'totp': 0.9,
            'sms': 0.6,
            'email': 0.5,
            'backup_codes': 0.8
        }
        score += type_scores.get(device.device_type, 0.5)
        
        # Bonus for recent usage
        if device.last_used:
            days_since_use = (timezone.now() - device.last_used).days
            if days_since_use < 7:
                score += 0.1
            elif days_since_use < 30:
                score += 0.05
        
        # Penalty for old devices
        device_age_days = (timezone.now() - device.created_at).days
        if device_age_days > 365:
            score -= 0.1
        
        return min(1.0, max(0.0, score))
    
    def _get_device_last_activity(self, device: MFADevice) -> Optional[Dict[str, Any]]:
        """Get the last activity information for a device."""
        if not device.last_used:
            return None
        
        return {
            'timestamp': device.last_used.isoformat(),
            'ip_address': device.last_used_ip,
            'user_agent': device.created_user_agent  # Simplified for now
        }
    
    def _get_device_usage_statistics(self, device: MFADevice) -> Dict[str, Any]:
        """Get usage statistics for a device."""
        from ..models import MFAAttempt
        
        # Get attempts for the last 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        attempts = MFAAttempt.objects.filter(
            device=device,
            created_at__gte=cutoff_date
        )
        
        total_attempts = attempts.count()
        successful_attempts = attempts.filter(result='success').count()
        failed_attempts = attempts.filter(result='failure').count()
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'failed_attempts': failed_attempts,
            'success_rate': (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        }
    
    def _verify_current_mfa(
        self,
        user: UserProfile,
        verification_data: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> bool:
        """Verify current MFA for sensitive operations."""
        verification_type = verification_data.get('type')
        code = verification_data.get('code')
        device_id = verification_data.get('device_id')
        
        if not verification_type or not code:
            raise MFAError("MFA verification type and code are required")
        
        if verification_type == 'totp':
            from .mfa_service import MFAService
            mfa_service = MFAService()
            return mfa_service.verify_totp(user, code, device_id, ip_address, user_agent)
        elif verification_type == 'backup_code':
            return self.backup_codes_service.verify_backup_code(user, code, ip_address, user_agent)
        else:
            raise MFAError(f"Unsupported MFA verification type: {verification_type}")
    
    def _check_org_policy_allows_removal(self, user: UserProfile, device: MFADevice) -> bool:
        """Check if organization policy allows removal of this device."""
        if not user.organization:
            return True
        
        policy = self.get_organization_mfa_policy(user.organization)
        
        # Check if device type is required
        if device.device_type not in policy.get('allowed_device_types', []):
            return True  # Can remove disallowed device types
        
        # Check if removing this device would violate minimum requirements
        active_devices = MFADevice.objects.get_active_devices(user)
        remaining_devices = active_devices.exclude(id=device.id)
        
        if remaining_devices.count() < policy.get('min_devices_required', 0):
            return False
        
        # Check backup codes requirement
        if policy.get('require_backup_codes', False) and device.device_type == 'backup_codes':
            return False
        
        return True
    
    def _get_enforcement_actions(
        self,
        compliance_status: str,
        compliance_issues: List[str]
    ) -> List[str]:
        """Get enforcement actions based on compliance status."""
        actions = []
        
        if compliance_status == 'non_compliant':
            actions.extend([
                'block_access',
                'require_mfa_setup',
                'send_admin_alert'
            ])
        elif compliance_status == 'grace_period':
            actions.extend([
                'show_warning',
                'encourage_mfa_setup',
                'send_reminder_email'
            ])
        elif 'backup codes' in ' '.join(compliance_issues).lower():
            actions.append('encourage_backup_codes')
        
        return actions


        # Bonus for recent usage
        if device.last_used:
            days_since_use = (timezone.now() - device.last_used).days
            if days_since_use < 7:
                score += 0.1
            elif days_since_use < 30:
                score += 0.05
        
        # Penalty for old devices
        days_since_creation = (timezone.now() - device.created_at).days
        if days_since_creation > 365:
            score -= 0.1
        
        return min(1.0, max(0.0, score))
    
    def _get_device_last_activity(self, device: MFADevice) -> Optional[Dict[str, Any]]:
        """Get the last activity information for a device."""
        if not device.last_used:
            return None
        
        last_attempt = MFAAttempt.objects.filter(
            device=device,
            result='success'
        ).order_by('-created_at').first()
        
        if last_attempt:
            return {
                'timestamp': last_attempt.created_at.isoformat(),
                'ip_address': last_attempt.ip_address,
                'user_agent': last_attempt.user_agent[:100] if last_attempt.user_agent else None
            }
        
        return {
            'timestamp': device.last_used.isoformat(),
            'ip_address': device.last_used_ip,
            'user_agent': None
        }
    
    def _get_device_usage_statistics(self, device: MFADevice) -> Dict[str, Any]:
        """Get usage statistics for a device."""
        attempts = MFAAttempt.objects.filter(device=device)
        
        return {
            'total_attempts': attempts.count(),
            'successful_attempts': attempts.filter(result='success').count(),
            'failed_attempts': attempts.filter(result='failure').count(),
            'usage_count': device.usage_count,
            'first_used': device.created_at.isoformat(),
            'last_used': device.last_used.isoformat() if device.last_used else None
        }
    
    def _verify_current_mfa(
        self,
        user: UserProfile,
        verification_data: Dict[str, Any],
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> None:
        """Verify current MFA for sensitive operations."""
        verification_type = verification_data.get('type')
        
        if verification_type == 'totp':
            from .mfa_service import MFAService
            mfa_service = MFAService()
            mfa_service.verify_totp(
                user,
                verification_data.get('code'),
                verification_data.get('device_id'),
                ip_address,
                user_agent
            )
        elif verification_type == 'backup_code':
            self.backup_codes_service.validate_backup_code(
                user,
                verification_data.get('code'),
                ip_address,
                user_agent
            )
        else:
            raise MFAError("Invalid MFA verification type")
    
    def _check_org_policy_allows_removal(self, user: UserProfile, device: MFADevice) -> bool:
        """Check if organization policy allows removal of this device."""
        if not user.organization:
            return True
        
        policy = self.get_organization_mfa_policy(user.organization)
        
        # Check if removing this device would violate policy
        active_devices = MFADevice.objects.get_active_devices(user)
        
        if device.status == 'active':
            remaining_devices = active_devices.exclude(id=device.id)
            
            # Check minimum devices requirement
            if remaining_devices.count() < policy.get('min_devices_required', 0):
                return False
            
            # Check backup codes requirement
            if policy.get('require_backup_codes', False):
                if device.device_type == 'backup_codes':
                    if not remaining_devices.filter(device_type='backup_codes').exists():
                        return False
        
        return True
    
    def _get_enforcement_actions(
        self,
        compliance_status: str,
        compliance_issues: List[str]
    ) -> List[str]:
        """Get enforcement actions based on compliance status."""
        actions = []
        
        if compliance_status == 'non_compliant':
            actions.append('block_access')
            actions.append('require_mfa_setup')
        elif compliance_status == 'grace_period':
            actions.append('show_warning')
            actions.append('encourage_mfa_setup')
        
        return actions


# Global service instance
mfa_device_management_service = MFADeviceManagementService()