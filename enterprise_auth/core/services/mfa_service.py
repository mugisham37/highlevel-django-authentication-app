"""
Multi-Factor Authentication service for enterprise authentication system.

This module provides comprehensive MFA functionality including TOTP setup,
verification, backup codes, and device management with security features.
"""

import io
import secrets
import time
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import quote

import pyotp
import qrcode
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from ..models import UserProfile, MFADevice, MFAAttempt
from ..exceptions import (
    MFAError, 
    MFADeviceNotFoundError, 
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)
from .audit_service import AuditService


class MFAService:
    """
    Service for managing Multi-Factor Authentication operations.
    
    Provides TOTP setup, verification, backup codes, and device management
    with comprehensive security features and rate limiting.
    """
    
    def __init__(self):
        """Initialize the MFA service."""
        self.audit_service = AuditService()
        
        # Configuration
        self.totp_window = getattr(settings, 'MFA_TOTP_WINDOW', 1)  # 30-second windows
        self.totp_issuer = getattr(settings, 'MFA_TOTP_ISSUER', 'Enterprise Auth')
        self.rate_limit_window = getattr(settings, 'MFA_RATE_LIMIT_WINDOW', 300)  # 5 minutes
        self.max_attempts_per_window = getattr(settings, 'MFA_MAX_ATTEMPTS_PER_WINDOW', 5)
        self.backup_codes_count = getattr(settings, 'MFA_BACKUP_CODES_COUNT', 10)
    
    def setup_totp(
        self,
        user: UserProfile,
        device_name: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Set up TOTP for a user with QR code generation.
        
        Args:
            user: User to set up TOTP for
            device_name: User-friendly name for the device
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing setup information including QR code
            
        Raises:
            MFAError: If setup fails
        """
        try:
            # Generate a secure secret key
            secret_key = pyotp.random_base32()
            
            # Create the MFA device
            device = MFADevice.objects.create_totp_device(
                user=user,
                device_name=device_name,
                secret_key=secret_key,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Generate TOTP URI for QR code
            totp_uri = self._generate_totp_uri(user, secret_key)
            
            # Generate QR code
            qr_code_data = self._generate_qr_code(totp_uri)
            
            # Log the setup attempt
            self.audit_service.log_authentication_event(
                event_type='mfa_totp_setup_initiated',
                user=user,
                description=f'TOTP setup initiated for device: {device_name}',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': str(device.id),
                    'device_name': device_name,
                    'device_type': 'totp'
                }
            )
            
            return {
                'device_id': str(device.id),
                'secret_key': secret_key,
                'qr_code_uri': totp_uri,
                'qr_code_data': qr_code_data,
                'backup_codes': None,  # Generated after confirmation
                'manual_entry_key': self._format_secret_for_manual_entry(secret_key),
                'issuer': self.totp_issuer,
                'account_name': user.email
            }
            
        except Exception as e:
            self.audit_service.log_authentication_event(
                event_type='mfa_totp_setup_failed',
                user=user,
                description=f'TOTP setup failed for device: {device_name}',
                severity='high',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'error': str(e),
                    'device_name': device_name
                }
            )
            raise MFAError(f"Failed to set up TOTP: {str(e)}")
    
    def confirm_totp_setup(
        self,
        user: UserProfile,
        device_id: str,
        verification_code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Confirm TOTP setup by verifying the first code.
        
        Args:
            user: User confirming the setup
            device_id: ID of the MFA device
            verification_code: TOTP code to verify
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing confirmation result and backup codes
            
        Raises:
            MFADeviceNotFoundError: If device not found
            MFAVerificationError: If verification fails
        """
        try:
            # Get the device
            device = MFADevice.objects.get(
                id=device_id,
                user=user,
                device_type='totp',
                status='pending'
            )
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("TOTP device not found or already confirmed")
        
        # Verify the TOTP code
        if not self._verify_totp_code(device, verification_code):
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_code')
            raise MFAVerificationError("Invalid TOTP code")
        
        # Confirm the device
        device.confirm_device(ip_address)
        
        # Generate backup codes
        backup_codes_device = MFADevice.objects.create_backup_codes_device(
            user=user,
            ip_address=ip_address,
            user_agent=user_agent
        )
        backup_codes_device.confirm_device(ip_address)
        backup_codes = backup_codes_device.get_backup_codes()
        
        # Record successful setup
        self._record_successful_attempt(device, ip_address, user_agent)
        
        self.audit_service.log_authentication_event(
            event_type='mfa_totp_setup_completed',
            user=user,
            description=f'TOTP setup completed for device: {device.device_name}',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'backup_codes_generated': len(backup_codes)
            }
        )
        
        return {
            'device_id': str(device.id),
            'device_name': device.device_name,
            'backup_codes': backup_codes,
            'confirmed_at': device.created_at.isoformat(),
            'status': 'active'
        }
    
    def verify_totp(
        self,
        user: UserProfile,
        verification_code: str,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify a TOTP code with time window tolerance.
        
        Args:
            user: User to verify TOTP for
            verification_code: TOTP code to verify
            device_id: Specific device ID (optional)
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing verification result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no active TOTP devices found
            MFAVerificationError: If verification fails
        """
        # Check rate limiting
        self._check_rate_limit(user, ip_address)
        
        # Get TOTP devices
        if device_id:
            try:
                devices = [MFADevice.objects.get(
                    id=device_id,
                    user=user,
                    device_type='totp',
                    status='active',
                    is_confirmed=True
                )]
            except MFADevice.DoesNotExist:
                raise MFADeviceNotFoundError("TOTP device not found")
        else:
            devices = list(MFADevice.objects.get_totp_devices(user, active_only=True))
        
        if not devices:
            raise MFADeviceNotFoundError("No active TOTP devices found")
        
        # Try to verify with each device
        for device in devices:
            if self._verify_totp_code(device, verification_code):
                # Record successful verification
                self._record_successful_attempt(device, ip_address, user_agent)
                
                self.audit_service.log_authentication_event(
                    event_type='mfa_totp_verification_success',
                    user=user,
                    description=f'TOTP verification successful for device: {device.device_name}',
                    request_info={
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    },
                    metadata={
                        'device_id': str(device.id),
                        'device_name': device.device_name
                    }
                )
                
                return {
                    'verified': True,
                    'device_id': str(device.id),
                    'device_name': device.device_name,
                    'verified_at': timezone.now().isoformat()
                }
        
        # Record failed attempts for all devices
        for device in devices:
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_code')
        
        self.audit_service.log_authentication_event(
            event_type='mfa_totp_verification_failed',
            user=user,
            description=f'TOTP verification failed for {len(devices)} devices',
            severity='medium',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'devices_tried': len(devices),
                'verification_code_length': len(verification_code)
            }
        )
        
        raise MFAVerificationError("Invalid TOTP code")
    
    def verify_backup_code(
        self,
        user: UserProfile,
        backup_code: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify a backup code (single-use).
        
        Args:
            user: User to verify backup code for
            backup_code: Backup code to verify
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            Dictionary containing verification result
            
        Raises:
            MFARateLimitError: If rate limit exceeded
            MFADeviceNotFoundError: If no backup codes device found
            MFAVerificationError: If verification fails
        """
        # Check rate limiting
        self._check_rate_limit(user, ip_address)
        
        # Get backup codes device
        device = MFADevice.objects.get_backup_codes_device(user)
        if not device:
            raise MFADeviceNotFoundError("No backup codes device found")
        
        # Verify the backup code
        if device.use_backup_code(backup_code):
            self._record_successful_attempt(device, ip_address, user_agent)
            
            remaining_codes = len(device.get_backup_codes())
            
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_code_used',
                user=user,
                description=f'Backup code used, {remaining_codes} codes remaining',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': str(device.id),
                    'remaining_codes': remaining_codes
                }
            )
            
            # Warn if running low on backup codes
            warning = None
            if remaining_codes <= 2:
                warning = f"Only {remaining_codes} backup codes remaining. Generate new ones soon."
            
            return {
                'verified': True,
                'device_id': str(device.id),
                'remaining_codes': remaining_codes,
                'warning': warning,
                'verified_at': timezone.now().isoformat()
            }
        else:
            self._record_failed_attempt(device, ip_address, user_agent, 'invalid_backup_code')
            
            self.audit_service.log_authentication_event(
                event_type='mfa_backup_code_verification_failed',
                user=user,
                description='Backup code verification failed',
                severity='medium',
                request_info={
                    'ip_address': ip_address,
                    'user_agent': user_agent
                },
                metadata={
                    'device_id': str(device.id)
                }
            )
            
            raise MFAVerificationError("Invalid backup code")
    
    def regenerate_backup_codes(
        self,
        user: UserProfile,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> List[str]:
        """
        Regenerate backup codes for a user.
        
        Args:
            user: User to regenerate backup codes for
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            List of new backup codes
            
        Raises:
            MFADeviceNotFoundError: If no backup codes device found
        """
        device = MFADevice.objects.get_backup_codes_device(user)
        if not device:
            raise MFADeviceNotFoundError("No backup codes device found")
        
        # Generate new backup codes
        new_codes = device.generate_backup_codes(self.backup_codes_count)
        
        self.audit_service.log_authentication_event(
            event_type='mfa_backup_codes_regenerated',
            user=user,
            description=f'Backup codes regenerated: {len(new_codes)} new codes',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'codes_generated': len(new_codes)
            }
        )
        
        return new_codes
    
    def get_user_mfa_devices(self, user: UserProfile) -> List[Dict[str, Any]]:
        """
        Get all MFA devices for a user.
        
        Args:
            user: User to get devices for
            
        Returns:
            List of device information dictionaries
        """
        devices = MFADevice.objects.get_user_devices(user, active_only=False)
        return [device.get_display_info() for device in devices]
    
    def disable_mfa_device(
        self,
        user: UserProfile,
        device_id: str,
        reason: str = 'user_request',
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Disable an MFA device.
        
        Args:
            user: User who owns the device
            device_id: ID of the device to disable
            reason: Reason for disabling
            ip_address: IP address of the request
            user_agent: User agent string
            
        Returns:
            True if device was disabled
            
        Raises:
            MFADeviceNotFoundError: If device not found
        """
        try:
            device = MFADevice.objects.get(id=device_id, user=user)
        except MFADevice.DoesNotExist:
            raise MFADeviceNotFoundError("MFA device not found")
        
        device.disable_device(reason)
        
        self.audit_service.log_authentication_event(
            event_type='mfa_device_disabled',
            user=user,
            description=f'MFA device disabled: {device.device_name} ({reason})',
            request_info={
                'ip_address': ip_address,
                'user_agent': user_agent
            },
            metadata={
                'device_id': str(device.id),
                'device_name': device.device_name,
                'device_type': device.device_type,
                'reason': reason
            }
        )
        
        return True
    
    def has_active_mfa(self, user: UserProfile) -> bool:
        """
        Check if a user has any active MFA devices.
        
        Args:
            user: User to check
            
        Returns:
            True if user has active MFA devices
        """
        return MFADevice.objects.has_active_mfa(user)
    
    def _generate_totp_uri(self, user: UserProfile, secret_key: str) -> str:
        """
        Generate TOTP URI for QR code.
        
        Args:
            user: User for the TOTP
            secret_key: TOTP secret key
            
        Returns:
            TOTP URI string
        """
        account_name = quote(user.email)
        issuer = quote(self.totp_issuer)
        
        return f"otpauth://totp/{issuer}:{account_name}?secret={secret_key}&issuer={issuer}"
    
    def _generate_qr_code(self, totp_uri: str) -> str:
        """
        Generate QR code data URL for TOTP URI.
        
        Args:
            totp_uri: TOTP URI string
            
        Returns:
            Base64 encoded QR code image data URL
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 data URL
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        import base64
        img_data = base64.b64encode(buffer.getvalue()).decode()
        return f"data:image/png;base64,{img_data}"
    
    def _format_secret_for_manual_entry(self, secret_key: str) -> str:
        """
        Format secret key for manual entry (groups of 4 characters).
        
        Args:
            secret_key: TOTP secret key
            
        Returns:
            Formatted secret key
        """
        return ' '.join([secret_key[i:i+4] for i in range(0, len(secret_key), 4)])
    
    def _verify_totp_code(self, device: MFADevice, code: str) -> bool:
        """
        Verify TOTP code with time window tolerance.
        
        Args:
            device: MFA device to verify against
            code: TOTP code to verify
            
        Returns:
            True if code is valid
        """
        secret_key = device.get_secret_key()
        if not secret_key:
            return False
        
        totp = pyotp.TOTP(secret_key)
        
        # Verify with time window tolerance
        return totp.verify(code, valid_window=self.totp_window)
    
    def _check_rate_limit(self, user: UserProfile, ip_address: Optional[str]) -> None:
        """
        Check rate limiting for MFA attempts.
        
        Args:
            user: User making the attempt
            ip_address: IP address of the attempt
            
        Raises:
            MFARateLimitError: If rate limit exceeded
        """
        # Check user-based rate limiting
        user_key = f"mfa_attempts:user:{user.id}"
        user_attempts = cache.get(user_key, 0)
        
        if user_attempts >= self.max_attempts_per_window:
            raise MFARateLimitError("Too many MFA attempts. Please try again later.")
        
        # Check IP-based rate limiting if IP is provided
        if ip_address:
            ip_key = f"mfa_attempts:ip:{ip_address}"
            ip_attempts = cache.get(ip_key, 0)
            
            if ip_attempts >= self.max_attempts_per_window * 2:  # Higher limit for IP
                raise MFARateLimitError("Too many MFA attempts from this IP. Please try again later.")
    
    def _record_failed_attempt(
        self,
        device: MFADevice,
        ip_address: Optional[str],
        user_agent: Optional[str],
        failure_reason: str
    ) -> None:
        """
        Record a failed MFA attempt.
        
        Args:
            device: MFA device used
            ip_address: IP address of the attempt
            user_agent: User agent string
            failure_reason: Reason for failure
        """
        # Record in database
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='failure',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent,
            failure_reason=failure_reason
        )
        
        # Update rate limiting counters
        user_key = f"mfa_attempts:user:{device.user.id}"
        cache.set(user_key, cache.get(user_key, 0) + 1, self.rate_limit_window)
        
        if ip_address:
            ip_key = f"mfa_attempts:ip:{ip_address}"
            cache.set(ip_key, cache.get(ip_key, 0) + 1, self.rate_limit_window)
    
    def _record_successful_attempt(
        self,
        device: MFADevice,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> None:
        """
        Record a successful MFA attempt.
        
        Args:
            device: MFA device used
            ip_address: IP address of the attempt
            user_agent: User agent string
        """
        # Record in database
        MFAAttempt.objects.create(
            user=device.user,
            device=device,
            result='success',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent
        )
        
        # Mark device as used
        device.mark_as_used(ip_address)
        
        # Clear rate limiting counters on success
        user_key = f"mfa_attempts:user:{device.user.id}"
        cache.delete(user_key)