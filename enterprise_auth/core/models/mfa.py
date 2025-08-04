"""
Multi-Factor Authentication models for enterprise authentication system.

This module contains models for managing MFA devices including TOTP,
SMS, email verification, and backup codes.
"""

import uuid
import secrets
import json
from typing import List, Optional, Dict, Any

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator

from .base import TimestampedModel, EncryptedFieldMixin
from ..managers import MFADeviceManager


class MFADevice(TimestampedModel, EncryptedFieldMixin):
    """
    Model for managing Multi-Factor Authentication devices.
    
    Supports TOTP, SMS, email, and backup codes for enhanced security.
    """
    
    # MFA device type choices
    DEVICE_TYPE_CHOICES = [
        ('totp', 'TOTP (Time-based One-Time Password)'),
        ('sms', 'SMS Verification'),
        ('email', 'Email Verification'),
        ('backup_codes', 'Backup Codes'),
        ('hardware_key', 'Hardware Security Key'),  # Future implementation
    ]
    
    # Device status choices
    STATUS_CHOICES = [
        ('pending', 'Pending Setup'),
        ('active', 'Active'),
        ('disabled', 'Disabled'),
        ('compromised', 'Compromised'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this MFA device"
    )
    
    user = models.ForeignKey(
        'UserProfile',
        on_delete=models.CASCADE,
        related_name='mfa_devices',
        help_text="User this MFA device belongs to"
    )
    
    device_type = models.CharField(
        max_length=20,
        choices=DEVICE_TYPE_CHOICES,
        help_text="Type of MFA device"
    )
    
    device_name = models.CharField(
        max_length=100,
        help_text="User-friendly name for this device"
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        help_text="Current status of the MFA device"
    )
    
    # TOTP-specific fields (encrypted)
    secret_key = models.TextField(
        blank=True,
        null=True,
        help_text="Encrypted TOTP secret key"
    )
    
    # SMS/Email-specific fields
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
            )
        ],
        help_text="Phone number for SMS MFA (encrypted)"
    )
    
    email_address = models.EmailField(
        blank=True,
        null=True,
        help_text="Email address for email MFA"
    )
    
    # Backup codes (encrypted JSON array)
    backup_codes = models.TextField(
        blank=True,
        null=True,
        help_text="Encrypted backup codes as JSON array"
    )
    
    # Usage tracking
    is_confirmed = models.BooleanField(
        default=False,
        help_text="Whether the device has been confirmed by the user"
    )
    
    last_used = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When this device was last used for authentication"
    )
    
    usage_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this device has been used"
    )
    
    # Security metadata
    created_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address where this device was created"
    )
    
    created_user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent string when device was created"
    )
    
    last_used_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address where this device was last used"
    )
    
    # Configuration options
    configuration = models.JSONField(
        default=dict,
        help_text="Device-specific configuration options"
    )
    
    # Custom manager
    objects = MFADeviceManager()
    
    class Meta:
        db_table = 'auth_mfadevice'
        verbose_name = _('MFA Device')
        verbose_name_plural = _('MFA Devices')
        indexes = [
            models.Index(fields=['user', 'device_type']),
            models.Index(fields=['user', 'status']),
            models.Index(fields=['device_type', 'status']),
            models.Index(fields=['is_confirmed']),
            models.Index(fields=['-last_used']),
            models.Index(fields=['-created_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'device_name'],
                name='unique_device_name_per_user'
            ),
        ]
    
    def __str__(self):
        """String representation of the MFA device."""
        return f"{self.user.email} - {self.device_name} ({self.device_type})"
    
    @property
    def is_active(self) -> bool:
        """Check if the device is active and confirmed."""
        return self.status == 'active' and self.is_confirmed
    
    @property
    def is_totp_device(self) -> bool:
        """Check if this is a TOTP device."""
        return self.device_type == 'totp'
    
    @property
    def is_sms_device(self) -> bool:
        """Check if this is an SMS device."""
        return self.device_type == 'sms'
    
    @property
    def is_email_device(self) -> bool:
        """Check if this is an email device."""
        return self.device_type == 'email'
    
    @property
    def is_backup_codes_device(self) -> bool:
        """Check if this is a backup codes device."""
        return self.device_type == 'backup_codes'
    
    def set_secret_key(self, secret: str) -> None:
        """
        Set the encrypted TOTP secret key.
        
        Args:
            secret: TOTP secret key to encrypt and store
        """
        self.secret_key = self.encrypt_field('secret_key', secret)
        self.save(update_fields=['secret_key'])
    
    def get_secret_key(self) -> Optional[str]:
        """
        Get the decrypted TOTP secret key.
        
        Returns:
            Decrypted secret key or None if not available
        """
        if not self.secret_key:
            return None
        try:
            return self.decrypt_field('secret_key', self.secret_key)
        except Exception:
            return None
    
    def set_phone_number(self, phone: str) -> None:
        """
        Set the encrypted phone number.
        
        Args:
            phone: Phone number to encrypt and store
        """
        self.phone_number = self.encrypt_field('phone_number', phone)
        self.save(update_fields=['phone_number'])
    
    def get_phone_number(self) -> Optional[str]:
        """
        Get the decrypted phone number.
        
        Returns:
            Decrypted phone number or None if not available
        """
        if not self.phone_number:
            return None
        try:
            return self.decrypt_field('phone_number', self.phone_number)
        except Exception:
            return None
    
    def set_backup_codes(self, codes: List[str]) -> None:
        """
        Set the encrypted backup codes.
        
        Args:
            codes: List of backup codes to encrypt and store
        """
        codes_json = json.dumps(codes)
        self.backup_codes = self.encrypt_field('backup_codes', codes_json)
        self.save(update_fields=['backup_codes'])
    
    def get_backup_codes(self) -> List[str]:
        """
        Get the decrypted backup codes.
        
        Returns:
            List of backup codes or empty list if not available
        """
        if not self.backup_codes:
            return []
        try:
            codes_json = self.decrypt_field('backup_codes', self.backup_codes)
            return json.loads(codes_json)
        except Exception:
            return []
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate new backup codes.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of generated backup codes
        """
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric codes
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            codes.append(code)
        
        self.set_backup_codes(codes)
        return codes
    
    def use_backup_code(self, code: str) -> bool:
        """
        Use a backup code (single-use).
        
        Args:
            code: Backup code to use
            
        Returns:
            True if code was valid and used, False otherwise
        """
        codes = self.get_backup_codes()
        if code.upper() in codes:
            codes.remove(code.upper())
            self.set_backup_codes(codes)
            self.mark_as_used()
            return True
        return False
    
    def confirm_device(self, ip_address: Optional[str] = None) -> None:
        """
        Confirm the MFA device as active.
        
        Args:
            ip_address: IP address where confirmation occurred
        """
        self.is_confirmed = True
        self.status = 'active'
        if ip_address:
            self.created_ip = ip_address
        self.save(update_fields=['is_confirmed', 'status', 'created_ip'])
    
    def mark_as_used(self, ip_address: Optional[str] = None) -> None:
        """
        Mark the device as recently used.
        
        Args:
            ip_address: IP address where device was used
        """
        self.last_used = timezone.now()
        self.usage_count += 1
        if ip_address:
            self.last_used_ip = ip_address
        self.save(update_fields=['last_used', 'usage_count', 'last_used_ip'])
    
    def disable_device(self, reason: str = 'user_request') -> None:
        """
        Disable the MFA device.
        
        Args:
            reason: Reason for disabling the device
        """
        self.status = 'disabled'
        self.configuration['disabled_reason'] = reason
        self.configuration['disabled_at'] = timezone.now().isoformat()
        self.save(update_fields=['status', 'configuration'])
    
    def mark_compromised(self, reason: str = 'security_incident') -> None:
        """
        Mark the device as compromised.
        
        Args:
            reason: Reason for marking as compromised
        """
        self.status = 'compromised'
        self.configuration['compromised_reason'] = reason
        self.configuration['compromised_at'] = timezone.now().isoformat()
        self.save(update_fields=['status', 'configuration'])
    
    def get_display_info(self) -> Dict[str, Any]:
        """
        Get display information for the device.
        
        Returns:
            Dictionary with device display information
        """
        info = {
            'id': str(self.id),
            'name': self.device_name,
            'type': self.device_type,
            'type_display': self.get_device_type_display(),
            'status': self.status,
            'status_display': self.get_status_display(),
            'is_confirmed': self.is_confirmed,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
        }
        
        # Add type-specific information
        if self.is_sms_device and self.phone_number:
            phone = self.get_phone_number()
            if phone:
                # Mask phone number for display
                info['phone_number_masked'] = f"***-***-{phone[-4:]}"
        
        if self.is_email_device and self.email_address:
            # Mask email for display
            email_parts = self.email_address.split('@')
            if len(email_parts) == 2:
                masked_local = email_parts[0][:2] + '*' * (len(email_parts[0]) - 2)
                info['email_masked'] = f"{masked_local}@{email_parts[1]}"
        
        if self.is_backup_codes_device:
            codes = self.get_backup_codes()
            info['remaining_codes'] = len(codes)
        
        return info


class MFAAttempt(TimestampedModel):
    """
    Model for tracking MFA authentication attempts.
    
    Used for security monitoring and rate limiting.
    """
    
    # Attempt result choices
    RESULT_CHOICES = [
        ('success', 'Success'),
        ('failure', 'Failure'),
        ('expired', 'Expired'),
        ('rate_limited', 'Rate Limited'),
        ('device_disabled', 'Device Disabled'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this MFA attempt"
    )
    
    user = models.ForeignKey(
        'UserProfile',
        on_delete=models.CASCADE,
        related_name='mfa_attempts',
        help_text="User who made the MFA attempt"
    )
    
    device = models.ForeignKey(
        'MFADevice',
        on_delete=models.CASCADE,
        related_name='attempts',
        help_text="MFA device used for the attempt"
    )
    
    result = models.CharField(
        max_length=20,
        choices=RESULT_CHOICES,
        help_text="Result of the MFA attempt"
    )
    
    # Request metadata
    ip_address = models.GenericIPAddressField(
        help_text="IP address of the attempt"
    )
    
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent string of the attempt"
    )
    
    session_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Session ID associated with the attempt"
    )
    
    # Additional context
    failure_reason = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Reason for failure if applicable"
    )
    
    response_time_ms = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text="Response time in milliseconds"
    )
    
    class Meta:
        db_table = 'auth_mfaattempt'
        verbose_name = _('MFA Attempt')
        verbose_name_plural = _('MFA Attempts')
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['device', '-created_at']),
            models.Index(fields=['result', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['-created_at']),
        ]
    
    def __str__(self):
        """String representation of the MFA attempt."""
        return f"{self.user.email} - {self.device.device_name} - {self.result}"