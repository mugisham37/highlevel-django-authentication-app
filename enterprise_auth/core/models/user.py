"""
User models for enterprise authentication system.

This module contains the extended user model and identity management
models that support multiple authentication methods and enterprise features.
"""

import uuid
from typing import Optional, Dict, Any

from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .base import TimestampedModel, SoftDeleteModel, EncryptedFieldMixin
from ..managers import UserProfileManager, UserIdentityManager


class UserProfile(AbstractUser, EncryptedFieldMixin):
    """
    Extended user model with enterprise features and multiple authentication support.
    
    Extends Django's AbstractUser with additional fields for enterprise use cases,
    audit trails, and support for multiple identity providers.
    """
    
    # Override the default ID field to use UUID
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this user"
    )
    
    # Timestamp fields
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when this record was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp when this record was last updated"
    )
    
    # Soft delete fields
    is_deleted = models.BooleanField(
        default=False,
        help_text="Whether this record has been soft deleted"
    )
    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when this record was deleted"
    )
    deleted_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deleted_users',
        help_text="User who deleted this record"
    )
    
    # Enhanced email field with verification tracking
    email = models.EmailField(
        _('email address'),
        unique=True,
        help_text="User's email address (used as primary identifier)"
    )
    is_email_verified = models.BooleanField(
        default=False,
        help_text="Whether the user's email address has been verified"
    )
    email_verification_token = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Token for email verification (encrypted)"
    )
    email_verification_sent_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the email verification was last sent"
    )
    
    # Phone number with verification
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
        help_text="User's phone number in international format"
    )
    is_phone_verified = models.BooleanField(
        default=False,
        help_text="Whether the user's phone number has been verified"
    )
    
    # Enterprise fields
    organization = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Organization or company name"
    )
    department = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Department within the organization"
    )
    employee_id = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Employee ID or identifier within the organization"
    )
    job_title = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="User's job title or role"
    )
    
    # Security and account management
    account_locked_until = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Account is locked until this timestamp"
    )
    failed_login_attempts = models.PositiveIntegerField(
        default=0,
        help_text="Number of consecutive failed login attempts"
    )
    last_password_change = models.DateTimeField(
        default=timezone.now,
        help_text="When the password was last changed"
    )
    password_reset_token = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Token for password reset (encrypted)"
    )
    password_reset_sent_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the password reset was last sent"
    )
    
    # Profile information
    profile_picture_url = models.URLField(
        blank=True,
        null=True,
        help_text="URL to user's profile picture"
    )
    timezone = models.CharField(
        max_length=50,
        default='UTC',
        help_text="User's preferred timezone"
    )
    language = models.CharField(
        max_length=10,
        default='en',
        help_text="User's preferred language"
    )
    
    # Privacy and compliance
    terms_accepted_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the user accepted the terms of service"
    )
    privacy_policy_accepted_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the user accepted the privacy policy"
    )
    marketing_consent = models.BooleanField(
        default=False,
        help_text="Whether the user consents to marketing communications"
    )
    
    # Activity tracking
    last_login_ip = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address of the last login"
    )
    last_login_user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent string from the last login"
    )
    
    # Use email as the username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    # Custom manager
    objects = UserProfileManager()
    
    class Meta:
        db_table = 'users_userprofile'
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['organization']),
            models.Index(fields=['department']),
            models.Index(fields=['employee_id']),
            models.Index(fields=['is_email_verified']),
            models.Index(fields=['is_phone_verified']),
            models.Index(fields=['account_locked_until']),
            models.Index(fields=['last_login']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['is_deleted', '-created_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['employee_id', 'organization'],
                name='unique_employee_per_org',
                condition=models.Q(employee_id__isnull=False, organization__isnull=False)
            ),
        ]
    
    def __str__(self):
        """String representation of the user."""
        return f"{self.get_full_name()} ({self.email})"
    
    def get_full_name(self) -> str:
        """
        Return the user's full name.
        
        Returns:
            Full name combining first and last name
        """
        return f"{self.first_name} {self.last_name}".strip() or self.email
    
    def get_short_name(self) -> str:
        """
        Return the user's short name.
        
        Returns:
            First name or email if first name is not available
        """
        return self.first_name or self.email
    
    @property
    def is_account_locked(self) -> bool:
        """
        Check if the account is currently locked.
        
        Returns:
            True if account is locked, False otherwise
        """
        if not self.account_locked_until:
            return False
        return timezone.now() < self.account_locked_until
    
    @property
    def is_fully_verified(self) -> bool:
        """
        Check if the user has completed all verification steps.
        
        Returns:
            True if email is verified and phone is verified (if provided)
        """
        email_verified = self.is_email_verified
        phone_verified = not self.phone_number or self.is_phone_verified
        return email_verified and phone_verified
    
    @property
    def has_enterprise_profile(self) -> bool:
        """
        Check if the user has enterprise profile information.
        
        Returns:
            True if user has organization or employee_id
        """
        return bool(self.organization or self.employee_id)
    
    def lock_account(self, duration_minutes: int = 30) -> None:
        """
        Lock the user account for a specified duration.
        
        Args:
            duration_minutes: How long to lock the account in minutes
        """
        self.account_locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save(update_fields=['account_locked_until'])
    
    def unlock_account(self) -> None:
        """Unlock the user account."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['account_locked_until', 'failed_login_attempts'])
    
    def increment_failed_login_attempts(self) -> None:
        """Increment the failed login attempts counter."""
        self.failed_login_attempts += 1
        self.save(update_fields=['failed_login_attempts'])
    
    def reset_failed_login_attempts(self) -> None:
        """Reset the failed login attempts counter."""
        self.failed_login_attempts = 0
        self.save(update_fields=['failed_login_attempts'])
    
    def set_email_verification_token(self, token: str) -> None:
        """
        Set the email verification token (encrypted).
        
        Args:
            token: Verification token to encrypt and store
        """
        self.email_verification_token = self.encrypt_field('email_verification_token', token)
        self.email_verification_sent_at = timezone.now()
        self.save(update_fields=['email_verification_token', 'email_verification_sent_at'])
    
    def verify_email_token(self, token: str) -> bool:
        """
        Verify the email verification token.
        
        Args:
            token: Token to verify
            
        Returns:
            True if token is valid and not expired
        """
        if not self.email_verification_token:
            return False
        
        try:
            stored_token = self.decrypt_field('email_verification_token', self.email_verification_token)
            if stored_token != token:
                return False
            
            # Check if token is expired (24 hours)
            if self.email_verification_sent_at:
                expiry = self.email_verification_sent_at + timezone.timedelta(hours=24)
                if timezone.now() > expiry:
                    return False
            
            return True
        except Exception:
            return False
    
    def mark_email_verified(self) -> None:
        """Mark the email as verified and clear verification token."""
        self.is_email_verified = True
        self.email_verification_token = None
        self.email_verification_sent_at = None
        self.save(update_fields=['is_email_verified', 'email_verification_token', 'email_verification_sent_at'])
    
    def set_password_reset_token(self, token: str) -> None:
        """
        Set the password reset token (encrypted).
        
        Args:
            token: Reset token to encrypt and store
        """
        self.password_reset_token = self.encrypt_field('password_reset_token', token)
        self.password_reset_sent_at = timezone.now()
        self.save(update_fields=['password_reset_token', 'password_reset_sent_at'])
    
    def verify_password_reset_token(self, token: str) -> bool:
        """
        Verify the password reset token.
        
        Args:
            token: Token to verify
            
        Returns:
            True if token is valid and not expired
        """
        if not self.password_reset_token:
            return False
        
        try:
            stored_token = self.decrypt_field('password_reset_token', self.password_reset_token)
            if stored_token != token:
                return False
            
            # Check if token is expired (1 hour)
            if self.password_reset_sent_at:
                expiry = self.password_reset_sent_at + timezone.timedelta(hours=1)
                if timezone.now() > expiry:
                    return False
            
            return True
        except Exception:
            return False
    
    def clear_password_reset_token(self) -> None:
        """Clear the password reset token after successful reset."""
        self.password_reset_token = None
        self.password_reset_sent_at = None
        self.last_password_change = timezone.now()
        self.save(update_fields=['password_reset_token', 'password_reset_sent_at', 'last_password_change'])
    
    def update_login_metadata(self, ip_address: str, user_agent: str) -> None:
        """
        Update login metadata after successful authentication.
        
        Args:
            ip_address: IP address of the login
            user_agent: User agent string of the login
        """
        self.last_login_ip = ip_address
        self.last_login_user_agent = user_agent
        self.last_login = timezone.now()
        self.reset_failed_login_attempts()
        self.save(update_fields=['last_login_ip', 'last_login_user_agent', 'last_login', 'failed_login_attempts'])
    
    def delete(self, user: Optional['UserProfile'] = None, hard_delete: bool = False):
        """
        Soft delete the user record.
        
        Args:
            user: User performing the deletion
            hard_delete: If True, perform actual deletion instead of soft delete
        """
        if hard_delete:
            super().delete()
        else:
            self.is_deleted = True
            self.deleted_at = timezone.now()
            if user and user.is_authenticated:
                self.deleted_by = user
            self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'updated_at'])
    
    def restore(self, user: Optional['UserProfile'] = None):
        """
        Restore a soft-deleted user record.
        
        Args:
            user: User performing the restoration
        """
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'updated_at'])
    
    @property
    def is_active_user(self) -> bool:
        """
        Check if the user is active (not soft deleted).
        
        Returns:
            True if user is active, False if soft deleted
        """
        return not self.is_deleted


class UserIdentity(models.Model, EncryptedFieldMixin):
    """
    Model for linking user accounts to external identity providers.
    
    This model stores the relationship between a user and their accounts
    on external OAuth providers like Google, GitHub, Microsoft, etc.
    """
    
    # OAuth provider choices
    PROVIDER_CHOICES = [
        ('google', 'Google'),
        ('github', 'GitHub'),
        ('microsoft', 'Microsoft'),
        ('apple', 'Apple'),
        ('linkedin', 'LinkedIn'),
        ('facebook', 'Facebook'),
        ('twitter', 'Twitter'),
        ('custom', 'Custom OAuth Provider'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this identity"
    )
    
    user = models.ForeignKey(
        'UserProfile',
        on_delete=models.CASCADE,
        related_name='identities',
        help_text="User this identity belongs to"
    )
    provider = models.CharField(
        max_length=50,
        choices=PROVIDER_CHOICES,
        help_text="OAuth provider name"
    )
    provider_user_id = models.CharField(
        max_length=255,
        help_text="User ID from the OAuth provider"
    )
    provider_username = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Username from the OAuth provider"
    )
    provider_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Email address from the OAuth provider"
    )
    provider_data = models.JSONField(
        default=dict,
        help_text="Additional data from the OAuth provider"
    )
    
    # Token management (encrypted)
    access_token = models.TextField(
        blank=True,
        null=True,
        help_text="Encrypted OAuth access token"
    )
    refresh_token = models.TextField(
        blank=True,
        null=True,
        help_text="Encrypted OAuth refresh token"
    )
    token_expires_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the access token expires"
    )
    
    # Timestamp fields
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when this record was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp when this record was last updated"
    )
    
    # Metadata
    linked_at = models.DateTimeField(
        default=timezone.now,
        help_text="When this identity was linked to the user"
    )
    last_used = models.DateTimeField(
        default=timezone.now,
        help_text="When this identity was last used for authentication"
    )
    is_primary = models.BooleanField(
        default=False,
        help_text="Whether this is the primary identity for the provider"
    )
    is_verified = models.BooleanField(
        default=False,
        help_text="Whether this identity has been verified"
    )
    
    # Custom manager
    objects = UserIdentityManager()
    
    class Meta:
        db_table = 'users_useridentity'
        verbose_name = _('User Identity')
        verbose_name_plural = _('User Identities')
        unique_together = [
            ('provider', 'provider_user_id'),
        ]
        indexes = [
            models.Index(fields=['user', 'provider']),
            models.Index(fields=['provider', 'provider_user_id']),
            models.Index(fields=['provider_email']),
            models.Index(fields=['is_primary']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['-last_used']),
            models.Index(fields=['-linked_at']),
        ]
    
    def __str__(self):
        """String representation of the user identity."""
        return f"{self.user.email} - {self.provider} ({self.provider_user_id})"
    
    @property
    def is_token_expired(self) -> bool:
        """
        Check if the access token is expired.
        
        Returns:
            True if token is expired or expiry is unknown
        """
        if not self.token_expires_at:
            return True
        return timezone.now() >= self.token_expires_at
    
    def set_access_token(self, token: str, expires_in: Optional[int] = None) -> None:
        """
        Set the encrypted access token.
        
        Args:
            token: Access token to encrypt and store
            expires_in: Token lifetime in seconds
        """
        self.access_token = self.encrypt_field('access_token', token)
        if expires_in:
            self.token_expires_at = timezone.now() + timezone.timedelta(seconds=expires_in)
        self.save(update_fields=['access_token', 'token_expires_at'])
    
    def get_access_token(self) -> Optional[str]:
        """
        Get the decrypted access token.
        
        Returns:
            Decrypted access token or None if not available
        """
        if not self.access_token:
            return None
        try:
            return self.decrypt_field('access_token', self.access_token)
        except Exception:
            return None
    
    def set_refresh_token(self, token: str) -> None:
        """
        Set the encrypted refresh token.
        
        Args:
            token: Refresh token to encrypt and store
        """
        self.refresh_token = self.encrypt_field('refresh_token', token)
        self.save(update_fields=['refresh_token'])
    
    def get_refresh_token(self) -> Optional[str]:
        """
        Get the decrypted refresh token.
        
        Returns:
            Decrypted refresh token or None if not available
        """
        if not self.refresh_token:
            return None
        try:
            return self.decrypt_field('refresh_token', self.refresh_token)
        except Exception:
            return None
    
    def update_provider_data(self, data: Dict[str, Any]) -> None:
        """
        Update provider data with new information.
        
        Args:
            data: New provider data to merge
        """
        self.provider_data.update(data)
        self.last_used = timezone.now()
        self.save(update_fields=['provider_data', 'last_used'])
    
    def mark_as_used(self) -> None:
        """Mark this identity as recently used."""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])
    
    def verify_identity(self) -> None:
        """Mark this identity as verified."""
        self.is_verified = True
        self.save(update_fields=['is_verified'])
    
    def set_as_primary(self) -> None:
        """
        Set this identity as the primary one for this provider.
        
        This will unset any other primary identity for the same provider and user.
        """
        # Unset other primary identities for this provider and user
        UserIdentity.objects.filter(
            user=self.user,
            provider=self.provider,
            is_primary=True
        ).exclude(id=self.id).update(is_primary=False)
        
        self.is_primary = True
        self.save(update_fields=['is_primary'])