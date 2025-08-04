"""
JWT-related models for enterprise authentication system.

This module contains models for managing JWT tokens, refresh tokens,
and token blacklist entries in the database.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .base import TimestampedModel, EncryptedFieldMixin
from .user import UserProfile


class RefreshToken(TimestampedModel, EncryptedFieldMixin):
    """
    Model for tracking refresh tokens and their metadata.
    
    This model stores refresh token information for rotation tracking,
    device binding, and security monitoring.
    """
    
    # Token status choices
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('rotated', 'Rotated'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this refresh token"
    )
    
    # Token identification
    token_id = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique token identifier from JWT claims"
    )
    
    # User relationship
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='refresh_tokens',
        help_text="User this refresh token belongs to"
    )
    
    # Device information
    device_id = models.CharField(
        max_length=255,
        help_text="Unique device identifier"
    )
    device_fingerprint = models.CharField(
        max_length=255,
        help_text="Device fingerprint for binding"
    )
    device_type = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Type of device (mobile, desktop, tablet)"
    )
    browser = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Browser information"
    )
    operating_system = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Operating system information"
    )
    
    # Network information
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address when token was created"
    )
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent string when token was created"
    )
    
    # Token metadata
    scopes = models.JSONField(
        default=list,
        help_text="Scopes granted to this token"
    )
    session_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Associated session identifier"
    )
    
    # Token lifecycle
    issued_at = models.DateTimeField(
        help_text="When the token was issued"
    )
    expires_at = models.DateTimeField(
        help_text="When the token expires"
    )
    last_used = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the token was last used for refresh"
    )
    
    # Status and tracking
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        help_text="Current status of the refresh token"
    )
    rotation_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times this token has been rotated"
    )
    
    # Parent token tracking (for rotation chains)
    parent_token = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='child_tokens',
        help_text="Parent token if this is a rotated token"
    )
    
    # Revocation information
    revoked_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When the token was revoked"
    )
    revoked_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='revoked_refresh_tokens',
        help_text="User who revoked this token"
    )
    revocation_reason = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Reason for token revocation"
    )
    
    class Meta:
        db_table = 'jwt_refresh_token'
        verbose_name = _('Refresh Token')
        verbose_name_plural = _('Refresh Tokens')
        indexes = [
            models.Index(fields=['token_id']),
            models.Index(fields=['user', 'status']),
            models.Index(fields=['device_id']),
            models.Index(fields=['device_fingerprint']),
            models.Index(fields=['session_id']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['status', 'expires_at']),
            models.Index(fields=['user', 'device_id', 'status']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['-last_used']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__gt=models.F('issued_at')),
                name='refresh_token_expires_after_issued'
            ),
        ]
    
    def __str__(self):
        """String representation of the refresh token."""
        return f"RefreshToken {self.token_id[:8]}... for {self.user.email}"
    
    @property
    def is_expired(self) -> bool:
        """Check if the refresh token is expired."""
        return timezone.now() >= self.expires_at
    
    @property
    def is_active(self) -> bool:
        """Check if the refresh token is active."""
        return self.status == 'active' and not self.is_expired
    
    @property
    def time_until_expiry(self) -> Optional[timedelta]:
        """Get time until token expiry."""
        if self.is_expired:
            return None
        return self.expires_at - timezone.now()
    
    def mark_as_used(self) -> None:
        """Mark the token as recently used."""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])
    
    def rotate(self, new_token_id: str, new_expires_at: datetime) -> 'RefreshToken':
        """
        Create a new rotated token and mark this one as rotated.
        
        Args:
            new_token_id: Token ID for the new token
            new_expires_at: Expiration time for the new token
            
        Returns:
            New RefreshToken instance
        """
        # Mark current token as rotated
        self.status = 'rotated'
        self.revoked_at = timezone.now()
        self.revocation_reason = 'rotated'
        self.save(update_fields=['status', 'revoked_at', 'revocation_reason'])
        
        # Create new token
        new_token = RefreshToken.objects.create(
            token_id=new_token_id,
            user=self.user,
            device_id=self.device_id,
            device_fingerprint=self.device_fingerprint,
            device_type=self.device_type,
            browser=self.browser,
            operating_system=self.operating_system,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            scopes=self.scopes,
            session_id=self.session_id,
            issued_at=timezone.now(),
            expires_at=new_expires_at,
            rotation_count=self.rotation_count + 1,
            parent_token=self,
        )
        
        return new_token
    
    def revoke(self, revoked_by: Optional[UserProfile] = None, reason: str = 'manual') -> None:
        """
        Revoke the refresh token.
        
        Args:
            revoked_by: User who revoked the token
            reason: Reason for revocation
        """
        self.status = 'revoked'
        self.revoked_at = timezone.now()
        self.revoked_by = revoked_by
        self.revocation_reason = reason
        self.save(update_fields=['status', 'revoked_at', 'revoked_by', 'revocation_reason'])
    
    def get_rotation_chain(self) -> list:
        """Get the full rotation chain for this token."""
        chain = []
        current = self
        
        # Go back to the root
        while current.parent_token:
            current = current.parent_token
        
        # Collect the chain forward
        def collect_children(token):
            chain.append(token)
            for child in token.child_tokens.all():
                collect_children(child)
        
        collect_children(current)
        return chain


class TokenBlacklist(TimestampedModel):
    """
    Model for storing blacklisted JWT tokens.
    
    This model provides persistent storage for blacklisted tokens
    as a backup to the Redis-based blacklist system.
    """
    
    # Blacklist reason choices
    REASON_CHOICES = [
        ('revoked', 'Manually Revoked'),
        ('rotated', 'Token Rotated'),
        ('security_incident', 'Security Incident'),
        ('user_logout', 'User Logout'),
        ('admin_action', 'Administrative Action'),
        ('expired', 'Token Expired'),
        ('suspicious_activity', 'Suspicious Activity'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this blacklist entry"
    )
    
    # Token identification
    token_id = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique token identifier from JWT claims"
    )
    token_type = models.CharField(
        max_length=20,
        choices=[
            ('access', 'Access Token'),
            ('refresh', 'Refresh Token'),
        ],
        help_text="Type of token that was blacklisted"
    )
    
    # User relationship
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='blacklisted_tokens',
        help_text="User this token belonged to"
    )
    
    # Token metadata
    issued_at = models.DateTimeField(
        help_text="When the original token was issued"
    )
    expires_at = models.DateTimeField(
        help_text="When the original token expires"
    )
    
    # Blacklist information
    blacklisted_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the token was blacklisted"
    )
    blacklisted_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='blacklisted_tokens_by',
        help_text="User who blacklisted this token"
    )
    reason = models.CharField(
        max_length=50,
        choices=REASON_CHOICES,
        default='revoked',
        help_text="Reason for blacklisting"
    )
    reason_details = models.TextField(
        blank=True,
        null=True,
        help_text="Additional details about the blacklisting reason"
    )
    
    # Device and network information
    device_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Device ID associated with the token"
    )
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address when token was blacklisted"
    )
    
    class Meta:
        db_table = 'jwt_token_blacklist'
        verbose_name = _('Token Blacklist Entry')
        verbose_name_plural = _('Token Blacklist Entries')
        indexes = [
            models.Index(fields=['token_id']),
            models.Index(fields=['user', 'token_type']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['blacklisted_at']),
            models.Index(fields=['reason']),
            models.Index(fields=['device_id']),
            models.Index(fields=['-created_at']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(expires_at__gt=models.F('issued_at')),
                name='blacklist_expires_after_issued'
            ),
            models.CheckConstraint(
                check=models.Q(blacklisted_at__gte=models.F('issued_at')),
                name='blacklist_after_issued'
            ),
        ]
    
    def __str__(self):
        """String representation of the blacklist entry."""
        return f"Blacklisted {self.token_type} token {self.token_id[:8]}... for {self.user.email}"
    
    @property
    def is_expired(self) -> bool:
        """Check if the blacklisted token would have expired naturally."""
        return timezone.now() >= self.expires_at
    
    @property
    def time_since_blacklisted(self) -> timedelta:
        """Get time since the token was blacklisted."""
        return timezone.now() - self.blacklisted_at
    
    @classmethod
    def cleanup_expired_entries(cls) -> int:
        """
        Clean up blacklist entries for tokens that have naturally expired.
        
        Returns:
            Number of entries cleaned up
        """
        expired_entries = cls.objects.filter(expires_at__lt=timezone.now())
        count = expired_entries.count()
        expired_entries.delete()
        return count
    
    @classmethod
    def get_user_blacklisted_tokens(cls, user: UserProfile, token_type: Optional[str] = None) -> models.QuerySet:
        """
        Get all blacklisted tokens for a user.
        
        Args:
            user: User to get blacklisted tokens for
            token_type: Optional token type filter
            
        Returns:
            QuerySet of blacklisted tokens
        """
        queryset = cls.objects.filter(user=user)
        if token_type:
            queryset = queryset.filter(token_type=token_type)
        return queryset.order_by('-blacklisted_at')


class JWTKeyRotation(TimestampedModel):
    """
    Model for tracking JWT signing key rotations.
    
    This model maintains a history of key rotations for audit
    and compliance purposes.
    """
    
    # Key status choices
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('rotated', 'Rotated'),
        ('compromised', 'Compromised'),
        ('expired', 'Expired'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this key rotation record"
    )
    
    # Key identification
    key_id = models.CharField(
        max_length=255,
        unique=True,
        help_text="Unique identifier for the JWT signing key"
    )
    
    # Key metadata
    algorithm = models.CharField(
        max_length=20,
        default='RS256',
        help_text="Signing algorithm used with this key"
    )
    key_size = models.PositiveIntegerField(
        default=2048,
        help_text="Key size in bits"
    )
    
    # Key lifecycle
    activated_at = models.DateTimeField(
        default=timezone.now,
        help_text="When this key was activated"
    )
    rotated_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When this key was rotated out"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active',
        help_text="Current status of the key"
    )
    
    # Rotation information
    rotated_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name='rotated_jwt_keys',
        help_text="User who initiated the key rotation"
    )
    rotation_reason = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Reason for key rotation"
    )
    
    # Usage statistics
    tokens_signed = models.PositiveIntegerField(
        default=0,
        help_text="Number of tokens signed with this key"
    )
    last_used = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When this key was last used for signing"
    )
    
    class Meta:
        db_table = 'jwt_key_rotation'
        verbose_name = _('JWT Key Rotation')
        verbose_name_plural = _('JWT Key Rotations')
        indexes = [
            models.Index(fields=['key_id']),
            models.Index(fields=['status']),
            models.Index(fields=['activated_at']),
            models.Index(fields=['rotated_at']),
            models.Index(fields=['-created_at']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(rotated_at__isnull=True) | models.Q(rotated_at__gt=models.F('activated_at')),
                name='jwt_key_rotated_after_activated'
            ),
        ]
    
    def __str__(self):
        """String representation of the key rotation record."""
        return f"JWT Key {self.key_id[:8]}... ({self.status})"
    
    @property
    def is_active(self) -> bool:
        """Check if the key is currently active."""
        return self.status == 'active'
    
    @property
    def age(self) -> timedelta:
        """Get the age of the key."""
        return timezone.now() - self.activated_at
    
    def rotate(self, rotated_by: Optional[UserProfile] = None, reason: str = 'scheduled') -> None:
        """
        Mark this key as rotated.
        
        Args:
            rotated_by: User who initiated the rotation
            reason: Reason for rotation
        """
        self.status = 'rotated'
        self.rotated_at = timezone.now()
        self.rotated_by = rotated_by
        self.rotation_reason = reason
        self.save(update_fields=['status', 'rotated_at', 'rotated_by', 'rotation_reason'])
    
    def increment_usage(self) -> None:
        """Increment the usage counter for this key."""
        self.tokens_signed += 1
        self.last_used = timezone.now()
        self.save(update_fields=['tokens_signed', 'last_used'])
    
    @classmethod
    def get_active_key(cls) -> Optional['JWTKeyRotation']:
        """Get the currently active key."""
        return cls.objects.filter(status='active').first()
    
    @classmethod
    def get_key_history(cls) -> models.QuerySet:
        """Get the complete key rotation history."""
        return cls.objects.all().order_by('-activated_at')