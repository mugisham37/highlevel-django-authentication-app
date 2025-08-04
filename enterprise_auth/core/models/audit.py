"""
Audit logging models for enterprise authentication system.

This module contains models for tracking user actions and profile changes
to support compliance requirements and security monitoring.
"""

import uuid
from typing import Dict, Any, Optional

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .base import TimestampedModel


class AuditLog(TimestampedModel):
    """
    Model for tracking user actions and system events for audit compliance.
    
    This model provides comprehensive audit logging for user profile changes,
    authentication events, and other security-relevant actions.
    """
    
    # Event types
    EVENT_TYPE_CHOICES = [
        ('profile_update', 'Profile Update'),
        ('profile_view', 'Profile View'),
        ('password_change', 'Password Change'),
        ('email_verification', 'Email Verification'),
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('registration', 'User Registration'),
        ('account_lock', 'Account Lock'),
        ('account_unlock', 'Account Unlock'),
        ('mfa_setup', 'MFA Setup'),
        ('mfa_disable', 'MFA Disable'),
        ('oauth_link', 'OAuth Account Link'),
        ('oauth_unlink', 'OAuth Account Unlink'),
        ('data_export', 'Data Export'),
        ('data_deletion', 'Data Deletion'),
        ('permission_change', 'Permission Change'),
        ('role_assignment', 'Role Assignment'),
        ('api_access', 'API Access'),
        ('security_event', 'Security Event'),
        ('system_event', 'System Event'),
    ]
    
    # Severity levels
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this audit log entry"
    )
    
    # Event information
    event_type = models.CharField(
        max_length=50,
        choices=EVENT_TYPE_CHOICES,
        help_text="Type of event being logged"
    )
    event_description = models.TextField(
        help_text="Human-readable description of the event"
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='low',
        help_text="Severity level of the event"
    )
    
    # User information
    user = models.ForeignKey(
        'UserProfile',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs',
        help_text="User who performed the action"
    )
    user_email = models.EmailField(
        blank=True,
        null=True,
        help_text="Email of the user (stored for deleted users)"
    )
    impersonated_by = models.ForeignKey(
        'UserProfile',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='impersonation_logs',
        help_text="User who was impersonating (if applicable)"
    )
    
    # Request information
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address of the request"
    )
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent string of the request"
    )
    request_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Unique request identifier for correlation"
    )
    session_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Session identifier"
    )
    
    # Generic foreign key for related objects
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Content type of the related object"
    )
    object_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="ID of the related object"
    )
    content_object = GenericForeignKey('content_type', 'object_id')
    
    # Event data
    old_values = models.JSONField(
        default=dict,
        blank=True,
        help_text="Previous values before the change"
    )
    new_values = models.JSONField(
        default=dict,
        blank=True,
        help_text="New values after the change"
    )
    metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional metadata about the event"
    )
    
    # Compliance fields
    retention_until = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When this audit log should be deleted for compliance"
    )
    is_sensitive = models.BooleanField(
        default=False,
        help_text="Whether this log contains sensitive information"
    )
    
    class Meta:
        db_table = 'audit_auditlog'
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['event_type', '-created_at']),
            models.Index(fields=['severity', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['request_id']),
            models.Index(fields=['session_id']),
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['-created_at']),
            models.Index(fields=['retention_until']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        """String representation of the audit log."""
        user_info = self.user_email or (self.user.email if self.user else 'Anonymous')
        return f"{self.event_type} by {user_info} at {self.created_at}"
    
    @classmethod
    def log_event(
        cls,
        event_type: str,
        description: str,
        user: Optional['UserProfile'] = None,
        severity: str = 'low',
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        content_object: Optional[models.Model] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        is_sensitive: bool = False,
        retention_days: Optional[int] = None,
    ) -> 'AuditLog':
        """
        Create a new audit log entry.
        
        Args:
            event_type: Type of event being logged
            description: Human-readable description
            user: User who performed the action
            severity: Severity level of the event
            ip_address: IP address of the request
            user_agent: User agent string
            request_id: Unique request identifier
            session_id: Session identifier
            content_object: Related object
            old_values: Previous values before change
            new_values: New values after change
            metadata: Additional metadata
            is_sensitive: Whether log contains sensitive info
            retention_days: How long to retain this log
            
        Returns:
            Created AuditLog instance
        """
        # Calculate retention date
        retention_until = None
        if retention_days:
            retention_until = timezone.now() + timezone.timedelta(days=retention_days)
        
        # Store user email for deleted users
        user_email = user.email if user else None
        
        return cls.objects.create(
            event_type=event_type,
            event_description=description,
            severity=severity,
            user=user,
            user_email=user_email,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_id=session_id,
            content_object=content_object,
            old_values=old_values or {},
            new_values=new_values or {},
            metadata=metadata or {},
            is_sensitive=is_sensitive,
            retention_until=retention_until,
        )
    
    @classmethod
    def log_profile_update(
        cls,
        user: 'UserProfile',
        old_values: Dict[str, Any],
        new_values: Dict[str, Any],
        request_info: Optional[Dict[str, Any]] = None,
    ) -> 'AuditLog':
        """
        Log a user profile update event.
        
        Args:
            user: User whose profile was updated
            old_values: Previous profile values
            new_values: New profile values
            request_info: Request metadata (IP, user agent, etc.)
            
        Returns:
            Created AuditLog instance
        """
        request_info = request_info or {}
        
        # Filter out sensitive fields from logging
        sensitive_fields = {'password', 'password_reset_token', 'email_verification_token'}
        filtered_old = {k: v for k, v in old_values.items() if k not in sensitive_fields}
        filtered_new = {k: v for k, v in new_values.items() if k not in sensitive_fields}
        
        # Create description of changes
        changed_fields = []
        for field, new_value in filtered_new.items():
            old_value = filtered_old.get(field)
            if old_value != new_value:
                changed_fields.append(field)
        
        description = f"Profile updated. Changed fields: {', '.join(changed_fields)}"
        
        return cls.log_event(
            event_type='profile_update',
            description=description,
            user=user,
            severity='low',
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            request_id=request_info.get('request_id'),
            session_id=request_info.get('session_id'),
            content_object=user,
            old_values=filtered_old,
            new_values=filtered_new,
            metadata={'changed_fields': changed_fields},
            retention_days=2555,  # 7 years for compliance
        )
    
    @classmethod
    def log_profile_view(
        cls,
        user: 'UserProfile',
        viewed_by: Optional['UserProfile'] = None,
        request_info: Optional[Dict[str, Any]] = None,
    ) -> 'AuditLog':
        """
        Log a user profile view event.
        
        Args:
            user: User whose profile was viewed
            viewed_by: User who viewed the profile (if different)
            request_info: Request metadata
            
        Returns:
            Created AuditLog instance
        """
        request_info = request_info or {}
        viewer = viewed_by or user
        
        description = f"Profile viewed by {viewer.email}"
        if viewed_by and viewed_by != user:
            description += f" (viewing {user.email}'s profile)"
        
        return cls.log_event(
            event_type='profile_view',
            description=description,
            user=viewer,
            severity='low',
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            request_id=request_info.get('request_id'),
            session_id=request_info.get('session_id'),
            content_object=user,
            metadata={'viewed_user_id': str(user.id)},
            retention_days=365,  # 1 year for profile views
        )
    
    @classmethod
    def log_data_export(
        cls,
        user: 'UserProfile',
        export_type: str,
        request_info: Optional[Dict[str, Any]] = None,
    ) -> 'AuditLog':
        """
        Log a data export event for GDPR compliance.
        
        Args:
            user: User who requested data export
            export_type: Type of data exported
            request_info: Request metadata
            
        Returns:
            Created AuditLog instance
        """
        request_info = request_info or {}
        
        return cls.log_event(
            event_type='data_export',
            description=f"Data export requested: {export_type}",
            user=user,
            severity='medium',
            ip_address=request_info.get('ip_address'),
            user_agent=request_info.get('user_agent'),
            request_id=request_info.get('request_id'),
            session_id=request_info.get('session_id'),
            content_object=user,
            metadata={'export_type': export_type},
            retention_days=2555,  # 7 years for compliance
        )
    
    def get_changes_summary(self) -> Dict[str, Any]:
        """
        Get a summary of changes made in this audit log.
        
        Returns:
            Dictionary with change summary
        """
        if not self.old_values or not self.new_values:
            return {}
        
        changes = {}
        for field, new_value in self.new_values.items():
            old_value = self.old_values.get(field)
            if old_value != new_value:
                changes[field] = {
                    'old': old_value,
                    'new': new_value,
                }
        
        return changes
    
    def is_retention_expired(self) -> bool:
        """
        Check if this audit log has passed its retention period.
        
        Returns:
            True if retention period has expired
        """
        if not self.retention_until:
            return False
        return timezone.now() > self.retention_until


class ProfileChangeHistory(TimestampedModel):
    """
    Model for tracking detailed profile change history.
    
    This model provides a more detailed view of profile changes
    specifically for user profile management and compliance.
    """
    
    # Primary key
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this change record"
    )
    
    # User information
    user = models.ForeignKey(
        'UserProfile',
        on_delete=models.CASCADE,
        related_name='profile_changes',
        help_text="User whose profile was changed"
    )
    changed_by = models.ForeignKey(
        'UserProfile',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='profile_changes_made',
        help_text="User who made the change (if different)"
    )
    
    # Change information
    field_name = models.CharField(
        max_length=100,
        help_text="Name of the field that was changed"
    )
    old_value = models.TextField(
        blank=True,
        null=True,
        help_text="Previous value of the field"
    )
    new_value = models.TextField(
        blank=True,
        null=True,
        help_text="New value of the field"
    )
    
    # Request information
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        help_text="IP address of the change request"
    )
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="User agent of the change request"
    )
    request_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Request ID for correlation"
    )
    
    # Related audit log
    audit_log = models.ForeignKey(
        AuditLog,
        on_delete=models.CASCADE,
        related_name='profile_changes',
        help_text="Related audit log entry"
    )
    
    class Meta:
        db_table = 'audit_profilechangehistory'
        verbose_name = _('Profile Change History')
        verbose_name_plural = _('Profile Change Histories')
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['field_name', '-created_at']),
            models.Index(fields=['changed_by', '-created_at']),
            models.Index(fields=['audit_log']),
            models.Index(fields=['-created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        """String representation of the profile change."""
        return f"{self.user.email} - {self.field_name} changed at {self.created_at}"
    
    @classmethod
    def create_change_records(
        cls,
        user: 'UserProfile',
        old_values: Dict[str, Any],
        new_values: Dict[str, Any],
        audit_log: AuditLog,
        changed_by: Optional['UserProfile'] = None,
        request_info: Optional[Dict[str, Any]] = None,
    ) -> list['ProfileChangeHistory']:
        """
        Create detailed change records for profile updates.
        
        Args:
            user: User whose profile was changed
            old_values: Previous values
            new_values: New values
            audit_log: Related audit log entry
            changed_by: User who made the change
            request_info: Request metadata
            
        Returns:
            List of created ProfileChangeHistory instances
        """
        request_info = request_info or {}
        changes = []
        
        for field_name, new_value in new_values.items():
            old_value = old_values.get(field_name)
            if old_value != new_value:
                change = cls.objects.create(
                    user=user,
                    changed_by=changed_by or user,
                    field_name=field_name,
                    old_value=str(old_value) if old_value is not None else None,
                    new_value=str(new_value) if new_value is not None else None,
                    ip_address=request_info.get('ip_address'),
                    user_agent=request_info.get('user_agent'),
                    request_id=request_info.get('request_id'),
                    audit_log=audit_log,
                )
                changes.append(change)
        
        return changes