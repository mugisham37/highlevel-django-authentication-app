"""
Base model classes with audit fields and soft delete functionality.

This module provides base model classes that include common functionality
like timestamps, audit trails, and soft delete capabilities that can be
inherited by all models in the system.
"""

import uuid
from typing import Optional

from django.conf import settings
from django.db import models
from django.utils import timezone

from enterprise_auth.core.utils.correlation import get_correlation_id


class BaseModelManager(models.Manager):
    """
    Base manager for all models.
    
    Provides common query methods and optimizations.
    """
    
    def get_queryset(self):
        """
        Return the base queryset for this manager.
        
        Returns:
            QuerySet with select_related optimizations where appropriate
        """
        return super().get_queryset()
    
    def active(self):
        """
        Return only active (non-soft-deleted) records.
        
        Returns:
            QuerySet filtered to active records
        """
        return self.get_queryset().filter(is_deleted=False)
    
    def deleted(self):
        """
        Return only soft-deleted records.
        
        Returns:
            QuerySet filtered to deleted records
        """
        return self.get_queryset().filter(is_deleted=True)


class SoftDeleteManager(BaseModelManager):
    """
    Manager that excludes soft-deleted records by default.
    """
    
    def get_queryset(self):
        """
        Return queryset excluding soft-deleted records.
        
        Returns:
            QuerySet with soft-deleted records excluded
        """
        return super().get_queryset().filter(is_deleted=False)


class BaseModel(models.Model):
    """
    Abstract base model with UUID primary key and basic metadata.
    
    All models in the system should inherit from this class or one of its
    subclasses to ensure consistent structure and functionality.
    """
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for this record"
    )
    
    objects = BaseModelManager()
    
    class Meta:
        abstract = True
        ordering = ['-created_at'] if hasattr(models.Model, 'created_at') else ['id']
    
    def __str__(self):
        """
        String representation of the model.
        
        Returns:
            String representation using model name and ID
        """
        return f"{self.__class__.__name__}({self.id})"
    
    def __repr__(self):
        """
        Developer representation of the model.
        
        Returns:
            Detailed string representation
        """
        return f"<{self.__class__.__name__}: {self.id}>"


class TimestampedModel(BaseModel):
    """
    Abstract model with created_at and updated_at timestamps.
    
    Automatically manages creation and update timestamps.
    """
    
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp when this record was created"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="Timestamp when this record was last updated"
    )
    
    class Meta:
        abstract = True
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['-updated_at']),
        ]


class AuditableModel(TimestampedModel):
    """
    Abstract model with full audit trail capabilities.
    
    Tracks who created and modified records, along with correlation IDs
    for request tracking.
    """
    
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_created',
        help_text="User who created this record"
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_updated',
        help_text="User who last updated this record"
    )
    correlation_id = models.CharField(
        max_length=36,
        blank=True,
        null=True,
        help_text="Correlation ID for request tracking"
    )
    
    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['created_by']),
            models.Index(fields=['updated_by']),
            models.Index(fields=['correlation_id']),
        ]
    
    def save(self, *args, **kwargs):
        """
        Override save to automatically set audit fields.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        # Set correlation ID if not already set
        if not self.correlation_id:
            self.correlation_id = get_correlation_id()
        
        # Handle user tracking if user is provided in kwargs
        user = kwargs.pop('user', None)
        if user and user.is_authenticated:
            if not self.pk:  # New record
                self.created_by = user
            self.updated_by = user
        
        super().save(*args, **kwargs)


class SoftDeleteModel(AuditableModel):
    """
    Abstract model with soft delete functionality.
    
    Instead of actually deleting records, marks them as deleted
    and tracks when and by whom they were deleted.
    """
    
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
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='%(class)s_deleted',
        help_text="User who deleted this record"
    )
    
    objects = SoftDeleteManager()
    all_objects = BaseModelManager()  # Manager that includes deleted records
    
    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['is_deleted']),
            models.Index(fields=['deleted_at']),
            models.Index(fields=['deleted_by']),
            models.Index(fields=['is_deleted', '-created_at']),
        ]
    
    def delete(self, user: Optional[models.Model] = None, hard_delete: bool = False):
        """
        Soft delete the record.
        
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
    
    def restore(self, user: Optional[models.Model] = None):
        """
        Restore a soft-deleted record.
        
        Args:
            user: User performing the restoration
        """
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        if user and user.is_authenticated:
            self.updated_by = user
        self.save(update_fields=['is_deleted', 'deleted_at', 'deleted_by', 'updated_at', 'updated_by'])
    
    @property
    def is_active(self) -> bool:
        """
        Check if the record is active (not soft deleted).
        
        Returns:
            True if record is active, False if soft deleted
        """
        return not self.is_deleted


class VersionedModel(SoftDeleteModel):
    """
    Abstract model with version tracking.
    
    Tracks version numbers for optimistic locking and change detection.
    """
    
    version = models.PositiveIntegerField(
        default=1,
        help_text="Version number for optimistic locking"
    )
    
    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=['version']),
        ]
    
    def save(self, *args, **kwargs):
        """
        Override save to increment version number.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        if self.pk:  # Existing record
            self.version += 1
        super().save(*args, **kwargs)


class EncryptedFieldMixin:
    """
    Mixin for models that contain encrypted fields.
    
    Provides utilities for handling encrypted data in model fields.
    """
    
    def encrypt_field(self, field_name: str, value: str) -> str:
        """
        Encrypt a field value.
        
        Args:
            field_name: Name of the field being encrypted
            value: Value to encrypt
            
        Returns:
            Encrypted value
        """
        from enterprise_auth.core.utils.encryption import encrypt_sensitive_data
        return encrypt_sensitive_data(value)
    
    def decrypt_field(self, field_name: str, encrypted_value: str) -> str:
        """
        Decrypt a field value.
        
        Args:
            field_name: Name of the field being decrypted
            encrypted_value: Encrypted value to decrypt
            
        Returns:
            Decrypted value
        """
        from enterprise_auth.core.utils.encryption import decrypt_sensitive_data
        return decrypt_sensitive_data(encrypted_value)


class CacheableModelMixin:
    """
    Mixin for models that should be cached.
    
    Provides cache key generation and cache invalidation methods.
    """
    
    def get_cache_key(self, suffix: str = '') -> str:
        """
        Generate cache key for this model instance.
        
        Args:
            suffix: Optional suffix for the cache key
            
        Returns:
            Cache key string
        """
        base_key = f"{self.__class__.__name__.lower()}:{self.pk}"
        return f"{base_key}:{suffix}" if suffix else base_key
    
    def invalidate_cache(self):
        """
        Invalidate all cache entries for this model instance.
        """
        from django.core.cache import cache
        
        # Generate common cache key patterns
        cache_keys = [
            self.get_cache_key(),
            self.get_cache_key('detail'),
            self.get_cache_key('permissions'),
            self.get_cache_key('roles'),
        ]
        
        # Delete cache entries
        cache.delete_many(cache_keys)
    
    def save(self, *args, **kwargs):
        """
        Override save to invalidate cache.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        super().save(*args, **kwargs)
        self.invalidate_cache()
    
    def delete(self, *args, **kwargs):
        """
        Override delete to invalidate cache.
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        self.invalidate_cache()
        super().delete(*args, **kwargs)