"""
Tests for base model classes with audit fields and soft delete functionality.
"""

from django.test import TestCase
from django.contrib.auth.models import User
from django.db import models

from enterprise_auth.core.models.base import (
    BaseModel,
    TimestampedModel,
    AuditableModel,
    SoftDeleteModel,
    VersionedModel,
    EncryptedFieldMixin,
    CacheableModelMixin,
)
from enterprise_auth.core.utils.correlation import set_correlation_id, clear_correlation_id


# Test models for testing base functionality
class TestTimestampedModel(TimestampedModel):
    """Test model for timestamped functionality."""
    name = models.CharField(max_length=100)
    
    class Meta:
        app_label = 'enterprise_auth'


class TestAuditableModel(AuditableModel):
    """Test model for auditable functionality."""
    name = models.CharField(max_length=100)
    
    class Meta:
        app_label = 'enterprise_auth'


class TestSoftDeleteModel(SoftDeleteModel):
    """Test model for soft delete functionality."""
    name = models.CharField(max_length=100)
    
    class Meta:
        app_label = 'enterprise_auth'


class TestVersionedModel(VersionedModel):
    """Test model for versioned functionality."""
    name = models.CharField(max_length=100)
    
    class Meta:
        app_label = 'enterprise_auth'


class TestEncryptedModel(SoftDeleteModel, EncryptedFieldMixin):
    """Test model for encrypted field functionality."""
    name = models.CharField(max_length=100)
    encrypted_data = models.TextField()
    
    class Meta:
        app_label = 'enterprise_auth'
    
    def save(self, *args, **kwargs):
        # Encrypt the data before saving
        if self.encrypted_data and not self.encrypted_data.startswith('gAAAAA'):  # Not already encrypted
            self.encrypted_data = self.encrypt_field('encrypted_data', self.encrypted_data)
        super().save(*args, **kwargs)
    
    def get_decrypted_data(self):
        """Get decrypted data."""
        if self.encrypted_data:
            return self.decrypt_field('encrypted_data', self.encrypted_data)
        return None


class BaseModelTest(TestCase):
    """Test cases for base model functionality."""
    
    def setUp(self):
        clear_correlation_id()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_base_model_uuid_primary_key(self):
        """Test that base models use UUID primary keys."""
        instance = TestTimestampedModel.objects.create(name='test')
        self.assertIsNotNone(instance.id)
        # Should be a valid UUID string representation
        str(instance.id)  # This will raise ValueError if not valid UUID
    
    def test_timestamped_model_auto_timestamps(self):
        """Test that timestamped models automatically set timestamps."""
        instance = TestTimestampedModel.objects.create(name='test')
        
        self.assertIsNotNone(instance.created_at)
        self.assertIsNotNone(instance.updated_at)
        
        # Update the instance
        original_created = instance.created_at
        original_updated = instance.updated_at
        
        instance.name = 'updated'
        instance.save()
        
        # created_at should remain the same, updated_at should change
        self.assertEqual(instance.created_at, original_created)
        self.assertGreater(instance.updated_at, original_updated)
    
    def test_auditable_model_user_tracking(self):
        """Test that auditable models track user changes."""
        # Test creation with user
        instance = TestAuditableModel.objects.create(name='test')
        instance.save(user=self.user)
        
        # Refresh from database
        instance.refresh_from_db()
        self.assertEqual(instance.created_by, self.user)
        self.assertEqual(instance.updated_by, self.user)
    
    def test_auditable_model_correlation_id(self):
        """Test that auditable models capture correlation ID."""
        correlation_id = 'test-correlation-id'
        set_correlation_id(correlation_id)
        
        instance = TestAuditableModel.objects.create(name='test')
        self.assertEqual(instance.correlation_id, correlation_id)
    
    def test_soft_delete_functionality(self):
        """Test soft delete functionality."""
        instance = TestSoftDeleteModel.objects.create(name='test')
        instance_id = instance.id
        
        # Verify instance exists
        self.assertTrue(TestSoftDeleteModel.objects.filter(id=instance_id).exists())
        self.assertTrue(instance.is_active)
        
        # Soft delete the instance
        instance.delete(user=self.user)
        
        # Should not exist in default manager
        self.assertFalse(TestSoftDeleteModel.objects.filter(id=instance_id).exists())
        
        # Should exist in all_objects manager
        self.assertTrue(TestSoftDeleteModel.all_objects.filter(id=instance_id).exists())
        
        # Refresh instance and check soft delete fields
        instance.refresh_from_db()
        self.assertTrue(instance.is_deleted)
        self.assertIsNotNone(instance.deleted_at)
        self.assertEqual(instance.deleted_by, self.user)
        self.assertFalse(instance.is_active)
    
    def test_soft_delete_restore(self):
        """Test restoring soft-deleted records."""
        instance = TestSoftDeleteModel.objects.create(name='test')
        instance_id = instance.id
        
        # Soft delete
        instance.delete(user=self.user)
        self.assertFalse(TestSoftDeleteModel.objects.filter(id=instance_id).exists())
        
        # Restore
        instance.restore(user=self.user)
        
        # Should exist in default manager again
        self.assertTrue(TestSoftDeleteModel.objects.filter(id=instance_id).exists())
        
        # Check restore fields
        instance.refresh_from_db()
        self.assertFalse(instance.is_deleted)
        self.assertIsNone(instance.deleted_at)
        self.assertIsNone(instance.deleted_by)
        self.assertTrue(instance.is_active)
    
    def test_hard_delete(self):
        """Test hard delete functionality."""
        instance = TestSoftDeleteModel.objects.create(name='test')
        instance_id = instance.id
        
        # Hard delete
        instance.delete(hard_delete=True)
        
        # Should not exist in any manager
        self.assertFalse(TestSoftDeleteModel.objects.filter(id=instance_id).exists())
        self.assertFalse(TestSoftDeleteModel.all_objects.filter(id=instance_id).exists())
    
    def test_versioned_model_version_increment(self):
        """Test that versioned models increment version on save."""
        instance = TestVersionedModel.objects.create(name='test')
        self.assertEqual(instance.version, 1)
        
        # Update the instance
        instance.name = 'updated'
        instance.save()
        self.assertEqual(instance.version, 2)
        
        # Update again
        instance.name = 'updated again'
        instance.save()
        self.assertEqual(instance.version, 3)
    
    def test_encrypted_field_mixin(self):
        """Test encrypted field functionality."""
        original_data = 'sensitive_information_123'
        instance = TestEncryptedModel.objects.create(
            name='test',
            encrypted_data=original_data
        )
        
        # Data should be encrypted in the database
        instance.refresh_from_db()
        self.assertNotEqual(instance.encrypted_data, original_data)
        
        # Should be able to decrypt
        decrypted = instance.get_decrypted_data()
        self.assertEqual(decrypted, original_data)
    
    def test_model_string_representations(self):
        """Test model string representations."""
        instance = TestTimestampedModel.objects.create(name='test')
        
        str_repr = str(instance)
        self.assertIn('TestTimestampedModel', str_repr)
        self.assertIn(str(instance.id), str_repr)
        
        repr_str = repr(instance)
        self.assertIn('TestTimestampedModel', repr_str)
        self.assertIn(str(instance.id), repr_str)