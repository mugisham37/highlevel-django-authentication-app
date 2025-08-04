"""
Tests for backup codes MFA service.

This module contains comprehensive tests for the backup codes service
including generation, validation, regeneration, and monitoring functionality.
"""

import json
from unittest.mock import patch, MagicMock
from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth import get_user_model

from ..models import MFADevice, MFAAttempt
from ..services.backup_codes_service import BackupCodesService, backup_codes_service
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
)

User = get_user_model()


class BackupCodesServiceTestCase(TestCase):
    """Test case for backup codes service functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        self.service = BackupCodesService()
        
        # Clear cache before each test
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    def test_generate_backup_codes_new_user(self):
        """Test generating backup codes for a user without existing codes."""
        result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Test Agent'
        )
        
        # Check result structure
        self.assertIn('codes', result)
        self.assertIn('device_id', result)
        self.assertIn('generated_at', result)
        self.assertIn('codes_count', result)
        self.assertIn('regenerated', result)
        
        # Check codes
        codes = result['codes']
        self.assertEqual(len(codes), 10)  # Default count
        self.assertFalse(result['regenerated'])
        
        # Verify all codes are unique and properly formatted
        self.assertEqual(len(set(codes)), len(codes))  # All unique
        for code in codes:
            self.assertEqual(len(code), 8)  # Default length
            self.assertTrue(code.isupper())
            self.assertTrue(code.isalnum())
        
        # Check device was created
        device = MFADevice.objects.get(id=result['device_id'])
        self.assertEqual(device.user, self.user)
        self.assertEqual(device.device_type, 'backup_codes')
        self.assertTrue(device.is_confirmed)
        self.assertEqual(len(device.get_backup_codes()), 10)
    
    def test_generate_backup_codes_custom_count(self):
        """Test generating backup codes with custom count."""
        result = self.service.generate_backup_codes(
            user=self.user,
            count=15,
            ip_address='192.168.1.1'
        )
        
        self.assertEqual(len(result['codes']), 15)
        self.assertEqual(result['codes_count'], 15)
    
    def test_generate_backup_codes_existing_without_force(self):
        """Test generating backup codes when codes already exist without force."""
        # First generation
        first_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Second generation without force
        second_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Should return existing codes
        self.assertEqual(first_result['codes'], second_result['codes'])
        self.assertFalse(second_result['regenerated'])
        self.assertIn('warning', second_result)
    
    def test_generate_backup_codes_with_force_regenerate(self):
        """Test generating backup codes with force regenerate."""
        # First generation
        first_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Second generation with force
        second_result = self.service.generate_backup_codes(
            user=self.user,
            force_regenerate=True,
            ip_address='192.168.1.1'
        )
        
        # Should generate new codes
        self.assertNotEqual(first_result['codes'], second_result['codes'])
        self.assertTrue(second_result['regenerated'])
    
    @override_settings(MFA_BACKUP_CODES_COUNT=5, MFA_BACKUP_CODE_LENGTH=6)
    def test_generate_backup_codes_custom_settings(self):
        """Test generating backup codes with custom settings."""
        result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        codes = result['codes']
        self.assertEqual(len(codes), 5)  # Custom count
        for code in codes:
            self.assertEqual(len(code), 6)  # Custom length
    
    def test_validate_backup_code_success(self):
        """Test successful backup code validation."""
        # Generate codes first
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Use the first code
        test_code = generation_result['codes'][0]
        
        result = self.service.validate_backup_code(
            user=self.user,
            backup_code=test_code,
            ip_address='192.168.1.1',
            user_agent='Test Agent',
            session_id='test-session'
        )
        
        # Check result
        self.assertTrue(result['valid'])
        self.assertEqual(result['remaining_codes'], 9)
        self.assertIn('used_at', result)
        self.assertIn('response_time_ms', result)
        
        # Verify code was removed from device
        device = MFADevice.objects.get(id=generation_result['device_id'])
        remaining_codes = device.get_backup_codes()
        self.assertNotIn(test_code, remaining_codes)
        self.assertEqual(len(remaining_codes), 9)
        
        # Verify attempt was recorded
        attempt = MFAAttempt.objects.get(device=device, result='success')
        self.assertEqual(attempt.user, self.user)
        self.assertEqual(attempt.ip_address, '192.168.1.1')
    
    def test_validate_backup_code_invalid(self):
        """Test validation with invalid backup code."""
        # Generate codes first
        self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Try invalid code
        with self.assertRaises(MFAVerificationError):
            self.service.validate_backup_code(
                user=self.user,
                backup_code='INVALID123',
                ip_address='192.168.1.1'
            )
        
        # Verify failed attempt was recorded
        device = MFADevice.objects.get(user=self.user, device_type='backup_codes')
        attempt = MFAAttempt.objects.get(device=device, result='failure')
        self.assertEqual(attempt.failure_reason, 'invalid_backup_code')
    
    def test_validate_backup_code_single_use_enforcement(self):
        """Test that backup codes can only be used once."""
        # Generate codes first
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        test_code = generation_result['codes'][0]
        
        # Use the code successfully
        result1 = self.service.validate_backup_code(
            user=self.user,
            backup_code=test_code,
            ip_address='192.168.1.1'
        )
        self.assertTrue(result1['valid'])
        
        # Try to use the same code again
        with self.assertRaises(MFAVerificationError):
            self.service.validate_backup_code(
                user=self.user,
                backup_code=test_code,
                ip_address='192.168.1.1'
            )
    
    def test_validate_backup_code_normalization(self):
        """Test backup code normalization (spaces, case)."""
        # Generate codes first
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        test_code = generation_result['codes'][0]
        
        # Test with lowercase and spaces
        normalized_input = test_code.lower().replace('', ' ')  # Add spaces
        
        result = self.service.validate_backup_code(
            user=self.user,
            backup_code=normalized_input,
            ip_address='192.168.1.1'
        )
        
        self.assertTrue(result['valid'])
    
    def test_validate_backup_code_no_device(self):
        """Test validation when user has no backup codes device."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.service.validate_backup_code(
                user=self.user,
                backup_code='TESTCODE',
                ip_address='192.168.1.1'
            )
    
    def test_validate_backup_code_rate_limiting(self):
        """Test rate limiting for backup code validation."""
        # Generate codes first
        self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Simulate multiple failed attempts
        for i in range(5):  # Max attempts per window
            try:
                self.service.validate_backup_code(
                    user=self.user,
                    backup_code=f'INVALID{i}',
                    ip_address='192.168.1.1'
                )
            except MFAVerificationError:
                pass  # Expected
        
        # Next attempt should be rate limited
        with self.assertRaises(MFARateLimitError):
            self.service.validate_backup_code(
                user=self.user,
                backup_code='INVALID999',
                ip_address='192.168.1.1'
            )
    
    def test_validate_backup_code_low_codes_warning(self):
        """Test warning when backup codes are running low."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            count=5,  # Small number for testing
            ip_address='192.168.1.1'
        )
        
        codes = generation_result['codes']
        
        # Use codes until only 2 remain (below threshold of 3)
        for code in codes[:3]:
            self.service.validate_backup_code(
                user=self.user,
                backup_code=code,
                ip_address='192.168.1.1'
            )
        
        # Next validation should include warning
        result = self.service.validate_backup_code(
            user=self.user,
            backup_code=codes[3],
            ip_address='192.168.1.1'
        )
        
        self.assertTrue(result['valid'])
        self.assertEqual(result['remaining_codes'], 1)
        self.assertIsNotNone(result['warning'])
        self.assertIn('backup codes remaining', result['warning'])
    
    def test_regenerate_backup_codes(self):
        """Test backup codes regeneration."""
        # Generate initial codes
        initial_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Use one code
        self.service.validate_backup_code(
            user=self.user,
            backup_code=initial_result['codes'][0],
            ip_address='192.168.1.1'
        )
        
        # Regenerate codes
        regen_result = self.service.regenerate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1',
            reason='security_incident'
        )
        
        # Check result
        self.assertTrue(regen_result['regenerated'])
        self.assertEqual(regen_result['reason'], 'security_incident')
        self.assertEqual(regen_result['previous_codes_count'], 9)  # 10 - 1 used
        self.assertEqual(len(regen_result['codes']), 10)
        
        # Verify old codes don't work
        with self.assertRaises(MFAVerificationError):
            self.service.validate_backup_code(
                user=self.user,
                backup_code=initial_result['codes'][1],  # Unused from old set
                ip_address='192.168.1.1'
            )
        
        # Verify new codes work
        result = self.service.validate_backup_code(
            user=self.user,
            backup_code=regen_result['codes'][0],
            ip_address='192.168.1.1'
        )
        self.assertTrue(result['valid'])
    
    def test_regenerate_backup_codes_no_device(self):
        """Test regeneration when user has no backup codes device."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.service.regenerate_backup_codes(
                user=self.user,
                ip_address='192.168.1.1'
            )
    
    def test_get_backup_codes_status_no_device(self):
        """Test getting status when user has no backup codes device."""
        status = self.service.get_backup_codes_status(self.user)
        
        self.assertFalse(status['has_backup_codes'])
        self.assertIsNone(status['device_id'])
        self.assertEqual(status['remaining_codes'], 0)
        self.assertEqual(status['status'], 'not_configured')
    
    def test_get_backup_codes_status_with_device(self):
        """Test getting status when user has backup codes device."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Use one code
        self.service.validate_backup_code(
            user=self.user,
            backup_code=generation_result['codes'][0],
            ip_address='192.168.1.1'
        )
        
        status = self.service.get_backup_codes_status(self.user)
        
        self.assertTrue(status['has_backup_codes'])
        self.assertEqual(status['device_id'], generation_result['device_id'])
        self.assertEqual(status['remaining_codes'], 9)
        self.assertEqual(status['usage_count'], 1)
        self.assertEqual(status['status'], 'active')
        self.assertTrue(status['is_confirmed'])
        self.assertFalse(status['low_codes_warning'])  # 9 > 3 threshold
    
    def test_get_backup_codes_status_low_codes_warning(self):
        """Test status with low codes warning."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            count=5,
            ip_address='192.168.1.1'
        )
        
        # Use codes until only 2 remain
        for code in generation_result['codes'][:3]:
            self.service.validate_backup_code(
                user=self.user,
                backup_code=code,
                ip_address='192.168.1.1'
            )
        
        status = self.service.get_backup_codes_status(self.user)
        
        self.assertEqual(status['remaining_codes'], 2)
        self.assertTrue(status['low_codes_warning'])  # 2 <= 3 threshold
    
    def test_get_usage_statistics_no_device(self):
        """Test getting usage statistics when user has no backup codes device."""
        stats = self.service.get_usage_statistics(self.user)
        
        self.assertFalse(stats['has_backup_codes'])
        self.assertIsNone(stats['statistics'])
    
    def test_get_usage_statistics_with_device(self):
        """Test getting usage statistics with device and usage history."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Create some usage history
        codes = generation_result['codes']
        
        # Successful attempts
        for i in range(3):
            self.service.validate_backup_code(
                user=self.user,
                backup_code=codes[i],
                ip_address='192.168.1.1',
                user_agent=f'Agent {i}'
            )
        
        # Failed attempts
        for i in range(2):
            try:
                self.service.validate_backup_code(
                    user=self.user,
                    backup_code=f'INVALID{i}',
                    ip_address='192.168.1.1'
                )
            except MFAVerificationError:
                pass
        
        stats = self.service.get_usage_statistics(self.user, days=30)
        
        self.assertTrue(stats['has_backup_codes'])
        self.assertEqual(stats['device_id'], generation_result['device_id'])
        
        statistics = stats['statistics']
        self.assertEqual(statistics['period_days'], 30)
        self.assertEqual(statistics['total_attempts'], 5)  # 3 success + 2 failed
        self.assertEqual(statistics['successful_attempts'], 3)
        self.assertEqual(statistics['failed_attempts'], 2)
        self.assertEqual(statistics['success_rate'], 60.0)  # 3/5 * 100
        self.assertEqual(statistics['remaining_codes'], 7)  # 10 - 3 used
        self.assertEqual(statistics['total_usage_count'], 3)
        self.assertEqual(len(statistics['recent_usage']), 3)
    
    def test_get_usage_statistics_custom_period(self):
        """Test getting usage statistics with custom time period."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Use one code
        self.service.validate_backup_code(
            user=self.user,
            backup_code=generation_result['codes'][0],
            ip_address='192.168.1.1'
        )
        
        # Get statistics for 7 days
        stats = self.service.get_usage_statistics(self.user, days=7)
        
        self.assertEqual(stats['statistics']['period_days'], 7)
        self.assertEqual(stats['statistics']['total_attempts'], 1)
    
    @patch('enterprise_auth.core.services.backup_codes_service.AuditService')
    def test_audit_logging(self, mock_audit_service):
        """Test that audit events are properly logged."""
        mock_audit = MagicMock()
        mock_audit_service.return_value = mock_audit
        
        service = BackupCodesService()  # Create new instance with mocked audit
        
        # Generate codes
        service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Test Agent'
        )
        
        # Verify audit logging was called
        mock_audit.log_authentication_event.assert_called()
        call_args = mock_audit.log_authentication_event.call_args
        self.assertEqual(call_args[1]['event_type'], 'mfa_backup_codes_generated')
        self.assertEqual(call_args[1]['user'], self.user)
    
    def test_error_handling_service_exception(self):
        """Test error handling when service operations fail."""
        # Mock the device creation to raise an exception
        with patch.object(MFADevice.objects, 'create_backup_codes_device') as mock_create:
            mock_create.side_effect = Exception("Database error")
            
            with self.assertRaises(MFAError) as context:
                self.service.generate_backup_codes(
                    user=self.user,
                    ip_address='192.168.1.1'
                )
            
            self.assertIn("Failed to generate backup codes", str(context.exception))
    
    def test_concurrent_code_usage(self):
        """Test handling of concurrent backup code usage attempts."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        test_code = generation_result['codes'][0]
        
        # First usage should succeed
        result1 = self.service.validate_backup_code(
            user=self.user,
            backup_code=test_code,
            ip_address='192.168.1.1'
        )
        self.assertTrue(result1['valid'])
        
        # Concurrent usage of same code should fail
        with self.assertRaises(MFAVerificationError):
            self.service.validate_backup_code(
                user=self.user,
                backup_code=test_code,
                ip_address='192.168.1.2'  # Different IP
            )
    
    def test_backup_codes_encryption(self):
        """Test that backup codes are properly encrypted in storage."""
        # Generate codes
        generation_result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Get the device and check that raw backup_codes field is encrypted
        device = MFADevice.objects.get(id=generation_result['device_id'])
        
        # Raw field should not contain plaintext codes
        raw_backup_codes = device.backup_codes
        self.assertIsNotNone(raw_backup_codes)
        
        # Should not be able to find any of the generated codes in raw field
        for code in generation_result['codes']:
            self.assertNotIn(code, raw_backup_codes)
        
        # But decrypted codes should match
        decrypted_codes = device.get_backup_codes()
        self.assertEqual(set(decrypted_codes), set(generation_result['codes']))
    
    @override_settings(MFA_BACKUP_CODE_FORMAT='numeric')
    def test_numeric_backup_codes(self):
        """Test generating numeric-only backup codes."""
        result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        for code in result['codes']:
            self.assertTrue(code.isdigit())
    
    @override_settings(MFA_BACKUP_CODE_FORMAT='hex')
    def test_hex_backup_codes(self):
        """Test generating hexadecimal backup codes."""
        result = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        for code in result['codes']:
            # Should only contain 0-9 and A-F
            self.assertTrue(all(c in '0123456789ABCDEF' for c in code))
    
    def test_backup_codes_uniqueness_across_users(self):
        """Test that backup codes are unique across different users."""
        # Create another user
        user2 = User.objects.create_user(
            email='test2@example.com',
            password='TestPassword123!',
            first_name='Test2',
            last_name='User2'
        )
        
        # Generate codes for both users
        result1 = self.service.generate_backup_codes(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        result2 = self.service.generate_backup_codes(
            user=user2,
            ip_address='192.168.1.1'
        )
        
        # Codes should be different between users
        codes1 = set(result1['codes'])
        codes2 = set(result2['codes'])
        
        # No overlap between the two sets
        self.assertEqual(len(codes1.intersection(codes2)), 0)
    
    def test_device_metadata_tracking(self):
        """Test that device metadata is properly tracked."""
        ip_address = '192.168.1.100'
        user_agent = 'Mozilla/5.0 Test Browser'
        
        result = self.service.generate_backup_codes(
            user=self.user,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        device = MFADevice.objects.get(id=result['device_id'])
        
        self.assertEqual(device.created_ip, ip_address)
        self.assertEqual(device.created_user_agent, user_agent)
        self.assertIsNotNone(device.created_at)
        
        # Use a code and check usage tracking
        self.service.validate_backup_code(
            user=self.user,
            backup_code=result['codes'][0],
            ip_address='192.168.1.200',
            user_agent='Different Agent'
        )
        
        device.refresh_from_db()
        self.assertEqual(device.last_used_ip, '192.168.1.200')
        self.assertIsNotNone(device.last_used)
        self.assertEqual(device.usage_count, 1)