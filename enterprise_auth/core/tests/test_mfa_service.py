"""
Tests for MFA service functionality.

This module contains tests for TOTP setup, verification, backup codes,
and device management functionality.
"""

import pyotp
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.cache import cache
from unittest.mock import patch, MagicMock

from ..models import MFADevice, MFAAttempt
from ..services.mfa_service import MFAService
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError
)

User = get_user_model()


class MFAServiceTestCase(TestCase):
    """Test case for MFA service functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.mfa_service = MFAService()
        
        # Clear cache before each test
        cache.clear()
    
    def test_setup_totp_success(self):
        """Test successful TOTP setup."""
        device_name = "Test Phone"
        ip_address = "192.168.1.1"
        user_agent = "Test Agent"
        
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name=device_name,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Verify setup data structure
        self.assertIn('device_id', setup_data)
        self.assertIn('secret_key', setup_data)
        self.assertIn('qr_code_uri', setup_data)
        self.assertIn('qr_code_data', setup_data)
        self.assertIn('manual_entry_key', setup_data)
        self.assertIn('Enterprise Auth', setup_data['issuer'])
        self.assertEqual(setup_data['account_name'], self.user.email)
        
        # Verify device was created
        device = MFADevice.objects.get(id=setup_data['device_id'])
        self.assertEqual(device.user, self.user)
        self.assertEqual(device.device_name, device_name)
        self.assertEqual(device.device_type, 'totp')
        self.assertEqual(device.status, 'pending')
        self.assertFalse(device.is_confirmed)
        self.assertEqual(device.created_ip, ip_address)
        self.assertEqual(device.created_user_agent, user_agent)
        
        # Verify secret key is encrypted and stored
        self.assertIsNotNone(device.secret_key)
        decrypted_secret = device.get_secret_key()
        self.assertEqual(decrypted_secret, setup_data['secret_key'])
    
    def test_setup_totp_missing_device_name(self):
        """Test TOTP setup with missing device name."""
        with self.assertRaises(TypeError):
            self.mfa_service.setup_totp(user=self.user, device_name=None)
    
    def test_confirm_totp_setup_success(self):
        """Test successful TOTP setup confirmation."""
        # First set up TOTP
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name="Test Phone"
        )
        
        device_id = setup_data['device_id']
        secret_key = setup_data['secret_key']
        
        # Generate valid TOTP code
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        # Confirm setup
        confirmation_data = self.mfa_service.confirm_totp_setup(
            user=self.user,
            device_id=device_id,
            verification_code=verification_code
        )
        
        # Verify confirmation data
        self.assertEqual(confirmation_data['device_id'], device_id)
        self.assertEqual(confirmation_data['device_name'], "Test Phone")
        self.assertIn('backup_codes', confirmation_data)
        self.assertEqual(len(confirmation_data['backup_codes']), 10)
        self.assertEqual(confirmation_data['status'], 'active')
        
        # Verify device is confirmed
        device = MFADevice.objects.get(id=device_id)
        self.assertTrue(device.is_confirmed)
        self.assertEqual(device.status, 'active')
        
        # Verify backup codes device was created
        backup_device = MFADevice.objects.get(
            user=self.user,
            device_type='backup_codes'
        )
        self.assertTrue(backup_device.is_confirmed)
        self.assertEqual(backup_device.status, 'active')
        
        # Verify backup codes are stored encrypted
        stored_codes = backup_device.get_backup_codes()
        self.assertEqual(len(stored_codes), 10)
        self.assertEqual(set(stored_codes), set(confirmation_data['backup_codes']))
    
    def test_confirm_totp_setup_invalid_code(self):
        """Test TOTP setup confirmation with invalid code."""
        # First set up TOTP
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name="Test Phone"
        )
        
        device_id = setup_data['device_id']
        
        # Try to confirm with invalid code
        with self.assertRaises(MFAVerificationError):
            self.mfa_service.confirm_totp_setup(
                user=self.user,
                device_id=device_id,
                verification_code="000000"
            )
        
        # Verify device is still pending
        device = MFADevice.objects.get(id=device_id)
        self.assertFalse(device.is_confirmed)
        self.assertEqual(device.status, 'pending')
        
        # Verify failed attempt was recorded
        attempt = MFAAttempt.objects.get(device=device)
        self.assertEqual(attempt.result, 'failure')
        self.assertEqual(attempt.failure_reason, 'invalid_code')
    
    def test_confirm_totp_setup_device_not_found(self):
        """Test TOTP setup confirmation with non-existent device."""
        import uuid
        with self.assertRaises(MFADeviceNotFoundError):
            self.mfa_service.confirm_totp_setup(
                user=self.user,
                device_id=str(uuid.uuid4()),
                verification_code="123456"
            )
    
    def test_verify_totp_success(self):
        """Test successful TOTP verification."""
        # Set up and confirm TOTP device
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name="Test Phone"
        )
        
        device_id = setup_data['device_id']
        secret_key = setup_data['secret_key']
        
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        # Confirm setup first
        self.mfa_service.confirm_totp_setup(
            user=self.user,
            device_id=device_id,
            verification_code=verification_code
        )
        
        # Generate new code for verification
        import time
        time.sleep(1)  # Ensure we get a different code
        verification_code = totp.now()
        
        # Verify TOTP
        verification_data = self.mfa_service.verify_totp(
            user=self.user,
            verification_code=verification_code,
            device_id=device_id
        )
        
        # Verify response
        self.assertTrue(verification_data['verified'])
        self.assertEqual(verification_data['device_id'], device_id)
        self.assertEqual(verification_data['device_name'], "Test Phone")
        self.assertIn('verified_at', verification_data)
        
        # Verify successful attempt was recorded
        attempt = MFAAttempt.objects.filter(
            device_id=device_id,
            result='success'
        ).first()
        self.assertIsNotNone(attempt)
        
        # Verify device usage was updated
        device = MFADevice.objects.get(id=device_id)
        self.assertIsNotNone(device.last_used)
        self.assertEqual(device.usage_count, 2)  # Setup confirmation + verification
    
    def test_verify_totp_invalid_code(self):
        """Test TOTP verification with invalid code."""
        # Set up and confirm TOTP device
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name="Test Phone"
        )
        
        device_id = setup_data['device_id']
        secret_key = setup_data['secret_key']
        
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        self.mfa_service.confirm_totp_setup(
            user=self.user,
            device_id=device_id,
            verification_code=verification_code
        )
        
        # Try to verify with invalid code
        with self.assertRaises(MFAVerificationError):
            self.mfa_service.verify_totp(
                user=self.user,
                verification_code="000000",
                device_id=device_id
            )
        
        # Verify failed attempt was recorded
        failed_attempt = MFAAttempt.objects.filter(
            device_id=device_id,
            result='failure'
        ).first()
        self.assertIsNotNone(failed_attempt)
        self.assertEqual(failed_attempt.failure_reason, 'invalid_code')
    
    def test_verify_totp_no_active_devices(self):
        """Test TOTP verification with no active devices."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.mfa_service.verify_totp(
                user=self.user,
                verification_code="123456"
            )
    
    def test_verify_backup_code_success(self):
        """Test successful backup code verification."""
        # Set up and confirm TOTP device (which creates backup codes)
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name="Test Phone"
        )
        
        device_id = setup_data['device_id']
        secret_key = setup_data['secret_key']
        
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        confirmation_data = self.mfa_service.confirm_totp_setup(
            user=self.user,
            device_id=device_id,
            verification_code=verification_code
        )
        
        backup_codes = confirmation_data['backup_codes']
        backup_code = backup_codes[0]
        
        # Verify backup code
        verification_data = self.mfa_service.verify_backup_code(
            user=self.user,
            backup_code=backup_code
        )
        
        # Verify response
        self.assertTrue(verification_data['verified'])
        self.assertEqual(verification_data['remaining_codes'], 9)
        self.assertIn('verified_at', verification_data)
        
        # Verify code was removed from device
        backup_device = MFADevice.objects.get(
            user=self.user,
            device_type='backup_codes'
        )
        remaining_codes = backup_device.get_backup_codes()
        self.assertEqual(len(remaining_codes), 9)
        self.assertNotIn(backup_code, remaining_codes)
    
    def test_verify_backup_code_invalid(self):
        """Test backup code verification with invalid code."""
        # Set up backup codes device
        backup_device = MFADevice.objects.create_backup_codes_device(
            user=self.user
        )
        backup_device.confirm_device()
        
        # Try to verify with invalid code
        with self.assertRaises(MFAVerificationError):
            self.mfa_service.verify_backup_code(
                user=self.user,
                backup_code="INVALID1"
            )
    
    def test_verify_backup_code_no_device(self):
        """Test backup code verification with no backup codes device."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.mfa_service.verify_backup_code(
                user=self.user,
                backup_code="TESTCODE"
            )
    
    def test_regenerate_backup_codes(self):
        """Test backup codes regeneration."""
        # Set up backup codes device
        backup_device = MFADevice.objects.create_backup_codes_device(
            user=self.user
        )
        backup_device.confirm_device()
        
        original_codes = backup_device.get_backup_codes()
        
        # Regenerate codes
        new_codes = self.mfa_service.regenerate_backup_codes(user=self.user)
        
        # Verify new codes
        self.assertEqual(len(new_codes), 10)
        self.assertNotEqual(set(new_codes), set(original_codes))
        
        # Verify codes are stored in device
        backup_device.refresh_from_db()
        stored_codes = backup_device.get_backup_codes()
        self.assertEqual(set(stored_codes), set(new_codes))
    
    def test_get_user_mfa_devices(self):
        """Test getting user MFA devices."""
        # Create multiple devices
        totp_device = MFADevice.objects.create_totp_device(
            user=self.user,
            device_name="Phone",
            secret_key="TESTSECRET123456"
        )
        totp_device.confirm_device()
        
        backup_device = MFADevice.objects.create_backup_codes_device(
            user=self.user
        )
        backup_device.confirm_device()
        
        # Get devices
        devices = self.mfa_service.get_user_mfa_devices(self.user)
        
        # Verify response
        self.assertEqual(len(devices), 2)
        
        device_types = [d['type'] for d in devices]
        self.assertIn('totp', device_types)
        self.assertIn('backup_codes', device_types)
        
        for device in devices:
            self.assertIn('id', device)
            self.assertIn('name', device)
            self.assertIn('type', device)
            self.assertIn('status', device)
            self.assertIn('is_confirmed', device)
            self.assertIn('is_active', device)
    
    def test_disable_mfa_device(self):
        """Test disabling an MFA device."""
        # Create and confirm device
        totp_device = MFADevice.objects.create_totp_device(
            user=self.user,
            device_name="Phone",
            secret_key="TESTSECRET123456"
        )
        totp_device.confirm_device()
        
        # Disable device
        success = self.mfa_service.disable_mfa_device(
            user=self.user,
            device_id=str(totp_device.id),
            reason="test_disable"
        )
        
        # Verify device was disabled
        self.assertTrue(success)
        totp_device.refresh_from_db()
        self.assertEqual(totp_device.status, 'disabled')
        self.assertEqual(
            totp_device.configuration['disabled_reason'],
            'test_disable'
        )
    
    def test_disable_mfa_device_not_found(self):
        """Test disabling non-existent MFA device."""
        import uuid
        with self.assertRaises(MFADeviceNotFoundError):
            self.mfa_service.disable_mfa_device(
                user=self.user,
                device_id=str(uuid.uuid4())
            )
    
    def test_has_active_mfa(self):
        """Test checking if user has active MFA."""
        # Initially no MFA
        self.assertFalse(self.mfa_service.has_active_mfa(self.user))
        
        # Create and confirm device
        totp_device = MFADevice.objects.create_totp_device(
            user=self.user,
            device_name="Phone",
            secret_key="TESTSECRET123456"
        )
        totp_device.confirm_device()
        
        # Now has active MFA
        self.assertTrue(self.mfa_service.has_active_mfa(self.user))
        
        # Disable device
        totp_device.disable_device()
        
        # No longer has active MFA
        self.assertFalse(self.mfa_service.has_active_mfa(self.user))
    
    @patch('enterprise_auth.core.services.mfa_service.cache')
    def test_rate_limiting(self, mock_cache):
        """Test MFA rate limiting functionality."""
        # Mock cache to simulate rate limit exceeded
        mock_cache.get.return_value = 10  # Exceeds limit
        
        with self.assertRaises(MFARateLimitError):
            self.mfa_service.verify_totp(
                user=self.user,
                verification_code="123456"
            )
    
    def test_totp_time_window_tolerance(self):
        """Test TOTP verification with time window tolerance."""
        # Set up and confirm TOTP device
        setup_data = self.mfa_service.setup_totp(
            user=self.user,
            device_name="Test Phone"
        )
        
        device_id = setup_data['device_id']
        secret_key = setup_data['secret_key']
        
        totp = pyotp.TOTP(secret_key)
        verification_code = totp.now()
        
        self.mfa_service.confirm_totp_setup(
            user=self.user,
            device_id=device_id,
            verification_code=verification_code
        )
        
        # Test with previous time window code
        import time
        current_time = int(time.time())
        previous_code = totp.at(current_time - 30)  # Previous 30-second window
        
        # Should work due to time window tolerance
        verification_data = self.mfa_service.verify_totp(
            user=self.user,
            verification_code=previous_code,
            device_id=device_id
        )
        
        self.assertTrue(verification_data['verified'])