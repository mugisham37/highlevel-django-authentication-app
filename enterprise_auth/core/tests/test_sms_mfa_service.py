"""
Tests for SMS Multi-Factor Authentication service.

This module contains comprehensive tests for SMS MFA functionality including
setup, verification, rate limiting, and error handling.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, override_settings
from django.core.cache import cache
from django.utils import timezone
from twilio.base.exceptions import TwilioException

from ..models import UserProfile, MFADevice, MFAAttempt
from ..services.sms_mfa_service import SMSMFAService
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)


class SMSMFAServiceTestCase(TestCase):
    """Test cases for SMS MFA service."""
    
    def setUp(self):
        """Set up test data."""
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.sms_service = SMSMFAService()
        
        # Clear cache before each test
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    @override_settings(
        TWILIO_ACCOUNT_SID='test_sid',
        TWILIO_AUTH_TOKEN='test_token',
        TWILIO_PHONE_NUMBER='+1234567890'
    )
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_setup_sms_success(self, mock_twilio_client):
        """Test successful SMS MFA setup."""
        # Mock Twilio client
        mock_client = Mock()
        mock_message = Mock()
        mock_message.sid = 'test_message_sid'
        mock_message.status = 'queued'
        mock_client.messages.create.return_value = mock_message
        mock_twilio_client.return_value = mock_client
        
        # Test setup
        result = self.sms_service.setup_sms(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890',
            ip_address='127.0.0.1',
            user_agent='test-agent'
        )
        
        # Verify result
        self.assertIn('device_id', result)
        self.assertEqual(result['phone_number_masked'], '***-***-7890')
        self.assertTrue(result['code_sent'])
        self.assertEqual(result['delivery_status'], 'queued')
        self.assertEqual(result['message_sid'], 'test_message_sid')
        
        # Verify device was created
        device = MFADevice.objects.get(id=result['device_id'])
        self.assertEqual(device.user, self.user)
        self.assertEqual(device.device_type, 'sms')
        self.assertEqual(device.device_name, 'Test Phone')
        self.assertEqual(device.status, 'pending')
        
        # Verify SMS was sent
        mock_client.messages.create.assert_called_once()
        call_args = mock_client.messages.create.call_args
        self.assertEqual(call_args[1]['from_'], '+1234567890')
        self.assertEqual(call_args[1]['to'], '+1234567890')
        self.assertIn('verification code', call_args[1]['body'])
    
    def test_setup_sms_invalid_phone(self):
        """Test SMS setup with invalid phone number."""
        with self.assertRaises(MFAError) as context:
            self.sms_service.setup_sms(
                user=self.user,
                device_name='Test Phone',
                phone_number='invalid',
                ip_address='127.0.0.1'
            )
        
        self.assertIn('Invalid phone number format', str(context.exception))
    
    def test_setup_sms_no_twilio_config(self):
        """Test SMS setup without Twilio configuration."""
        # Service should initialize without Twilio client
        service = SMSMFAService()
        
        with self.assertRaises(MFAError) as context:
            service.setup_sms(
                user=self.user,
                device_name='Test Phone',
                phone_number='+1234567890',
                ip_address='127.0.0.1'
            )
        
        self.assertIn('SMS service is not configured', str(context.exception))
    
    @override_settings(
        TWILIO_ACCOUNT_SID='test_sid',
        TWILIO_AUTH_TOKEN='test_token',
        TWILIO_PHONE_NUMBER='+1234567890'
    )
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_setup_sms_twilio_error(self, mock_twilio_client):
        """Test SMS setup with Twilio error."""
        # Mock Twilio client to raise exception
        mock_client = Mock()
        mock_client.messages.create.side_effect = TwilioException('Twilio error')
        mock_twilio_client.return_value = mock_client
        
        with self.assertRaises(MFAError) as context:
            self.sms_service.setup_sms(
                user=self.user,
                device_name='Test Phone',
                phone_number='+1234567890',
                ip_address='127.0.0.1'
            )
        
        self.assertIn('Failed to set up SMS MFA', str(context.exception))
    
    def test_confirm_sms_setup_success(self):
        """Test successful SMS setup confirmation."""
        # Create pending SMS device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        
        # Store verification code in cache
        verification_code = '123456'
        cache_key = f"sms_code:{device.id}"
        cache_data = {
            'code': verification_code,
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=300)
        
        # Test confirmation
        result = self.sms_service.confirm_sms_setup(
            user=self.user,
            device_id=str(device.id),
            verification_code=verification_code,
            ip_address='127.0.0.1'
        )
        
        # Verify result
        self.assertEqual(result['device_id'], str(device.id))
        self.assertEqual(result['device_name'], 'Test Phone')
        self.assertEqual(result['status'], 'active')
        
        # Verify device was confirmed
        device.refresh_from_db()
        self.assertTrue(device.is_confirmed)
        self.assertEqual(device.status, 'active')
    
    def test_confirm_sms_setup_invalid_code(self):
        """Test SMS setup confirmation with invalid code."""
        # Create pending SMS device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        
        # Store different verification code in cache
        cache_key = f"sms_code:{device.id}"
        cache_data = {
            'code': '123456',
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=300)
        
        # Test confirmation with wrong code
        with self.assertRaises(MFAVerificationError):
            self.sms_service.confirm_sms_setup(
                user=self.user,
                device_id=str(device.id),
                verification_code='654321',
                ip_address='127.0.0.1'
            )
    
    def test_confirm_sms_setup_device_not_found(self):
        """Test SMS setup confirmation with non-existent device."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.sms_service.confirm_sms_setup(
                user=self.user,
                device_id='non-existent-id',
                verification_code='123456',
                ip_address='127.0.0.1'
            )
    
    @override_settings(
        TWILIO_ACCOUNT_SID='test_sid',
        TWILIO_AUTH_TOKEN='test_token',
        TWILIO_PHONE_NUMBER='+1234567890'
    )
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_send_sms_code_success(self, mock_twilio_client):
        """Test successful SMS code sending."""
        # Create active SMS device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        device.confirm_device()
        
        # Mock Twilio client
        mock_client = Mock()
        mock_message = Mock()
        mock_message.sid = 'test_message_sid'
        mock_message.status = 'sent'
        mock_client.messages.create.return_value = mock_message
        mock_twilio_client.return_value = mock_client
        
        # Test sending code
        result = self.sms_service.send_sms_code(
            user=self.user,
            device_id=str(device.id),
            ip_address='127.0.0.1'
        )
        
        # Verify result
        self.assertEqual(result['device_id'], str(device.id))
        self.assertTrue(result['code_sent'])
        self.assertEqual(result['delivery_status'], 'sent')
        self.assertEqual(result['message_sid'], 'test_message_sid')
        
        # Verify code was stored in cache
        cache_key = f"sms_code:{device.id}"
        cache_data = cache.get(cache_key)
        self.assertIsNotNone(cache_data)
        self.assertIn('code', cache_data)
        self.assertEqual(len(cache_data['code']), 6)  # Default code length
    
    def test_verify_sms_success(self):
        """Test successful SMS code verification."""
        # Create active SMS device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        device.confirm_device()
        
        # Store verification code in cache
        verification_code = '123456'
        cache_key = f"sms_code:{device.id}"
        cache_data = {
            'code': verification_code,
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=300)
        
        # Test verification
        result = self.sms_service.verify_sms(
            user=self.user,
            verification_code=verification_code,
            device_id=str(device.id),
            ip_address='127.0.0.1'
        )
        
        # Verify result
        self.assertTrue(result['verified'])
        self.assertEqual(result['device_id'], str(device.id))
        self.assertEqual(result['device_name'], 'Test Phone')
        
        # Verify code was cleared from cache
        cache_data = cache.get(cache_key)
        self.assertIsNone(cache_data)
    
    def test_verify_sms_invalid_code(self):
        """Test SMS verification with invalid code."""
        # Create active SMS device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        device.confirm_device()
        
        # Store different verification code in cache
        cache_key = f"sms_code:{device.id}"
        cache_data = {
            'code': '123456',
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=300)
        
        # Test verification with wrong code
        with self.assertRaises(MFAVerificationError):
            self.sms_service.verify_sms(
                user=self.user,
                verification_code='654321',
                device_id=str(device.id),
                ip_address='127.0.0.1'
            )
    
    def test_verify_sms_no_active_devices(self):
        """Test SMS verification with no active devices."""
        with self.assertRaises(MFADeviceNotFoundError):
            self.sms_service.verify_sms(
                user=self.user,
                verification_code='123456',
                ip_address='127.0.0.1'
            )
    
    @override_settings(MFA_MAX_SMS_PER_WINDOW=2, MFA_SMS_RATE_LIMIT_WINDOW=3600)
    def test_sms_rate_limiting(self):
        """Test SMS rate limiting."""
        # Simulate reaching rate limit
        user_key = f"sms_attempts:user:{self.user.id}"
        cache.set(user_key, 2, timeout=3600)  # Set to limit
        
        with self.assertRaises(MFARateLimitError) as context:
            self.sms_service.setup_sms(
                user=self.user,
                device_name='Test Phone',
                phone_number='+1234567890',
                ip_address='127.0.0.1'
            )
        
        self.assertIn('Too many SMS requests', str(context.exception))
    
    def test_phone_number_validation(self):
        """Test phone number validation."""
        service = SMSMFAService()
        
        # Valid phone numbers
        self.assertTrue(service._validate_phone_number('+1234567890'))
        self.assertTrue(service._validate_phone_number('1234567890'))
        self.assertTrue(service._validate_phone_number('+44123456789012'))
        
        # Invalid phone numbers
        self.assertFalse(service._validate_phone_number('123'))
        self.assertFalse(service._validate_phone_number('abc'))
        self.assertFalse(service._validate_phone_number(''))
        self.assertFalse(service._validate_phone_number('+123456789012345678'))
    
    def test_phone_number_masking(self):
        """Test phone number masking for display."""
        service = SMSMFAService()
        
        self.assertEqual(service._mask_phone_number('+1234567890'), '***-***-7890')
        self.assertEqual(service._mask_phone_number('1234567890'), '***-***-7890')
        self.assertEqual(service._mask_phone_number('123'), '***-***-****')
        self.assertEqual(service._mask_phone_number(''), '')
    
    def test_sms_code_generation(self):
        """Test SMS code generation."""
        service = SMSMFAService()
        
        code = service._generate_sms_code()
        self.assertEqual(len(code), 6)  # Default length
        self.assertTrue(code.isdigit())
        
        # Test uniqueness
        codes = [service._generate_sms_code() for _ in range(100)]
        self.assertEqual(len(set(codes)), 100)  # All should be unique
    
    def test_sms_code_storage_and_retrieval(self):
        """Test SMS code storage and retrieval from cache."""
        # Create device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        
        service = SMSMFAService()
        
        # Store code
        code = '123456'
        service._store_sms_code(device, code)
        
        # Verify code can be retrieved and verified
        self.assertTrue(service._verify_sms_code(device, code))
        self.assertFalse(service._verify_sms_code(device, '654321'))
        
        # Clear code
        service._clear_sms_code(device)
        self.assertFalse(service._verify_sms_code(device, code))
    
    def test_failed_attempt_recording(self):
        """Test recording of failed MFA attempts."""
        # Create device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        
        service = SMSMFAService()
        
        # Record failed attempt
        service._record_failed_attempt(
            device=device,
            ip_address='127.0.0.1',
            user_agent='test-agent',
            failure_reason='invalid_sms_code'
        )
        
        # Verify attempt was recorded
        attempt = MFAAttempt.objects.get(device=device)
        self.assertEqual(attempt.result, 'failure')
        self.assertEqual(attempt.failure_reason, 'invalid_sms_code')
        self.assertEqual(attempt.ip_address, '127.0.0.1')
        self.assertEqual(attempt.user_agent, 'test-agent')
    
    def test_successful_attempt_recording(self):
        """Test recording of successful MFA attempts."""
        # Create device
        device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='Test Phone',
            phone_number='+1234567890'
        )
        
        service = SMSMFAService()
        
        # Record successful attempt
        service._record_successful_attempt(
            device=device,
            ip_address='127.0.0.1',
            user_agent='test-agent'
        )
        
        # Verify attempt was recorded
        attempt = MFAAttempt.objects.get(device=device)
        self.assertEqual(attempt.result, 'success')
        self.assertEqual(attempt.ip_address, '127.0.0.1')
        self.assertEqual(attempt.user_agent, 'test-agent')
        
        # Verify device was marked as used
        device.refresh_from_db()
        self.assertIsNotNone(device.last_used)
        self.assertEqual(device.usage_count, 1)


@pytest.mark.django_db
class TestSMSMFAIntegration:
    """Integration tests for SMS MFA functionality."""
    
    def test_complete_sms_mfa_flow(self):
        """Test complete SMS MFA flow from setup to verification."""
        # Create user
        user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        service = SMSMFAService()
        
        with patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient') as mock_twilio:
            # Mock Twilio client
            mock_client = Mock()
            mock_message = Mock()
            mock_message.sid = 'test_message_sid'
            mock_message.status = 'sent'
            mock_client.messages.create.return_value = mock_message
            mock_twilio.return_value = mock_client
            
            # Step 1: Setup SMS MFA
            setup_result = service.setup_sms(
                user=user,
                device_name='Test Phone',
                phone_number='+1234567890',
                ip_address='127.0.0.1'
            )
            
            device_id = setup_result['device_id']
            
            # Step 2: Get the verification code from cache
            cache_key = f"sms_code:{device_id}"
            cache_data = cache.get(cache_key)
            verification_code = cache_data['code']
            
            # Step 3: Confirm setup
            confirm_result = service.confirm_sms_setup(
                user=user,
                device_id=device_id,
                verification_code=verification_code,
                ip_address='127.0.0.1'
            )
            
            assert confirm_result['status'] == 'active'
            
            # Step 4: Send new verification code
            send_result = service.send_sms_code(
                user=user,
                device_id=device_id,
                ip_address='127.0.0.1'
            )
            
            assert send_result['code_sent'] is True
            
            # Step 5: Get new verification code from cache
            cache_data = cache.get(cache_key)
            new_verification_code = cache_data['code']
            
            # Step 6: Verify SMS code
            verify_result = service.verify_sms(
                user=user,
                verification_code=new_verification_code,
                device_id=device_id,
                ip_address='127.0.0.1'
            )
            
            assert verify_result['verified'] is True
            
            # Verify device state
            device = MFADevice.objects.get(id=device_id)
            assert device.is_active
            assert device.usage_count == 2  # Setup confirmation + verification