"""
Tests for Email Multi-Factor Authentication service.

This module contains unit tests for the EmailMFAService class,
testing email code generation, delivery, verification, and security features.
"""

import pytest
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.core.cache import cache
from django.utils import timezone

from ..models import UserProfile, MFADevice, MFAAttempt
from ..services.email_mfa_service import EmailMFAService
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
    MFADeviceDisabledError
)


class EmailMFAServiceTest(TestCase):
    """Test cases for EmailMFAService."""
    
    def setUp(self):
        """Set up test data."""
        self.service = EmailMFAService()
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Clear cache before each test
        cache.clear()
    
    def tearDown(self):
        """Clean up after each test."""
        cache.clear()
    
    def test_setup_email_mfa_success(self):
        """Test successful email MFA setup."""
        with patch('enterprise_auth.core.tasks.email_tasks.send_mfa_verification_email.delay') as mock_task:
            mock_task.return_value = MagicMock(id='task-123')
            
            result = self.service.setup_email_mfa(
                user=self.user,
                device_name='My Email',
                email_address='test@example.com',
                ip_address='192.168.1.1',
                user_agent='Test Browser'
            )
            
            # Check result
            self.assertTrue(result['code_sent'])
            self.assertEqual(result['email_address_masked'], 'te***@example.com')
            self.assertEqual(result['expires_in_minutes'], 10)
            
            # Check device was created
            device = MFADevice.objects.get(id=result['device_id'])
            self.assertEqual(device.user, self.user)
            self.assertEqual(device.device_type, 'email')
            self.assertEqual(device.device_name, 'My Email')
            self.assertEqual(device.email_address, 'test@example.com')
            self.assertEqual(device.status, 'pending')
            self.assertFalse(device.is_confirmed)
            
            # Check email task was called
            mock_task.assert_called_once()
    
    def test_setup_email_mfa_default_email(self):
        """Test email MFA setup with default user email."""
        with patch('enterprise_auth.core.tasks.email_tasks.send_mfa_verification_email.delay') as mock_task:
            mock_task.return_value = MagicMock(id='task-123')
            
            result = self.service.setup_email_mfa(
                user=self.user,
                device_name='My Email',
                ip_address='192.168.1.1'
            )
            
            # Check device was created with user's email
            device = MFADevice.objects.get(id=result['device_id'])
            self.assertEqual(device.email_address, self.user.email)
    
    def test_setup_email_mfa_invalid_email(self):
        """Test email MFA setup with invalid email address."""
        with self.assertRaises(MFAError) as context:
            self.service.setup_email_mfa(
                user=self.user,
                device_name='My Email',
                email_address='invalid-email',
                ip_address='192.168.1.1'
            )
        
        self.assertIn('Invalid email address format', str(context.exception))
    
    def test_confirm_email_setup_success(self):
        """Test successful email MFA setup confirmation."""
        # Create pending device
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        
        # Store verification code
        verification_code = '123456'
        self.service._store_email_code(device, verification_code)
        
        result = self.service.confirm_email_setup(
            user=self.user,
            device_id=str(device.id),
            verification_code=verification_code,
            ip_address='192.168.1.1'
        )
        
        # Check result
        self.assertEqual(result['device_id'], str(device.id))
        self.assertEqual(result['device_name'], 'My Email')
        self.assertEqual(result['status'], 'active')
        
        # Check device was confirmed
        device.refresh_from_db()
        self.assertTrue(device.is_confirmed)
        self.assertEqual(device.status, 'active')
    
    def test_confirm_email_setup_invalid_code(self):
        """Test email MFA setup confirmation with invalid code."""
        # Create pending device
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        
        # Store verification code
        self.service._store_email_code(device, '123456')
        
        with self.assertRaises(MFAVerificationError) as context:
            self.service.confirm_email_setup(
                user=self.user,
                device_id=str(device.id),
                verification_code='wrong_code',
                ip_address='192.168.1.1'
            )
        
        self.assertIn('Invalid or expired email code', str(context.exception))
    
    def test_confirm_email_setup_device_not_found(self):
        """Test email MFA setup confirmation with non-existent device."""
        with self.assertRaises(MFADeviceNotFoundError) as context:
            self.service.confirm_email_setup(
                user=self.user,
                device_id='non-existent-id',
                verification_code='123456',
                ip_address='192.168.1.1'
            )
        
        self.assertIn('Email device not found', str(context.exception))
    
    def test_send_email_code_success(self):
        """Test successful email code sending."""
        # Create active device
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        device.confirm_device()
        
        with patch('enterprise_auth.core.tasks.email_tasks.send_mfa_verification_email.delay') as mock_task:
            mock_task.return_value = MagicMock(id='task-123')
            
            result = self.service.send_email_code(
                user=self.user,
                device_id=str(device.id),
                ip_address='192.168.1.1'
            )
            
            # Check result
            self.assertTrue(result['code_sent'])
            self.assertEqual(result['device_id'], str(device.id))
            self.assertEqual(result['device_name'], 'My Email')
            
            # Check email task was called
            mock_task.assert_called_once()
    
    def test_send_email_code_no_device(self):
        """Test email code sending with no active devices."""
        with self.assertRaises(MFADeviceNotFoundError) as context:
            self.service.send_email_code(
                user=self.user,
                ip_address='192.168.1.1'
            )
        
        self.assertIn('No active email devices found', str(context.exception))
    
    def test_verify_email_success(self):
        """Test successful email code verification."""
        # Create active device
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        device.confirm_device()
        
        # Store verification code
        verification_code = '123456'
        self.service._store_email_code(device, verification_code)
        
        result = self.service.verify_email(
            user=self.user,
            verification_code=verification_code,
            device_id=str(device.id),
            ip_address='192.168.1.1'
        )
        
        # Check result
        self.assertTrue(result['verified'])
        self.assertEqual(result['device_id'], str(device.id))
        self.assertEqual(result['device_name'], 'My Email')
        
        # Check code was cleared
        cache_key = f"email_code:{device.id}"
        self.assertIsNone(cache.get(cache_key))
    
    def test_verify_email_invalid_code(self):
        """Test email code verification with invalid code."""
        # Create active device
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        device.confirm_device()
        
        # Store verification code
        self.service._store_email_code(device, '123456')
        
        with self.assertRaises(MFAVerificationError) as context:
            self.service.verify_email(
                user=self.user,
                verification_code='wrong_code',
                device_id=str(device.id),
                ip_address='192.168.1.1'
            )
        
        self.assertIn('Invalid or expired email code', str(context.exception))
    
    def test_resend_email_code_success(self):
        """Test successful email code resending."""
        # Create active device
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        device.confirm_device()
        
        with patch('enterprise_auth.core.tasks.email_tasks.send_mfa_verification_email.delay') as mock_task:
            mock_task.return_value = MagicMock(id='task-123')
            
            result = self.service.resend_email_code(
                user=self.user,
                device_id=str(device.id),
                ip_address='192.168.1.1'
            )
            
            # Check result
            self.assertTrue(result['code_sent'])
            self.assertEqual(result['device_id'], str(device.id))
            
            # Check email task was called
            mock_task.assert_called_once()
    
    def test_resend_email_code_device_not_found(self):
        """Test email code resending with non-existent device."""
        with self.assertRaises(MFADeviceNotFoundError) as context:
            self.service.resend_email_code(
                user=self.user,
                device_id='non-existent-id',
                ip_address='192.168.1.1'
            )
        
        self.assertIn('Email device not found', str(context.exception))
    
    def test_trigger_sms_fallback_success(self):
        """Test successful SMS fallback triggering."""
        # Create SMS device
        sms_device = MFADevice.objects.create_sms_device(
            user=self.user,
            device_name='My Phone',
            phone_number='+1234567890'
        )
        sms_device.confirm_device()
        
        with patch('enterprise_auth.core.services.sms_mfa_service.SMSMFAService.send_sms_code') as mock_sms:
            mock_sms.return_value = {
                'device_id': str(sms_device.id),
                'code_sent': True
            }
            
            result = self.service.trigger_sms_fallback(
                user=self.user,
                ip_address='192.168.1.1'
            )
            
            # Check result
            self.assertTrue(result['fallback_triggered'])
            self.assertEqual(result['fallback_method'], 'sms')
            self.assertEqual(result['sms_device_id'], str(sms_device.id))
            
            # Check SMS service was called
            mock_sms.assert_called_once()
    
    def test_trigger_sms_fallback_no_sms_devices(self):
        """Test SMS fallback triggering with no SMS devices."""
        with self.assertRaises(MFAError) as context:
            self.service.trigger_sms_fallback(
                user=self.user,
                ip_address='192.168.1.1'
            )
        
        self.assertIn('No SMS devices available for fallback', str(context.exception))
    
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        # Simulate multiple attempts to trigger rate limiting
        for i in range(6):  # Exceed the default limit of 5
            try:
                self.service._check_rate_limit(self.user, '192.168.1.1')
            except MFARateLimitError:
                # Should be raised on the 6th attempt
                self.assertEqual(i, 5)
                break
        else:
            self.fail("Rate limiting should have been triggered")
    
    def test_email_rate_limiting(self):
        """Test email-specific rate limiting."""
        # Simulate multiple email attempts to trigger rate limiting
        for i in range(11):  # Exceed the default limit of 10
            try:
                self.service._check_email_rate_limit(self.user, '192.168.1.1')
            except MFARateLimitError:
                # Should be raised on the 11th attempt
                self.assertEqual(i, 10)
                break
        else:
            self.fail("Email rate limiting should have been triggered")
    
    def test_email_address_masking(self):
        """Test email address masking for privacy."""
        test_cases = [
            ('test@example.com', 'te***@example.com'),
            ('a@b.com', 'a***@b.com'),
            ('user.name@domain.co.uk', 'us***@domain.co.uk'),
            ('', '***@***.***'),
            ('invalid-email', '***@***.***'),
        ]
        
        for email, expected in test_cases:
            with self.subTest(email=email):
                result = self.service._mask_email_address(email)
                self.assertEqual(result, expected)
    
    def test_email_code_generation(self):
        """Test email verification code generation."""
        code = self.service._generate_email_code()
        
        # Check code properties
        self.assertEqual(len(code), 6)  # Default length
        self.assertTrue(code.isdigit())
        
        # Check uniqueness
        codes = set()
        for _ in range(100):
            codes.add(self.service._generate_email_code())
        
        # Should have high uniqueness (at least 90% unique)
        self.assertGreater(len(codes), 90)
    
    def test_email_code_storage_and_retrieval(self):
        """Test email code storage and retrieval from cache."""
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        
        code = '123456'
        
        # Store code
        self.service._store_email_code(device, code)
        
        # Verify code
        self.assertTrue(self.service._verify_email_code(device, code))
        
        # Verify wrong code
        self.assertFalse(self.service._verify_email_code(device, 'wrong'))
        
        # Clear code
        self.service._clear_email_code(device)
        
        # Verify code is cleared
        self.assertFalse(self.service._verify_email_code(device, code))
    
    def test_email_code_expiry(self):
        """Test email code expiry functionality."""
        device = MFADevice.objects.create_email_device(
            user=self.user,
            device_name='My Email',
            email_address='test@example.com'
        )
        
        code = '123456'
        
        # Store code with short expiry
        cache_key = f"email_code:{device.id}"
        cache_data = {
            'code': code,
            'created_at': timezone.now().isoformat(),
            'attempts': 0
        }
        cache.set(cache_key, cache_data, timeout=1)  # 1 second expiry
        
        # Verify code works initially
        self.assertTrue(self.service._verify_email_code(device, code))
        
        # Wait for expiry and verify code no longer works
        import time
        time.sleep(2)
        self.assertFalse(self.service._verify_email_code(device, code))