"""
Tests for SMS Multi-Factor Authentication API views.

This module contains tests for SMS MFA API endpoints including
setup, verification, and error handling.
"""

import json
from unittest.mock import patch, Mock
from django.test import TestCase
from django.urls import reverse
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from ..models import UserProfile, MFADevice


class SMSMFAViewsTestCase(TestCase):
    """Test cases for SMS MFA API views."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Authenticate user
        self.client.force_authenticate(user=self.user)
        
        # Clear cache before each test
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_setup_sms_mfa_success(self, mock_twilio_client):
        """Test successful SMS MFA setup via API."""
        # Mock Twilio client
        mock_client = Mock()
        mock_message = Mock()
        mock_message.sid = 'test_message_sid'
        mock_message.status = 'queued'
        mock_client.messages.create.return_value = mock_message
        mock_twilio_client.return_value = mock_client
        
        url = reverse('core:sms_mfa:setup_sms_mfa')
        data = {
            'device_name': 'Test Phone',
            'phone_number': '+1234567890'
        }
        
        with self.settings(
            TWILIO_ACCOUNT_SID='test_sid',
            TWILIO_AUTH_TOKEN='test_token',
            TWILIO_PHONE_NUMBER='+1234567890'
        ):
            response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        response_data = response.json()
        self.assertIn('device_id', response_data)
        self.assertEqual(response_data['phone_number_masked'], '***-***-7890')
        self.assertTrue(response_data['code_sent'])
        self.assertEqual(response_data['delivery_status'], 'queued')
        self.assertEqual(response_data['message_sid'], 'test_message_sid')
    
    def test_setup_sms_mfa_missing_device_name(self):
        """Test SMS MFA setup with missing device name."""
        url = reverse('core:sms_mfa:setup_sms_mfa')
        data = {
            'phone_number': '+1234567890'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Device name is required', response.json()['error'])
    
    def test_setup_sms_mfa_missing_phone_number(self):
        """Test SMS MFA setup with missing phone number."""
        url = reverse('core:sms_mfa:setup_sms_mfa')
        data = {
            'device_name': 'Test Phone'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Phone number is required', response.json()['error'])
    
    def test_setup_sms_mfa_invalid_phone_number(self):
        """Test SMS MFA setup with invalid phone number."""
        url = reverse('core:sms_mfa:setup_sms_mfa')
        data = {
            'device_name': 'Test Phone',
            'phone_number': 'invalid'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid phone number format', response.json()['error'])
    
    def test_setup_sms_mfa_no_twilio_config(self):
        """Test SMS MFA setup without Twilio configuration."""
        url = reverse('core:sms_mfa:setup_sms_mfa')
        data = {
            'device_name': 'Test Phone',
            'phone_number': '+1234567890'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('SMS service is not configured', response.json()['error'])
    
    def test_confirm_sms_setup_success(self):
        """Test successful SMS setup confirmation via API."""
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
        
        url = reverse('core:sms_mfa:confirm_sms_setup')
        data = {
            'device_id': str(device.id),
            'verification_code': verification_code
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertEqual(response_data['device_id'], str(device.id))
        self.assertEqual(response_data['device_name'], 'Test Phone')
        self.assertEqual(response_data['status'], 'active')
        
        # Verify device was confirmed
        device.refresh_from_db()
        self.assertTrue(device.is_confirmed)
        self.assertEqual(device.status, 'active')
    
    def test_confirm_sms_setup_missing_device_id(self):
        """Test SMS setup confirmation with missing device ID."""
        url = reverse('core:sms_mfa:confirm_sms_setup')
        data = {
            'verification_code': '123456'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Device ID is required', response.json()['error'])
    
    def test_confirm_sms_setup_missing_verification_code(self):
        """Test SMS setup confirmation with missing verification code."""
        url = reverse('core:sms_mfa:confirm_sms_setup')
        data = {
            'device_id': 'test-device-id'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Verification code is required', response.json()['error'])
    
    def test_confirm_sms_setup_device_not_found(self):
        """Test SMS setup confirmation with non-existent device."""
        url = reverse('core:sms_mfa:confirm_sms_setup')
        data = {
            'device_id': 'non-existent-id',
            'verification_code': '123456'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('SMS device not found', response.json()['error'])
    
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
        
        url = reverse('core:sms_mfa:confirm_sms_setup')
        data = {
            'device_id': str(device.id),
            'verification_code': '654321'  # Wrong code
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid or expired SMS code', response.json()['error'])
    
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_send_sms_code_success(self, mock_twilio_client):
        """Test successful SMS code sending via API."""
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
        
        url = reverse('core:sms_mfa:send_sms_code')
        data = {
            'device_id': str(device.id)
        }
        
        with self.settings(
            TWILIO_ACCOUNT_SID='test_sid',
            TWILIO_AUTH_TOKEN='test_token',
            TWILIO_PHONE_NUMBER='+1234567890'
        ):
            response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertEqual(response_data['device_id'], str(device.id))
        self.assertTrue(response_data['code_sent'])
        self.assertEqual(response_data['delivery_status'], 'sent')
        self.assertEqual(response_data['message_sid'], 'test_message_sid')
    
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_send_sms_code_no_device_id(self, mock_twilio_client):
        """Test SMS code sending without device ID (uses first active device)."""
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
        
        url = reverse('core:sms_mfa:send_sms_code')
        data = {}  # No device_id
        
        with self.settings(
            TWILIO_ACCOUNT_SID='test_sid',
            TWILIO_AUTH_TOKEN='test_token',
            TWILIO_PHONE_NUMBER='+1234567890'
        ):
            response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertEqual(response_data['device_id'], str(device.id))
        self.assertTrue(response_data['code_sent'])
    
    def test_send_sms_code_no_active_devices(self):
        """Test SMS code sending with no active devices."""
        url = reverse('core:sms_mfa:send_sms_code')
        data = {}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('No active SMS devices found', response.json()['error'])
    
    def test_verify_sms_code_success(self):
        """Test successful SMS code verification via API."""
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
        
        url = reverse('core:sms_mfa:verify_sms_code')
        data = {
            'verification_code': verification_code,
            'device_id': str(device.id)
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['verified'])
        self.assertEqual(response_data['device_id'], str(device.id))
        self.assertEqual(response_data['device_name'], 'Test Phone')
        
        # Verify code was cleared from cache
        cache_data = cache.get(cache_key)
        self.assertIsNone(cache_data)
    
    def test_verify_sms_code_missing_verification_code(self):
        """Test SMS code verification with missing verification code."""
        url = reverse('core:sms_mfa:verify_sms_code')
        data = {}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Verification code is required', response.json()['error'])
    
    def test_verify_sms_code_invalid_code(self):
        """Test SMS code verification with invalid code."""
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
        
        url = reverse('core:sms_mfa:verify_sms_code')
        data = {
            'verification_code': '654321',  # Wrong code
            'device_id': str(device.id)
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid or expired SMS code', response.json()['error'])
    
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_resend_sms_code_success(self, mock_twilio_client):
        """Test successful SMS code resending via API."""
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
        
        url = reverse('core:sms_mfa:resend_sms_code')
        data = {
            'device_id': str(device.id)
        }
        
        with self.settings(
            TWILIO_ACCOUNT_SID='test_sid',
            TWILIO_AUTH_TOKEN='test_token',
            TWILIO_PHONE_NUMBER='+1234567890'
        ):
            response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertEqual(response_data['device_id'], str(device.id))
        self.assertTrue(response_data['code_sent'])
        self.assertEqual(response_data['delivery_status'], 'sent')
        self.assertEqual(response_data['message_sid'], 'test_message_sid')
    
    def test_resend_sms_code_missing_device_id(self):
        """Test SMS code resending with missing device ID."""
        url = reverse('core:sms_mfa:resend_sms_code')
        data = {}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Device ID is required', response.json()['error'])
    
    def test_resend_sms_code_device_not_found(self):
        """Test SMS code resending with non-existent device."""
        url = reverse('core:sms_mfa:resend_sms_code')
        data = {
            'device_id': 'non-existent-id'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertIn('SMS device not found', response.json()['error'])
    
    @patch('enterprise_auth.core.services.sms_mfa_service.TwilioClient')
    def test_get_sms_delivery_status_success(self, mock_twilio_client):
        """Test successful SMS delivery status retrieval via API."""
        # Mock Twilio client
        mock_client = Mock()
        mock_message = Mock()
        mock_message.sid = 'test_message_sid'
        mock_message.status = 'delivered'
        mock_message.error_code = None
        mock_message.error_message = None
        mock_message.date_sent = timezone.now()
        mock_message.date_updated = timezone.now()
        mock_message.price = '0.0075'
        mock_message.price_unit = 'USD'
        mock_message.direction = 'outbound-api'
        mock_message.num_segments = 1
        mock_client.messages.return_value.fetch.return_value = mock_message
        mock_twilio_client.return_value = mock_client
        
        url = reverse('core:sms_mfa:get_sms_delivery_status')
        
        with self.settings(
            TWILIO_ACCOUNT_SID='test_sid',
            TWILIO_AUTH_TOKEN='test_token'
        ):
            response = self.client.get(url, {'message_sid': 'test_message_sid'})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertEqual(response_data['message_sid'], 'test_message_sid')
        self.assertEqual(response_data['status'], 'delivered')
        self.assertEqual(response_data['price'], '0.0075')
        self.assertEqual(response_data['price_unit'], 'USD')
    
    def test_get_sms_delivery_status_missing_message_sid(self):
        """Test SMS delivery status retrieval with missing message SID."""
        url = reverse('core:sms_mfa:get_sms_delivery_status')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Message SID is required', response.json()['error'])
    
    def test_unauthenticated_access(self):
        """Test that unauthenticated users cannot access SMS MFA endpoints."""
        # Remove authentication
        self.client.force_authenticate(user=None)
        
        endpoints = [
            ('core:sms_mfa:setup_sms_mfa', 'post'),
            ('core:sms_mfa:confirm_sms_setup', 'post'),
            ('core:sms_mfa:send_sms_code', 'post'),
            ('core:sms_mfa:verify_sms_code', 'post'),
            ('core:sms_mfa:resend_sms_code', 'post'),
            ('core:sms_mfa:get_sms_delivery_status', 'get'),
        ]
        
        for endpoint_name, method in endpoints:
            url = reverse(endpoint_name)
            
            if method == 'post':
                response = self.client.post(url, {}, format='json')
            else:
                response = self.client.get(url)
            
            self.assertEqual(
                response.status_code, 
                status.HTTP_401_UNAUTHORIZED,
                f"Endpoint {endpoint_name} should require authentication"
            )
    
    @patch('enterprise_auth.core.services.sms_mfa_service.cache')
    def test_rate_limiting_response(self, mock_cache):
        """Test rate limiting response from SMS MFA endpoints."""
        # Mock cache to simulate rate limit exceeded
        mock_cache.get.return_value = 10  # Exceeds limit
        
        url = reverse('core:sms_mfa:setup_sms_mfa')
        data = {
            'device_name': 'Test Phone',
            'phone_number': '+1234567890'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('Too many', response.json()['error'])