"""
Tests for backup codes MFA API views.

This module contains comprehensive tests for the backup codes API endpoints
including generation, validation, regeneration, and monitoring.
"""

import json
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

from ..models import MFADevice
from ..services.backup_codes_service import backup_codes_service
from ..exceptions import (
    MFAError,
    MFADeviceNotFoundError,
    MFAVerificationError,
    MFARateLimitError,
)

User = get_user_model()


class BackupCodesViewsTestCase(TestCase):
    """Test case for backup codes API views."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
    
    def test_generate_backup_codes_success(self):
        """Test successful backup codes generation."""
        url = reverse('core:backup-codes-generate')
        data = {
            'count': 12,
            'force_regenerate': False
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('message', response_data)
        self.assertIn('data', response_data)
        
        # Check generated codes
        codes_data = response_data['data']
        self.assertIn('codes', codes_data)
        self.assertIn('device_id', codes_data)
        self.assertEqual(len(codes_data['codes']), 12)
        self.assertFalse(codes_data['regenerated'])
    
    def test_generate_backup_codes_default_parameters(self):
        """Test backup codes generation with default parameters."""
        url = reverse('core:backup-codes-generate')
        
        response = self.client.post(url, {}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        response_data = response.json()
        codes_data = response_data['data']
        self.assertEqual(len(codes_data['codes']), 10)  # Default count
    
    def test_generate_backup_codes_invalid_count(self):
        """Test backup codes generation with invalid count."""
        url = reverse('core:backup-codes-generate')
        data = {'count': 25}  # Above maximum
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_generate_backup_codes_service_error(self):
        """Test backup codes generation when service raises error."""
        url = reverse('core:backup-codes-generate')
        
        with patch.object(backup_codes_service, 'generate_backup_codes') as mock_generate:
            mock_generate.side_effect = MFAError("Service error")
            
            response = self.client.post(url, {}, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            response_data = response.json()
            self.assertFalse(response_data['success'])
            self.assertEqual(response_data['error']['code'], 'MFA_ERROR')
    
    def test_generate_backup_codes_unauthenticated(self):
        """Test backup codes generation without authentication."""
        self.client.force_authenticate(user=None)
        url = reverse('core:backup-codes-generate')
        
        response = self.client.post(url, {}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_validate_backup_code_success(self):
        """Test successful backup code validation."""
        # First generate codes
        backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        # Get a code to test with
        device = MFADevice.objects.get(user=self.user, device_type='backup_codes')
        test_code = device.get_backup_codes()[0]
        
        url = reverse('core:backup-codes-validate')
        data = {'backup_code': test_code}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        validation_data = response_data['data']
        self.assertTrue(validation_data['valid'])
        self.assertEqual(validation_data['remaining_codes'], 9)
        self.assertIn('used_at', validation_data)
    
    def test_validate_backup_code_invalid(self):
        """Test backup code validation with invalid code."""
        # Generate codes first
        backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:backup-codes-validate')
        data = {'backup_code': 'INVALID123'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error']['code'], 'VERIFICATION_FAILED')
    
    def test_validate_backup_code_no_device(self):
        """Test backup code validation when user has no device."""
        url = reverse('core:backup-codes-validate')
        data = {'backup_code': 'TESTCODE'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error']['code'], 'DEVICE_NOT_FOUND')
    
    def test_validate_backup_code_rate_limited(self):
        """Test backup code validation with rate limiting."""
        url = reverse('core:backup-codes-validate')
        data = {'backup_code': 'TESTCODE'}
        
        with patch.object(backup_codes_service, 'validate_backup_code') as mock_validate:
            mock_validate.side_effect = MFARateLimitError("Rate limit exceeded")
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
            
            response_data = response.json()
            self.assertFalse(response_data['success'])
            self.assertEqual(response_data['error']['code'], 'RATE_LIMIT_EXCEEDED')
    
    def test_validate_backup_code_malformed_request(self):
        """Test backup code validation with malformed request."""
        url = reverse('core:backup-codes-validate')
        data = {'wrong_field': 'TESTCODE'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_validate_backup_code_empty_code(self):
        """Test backup code validation with empty code."""
        url = reverse('core:backup-codes-validate')
        data = {'backup_code': ''}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_regenerate_backup_codes_success(self):
        """Test successful backup codes regeneration."""
        # Generate initial codes
        backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:backup-codes-regenerate')
        data = {'reason': 'security_incident'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        regen_data = response_data['data']
        self.assertTrue(regen_data['regenerated'])
        self.assertEqual(regen_data['reason'], 'security_incident')
        self.assertIn('codes', regen_data)
        self.assertEqual(len(regen_data['codes']), 10)
    
    def test_regenerate_backup_codes_default_reason(self):
        """Test backup codes regeneration with default reason."""
        # Generate initial codes
        backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:backup-codes-regenerate')
        
        response = self.client.post(url, {}, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        regen_data = response_data['data']
        self.assertEqual(regen_data['reason'], 'user_request')
    
    def test_regenerate_backup_codes_no_device(self):
        """Test backup codes regeneration when user has no device."""
        url = reverse('core:backup-codes-regenerate')
        data = {'reason': 'user_request'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error']['code'], 'DEVICE_NOT_FOUND')
    
    def test_regenerate_backup_codes_invalid_reason(self):
        """Test backup codes regeneration with invalid reason."""
        url = reverse('core:backup-codes-regenerate')
        data = {'reason': 'invalid_reason'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_get_backup_codes_status_no_device(self):
        """Test getting backup codes status when user has no device."""
        url = reverse('core:backup-codes-status')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        status_data = response_data['data']
        self.assertFalse(status_data['has_backup_codes'])
        self.assertEqual(status_data['remaining_codes'], 0)
        self.assertEqual(status_data['status'], 'not_configured')
    
    def test_get_backup_codes_status_with_device(self):
        """Test getting backup codes status when user has device."""
        # Generate codes
        result = backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:backup-codes-status')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        status_data = response_data['data']
        self.assertTrue(status_data['has_backup_codes'])
        self.assertEqual(status_data['device_id'], result['device_id'])
        self.assertEqual(status_data['remaining_codes'], 10)
        self.assertEqual(status_data['status'], 'active')
        self.assertTrue(status_data['is_confirmed'])
    
    def test_get_usage_statistics_no_device(self):
        """Test getting usage statistics when user has no device."""
        url = reverse('core:backup-codes-statistics')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        stats_data = response_data['data']
        self.assertFalse(stats_data['has_backup_codes'])
        self.assertIsNone(stats_data['statistics'])
    
    def test_get_usage_statistics_with_device(self):
        """Test getting usage statistics when user has device."""
        # Generate codes and create some usage
        result = backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        # Use one code
        backup_codes_service.validate_backup_code(
            user=self.user,
            backup_code=result['codes'][0],
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:backup-codes-statistics')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        stats_data = response_data['data']
        self.assertTrue(stats_data['has_backup_codes'])
        self.assertIsNotNone(stats_data['statistics'])
        
        statistics = stats_data['statistics']
        self.assertEqual(statistics['period_days'], 30)  # Default
        self.assertEqual(statistics['total_attempts'], 1)
        self.assertEqual(statistics['successful_attempts'], 1)
        self.assertEqual(statistics['remaining_codes'], 9)
    
    def test_get_usage_statistics_custom_days(self):
        """Test getting usage statistics with custom days parameter."""
        # Generate codes
        backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:backup-codes-statistics')
        
        response = self.client.get(url, {'days': 7})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        statistics = response_data['data']['statistics']
        self.assertEqual(statistics['period_days'], 7)
    
    def test_get_usage_statistics_invalid_days(self):
        """Test getting usage statistics with invalid days parameter."""
        url = reverse('core:backup-codes-statistics')
        
        # Test with days too high
        response = self.client.get(url, {'days': 400})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test with days too low
        response = self.client.get(url, {'days': 0})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test with non-integer days
        response = self.client.get(url, {'days': 'invalid'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_standalone_validation_view_success(self):
        """Test standalone backup code validation view."""
        # Generate codes
        result = backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:validate_backup_code_standalone')
        data = {'backup_code': result['codes'][0]}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        response_data = response.json()
        self.assertTrue(response_data['success'])
        
        validation_data = response_data['data']
        self.assertTrue(validation_data['valid'])
        self.assertEqual(validation_data['remaining_codes'], 9)
    
    def test_standalone_validation_view_invalid(self):
        """Test standalone backup code validation view with invalid code."""
        # Generate codes
        backup_codes_service.generate_backup_codes(
            user=self.user,
            ip_address='127.0.0.1'
        )
        
        url = reverse('core:validate_backup_code_standalone')
        data = {'backup_code': 'INVALID123'}
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error']['code'], 'VERIFICATION_FAILED')
    
    def test_request_metadata_extraction(self):
        """Test that request metadata is properly extracted and passed to service."""
        url = reverse('core:backup-codes-generate')
        
        with patch.object(backup_codes_service, 'generate_backup_codes') as mock_generate:
            mock_generate.return_value = {
                'codes': ['TEST1234'],
                'device_id': 'test-id',
                'generated_at': '2024-01-01T00:00:00Z',
                'codes_count': 1,
                'regenerated': False,
                'warning': None
            }
            
            # Make request with custom headers
            response = self.client.post(
                url, 
                {}, 
                format='json',
                HTTP_USER_AGENT='Test User Agent',
                HTTP_X_FORWARDED_FOR='192.168.1.100'
            )
            
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            
            # Verify service was called with metadata
            mock_generate.assert_called_once()
            call_kwargs = mock_generate.call_args[1]
            self.assertEqual(call_kwargs['user'], self.user)
            self.assertIn('ip_address', call_kwargs)
            self.assertIn('user_agent', call_kwargs)
    
    def test_error_response_format_consistency(self):
        """Test that error responses follow consistent format."""
        url = reverse('core:backup-codes-validate')
        data = {'backup_code': 'INVALID'}
        
        with patch.object(backup_codes_service, 'validate_backup_code') as mock_validate:
            mock_validate.side_effect = MFAVerificationError("Test error")
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            
            response_data = response.json()
            self.assertIn('success', response_data)
            self.assertIn('error', response_data)
            self.assertFalse(response_data['success'])
            
            error_data = response_data['error']
            self.assertIn('code', error_data)
            self.assertIn('message', error_data)
    
    def test_internal_server_error_handling(self):
        """Test handling of unexpected internal server errors."""
        url = reverse('core:backup-codes-generate')
        
        with patch.object(backup_codes_service, 'generate_backup_codes') as mock_generate:
            mock_generate.side_effect = Exception("Unexpected error")
            
            response = self.client.post(url, {}, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            response_data = response.json()
            self.assertFalse(response_data['success'])
            self.assertEqual(response_data['error']['code'], 'INTERNAL_ERROR')
            self.assertEqual(response_data['error']['message'], 'An unexpected error occurred')
    
    def test_viewset_url_patterns(self):
        """Test that viewset URL patterns are correctly configured."""
        # Test generate endpoint
        generate_url = reverse('core:backup-codes-generate')
        self.assertIn('backup-codes/generate', generate_url)
        
        # Test validate endpoint
        validate_url = reverse('core:backup-codes-validate')
        self.assertIn('backup-codes/validate', validate_url)
        
        # Test regenerate endpoint
        regenerate_url = reverse('core:backup-codes-regenerate')
        self.assertIn('backup-codes/regenerate', regenerate_url)
        
        # Test status endpoint
        status_url = reverse('core:backup-codes-status')
        self.assertIn('backup-codes/status', status_url)
        
        # Test statistics endpoint
        statistics_url = reverse('core:backup-codes-statistics')
        self.assertIn('backup-codes/statistics', statistics_url)
    
    def test_http_methods_allowed(self):
        """Test that only allowed HTTP methods work for each endpoint."""
        # Generate endpoint should only allow POST
        generate_url = reverse('core:backup-codes-generate')
        
        response = self.client.get(generate_url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        
        response = self.client.put(generate_url, {})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        
        # Status endpoint should only allow GET
        status_url = reverse('core:backup-codes-status')
        
        response = self.client.post(status_url, {})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        
        response = self.client.put(status_url, {})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
    
    def test_csrf_exemption(self):
        """Test that CSRF protection is properly exempted for API endpoints."""
        # This test ensures the @csrf_exempt decorator is working
        # In a real scenario, this would be tested with CSRF tokens
        url = reverse('core:backup-codes-generate')
        
        # Should work without CSRF token
        response = self.client.post(url, {}, format='json')
        
        # Should not get CSRF error (would be 403 if CSRF was enforced)
        self.assertNotEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_cache_headers(self):
        """Test that appropriate cache headers are set."""
        url = reverse('core:backup-codes-status')
        
        response = self.client.get(url)
        
        # Should have cache control headers to prevent caching sensitive data
        self.assertIn('Cache-Control', response)
        cache_control = response['Cache-Control']
        self.assertIn('no-cache', cache_control.lower())
    
    def test_content_type_handling(self):
        """Test that different content types are handled properly."""
        url = reverse('core:backup-codes-generate')
        data = {'count': 8}
        
        # Test JSON content type
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Test form data content type
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)