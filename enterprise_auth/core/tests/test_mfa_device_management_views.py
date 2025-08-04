"""
Integration tests for MFA Device Management views.

This module contains comprehensive tests for MFA device management API endpoints
including registration, confirmation, listing, removal, and policy enforcement.
"""

import json
from unittest.mock import patch, Mock
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
from django.core.cache import cache

from enterprise_auth.core.models import UserProfile, MFADevice, MFAAttempt
from enterprise_auth.core.services.mfa_device_management_service import mfa_device_management_service

User = get_user_model()


class TestMFADeviceManagementViews(TestCase):
    """Test cases for MFA Device Management API views."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            organization='Test Corp'
        )
        
        # Authenticate user
        self.client.force_authenticate(user=self.user)
        
        # Clear cache
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    def test_register_mfa_device_totp_success(self):
        """Test successful TOTP device registration."""
        url = reverse('core:register_mfa_device')
        data = {
            'device_type': 'totp',
            'device_name': 'My Phone',
            'device_config': {}
        }
        
        with patch.object(mfa_device_management_service, 'register_device') as mock_register:
            mock_register.return_value = {
                'device_id': 'test-device-id',
                'device_type': 'totp',
                'device_name': 'My Phone',
                'status': 'pending',
                'registration_data': {
                    'secret_key': 'TESTSECRET123',
                    'qr_code_uri': 'otpauth://totp/test'
                },
                'confirmation_required': True,
                'confirmation_timeout_seconds': 3600
            }
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertIn('device_id', response.data['data'])
            self.assertEqual(response.data['data']['device_type'], 'totp')
            
            mock_register.assert_called_once_with(
                user=self.user,
                device_type='totp',
                device_name='My Phone',
                device_config={},
                ip_address=None,  # Mock request doesn't have real IP
                user_agent=None
            )
    
    def test_register_mfa_device_sms_success(self):
        """Test successful SMS device registration."""
        url = reverse('core:register_mfa_device')
        data = {
            'device_type': 'sms',
            'device_name': 'My SMS',
            'device_config': {
                'phone_number': '+1234567890'
            }
        }
        
        with patch.object(mfa_device_management_service, 'register_device') as mock_register:
            mock_register.return_value = {
                'device_id': 'test-sms-device-id',
                'device_type': 'sms',
                'device_name': 'My SMS',
                'status': 'pending',
                'phone_number_masked': '***-***-7890',
                'code_sent': True
            }
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertIn('phone_number_masked', response.data['data'])
            
            mock_register.assert_called_once_with(
                user=self.user,
                device_type='sms',
                device_name='My SMS',
                device_config={'phone_number': '+1234567890'},
                ip_address=None,
                user_agent=None
            )
    
    def test_register_mfa_device_missing_type(self):
        """Test device registration with missing device type."""
        url = reverse('core:register_mfa_device')
        data = {
            'device_name': 'My Device',
            'device_config': {}
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'MISSING_DEVICE_TYPE')
    
    def test_register_mfa_device_missing_name(self):
        """Test device registration with missing device name."""
        url = reverse('core:register_mfa_device')
        data = {
            'device_type': 'totp',
            'device_config': {}
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'MISSING_DEVICE_NAME')
    
    def test_register_mfa_device_service_error(self):
        """Test device registration when service raises error."""
        url = reverse('core:register_mfa_device')
        data = {
            'device_type': 'totp',
            'device_name': 'My Phone',
            'device_config': {}
        }
        
        with patch.object(mfa_device_management_service, 'register_device') as mock_register:
            from enterprise_auth.core.exceptions import MFAError
            mock_register.side_effect = MFAError("Registration failed")
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertFalse(response.data['success'])
            self.assertIn('Registration failed', response.data['error']['message'])
    
    def test_confirm_mfa_device_registration_success(self):
        """Test successful device registration confirmation."""
        # Create pending device
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='My Phone',
            status='pending'
        )
        
        url = reverse('core:confirm_mfa_device_registration')
        data = {
            'device_id': str(device.id),
            'confirmation_data': {
                'verification_code': '123456'
            }
        }
        
        with patch.object(mfa_device_management_service, 'confirm_device_registration') as mock_confirm:
            mock_confirm.return_value = {
                'device_id': str(device.id),
                'device_name': 'My Phone',
                'device_type': 'totp',
                'status': 'active',
                'confirmed_at': '2024-01-15T10:30:00Z',
                'security_score': 0.9
            }
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['status'], 'active')
            
            mock_confirm.assert_called_once_with(
                user=self.user,
                device_id=str(device.id),
                confirmation_data={'verification_code': '123456'},
                ip_address=None,
                user_agent=None
            )
    
    def test_confirm_mfa_device_registration_missing_device_id(self):
        """Test device confirmation with missing device ID."""
        url = reverse('core:confirm_mfa_device_registration')
        data = {
            'confirmation_data': {
                'verification_code': '123456'
            }
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'MISSING_DEVICE_ID')
    
    def test_confirm_mfa_device_registration_device_not_found(self):
        """Test device confirmation with non-existent device."""
        url = reverse('core:confirm_mfa_device_registration')
        data = {
            'device_id': 'non-existent-id',
            'confirmation_data': {
                'verification_code': '123456'
            }
        }
        
        with patch.object(mfa_device_management_service, 'confirm_device_registration') as mock_confirm:
            from enterprise_auth.core.exceptions import MFADeviceNotFoundError
            mock_confirm.side_effect = MFADeviceNotFoundError("Device not found")
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            self.assertFalse(response.data['success'])
    
    def test_list_mfa_devices_success(self):
        """Test successful MFA devices listing."""
        # Create test devices
        active_device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Active Device',
            status='active',
            is_confirmed=True
        )
        
        pending_device = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Pending Device',
            status='pending'
        )
        
        url = reverse('core:list_mfa_devices_detailed')
        
        with patch.object(mfa_device_management_service, 'list_user_devices') as mock_list:
            mock_list.return_value = [
                {
                    'id': str(active_device.id),
                    'name': 'Active Device',
                    'type': 'totp',
                    'status': 'active',
                    'is_active': True,
                    'is_primary': True,
                    'can_be_removed': False,
                    'security_score': 0.9
                }
            ]
            
            response = self.client.get(url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(len(response.data['data']['devices']), 1)
            self.assertEqual(response.data['data']['total_devices'], 1)
            self.assertEqual(response.data['data']['active_devices'], 1)
            
            mock_list.assert_called_once_with(
                user=self.user,
                include_inactive=False,
                device_type_filter=None
            )
    
    def test_list_mfa_devices_with_filters(self):
        """Test MFA devices listing with filters."""
        url = reverse('core:list_mfa_devices_detailed')
        
        with patch.object(mfa_device_management_service, 'list_user_devices') as mock_list:
            mock_list.return_value = []
            
            response = self.client.get(url, {
                'include_inactive': 'true',
                'device_type': 'totp'
            })
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            
            mock_list.assert_called_once_with(
                user=self.user,
                include_inactive=True,
                device_type_filter='totp'
            )
    
    def test_remove_mfa_device_success(self):
        """Test successful MFA device removal."""
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device to Remove',
            status='active',
            is_confirmed=True
        )
        
        url = reverse('core:remove_mfa_device')
        data = {
            'device_id': str(device.id),
            'removal_reason': 'user_request',
            'current_mfa_verification': {
                'type': 'totp',
                'code': '123456'
            }
        }
        
        with patch.object(mfa_device_management_service, 'remove_device') as mock_remove:
            mock_remove.return_value = {
                'removed': True,
                'device_info': {
                    'device_id': str(device.id),
                    'device_name': 'Device to Remove',
                    'device_type': 'totp',
                    'status': 'active',
                    'usage_count': 5
                },
                'removal_reason': 'user_request',
                'removed_at': '2024-01-15T10:30:00Z'
            }
            
            response = self.client.delete(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertTrue(response.data['data']['removed'])
            
            mock_remove.assert_called_once_with(
                user=self.user,
                device_id=str(device.id),
                removal_reason='user_request',
                current_mfa_verification={
                    'type': 'totp',
                    'code': '123456'
                },
                ip_address=None,
                user_agent=None
            )
    
    def test_remove_mfa_device_missing_device_id(self):
        """Test device removal with missing device ID."""
        url = reverse('core:remove_mfa_device')
        data = {
            'removal_reason': 'user_request'
        }
        
        response = self.client.delete(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'MISSING_DEVICE_ID')
    
    def test_remove_mfa_device_not_found(self):
        """Test removing non-existent device."""
        url = reverse('core:remove_mfa_device')
        data = {
            'device_id': 'non-existent-id',
            'removal_reason': 'user_request'
        }
        
        with patch.object(mfa_device_management_service, 'remove_device') as mock_remove:
            from enterprise_auth.core.exceptions import MFADeviceNotFoundError
            mock_remove.side_effect = MFADeviceNotFoundError("Device not found")
            
            response = self.client.delete(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            self.assertFalse(response.data['success'])
    
    def test_get_organization_mfa_policy_success(self):
        """Test successful organization MFA policy retrieval."""
        url = reverse('core:get_organization_mfa_policy')
        
        with patch.object(mfa_device_management_service, 'get_organization_mfa_policy') as mock_get_policy:
            mock_get_policy.return_value = {
                'enforcement_enabled': True,
                'mfa_required': True,
                'allowed_device_types': ['totp', 'sms', 'email', 'backup_codes'],
                'min_devices_required': 2,
                'max_devices_allowed': 10,
                'require_backup_codes': True,
                'allowed_grace_period_hours': 24,
                'enforce_device_diversity': False
            }
            
            response = self.client.get(url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['organization'], 'Test Corp')
            self.assertTrue(response.data['data']['enforcement_enabled'])
            
            mock_get_policy.assert_called_once_with('Test Corp')
    
    def test_get_organization_mfa_policy_no_organization(self):
        """Test organization policy retrieval for user without organization."""
        # Create user without organization
        user_no_org = UserProfile.objects.create_user(
            email='noorg@example.com',
            password='testpass123',
            first_name='No',
            last_name='Org'
        )
        
        self.client.force_authenticate(user=user_no_org)
        
        url = reverse('core:get_organization_mfa_policy')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'NO_ORGANIZATION')
    
    def test_enforce_organization_mfa_policy_success(self):
        """Test successful organization MFA policy enforcement."""
        url = reverse('core:enforce_organization_mfa_policy')
        
        with patch.object(mfa_device_management_service, 'enforce_organization_mfa_policy') as mock_enforce:
            mock_enforce.return_value = {
                'policy_enforced': True,
                'organization': 'Test Corp',
                'compliance_status': 'compliant',
                'compliance_issues': [],
                'active_devices_count': 2,
                'device_types': ['totp', 'backup_codes'],
                'enforcement_actions': [],
                'policy': {
                    'enforcement_enabled': True,
                    'mfa_required': True
                }
            }
            
            response = self.client.post(url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['compliance_status'], 'compliant')
            
            mock_enforce.assert_called_once_with(
                user=self.user,
                ip_address=None,
                user_agent=None
            )
    
    def test_get_device_management_statistics_success(self):
        """Test successful device management statistics retrieval."""
        url = reverse('core:get_device_management_statistics')
        
        with patch.object(mfa_device_management_service, 'get_device_management_statistics') as mock_get_stats:
            mock_get_stats.return_value = {
                'period_days': 30,
                'total_devices': 3,
                'active_devices': 2,
                'pending_devices': 0,
                'disabled_devices': 1,
                'device_type_statistics': {
                    'totp': {
                        'device_count': 1,
                        'total_attempts': 50,
                        'successful_attempts': 48,
                        'failed_attempts': 2
                    }
                }
            }
            
            response = self.client.get(url)
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['total_devices'], 3)
            self.assertEqual(response.data['data']['active_devices'], 2)
            
            mock_get_stats.assert_called_once_with(
                user=self.user,
                days=30
            )
    
    def test_get_device_management_statistics_custom_days(self):
        """Test device management statistics with custom days parameter."""
        url = reverse('core:get_device_management_statistics')
        
        with patch.object(mfa_device_management_service, 'get_device_management_statistics') as mock_get_stats:
            mock_get_stats.return_value = {'period_days': 7}
            
            response = self.client.get(url, {'days': '7'})
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            
            mock_get_stats.assert_called_once_with(
                user=self.user,
                days=7
            )
    
    def test_get_device_management_statistics_invalid_days(self):
        """Test device management statistics with invalid days parameter."""
        url = reverse('core:get_device_management_statistics')
        
        response = self.client.get(url, {'days': 'invalid'})
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'INVALID_DAYS_PARAMETER')
    
    def test_bulk_device_operation_remove_success(self):
        """Test successful bulk device removal operation."""
        # Create test devices
        device1 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device 1',
            status='active',
            is_confirmed=True
        )
        
        device2 = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Device 2',
            status='active',
            is_confirmed=True
        )
        
        # Keep one device to satisfy minimum requirement
        MFADevice.objects.create(
            user=self.user,
            device_type='backup_codes',
            device_name='Backup Codes',
            status='active',
            is_confirmed=True
        )
        
        url = reverse('core:bulk_device_operation')
        data = {
            'operation': 'remove',
            'device_ids': [str(device1.id), str(device2.id)],
            'reason': 'bulk_test',
            'current_mfa_verification': {
                'type': 'backup_code',
                'code': 'ABCD1234'
            }
        }
        
        with patch.object(mfa_device_management_service, 'remove_device') as mock_remove:
            mock_remove.return_value = {
                'removed': True,
                'device_info': {'device_name': 'Test Device'}
            }
            
            response = self.client.post(url, data, format='json')
            
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertTrue(response.data['success'])
            self.assertEqual(response.data['data']['operation'], 'remove')
            self.assertEqual(response.data['data']['total_devices'], 2)
            self.assertEqual(response.data['data']['successful_operations'], 2)
            self.assertEqual(response.data['data']['failed_operations'], 0)
    
    def test_bulk_device_operation_disable_success(self):
        """Test successful bulk device disable operation."""
        # Create test devices
        device1 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Device 1',
            status='active',
            is_confirmed=True
        )
        
        device2 = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Device 2',
            status='active',
            is_confirmed=True
        )
        
        url = reverse('core:bulk_device_operation')
        data = {
            'operation': 'disable',
            'device_ids': [str(device1.id), str(device2.id)],
            'reason': 'security_incident'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['data']['operation'], 'disable')
        self.assertEqual(response.data['data']['successful_operations'], 2)
        
        # Verify devices were disabled
        device1.refresh_from_db()
        device2.refresh_from_db()
        self.assertEqual(device1.status, 'disabled')
        self.assertEqual(device2.status, 'disabled')
    
    def test_bulk_device_operation_missing_operation(self):
        """Test bulk operation with missing operation parameter."""
        url = reverse('core:bulk_device_operation')
        data = {
            'device_ids': ['device1', 'device2']
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'MISSING_OPERATION')
    
    def test_bulk_device_operation_missing_device_ids(self):
        """Test bulk operation with missing device IDs."""
        url = reverse('core:bulk_device_operation')
        data = {
            'operation': 'disable'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'MISSING_DEVICE_IDS')
    
    def test_bulk_device_operation_invalid_operation(self):
        """Test bulk operation with invalid operation type."""
        url = reverse('core:bulk_device_operation')
        data = {
            'operation': 'invalid_operation',
            'device_ids': ['device1', 'device2']
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['error']['code'], 'INVALID_OPERATION')
    
    def test_bulk_device_operation_partial_failure(self):
        """Test bulk operation with partial failures."""
        # Create one valid device and reference one invalid
        device1 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Valid Device',
            status='active',
            is_confirmed=True
        )
        
        url = reverse('core:bulk_device_operation')
        data = {
            'operation': 'disable',
            'device_ids': [str(device1.id), 'invalid-device-id'],
            'reason': 'test'
        }
        
        response = self.client.post(url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['data']['successful_operations'], 1)
        self.assertEqual(response.data['data']['failed_operations'], 1)
        
        # Check individual results
        results = response.data['data']['results']
        self.assertEqual(len(results), 2)
        
        # First device should succeed
        self.assertTrue(results[0]['success'])
        self.assertEqual(results[0]['device_id'], str(device1.id))
        
        # Second device should fail
        self.assertFalse(results[1]['success'])
        self.assertEqual(results[1]['device_id'], 'invalid-device-id')
        self.assertIn('error', results[1])
    
    def test_unauthenticated_access_denied(self):
        """Test that unauthenticated requests are denied."""
        self.client.force_authenticate(user=None)
        
        urls = [
            reverse('core:register_mfa_device'),
            reverse('core:confirm_mfa_device_registration'),
            reverse('core:list_mfa_devices_detailed'),
            reverse('core:remove_mfa_device'),
            reverse('core:get_organization_mfa_policy'),
            reverse('core:enforce_organization_mfa_policy'),
            reverse('core:get_device_management_statistics'),
            reverse('core:bulk_device_operation'),
        ]
        
        for url in urls:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TestMFADeviceManagementViewsIntegration(TestCase):
    """Integration tests for MFA Device Management views with real service calls."""
    
    def setUp(self):
        """Set up test data."""
        self.client = APIClient()
        
        # Create test user
        self.user = UserProfile.objects.create_user(
            email='integration@example.com',
            password='testpass123',
            first_name='Integration',
            last_name='Test',
            organization='Integration Corp'
        )
        
        # Authenticate user
        self.client.force_authenticate(user=self.user)
        
        # Clear cache
        cache.clear()
    
    def tearDown(self):
        """Clean up after tests."""
        cache.clear()
    
    def test_device_lifecycle_integration(self):
        """Test complete device lifecycle through API endpoints."""
        # 1. Register TOTP device
        register_url = reverse('core:register_mfa_device')
        register_data = {
            'device_type': 'totp',
            'device_name': 'Integration Test Device',
            'device_config': {}
        }
        
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.setup_totp.return_value = {
                'device_id': 'test-device-id',
                'secret_key': 'TESTSECRET123'
            }
            
            register_response = self.client.post(register_url, register_data, format='json')
            self.assertEqual(register_response.status_code, status.HTTP_200_OK)
        
        # 2. Create actual device for confirmation
        device = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Integration Test Device',
            status='pending'
        )
        
        # 3. Confirm device registration
        confirm_url = reverse('core:confirm_mfa_device_registration')
        confirm_data = {
            'device_id': str(device.id),
            'confirmation_data': {
                'verification_code': '123456'
            }
        }
        
        with patch('enterprise_auth.core.services.mfa_device_management_service.MFAService') as mock_mfa_service:
            mock_mfa_service.return_value.confirm_totp_setup.return_value = {
                'device_id': str(device.id),
                'device_name': 'Integration Test Device',
                'status': 'active'
            }
            
            confirm_response = self.client.post(confirm_url, confirm_data, format='json')
            self.assertEqual(confirm_response.status_code, status.HTTP_200_OK)
        
        # 4. List devices
        list_url = reverse('core:list_mfa_devices_detailed')
        list_response = self.client.get(list_url)
        
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        # Note: This will show 0 devices because the mock didn't actually confirm the device
        # In a real scenario, the device would be confirmed and show up in the list
        
        # 5. Get statistics
        stats_url = reverse('core:get_device_management_statistics')
        stats_response = self.client.get(stats_url)
        
        self.assertEqual(stats_response.status_code, status.HTTP_200_OK)
        self.assertIn('total_devices', stats_response.data['data'])
    
    def test_organization_policy_integration(self):
        """Test organization policy enforcement through API endpoints."""
        # 1. Get organization policy
        policy_url = reverse('core:get_organization_mfa_policy')
        policy_response = self.client.get(policy_url)
        
        self.assertEqual(policy_response.status_code, status.HTTP_200_OK)
        self.assertEqual(policy_response.data['data']['organization'], 'Integration Corp')
        
        # 2. Enforce organization policy
        enforce_url = reverse('core:enforce_organization_mfa_policy')
        enforce_response = self.client.post(enforce_url)
        
        self.assertEqual(enforce_response.status_code, status.HTTP_200_OK)
        self.assertIn('compliance_status', enforce_response.data['data'])
    
    def test_bulk_operations_integration(self):
        """Test bulk operations through API endpoints."""
        # Create test devices
        device1 = MFADevice.objects.create(
            user=self.user,
            device_type='totp',
            device_name='Bulk Test Device 1',
            status='active',
            is_confirmed=True
        )
        
        device2 = MFADevice.objects.create(
            user=self.user,
            device_type='sms',
            device_name='Bulk Test Device 2',
            status='active',
            is_confirmed=True
        )
        
        # Test bulk disable
        bulk_url = reverse('core:bulk_device_operation')
        bulk_data = {
            'operation': 'disable',
            'device_ids': [str(device1.id), str(device2.id)],
            'reason': 'integration_test'
        }
        
        bulk_response = self.client.post(bulk_url, bulk_data, format='json')
        
        self.assertEqual(bulk_response.status_code, status.HTTP_200_OK)
        self.assertEqual(bulk_response.data['data']['successful_operations'], 2)
        
        # Verify devices were disabled
        device1.refresh_from_db()
        device2.refresh_from_db()
        self.assertEqual(device1.status, 'disabled')
        self.assertEqual(device2.status, 'disabled')